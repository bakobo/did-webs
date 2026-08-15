"""didwebs.document — the DID document derived from verified state.

Every assertion here is against the spec's own normative text (`## DID documents` and the
sections under it, in ``~/code/wot/kswg-did-method-webs-specification/spec/body.md``), and the
last group reproduces the spec's `### Full Example` end to end as a golden fixture.

Two kinds of input. Where a property is a projection of *key state* — verification methods,
thresholds, services — the tests plant that state directly: a :class:`KeyState` stub carrying
exactly the Kever attributes the module reads, and location/endpoint records written into a
scratch keripy database. That is how the spec's worked examples, whose private keys nobody has,
can be run through our derivation at all. Where a property is a projection of a *stream* —
designations, delegation, abandonment — the tests use the fixture toolkit and go through
``ingest``, so the whole pipeline is under test rather than a convenient shape.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64encode
from dataclasses import dataclass, field

import builders
import keri_api
import pytest
from bakobo.errors import BakoboError
from keri.core import coring
from keri.core.coring import MtrDex
from keri.recording import EndpointRecord, LocationRecord

from didwebs import did as did_module
from didwebs import document, ingest

# The spec's `### Full Example`, verbatim: its controller AID, its signing key, its witness,
# and the two designations its ACDC carries.
SPEC_AID = "EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP"
SPEC_KEY = "DJg7AQUSKAEo-Pkgj4tVF7L0-FqJt0QFxFh5878AcZv6"
SPEC_X = "mDsBBRIoASj4-SCPi1UXsvT4Wom3RAXEWHnzvwBxm_o"
SPEC_WITNESS = "BJqHtDoLT_K_XyOgr2ejBOqD9276TYMTg2EEqWKs-V0q"
SPEC_HTTPS = "https://wit1.did-webs-service:5641/"
SPEC_TCP = "tcp://wit1.did-webs-service:5631/"
SPEC_DID = f"did:webs:did-webs-service%3a7702:{SPEC_AID}"
SPEC_IDS = [f"did:web:did-webs-service%3a7702:{SPEC_AID}", SPEC_DID]

# Two keys from the spec's `#### Thresholds` examples, whose expected weights the spec states.
KEY_A = "DA-vW9ynSkvOWv5e7idtikLANdS6pGO2IHJy7v0rypvE"
KEY_B = "DLWJrsKIHrrn1Q1jy2oEi8Bmv6aEcwuyIqgngVf2nNwu"


@dataclass
class KeyState:
    """The Kever surface :mod:`didwebs.document` reads, and nothing else.

    A real ``Kever`` cannot be built for a key whose private half nobody has, so the spec's
    worked examples are run through the derivation with this stub. Every field is named and
    typed exactly as ``keri.core.eventing.Kever`` names it, so the stub cannot drift into
    testing an interface the product does not use.
    """

    verfers: list
    tholder: coring.Tholder
    wits: list = field(default_factory=list)
    ndigers: list = field(default_factory=lambda: [object()])
    delpre: str | None = None


def verfer(qb64: str) -> coring.Verfer:
    return coring.Verfer(qb64=qb64)


def state(*keys: str, sith="1", wits=(), **kwa) -> KeyState:
    return KeyState(
        verfers=[verfer(key) for key in keys],
        tholder=coring.Tholder(sith=sith),
        wits=list(wits),
        **kwa,
    )


def parsed(did: str = SPEC_DID) -> did_module.WebsDid:
    return did_module.parse(did)


@pytest.fixture
def db():
    """An empty scratch keripy database, for planting endpoint state into."""
    with ingest.open_scratch() as scratch:
        yield scratch.hby.db


def plant_location(db, eid: str, scheme: str, url: str) -> None:
    """What an accepted ``/loc/scheme`` reply leaves behind (keripy ``db.locs``)."""
    db.locs.pin(keys=(eid, scheme), val=LocationRecord(url=url))


def plant_role(db, cid: str, role: str, eid: str, *, allowed: bool = True) -> None:
    """What an accepted ``/end/role/add`` reply leaves behind (keripy ``db.ends``)."""
    db.ends.pin(keys=(cid, role, eid), val=EndpointRecord(allowed=allowed))


def fixture(knob, tmp_path):
    return builders.KNOBS[knob](tmp_path)


def derived(knob, tmp_path):
    """The document a fixture's stream derives, through the whole pipeline."""
    stream, facts = fixture(knob, tmp_path)
    did = did_module.parse(facts["did_webs"])
    with ingest.ingest(stream, did) as verified:
        return document.derive_document(verified, did), facts


# ---------------------------------------------------------------- verification methods


def test_an_ed25519_key_becomes_a_json_web_key_verification_method():
    """`#### Ed25519`: type JsonWebKey, a relative-DID-URL id fragmented on the CESR key, and a
    JWK whose `x` is the raw key — the CESR derivation code stripped — in unpadded base64url."""
    methods, _ = document.verification_methods(state(SPEC_KEY), parsed())

    assert methods == [
        {
            "id": f"#{SPEC_KEY}",
            "type": "JsonWebKey",
            "controller": parsed().compose(),
            "publicKeyJwk": {
                "kid": SPEC_KEY,
                "kty": "OKP",
                "crv": "Ed25519",
                "x": SPEC_X,
            },
        }
    ]


def test_the_jwk_x_value_is_the_raw_key_and_carries_no_padding():
    raw = verfer(SPEC_KEY).raw
    assert SPEC_X == urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert len(raw) == 32  # the derivation code is stripped, not encoded


def test_a_non_ed25519_key_is_refused_rather_than_encoded_as_one(tmp_path):
    """Decision 3woefn, end to end: everything about this publication is valid except the
    curve, and the pipeline says so instead of emitting an Ed25519 JWK over secp key bytes."""
    stream, facts = fixture("secp_keys", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified, pytest.raises(BakoboError) as caught:
        document.derive_document(verified, did)

    assert caught.value.code == "e.feature.unsupported.key.alg.f"
    assert caught.value.retryable is False
    assert facts["key_alg"] in str(caught.value)


def test_the_key_algorithm_name_is_the_curve_the_spec_names_it():
    """The names in the error come from the spec's own subsection headings, so an operator
    reading `e.feature.unsupported.key.alg.f` sees `secp256k1`, not a CESR code."""
    assert document.key_algorithm(MtrDex.ECDSA_256k1) == "secp256k1"
    assert document.key_algorithm(MtrDex.ECDSA_256k1N) == "secp256k1"
    assert document.key_algorithm(MtrDex.ECDSA_256r1) == "secp256r1"
    assert document.key_algorithm(MtrDex.ECDSA_256r1N) == "secp256r1"


def test_a_key_algorithm_this_build_has_no_name_for_is_reported_by_its_cesr_code():
    """Fail closed and stay honest: an unnamed code is named as itself rather than guessed at."""
    assert document.key_algorithm(MtrDex.X25519) == MtrDex.X25519


# ------------------------------------------------------------------------- thresholds


def test_a_single_key_threshold_adds_no_conditional_proof():
    """`#### Thresholds` only mandates a ConditionalProof2022 when kt is greater than 1."""
    methods, references = document.verification_methods(state(SPEC_KEY), parsed())

    assert [method["type"] for method in methods] == ["JsonWebKey"]
    assert references == [f"#{SPEC_KEY}"]


def test_an_integer_threshold_above_one_adds_a_conditional_proof_over_every_key():
    methods, references = document.verification_methods(
        state(SPEC_KEY, KEY_A, KEY_B, sith="2"), parsed()
    )

    assert methods[-1] == {
        "id": f"#{SPEC_AID}",
        "type": "ConditionalProof2022",
        "controller": parsed().compose(),
        "threshold": 2,
        "conditionThreshold": [f"#{SPEC_KEY}", f"#{KEY_A}", f"#{KEY_B}"],
    }
    assert references == [f"#{SPEC_AID}"]


def test_a_single_weighted_clause_expands_over_the_lowest_common_denominator():
    """The spec's own worked example: `["1/2", "1/3", "1/4"]` becomes threshold 12 with
    weights 6, 4 and 3."""
    methods, references = document.verification_methods(
        state(SPEC_KEY, KEY_A, KEY_B, sith=["1/2", "1/3", "1/4"]), parsed()
    )

    assert methods[-1] == {
        "id": f"#{SPEC_AID}",
        "type": "ConditionalProof2022",
        "controller": parsed().compose(),
        "threshold": 12,
        "conditionWeightedThreshold": [
            {"condition": f"#{SPEC_KEY}", "weight": 6},
            {"condition": f"#{KEY_A}", "weight": 4},
            {"condition": f"#{KEY_B}", "weight": 3},
        ],
    }
    assert references == [f"#{SPEC_AID}"]


def test_a_multi_clause_threshold_fails_closed_and_projects_nothing(tmp_path):
    """KRT-F3, end to end. The GLEIF reference truncates a conjunctive threshold to its first
    clause and publishes a document understating the controller's threshold. Two predicates
    here: the publication fails with the unsupported-threshold code, and — the half that
    catches a truncating implementation — no document, and no clause-0 projection of it,
    escapes."""
    stream, facts = fixture("multi_clause_kt", tmp_path)
    did = did_module.parse(facts["did_webs"])
    assert facts["kt"] == builders.MULTI_CLAUSE_SITH  # the fixture really is conjunctive

    with ingest.ingest(stream, did) as verified:
        with pytest.raises(BakoboError) as caught:
            document.derive_document(verified, did)

        assert caught.value.code == "e.feature.unsupported.threshold.f"
        assert caught.value.retryable is False

        kever = verified.hby.kevers[did.aid]
        truncated = document.threshold_method(
            coring.Tholder(thold=kever.tholder.thold[:1]), [], parsed(), did.aid
        )
        assert truncated["threshold"] == 2  # what the reference would have published
        with pytest.raises(BakoboError):
            document.verification_methods(kever, did)  # and what we refuse to


def test_a_nested_weighted_set_fails_closed_too():
    """A clause may itself weight a *set* of keys. ConditionalProof2022 as the spec maps it has
    one flat list of conditions and cannot express that either, so it takes the same refusal —
    the code's message names the multi-clause case, which is the same unrepresentability."""
    nested = coring.Tholder(sith=[{"1/2": ["1", "1"]}, "1/2"])

    with pytest.raises(BakoboError) as caught:
        document.threshold_method(nested, [], parsed(), SPEC_AID)

    assert caught.value.code == "e.feature.unsupported.threshold.f"


# --------------------------------------------------------------- verification relationships


def test_both_relationships_are_mandatory_and_carry_the_same_references(tmp_path):
    """`### Verification Relationships`: a conforming document MUST include `authentication`
    and `assertionMethod`, and did:webs commits the same keys to both. The reference omits
    them entirely."""
    doc, _ = derived("base", tmp_path)

    assert doc["authentication"] == doc["assertionMethod"]
    assert doc["authentication"] == [method["id"] for method in doc["verificationMethod"]]
    assert all(reference.startswith("#") for reference in doc["authentication"])


# --------------------------------------------------------------------------- alsoKnownAs


def test_also_known_as_carries_the_designated_aliases_and_always_did_keri(tmp_path):
    """`### Also Known As`: every AID-controlled identifier the designation authorizes, and
    `did:keri:<aid>`, which a did:webs document MUST provide. The document's own id is not
    among them — it is the subject, not an alias, which is what the spec's Full Example and
    its designated-aliases example both show."""
    doc, facts = derived("base", tmp_path)

    assert doc["alsoKnownAs"] == [facts["did_web"], f"did:keri:{facts['aid']}"]
    assert doc["id"] not in doc["alsoKnownAs"]


def test_a_designation_spelled_differently_is_still_the_documents_own_subject(tmp_path):
    """KRT-F5 on the emission side: the designation spells the port marker `%3a` and the host
    in upper case, the document id spells them canonically, and the two are the same
    identifier — so the subject is not also listed as an alias of itself."""
    stream, facts = fixture("spelling_variants", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified:
        doc = document.derive_document(verified, did)

    assert doc["id"] not in doc["alsoKnownAs"]
    assert doc["id"] != verified.acdc.attrib["ids"][1]  # spelled differently, same identifier
    assert len(doc["alsoKnownAs"]) == 2  # the did:web form, then did:keri


def test_an_alias_naming_another_aid_fails_the_publication(tmp_path):
    """KRT-F4. The spec constrains `alsoKnownAs` to DIDs with the same AID; ingest deliberately
    tolerates a designation this method cannot read, so enforcing the same-AID rule on the ones
    it *can* read is this module's job."""
    stream, facts = fixture("alias_foreign_aid", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified, pytest.raises(BakoboError) as caught:
        document.derive_document(verified, did)

    assert caught.value.code == "e.rule.alias.aid.mismatch.f"
    assert caught.value.retryable is False
    assert facts["foreign_alias"] in str(caught.value)


def test_a_designation_of_another_did_method_is_not_published_as_an_alias():
    """An entry this method cannot parse cannot be checked against the same-AID rule either.
    Publishing it anyway would put an unverifiable alias under Bakobo's domain, so it is
    dropped — the same fail-closed reading ingest applies when it declines to be scoped by it."""
    aliases = document.also_known_as(
        [
            f"did:web:example.com:{SPEC_AID}",
            f"did:example:{SPEC_AID}",
            f"did:webs:not a host:{SPEC_AID}",
        ],
        parsed(),
    )

    assert aliases == [f"did:web:example.com:{SPEC_AID}", f"did:keri:{SPEC_AID}"]


def test_a_designation_that_already_names_the_did_keri_form_is_not_duplicated():
    """`did:keri:<aid>` is appended because the spec says a did:webs document MUST provide it,
    and a designation of the same string cannot duplicate it: a did:keri entry is not a
    did:web(s) identifier, so it is dropped along with every other unreadable designation."""
    aliases = document.also_known_as([f"did:keri:{SPEC_AID}"], parsed())

    assert aliases == [f"did:keri:{SPEC_AID}"]


def test_the_subject_is_dropped_wherever_the_controller_designated_it():
    """The designation order is the controller's, and the subject may sit anywhere in it."""
    aliases = document.also_known_as(
        [SPEC_DID, SPEC_IDS[0], f"did:webs:foo.example:{SPEC_AID}"], parsed()
    )

    assert aliases == [SPEC_IDS[0], f"did:webs:foo.example:{SPEC_AID}", f"did:keri:{SPEC_AID}"]


# ------------------------------------------------------------------------------ services


def test_a_witness_in_key_state_with_a_location_becomes_a_witness_service(db):
    """`#### Witness Service Endpoint`: the witness role comes from the KEL's `b` field, the
    URLs from `/loc/scheme` replies, and the entry is keyed `#<witness-aid>/witness`."""
    plant_location(db, SPEC_WITNESS, "https", SPEC_HTTPS)
    plant_location(db, SPEC_WITNESS, "tcp", SPEC_TCP)

    services = document.services(db, state(SPEC_KEY, wits=[SPEC_WITNESS]), parsed())

    assert services == [
        {
            "id": f"#{SPEC_WITNESS}/witness",
            "type": "witness",
            "serviceEndpoint": {"https": SPEC_HTTPS, "tcp": SPEC_TCP},
        }
    ]


def test_a_witness_with_no_declared_location_projects_no_service(db):
    """Both halves are required: a witness nobody can reach has no endpoint to publish."""
    assert document.services(db, state(SPEC_KEY, wits=[SPEC_WITNESS]), parsed()) == []


def test_a_nullified_location_is_not_published_as_an_endpoint(db):
    """BADA nullifies a location by replying with an empty url; the record stays, the endpoint
    is gone."""
    plant_location(db, SPEC_WITNESS, "https", "")

    assert document.services(db, state(SPEC_KEY, wits=[SPEC_WITNESS]), parsed()) == []


def test_mailbox_and_agent_roles_are_projected_from_a_real_endpoint_stream(tmp_path):
    """`#### Mailbox Service Endpoint` and `#### Agent Service Endpoint`, end to end: the
    `endpoints` fixture's four reply records, ingested and audited, become two services."""
    doc, facts = derived("endpoints", tmp_path)

    assert doc["service"] == [
        {
            "id": f"#{facts['mailbox_aid']}/mailbox",
            "type": "mailbox",
            "serviceEndpoint": {"http": facts["mailbox_url"]},
        },
        {
            "id": f"#{facts['agent_aid']}/agent",
            "type": "agent",
            "serviceEndpoint": {"http": facts["agent_url"]},
        },
    ]


def test_a_role_authorization_that_was_cut_projects_nothing(db):
    """`/end/role/cut` records the eid as disallowed; a cut endpoint is not current state."""
    plant_location(db, SPEC_WITNESS, "http", SPEC_HTTPS)
    plant_role(db, SPEC_AID, "mailbox", SPEC_WITNESS, allowed=False)

    assert document.services(db, state(SPEC_KEY), parsed()) == []


def test_an_authorized_endpoint_that_declared_no_location_projects_nothing(db):
    """The authorization says who may act as mailbox; only a location scheme says where it is,
    and a service entry with no endpoint would be a promise the state does not support."""
    plant_role(db, SPEC_AID, "mailbox", SPEC_WITNESS)

    assert document.services(db, state(SPEC_KEY), parsed()) == []


def test_a_role_the_spec_defines_no_mapping_for_is_not_projected(db):
    """The spec names witness, mailbox, agent and delegator. A `controller` endpoint role is
    real KERI state with no did:webs service mapping, so it is left out rather than invented."""
    plant_location(db, SPEC_WITNESS, "http", SPEC_HTTPS)
    plant_role(db, SPEC_AID, "controller", SPEC_WITNESS)

    assert document.services(db, state(SPEC_KEY), parsed()) == []


def test_a_stream_with_no_endpoints_at_all_publishes_an_empty_service_array(tmp_path):
    doc, _ = derived("base", tmp_path)

    assert doc["service"] == []


# ---------------------------------------------------------------------------- delegation


def test_a_delegated_aid_without_a_reachable_delegator_publishes_no_oobi(tmp_path):
    """`#### Delegator Service Endpoint` requires the serviceEndpoint to be a valid OOBI URL.
    Phase 1 never dereferences an OOBI and never invents one: when the delegator has declared
    no location in the verified stream, there is no URL to publish and the entry is omitted —
    which is what the reference does too, and a spec MUST we cannot satisfy from verified
    state (reported, not papered over)."""
    doc, facts = derived("delegated", tmp_path)

    assert facts["delegator_aid"] != facts["aid"]
    assert doc["service"] == []


def test_a_delegated_aid_whose_delegator_declared_a_location_publishes_its_oobi(tmp_path):
    """With a location for the delegator in verified state, the OOBI is keripy's canonical
    controller OOBI, and the service id is the seal that commits the delegated inception."""
    stream, facts = fixture("delegated", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified:
        plant_location(verified.hby.db, facts["delegator_aid"], "http", "http://del.example:3902/")
        doc = document.derive_document(verified, did)

    assert doc["service"] == [
        {
            "id": facts["aid"],
            "type": "DelegatorOOBI",
            "serviceEndpoint": f"http://del.example:3902/oobi/{facts['delegator_aid']}/controller",
        }
    ]


def test_the_delegator_oobi_prefers_https_over_http(tmp_path):
    stream, facts = fixture("delegated", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified:
        plant_location(verified.hby.db, facts["delegator_aid"], "http", "http://del.example:3902/")
        plant_location(
            verified.hby.db, facts["delegator_aid"], "https", "https://del.example:3903/"
        )
        doc = document.derive_document(verified, did)

    assert doc["service"][0]["serviceEndpoint"].startswith("https://del.example:3903/oobi/")


def test_an_undelegated_aid_never_carries_a_delegator_service(db):
    assert document.delegator_service(db, state(SPEC_KEY), parsed()) is None


def test_a_delegation_whose_anchoring_event_is_not_in_the_database_projects_nothing(db):
    """A pure projection cannot assume its input passed ingest: with no delegator KEL there is
    no sealing event to name, and the derivation says nothing rather than guessing a SAID."""
    plant_location(db, SPEC_WITNESS, "http", SPEC_HTTPS)

    assert document.delegator_service(db, state(SPEC_KEY, delpre=SPEC_WITNESS), parsed()) is None


# ------------------------------------------------------- abandonment (KRT-F6's other half)


def test_an_abandoned_aid_publishes_while_a_non_transferable_aid_never_parses(tmp_path):
    """KRT-F6's conflation oracle, both predicates named in one test.

    ``is_abandoned`` is a question about *key state*: this controller rotated to a null next
    key, so it can never sign again, and `#### Deactivate` says its document MUST still be
    regenerated and republished. ``has_nontransferable_code`` is a question about a *derivation
    code*: a code-B identifier is not a did:webs subject at all and never reaches key state.
    An implementation that conflates the two either refuses to publish a deactivated DID or
    accepts an identifier the method does not admit."""
    stream, facts = fixture("deactivated", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified:
        kever = verified.hby.kevers[did.aid]
        assert document.is_abandoned(kever) is True
        doc = document.derive_document(verified, did)

    assert doc["id"] == did.compose()
    assert doc["verificationMethod"], "an abandoned AID still publishes its last key state"

    code_b = keri_api.did_webs("B" + facts["aid"][1:])
    assert did_module.has_nontransferable_code("B" + facts["aid"][1:]) is True
    with pytest.raises(BakoboError) as caught:
        did_module.parse(code_b)
    assert caught.value.code == "e.input.format.did.f"


def test_a_live_aid_is_not_abandoned(tmp_path):
    stream, facts = fixture("base", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified:
        assert document.is_abandoned(verified.hby.kevers[did.aid]) is False


# ------------------------------------------------------------------------ document shape


def test_the_document_carries_every_property_the_spec_mandates_in_a_stable_order(tmp_path):
    """Key order is fixed so that two publications of the same state diff cleanly, and
    `@context` leads because a JSON-LD processor reads it first."""
    doc, facts = derived("base", tmp_path)

    assert list(doc) == [
        "@context",
        "id",
        "controller",
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "service",
        "alsoKnownAs",
    ]
    assert doc["@context"] == document.CONTEXT
    assert doc["id"] == facts["did_webs"].replace("%3a", "%3A")
    assert doc["controller"] == doc["id"]


def test_the_document_is_json_serializable_as_it_stands(tmp_path):
    """It is written to disk verbatim; nothing in it may be a keripy object."""
    doc, _ = derived("base", tmp_path)

    assert json.loads(json.dumps(doc)) == doc


def test_deriving_twice_from_the_same_state_produces_the_same_document(tmp_path):
    stream, facts = fixture("base", tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as verified:
        assert document.derive_document(verified, did) == document.derive_document(verified, did)


# ------------------------------------------------------ the spec's Full Example as a golden


def spec_document(db) -> dict:
    """The spec's `### Full Example` inputs, run through our derivation.

    Its KSN, its witness reply records and its designated-aliases ACDC, planted as the state
    they would leave behind, so the comparison below is against the spec's own published
    document rather than against our own output.
    """
    plant_location(db, SPEC_WITNESS, "https", SPEC_HTTPS)
    plant_location(db, SPEC_WITNESS, "tcp", SPEC_TCP)
    return document.project_document(
        state(SPEC_KEY, wits=[SPEC_WITNESS]), db, SPEC_IDS, parsed(SPEC_DID)
    )


#: The document the spec's `### Full Example` publishes, verbatim.
SPEC_FULL_EXAMPLE = {
    "id": SPEC_DID,
    "controller": SPEC_DID,
    "verificationMethod": [
        {
            "id": f"#{SPEC_KEY}",
            "type": "JsonWebKey",
            "controller": SPEC_DID,
            "publicKeyJwk": {"kid": SPEC_KEY, "kty": "OKP", "crv": "Ed25519", "x": SPEC_X},
        }
    ],
    "authentication": [f"#{SPEC_KEY}"],
    "assertionMethod": [f"#{SPEC_KEY}"],
    "service": [
        {
            "id": f"#{SPEC_WITNESS}/witness",
            "type": "witness",
            "serviceEndpoint": {"https": SPEC_HTTPS, "tcp": SPEC_TCP},
        }
    ],
    "alsoKnownAs": [SPEC_IDS[0], f"did:keri:{SPEC_AID}"],
}

#: The two places our output differs from the spec's, both deliberate and both reported as
#: findings rather than absorbed into the expectation silently:
#:
#: 1. `@context`. `## DID documents` says a document MAY prepend one and the Full Example has
#:    none; docs/design.md mandates the property. Ours therefore has a property the spec's
#:    example does not.
#: 2. The port marker's case *in the subject DID*. The spec writes `%3a` here and `%3A` in
#:    `### Target System(s)`; both are legal, and `did.py` composes the canonical `%3A`
#:    (KRT-F5). It applies only to the identifiers this method composes — the designated
#:    aliases are published exactly as the controller designated them, so `alsoKnownAs` below
#:    matches the spec's bytes with no transformation at all.
SPEC_DELTAS = ("@context", "port-marker case in the composed subject DID")


def test_the_spec_worked_example_derives_to_the_document_the_spec_publishes(db):
    """Design oracle 4. The comparison is against the spec's own bytes, with the two known
    differences applied *visibly* — a golden that quietly absorbed a mismatch would be worth
    nothing."""
    derived_doc = dict(spec_document(db))

    assert derived_doc.pop("@context") == document.CONTEXT  # delta 1, named above
    canonical = SPEC_DID.replace("%3a", "%3A")  # delta 2, on the subject DID only
    expected = json.loads(json.dumps(SPEC_FULL_EXAMPLE).replace(SPEC_DID, canonical))

    assert derived_doc == expected
    assert derived_doc["alsoKnownAs"] == SPEC_FULL_EXAMPLE["alsoKnownAs"]  # untransformed


def test_the_golden_comparison_declares_exactly_the_two_known_differences():
    """A guard on the guard: if a third difference is ever needed, this fails and the mismatch
    gets reported instead of appearing as one more line in the transform above."""
    assert len(SPEC_DELTAS) == 2


# --------------------------------------------------- transformation to the did:web document


def test_the_did_web_document_rewrites_only_the_identifiers(db):
    """`### Transformation to did:web DID document`: the top-level id and controller, every
    verification method controller that equals the subject, and the reciprocal alsoKnownAs
    entry — and nothing else."""
    source = spec_document(db)
    transformed = document.to_did_web(source)

    web_did = SPEC_DID.replace("did:webs:", "did:web:").replace("%3a", "%3A")
    assert transformed["id"] == web_did
    assert transformed["controller"] == web_did
    assert [method["controller"] for method in transformed["verificationMethod"]] == [web_did]
    assert transformed["alsoKnownAs"] == [
        source["id"],
        f"did:keri:{SPEC_AID}",
    ]
    assert transformed["service"] == source["service"]
    assert transformed["@context"] == source["@context"]
    assert list(transformed) == list(source)


def test_the_transformation_leaves_the_did_webs_document_untouched(db):
    """It returns a new document; the caller still holds the did:webs one it passed in."""
    source = spec_document(db)
    before = json.dumps(source)

    document.to_did_web(source)

    assert json.dumps(source) == before


def test_a_verification_method_controlled_by_someone_else_is_left_alone(db):
    """The rule is scoped to methods whose controller *equals* the subject DID."""
    source = spec_document(db)
    source["verificationMethod"][0]["controller"] = f"did:webs:elsewhere.example:{SPEC_AID}"

    transformed = document.to_did_web(source)

    assert transformed["verificationMethod"][0]["controller"] == (
        f"did:webs:elsewhere.example:{SPEC_AID}"
    )


def test_a_document_without_the_reciprocal_alias_still_names_its_did_webs_form(db):
    """`### Also Known As`: the did:web version of the document MUST list the did:webs version.
    Ingest guarantees both forms are designated, so the replacement branch is the live one;
    this is the pure function refusing to drop the reciprocal link if ever handed a document
    that lacks it."""
    source = spec_document(db)
    source["alsoKnownAs"] = [f"did:keri:{SPEC_AID}"]

    transformed = document.to_did_web(source)

    assert transformed["alsoKnownAs"] == [source["id"], f"did:keri:{SPEC_AID}"]
