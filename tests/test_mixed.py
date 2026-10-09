"""Publication streams that mix KERI protocol v1 and v2.

Decision 8686h4tf as amended 2026-10-07: a KEL may migrate from v1 to v2 and keep its AID, and
so its DID, under five rules. Decision 7p6j5kde: any valid, unrevoked designation authorizes, and
the document reflects every one of them. Each refusal is a negative requirement and has a fixture
that supplies the bad input and asserts the exact code (cc ledger #22).
"""

from __future__ import annotations

import itertools
import json

import builders
import builders_mixed
import builders_v2
import keri_api
import pytest
from bakobo.errors import BakoboError
from keri import kering
from keri.app import habbing
from keri.core import eventing as keventing
from keri.core import parsing, serdering

from didwebs import assemble, document, ingest
from didwebs.did import parse as parse_did

V1_GENUS = builders_mixed.gvc(1)
V2_GENUS = builders_mixed.gvc(2)


def _claimed(facts):
    return parse_did(facts["did_webs"])


def _aliases(facts) -> list:
    """The alsoKnownAs a document for ``facts`` must carry: every designated identifier in
    order, without the subject itself, then did:keri."""
    return [i for i in facts["ids"] if i != facts["did_webs"]] + [f"did:keri:{facts['aid']}"]


def _expected_designations(facts) -> list:
    return facts.get("designations") or [facts["acdc_said"]]


def _messages(stream: bytes) -> list:
    """Every JSON message body in ``stream``, of either version, located by its version string.
    ``keri_api.bodies`` reads v1 only."""
    out, start = [], stream.find(b'{"v":"')
    while start >= 0:
        size = kering.smell(bytearray(stream[start:])).size
        out.append(json.loads(stream[start : start + size]))
        start = stream.find(b'{"v":"', start + size)
    return out


def _bodies(stream: bytes) -> list:
    """Every message body in ``stream`` with the genus it was read under, via the walk."""
    return [(frame.major, frame.genus) for frame in ingest.walk(stream).frames]


# ------------------------------------------------------------------------- the fixtures


def test_a_migrated_kel_really_carries_both_versions(tmp_path):
    stream, facts = builders_mixed.migrated_v1_designation(tmp_path)
    kel = [body for body in _messages(stream) if body.get("i") == facts["aid"] and "t" in body]

    assert [body["v"][:6] for body in kel] == ["KERI10", "KERI10", "KERI10", "KERICA", "KERICA"]
    assert V2_GENUS in stream and V1_GENUS in stream


# ----------------------------------------------------------------------------- ingest


@pytest.mark.parametrize("knob", builders_mixed.POSITIVE)
def test_a_valid_mixed_publication_verifies(knob, tmp_path):
    stream, facts = builders_mixed.KNOBS[knob](tmp_path)

    with ingest.ingest(stream, _claimed(facts)) as verified:
        assert verified.aid == facts["aid"]
        assert [c.said for c in verified.designations] == _expected_designations(facts)
        doc = document.derive_document(verified, _claimed(facts))

    assert doc["alsoKnownAs"] == _aliases(facts)
    assert [m["publicKeyJwk"]["kid"] for m in doc["verificationMethod"]] == [facts["current_key"]]


@pytest.mark.parametrize("knob", builders_mixed.NEGATIVE)
def test_the_mixed_negative_matrix_attributes_the_exact_code(knob, tmp_path):
    stream, facts = builders_mixed.KNOBS[knob](tmp_path)

    with pytest.raises(BakoboError) as caught, ingest.ingest(stream, _claimed(facts)):
        pass

    assert caught.value.code == facts["expected_code"]


def test_the_walk_records_the_genus_each_message_was_read_under(tmp_path):
    stream, _ = builders_mixed.migrated_v1_designation(tmp_path)

    read = _bodies(stream)

    assert read == [(1, 1)] * 3 + [(2, 2)] * 2 + [(1, 1)] * 3
    assert ingest.walk(stream).opening == keri_api.V1


def test_a_stream_may_open_with_an_explicit_v1_counter(tmp_path):
    """Rule 3 asks for a counter at each switch; a counter that switches to the genus a stream
    would open in anyway is redundant and harmless."""
    stream, facts = builders_mixed.migrated_v1_designation(tmp_path)

    with ingest.ingest(V1_GENUS + stream, _claimed(facts)) as verified:
        assert [c.said for c in verified.designations] == [facts["acdc_said"]]


def test_out_of_scope_outranks_revoked_when_no_designation_qualifies(tmp_path):
    """When nothing authorizes, the error names the furthest any candidate got: an unrevoked
    designation that does not cover the DID is out of scope, not revoked (7p6j5kde)."""
    with keri_api.scratch("scope-and-revoked", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        revoked = builders._issue(hab, regery, keri_api.designated_ids(hab.pre))
        assemble.revoke_aliases(hab, regery, revoked)
        elsewhere = builders._issue(
            hab, regery, keri_api.designated_ids(hab.pre, domain="elsewhere.example"),
            regname="second", nonce=keri_api.salt(builders.SPARE_REGISTRY_SALT),
        )
        stream = (
            keri_api.kel_bytes(hab)
            + b"".join(raw for _, raw in builders_mixed._v1_block(regery, revoked.creder))
            + b"".join(raw for _, raw in builders_mixed._v1_block(regery, elsewhere.creder))
        )
        did = parse_did(keri_api.did_webs(hab.pre))

    with pytest.raises(BakoboError) as caught, ingest.ingest(stream, did):
        pass

    assert caught.value.code == "e.grant.scope.alias.f"


# --------------------------------------------------------------------- the hosted stream


def _emitted(knob, tmp_path):
    stream, facts = builders_mixed.KNOBS[knob](tmp_path)
    with ingest.ingest(stream, _claimed(facts)) as verified:
        doc = document.derive_document(verified, _claimed(facts))
        emitted = assemble.emit_stream(verified)
    return facts, doc, emitted


@pytest.mark.parametrize("knob", builders_mixed.POSITIVE)
def test_the_hosted_mixed_stream_re_ingests_to_the_same_document(knob, tmp_path):
    facts, doc, emitted = _emitted(knob, tmp_path)

    with ingest.ingest(emitted, _claimed(facts)) as again:
        assert document.derive_document(again, _claimed(facts)) == doc
        assert [c.said for c in again.designations] == _expected_designations(facts)


@pytest.mark.parametrize("knob", builders_mixed.POSITIVE)
def test_every_hosted_message_is_in_its_own_genus_with_a_counter_at_each_switch(knob, tmp_path):
    _, _, emitted = _emitted(knob, tmp_path)

    read = _bodies(emitted)

    assert all(major == genus for major, genus in read)
    switches = sum(1 for a, b in itertools.pairwise(read) if a[1] != b[1])
    opening = 0 if {genus for _, genus in read} == {1} else 1  # pure v1 names no genus
    assert emitted.count(V1_GENUS) + emitted.count(V2_GENUS) == switches + opening


@pytest.mark.parametrize("knob", builders_mixed.POSITIVE)
def test_a_hosted_mixed_stream_names_its_opening_genus(knob, tmp_path):
    """A stream that carries both versions opens with an explicit counter even when it opens in
    v1, so a reader whose parser starts in keripy's default genus, v2, still reaches the key
    state we publish from (panel SEC-F3). A pure v1 stream keeps none: that is what the deployed
    ecosystem reads."""
    facts, _, emitted = _emitted(knob, tmp_path)
    if {major for major, _ in _bodies(emitted)} == {1}:
        assert not emitted.startswith(V1_GENUS)
        return

    hby = habbing.Habery(name="stranger", base="", temp=True)  # keripy's default genus
    try:
        kevery = keventing.Kevery(db=hby.db, lax=False, local=False)
        parsing.Parser(framed=True).parse(ims=bytearray(emitted), kvy=kevery, local=False)
        assert hby.kevers[facts["aid"]].sner.num == facts["kel_sn"]
    finally:
        hby.close(clear=True)


def test_a_migrated_kel_is_hosted_v1_events_first_then_v2_then_its_v1_log(tmp_path):
    facts, _, emitted = _emitted("migrated_v1_designation", tmp_path)

    kel = [
        body["v"][:6] for body in _messages(emitted)
        if body.get("i") == facts["aid"] and body.get("t") in {"icp", "ixn", "rot"}
    ]
    assert kel == ["KERI10", "KERI10", "KERI10", "KERICA", "KERICA"]
    assert emitted.startswith(V1_GENUS)
    assert emitted.index(V2_GENUS) < emitted.index(V1_GENUS, len(V1_GENUS))


def test_the_hosted_mixed_stream_ends_on_an_attached_frame(tmp_path):
    """keripy cannot extract an attachment-less final frame (~3rz6), so a hosted stream with a
    v2 registry still ends on its attached update."""
    _, _, emitted = _emitted("migrated_both_designations", tmp_path)

    frames = ingest.walk(emitted).frames
    assert frames[-1].ilk == "bup"


@pytest.mark.parametrize(
    ("module", "knob"),
    [(builders, "base"), (builders, "endpoints"), (builders, "delegated"),
     (builders_v2, "base"), (builders_v2, "endpoints"), (builders_v2, "delegated")],
)
def test_a_single_version_publication_is_hosted_with_no_counter_but_v2s_opening_one(
    module, knob, tmp_path
):
    """The byte-for-byte promise, in the form that survives keripy's wall-clock first-seen
    stamps: a v1 publication is hosted with no genus-version counter at all, and a v2 one with
    exactly the one it opens with."""
    stream, facts = module.KNOBS[knob](tmp_path)
    with ingest.ingest(stream, _claimed(facts)) as verified:
        emitted = assemble.emit_stream(verified)

    counters = emitted.count(V1_GENUS) + emitted.count(V2_GENUS)
    if module is builders:
        assert counters == 0
    else:
        assert counters == 1 and emitted.startswith(V2_GENUS)


# ----------------------------------------------------------------------- the keystore side


def test_a_v1_controller_may_issue_a_v2_designation_anchored_in_v1(tmp_path):
    """The keystore refusal e.rule.stream.version.f is gone (8686h4tf as amended), and issuing
    does not migrate the KEL as a side effect: the anchors are in the KEL's own version."""
    with keri_api.scratch_mixed("v1-issues-v2", tmp_path) as (hby, _, rgy):
        hab = keri_api.make_hab(hby, "controller")
        assemble.issue_aliases_v2(hab, rgy, keri_api.designated_ids(hab.pre))
        versions = {
            serdering.SerderKERI(raw=bytes(m)).pvrsn.major
            for m in hby.db.clonePreIter(pre=hab.pre, fn=0, gvrsn=keri_api.V1)
        }

    assert versions == {1}


def test_a_migrated_controller_anchors_a_v1_revocation_in_v2(tmp_path):
    """Revoking a v1 designation after migration must not backslide the KEL (rule 2)."""
    with keri_api.scratch_mixed("revoke-after", tmp_path) as (hby, regery, _):
        hab, issued = builders_mixed._migrated(hby, regery)
        revoked = assemble.revoke_aliases(hab, regery, issued)

    assert revoked.anc_serder.pvrsn.major == 2



def test_a_designation_on_a_registry_the_aid_did_not_anchor_does_not_authorize(tmp_path):
    """The issuer binding, for both versions, below the audit that normally stops such a stream
    first: a credential of the claimed AID riding a registry that is not its own is treated as
    absent (KRT-F1)."""
    stream, facts = builders_mixed.migrated_both_designations(tmp_path)
    walked = ingest.walk(stream)
    stranger = "E" + "A" * 43
    doctored = ingest.Walk(
        tuple(frame.replace(regid=stranger) if frame.is_acdc else frame
              for frame in walked.frames),
        None,
    )
    with ingest.open_scratch(walked.opening) as scratch:
        scratch.load(stream)
        ingest.audit(scratch, _claimed(facts), walked)
        assert len(ingest.authorize(scratch, _claimed(facts), walked)) == 2
        with pytest.raises(BakoboError) as caught:
            ingest.authorize(scratch, _claimed(facts), doctored)

    assert caught.value.code == "e.grant.missing.alias.f"
