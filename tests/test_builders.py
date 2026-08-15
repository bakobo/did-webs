"""Tests for the fixture toolkit — one property assertion per knob, plus the version oracle.

Every knob claims to derange exactly one thing about a valid publication stream. A builder
whose output is not observably deranged tests nothing downstream, and a derangement that
accidentally breaks a *second* property makes the negative oracle that consumes it pass for the
wrong reason. So each test below asserts the specific, observable property that makes the
fixture what its name says — a forked stream really carries two same-sn events, a tampered
stream really differs from its parent by one byte inside a signature, and so on.

The last test is the constraint-`qbqfst` oracle over the whole toolkit.
"""

from __future__ import annotations

import json

import builders
import keri_api
import pytest

ACDC_VS = "ACDC10JSON"
KERI_VS = "KERI10JSON"


def ilks(stream):
    """The `t` of every KERI frame in a stream; ACDC frames have no `t` and are skipped."""
    return [body["t"] for body in keri_api.bodies(stream) if "t" in body]


def kel_bodies(stream, aid):
    return [b for b in keri_api.bodies(stream) if b.get("i") == aid and "t" in b]


def acdc_body(stream):
    """The one ACDC in a stream, selected by its serialization.

    Selecting on the presence of an `ri` field would pick up the TEL `iss` event instead, whose
    `i` is the credential's SAID rather than its issuer.
    """
    acdcs = [
        json.loads(frame.body)
        for frame in keri_api.frames(stream)
        if frame.version_string == ACDC_VS
    ]
    assert len(acdcs) == 1
    return acdcs[0]


# ------------------------------------------------------------------------------------ base


def test_base_produces_a_complete_publication_stream(tmp_path):
    stream, facts = builders.base(tmp_path)
    assert ilks(stream) == ["icp", "ixn", "ixn", "vcp", "iss"]
    assert keri_api.version_strings(stream).count(ACDC_VS) == 1
    assert facts["aid"] in facts["did_webs"]
    assert facts["acdc_said"] and facts["regk"]


def test_base_designates_both_spellings_of_its_own_did(tmp_path):
    _, facts = builders.base(tmp_path)
    assert set(facts["ids"]) == {facts["did_web"], facts["did_webs"]}


def test_base_is_deterministic_in_everything_a_consuming_test_asserts_on(tmp_path):
    """Bytes are not stable — keripy stamps wall-clock first-seen couples into attachments —
    but every AID, SAID and DID a downstream test asserts against is."""
    first_stream, first_facts = builders.base(tmp_path / "one")
    second_stream, second_facts = builders.base(tmp_path / "two")
    assert first_facts == second_facts
    assert keri_api.bodies(first_stream) == keri_api.bodies(second_stream)


def test_every_builder_returns_a_stream_and_facts_pair(tmp_path):
    stream, facts = builders.base(tmp_path)
    assert isinstance(stream, bytes)
    assert facts["knob"] == "base"
    assert facts["schema_said"] == builders.SCHEMA_SAID


# ------------------------------------------------------------------------------------ knobs


def test_without_acdc_ships_a_complete_kel_and_no_credential_at_all(tmp_path):
    """The KEL still carries both anchor seals: it *claims* an authorization it does not ship."""
    stream, facts = builders.without_acdc(tmp_path)
    assert ACDC_VS not in keri_api.version_strings(stream)
    assert ilks(stream) == ["icp", "ixn", "ixn"]
    assert facts["acdc_said"] is None

    seals = [seal for body in keri_api.bodies(stream) for seal in body.get("a", [])]
    assert len(seals) == 2  # the vcp and iss anchors are still there


def test_revoked_acdc_carries_the_revocation_event_in_the_credential_tel(tmp_path):
    stream, facts = builders.revoked_acdc(tmp_path)
    assert "rev" in ilks(stream)
    assert ilks(stream).index("iss") < ilks(stream).index("rev")
    assert facts["revoked"] is True
    assert facts["acdc_said"]


def test_attacker_acdc_is_issued_by_an_aid_that_is_not_the_victim(tmp_path):
    """The attacker's own credential is internally valid — the flaw is *whose* it is."""
    stream, facts = builders.attacker_acdc(tmp_path)
    assert facts["issuer_aid"] != facts["aid"]
    assert facts["issuer_aid"] == facts["attacker_aid"]

    acdc = acdc_body(stream)
    assert acdc["i"] == facts["attacker_aid"]
    assert facts["did_webs"] in acdc["a"]["ids"]  # it names the victim's DID
    assert facts["aid"] in {b.get("i") for b in keri_api.bodies(stream)}  # victim KEL is there


def test_scope_miss_covers_neither_the_claimed_did_webs_nor_its_did_web_form(tmp_path):
    stream, facts = builders.scope_miss(tmp_path)
    acdc = acdc_body(stream)
    assert facts["did_webs"] not in acdc["a"]["ids"]
    assert facts["did_web"] not in acdc["a"]["ids"]
    assert acdc["a"]["ids"], "a scope miss must still designate *something*"
    assert acdc["i"] == facts["aid"]  # issuer is right; only the scope is wrong


def test_spelling_variants_differ_as_strings_but_match_once_normalized(tmp_path):
    """The accepted direction: %3a-vs-%3A and host case must not cause a false rejection."""
    stream, facts = builders.spelling_variants(tmp_path)
    acdc = acdc_body(stream)
    designated = acdc["a"]["ids"]

    assert facts["did_webs"] not in designated  # not a byte-for-byte match
    assert facts["did_webs"].lower() in {entry.lower() for entry in designated}
    assert any("%3a" in entry for entry in designated)
    assert "%3A" in facts["did_webs"]
    assert any(entry != entry.lower() for entry in designated)  # host case really varies


def test_tampered_sig_differs_from_its_parent_by_one_byte_inside_a_signature(tmp_path):
    stream, facts = builders.tampered_sig(tmp_path)
    parent = facts["parent_stream"]

    assert len(stream) == len(parent)
    differing = [i for i, (a, b) in enumerate(zip(stream, parent, strict=True)) if a != b]
    assert len(differing) == 1

    index = differing[0]
    frame = next(f for f in keri_api.frames(parent) if f.start <= index < f.end)
    assert frame.body_end <= index < frame.end  # in the attachments, not the body
    # Inside the siger itself, not merely inside the attachment group: an attachment block
    # also carries unsigned material (a FirstSeenReplayCouple datetime) whose mutation keripy
    # ignores, which is exactly the vacuity worker D caught (report 2026-08-15).
    attachments = parent[frame.body_end : frame.end]
    counter = attachments.find(b"-AAB")
    assert counter != -1  # one indexed controller signature on the icp
    siger_start = frame.body_end + counter + 4
    assert siger_start <= index < siger_start + 88  # within the 88-char qb64 siger
    assert index == facts["tampered_offset"]
    assert keri_api.bodies(stream) == keri_api.bodies(parent)  # bodies untouched


def test_forked_kel_carries_two_distinct_events_at_the_same_sequence_number(tmp_path):
    stream, facts = builders.forked_kel(tmp_path)
    events = kel_bodies(stream, facts["aid"])
    at_sn = [event for event in events if event["s"] == facts["fork_sn"]]

    assert len(at_sn) == 2
    assert at_sn[0]["d"] != at_sn[1]["d"]
    assert {event["t"] for event in at_sn} == {"ixn"}
    assert at_sn[0]["p"] == at_sn[1]["p"]  # both branch from the same prior event


def test_dropped_frame_candidate_appends_a_well_formed_event_keripy_cannot_accept(tmp_path):
    """Correctly signed, same AID, but its prior event is not in the stream — escrowed forever."""
    stream, facts = builders.dropped_frame_candidate(tmp_path)
    events = kel_bodies(stream, facts["aid"])
    sns = [int(event["s"], 16) for event in events]

    assert max(sns) == facts["orphan_sn"]
    assert facts["orphan_sn"] > facts["kel_sn"] + 1  # a gap, not the next event
    saids = {event["d"] for event in events}
    orphan = next(event for event in events if int(event["s"], 16) == facts["orphan_sn"])
    assert orphan["p"] not in saids  # its prior is genuinely absent


def test_third_party_appends_frames_about_an_unrelated_aid(tmp_path):
    stream, facts = builders.third_party(tmp_path)
    prefixes = {body.get("i") for body in keri_api.bodies(stream)}

    assert facts["third_party_aid"] in prefixes
    assert facts["third_party_aid"] != facts["aid"]
    assert facts["aid"] in prefixes  # the claimed AID's own stream is still intact and valid
    assert ilks(stream).count("icp") == 2


def test_cbor_frame_is_a_v1_cbor_event_on_the_claimed_aids_own_kel(tmp_path):
    """Serialization is the *only* thing wrong: same AID, same protocol version, valid signature."""
    stream, facts = builders.cbor_frame(tmp_path)
    strings = keri_api.version_strings(stream)

    assert "KERI10CBOR" in strings
    assert facts["deliberate_version_strings"] == frozenset({"KERI10CBOR"})
    assert set(strings) - facts["deliberate_version_strings"] == {KERI_VS, ACDC_VS}


def test_v2_frame_is_a_protocol_v2_event_on_a_v1_kel(tmp_path):
    """Exactly the qbqfst failure mode: one unpinned call site injecting a v2 frame."""
    stream, facts = builders.v2_frame(tmp_path)
    strings = keri_api.version_strings(stream)

    assert "KERICAACAAJSON" in strings
    assert facts["deliberate_version_strings"] == frozenset({"KERICAACAAJSON"})
    assert set(strings) - facts["deliberate_version_strings"] == {KERI_VS, ACDC_VS}


def test_secp_keys_puts_a_non_ed25519_key_in_the_current_key_state(tmp_path):
    stream, facts = builders.secp_keys(tmp_path)
    icp = next(body for body in keri_api.bodies(stream) if body.get("t") == "icp")

    assert icp["k"] == facts["keys"]
    assert all(key.startswith("1AAB") for key in icp["k"])  # ECDSA_256k1, not Ed25519 'D'
    assert facts["key_alg"] == "secp256k1"


def test_multi_clause_kt_is_a_conjunctive_threshold_of_more_than_one_clause(tmp_path):
    stream, facts = builders.multi_clause_kt(tmp_path)
    icp = next(body for body in keri_api.bodies(stream) if body.get("t") == "icp")

    assert isinstance(icp["kt"], list)
    assert len(icp["kt"]) > 1
    assert all(isinstance(clause, list) for clause in icp["kt"])
    assert icp["kt"] == facts["kt"]


def test_delegated_ships_a_dip_naming_its_delegator_and_the_delegators_kel(tmp_path):
    stream, facts = builders.delegated(tmp_path)
    dip = next(body for body in keri_api.bodies(stream) if body.get("t") == "dip")

    assert dip["i"] == facts["aid"]
    assert dip["di"] == facts["delegator_aid"]
    assert facts["delegator_aid"] in {b.get("i") for b in keri_api.bodies(stream)}
    assert facts["includes_delegator"] is True


def test_delegated_without_the_delegator_kel_omits_every_delegator_frame(tmp_path):
    stream, facts = builders.delegated(tmp_path, include_delegator=False)
    dip = next(body for body in keri_api.bodies(stream) if body.get("t") == "dip")

    assert dip["di"] == facts["delegator_aid"]  # still *names* the delegator
    assert facts["delegator_aid"] not in {b.get("i") for b in keri_api.bodies(stream)}
    assert facts["includes_delegator"] is False


def test_truncated_stops_partway_through_the_kel_and_ships_no_tel(tmp_path):
    stream, facts = builders.truncated(tmp_path)
    assert ilks(stream) == ["icp"]
    assert ACDC_VS not in keri_api.version_strings(stream)
    assert facts["kel_sn"] > 0  # the full KEL had more events; this is a prefix of it
    assert facts["acdc_said"] is None


def test_deactivated_rotates_to_a_null_next_key_state_and_stays_publishable(tmp_path):
    """A deactivated AID is a VALID publication, not a rejection — do not conflate the two."""
    stream, facts = builders.deactivated(tmp_path)
    establishment = [b for b in keri_api.bodies(stream) if b.get("t") in ("icp", "rot")]
    latest = establishment[-1]

    assert latest["t"] == "rot"
    assert latest["n"] == []
    assert latest["nt"] == "0"
    assert facts["deactivated"] is True
    assert keri_api.version_strings(stream).count(ACDC_VS) == 1  # complete, still authorized


def test_alias_foreign_aid_designates_a_did_whose_final_component_is_another_aid(tmp_path):
    stream, facts = builders.alias_foreign_aid(tmp_path)
    acdc = acdc_body(stream)
    foreign = facts["foreign_alias"]

    assert foreign in acdc["a"]["ids"]
    assert foreign.rsplit(":", 1)[-1] == facts["foreign_aid"]
    assert facts["foreign_aid"] != facts["aid"]
    assert acdc["i"] == facts["aid"]  # our own AID issued it — only the entry is foreign
    assert facts["did_webs"] in acdc["a"]["ids"]  # and the claimed DID is covered


# -------------------------------------------------------------------------- ingestability


def test_the_base_stream_really_ingests_into_a_fresh_keystore(tmp_path):
    """The fixture is verifiable, not merely well shaped — the whole toolkit rests on this.

    Drives keripy's own parser over the stream the way the spike harness drove the GLEIF
    resolver, and checks the same four things it checked: key state, transaction state, the
    credential saved, and its TEL state issued.
    """
    stream, facts = builders.base(tmp_path / "build")
    observed = keri_api.smoke_ingest(stream, facts["aid"], tmp_path / "ingest")

    assert observed["aid_in_kevers"] is True
    assert observed["kel_sn"] == facts["kel_sn"]
    assert facts["regk"] in observed["registries"]
    assert facts["acdc_said"] in observed["saved_credentials"]
    assert observed["vc_states"][facts["acdc_said"]] == "iss"


def test_the_revoked_stream_ingests_and_reports_revoked_tel_state(tmp_path):
    """Revocation is only visible by querying the TEL — the credential still saves and verifies."""
    stream, facts = builders.revoked_acdc(tmp_path / "build")
    observed = keri_api.smoke_ingest(stream, facts["aid"], tmp_path / "ingest")

    assert facts["acdc_said"] in observed["saved_credentials"]
    assert observed["vc_states"][facts["acdc_said"]] == "rev"


def test_the_deactivated_stream_ingests_as_cleanly_as_the_base_one(tmp_path):
    """A deactivated AID is publishable: it must reach full key state, not be refused."""
    stream, facts = builders.deactivated(tmp_path / "build")
    observed = keri_api.smoke_ingest(stream, facts["aid"], tmp_path / "ingest")

    assert observed["aid_in_kevers"] is True
    assert observed["kel_sn"] == facts["kel_sn"]
    assert observed["vc_states"][facts["acdc_said"]] == "iss"


def test_the_truncated_stream_does_not_reach_the_key_state_the_base_one_does(tmp_path):
    """A contrast case, so the smoke oracle is shown to discriminate rather than always pass."""
    stream, facts = builders.truncated(tmp_path / "build")
    observed = keri_api.smoke_ingest(stream, facts["aid"], tmp_path / "ingest")

    assert observed["kel_sn"] == 0 < facts["kel_sn"]
    assert observed["registries"] == set()
    assert observed["saved_credentials"] == set()


# ------------------------------------------------------------------- endpoints (document E)


def test_endpoints_carries_a_reply_record_for_every_endpoint_it_claims(tmp_path):
    """Four replies: a location scheme for the mailbox and for the agent, and the two
    ``/end/role/add`` authorizations that make those AIDs this controller's mailbox and agent."""
    stream, facts = builders.endpoints(tmp_path)
    replies = [body for body in keri_api.bodies(stream) if body.get("t") == "rpy"]

    assert [body["r"] for body in replies] == [
        "/loc/scheme",
        "/loc/scheme",
        "/end/role/add",
        "/end/role/add",
    ]
    assert [body["a"]["eid"] for body in replies] == [
        facts["mailbox_aid"],
        facts["agent_aid"],
        facts["mailbox_aid"],
        facts["agent_aid"],
    ]
    assert [body["a"]["role"] for body in replies[2:]] == ["mailbox", "agent"]
    assert {body["a"]["cid"] for body in replies[2:]} == {facts["aid"]}


def test_endpoints_declares_the_urls_a_document_oracle_projects(tmp_path):
    stream, facts = builders.endpoints(tmp_path)
    urls = {
        body["a"]["eid"]: (body["a"]["scheme"], body["a"]["url"])
        for body in keri_api.bodies(stream)
        if body.get("r") == "/loc/scheme"
    }
    assert urls[facts["mailbox_aid"]] == ("http", facts["mailbox_url"])
    assert urls[facts["agent_aid"]] == ("http", facts["agent_url"])


def test_endpoints_is_otherwise_the_base_stream_and_still_publishable(tmp_path):
    """The knob adds replies and changes nothing else: same complete KEL, TEL and ACDC."""
    stream, facts = builders.endpoints(tmp_path)
    assert ilks(stream) == ["icp", "ixn", "ixn", "rpy", "rpy", "rpy", "rpy", "vcp", "iss"]
    assert set(facts["ids"]) == {facts["did_web"], facts["did_webs"]}
    assert facts["acdc_said"] and facts["regk"]


def test_endpoints_names_no_witness_because_none_can_be_built_in_process(tmp_path):
    """The witness leg is deliberately absent (worker E, 2026-08-15): an AID with a witness
    needs receipts on every event, and ``assemble.issue_aliases`` blocks forever waiting for
    them without a receipting Doist. Witness projection is unit-tested on planted state
    instead, and this assertion records that the fixture does not pretend otherwise."""
    stream, _ = builders.endpoints(tmp_path)
    assert keri_api.bodies(stream)[0]["b"] == []


# --------------------------------------------------------------------- toolkit-wide oracles


def test_the_knob_registry_covers_every_name_the_brief_names():
    assert set(builders.KNOBS) == {
        "base",
        "without_acdc",
        "revoked_acdc",
        "attacker_acdc",
        "scope_miss",
        "spelling_variants",
        "tampered_sig",
        "forked_kel",
        "dropped_frame_candidate",
        "third_party",
        "cbor_frame",
        "v2_frame",
        "secp_keys",
        "multi_clause_kt",
        "delegated",
        "delegated:no-delegator",
        "truncated",
        "deactivated",
        "alias_foreign_aid",
        "endpoints",
    }


@pytest.mark.parametrize("knob", sorted(builders.KNOBS))
def test_every_builder_output_carries_only_v1_json_version_strings(knob, tmp_path):
    """Constraint qbqfst over the whole toolkit (design §Test strategy 3).

    The brief excludes only `v2_frame`. But a v1 CBOR frame's version string is `KERI10CBOR`,
    which violates the same assertion, so the exclusion is expressed as data instead: each
    fixture declares the version strings it is *deliberately* wrong about, and everything else
    it contains must be v1 JSON. Every knob is walked, and the next test proves the exclusion
    list stays empty for all but the two serialization knobs.
    """
    stream, facts = builders.KNOBS[knob](tmp_path)
    deliberate = facts["deliberate_version_strings"]
    assert set(keri_api.version_strings(stream)) - deliberate <= keri_api.ACCEPTED_VERSION_STRINGS


@pytest.mark.parametrize("knob", sorted(builders.KNOBS))
def test_only_the_two_serialization_knobs_declare_a_deliberate_version_violation(knob, tmp_path):
    _, facts = builders.KNOBS[knob](tmp_path)
    expected = {
        "cbor_frame": frozenset({"KERI10CBOR"}),
        "v2_frame": frozenset({"KERICAACAAJSON"}),
    }.get(knob, frozenset())
    assert facts["deliberate_version_strings"] == expected


@pytest.mark.parametrize("knob", sorted(builders.KNOBS))
def test_every_builder_names_itself_and_the_did_it_is_a_fixture_for(knob, tmp_path):
    stream, facts = builders.KNOBS[knob](tmp_path)
    assert facts["knob"] == knob
    assert facts["did_webs"].endswith(facts["aid"])
    assert facts["did_web"].endswith(facts["aid"])
    assert stream.startswith(b'{"v":"KERI10JSON')  # every stream opens on a v1 JSON inception


def test_building_a_fixture_leaves_no_keri_temp_directory(tmp_path):
    """keripy ignores ``headDirPath`` for temp stores (hio ``Filer.remake`` substitutes its own
    ``mkdtemp``) and its close removes only the leaf, so every keystore build would otherwise
    strand four ``/tmp/keri_*`` roots — hundreds per suite run, and a noise floor under any
    global no-leak assertion (worker D's finding, 2026-08-15). ``keri_api.scratch`` owns the
    removal."""
    import glob

    before = set(glob.glob("/tmp/keri_*"))
    builders.KNOBS["base"](tmp_path)
    assert set(glob.glob("/tmp/keri_*")) == before
