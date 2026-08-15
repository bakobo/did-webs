"""Tests for didwebs.assemble's keystore side — registry, self-attested ACDC, KEL anchors.

Two contracts are under test at once. The functional one: `issue_aliases` leaves a keystore
holding an anchored registry and an issued, schema-valid designated-aliases ACDC. And the
protocol one from constraint `qbqfst`: every artifact it produces is protocol v1, because this
keripy line defaults to v2 *per call site* and a stream with one v2 frame in it is silently
dropped by every deployed 1.2.x parser.
"""

from __future__ import annotations

import json

import builders
import keri_api
import pytest
from conftest import CONTROLLER_SALT, designated_ids
from keri.core import coring, counting
from keri.kering import Vrsn_1_0, Vrsn_2_0

from didwebs import assemble, document, ingest, schemaing
from didwebs import did as did_module


def kel_bodies(hab):
    """Every event in the Hab's KEL, parsed."""
    return [json.loads(frame.body) for frame in keri_api.frames(keri_api.kel_bytes(hab))]


def test_the_module_docstring_names_both_roles_so_the_split_is_discoverable():
    """The ingest-side `emit_stream` lands in a later brief; the docstring must say so."""
    doc = assemble.__doc__
    assert "emit_stream" in doc
    assert "issue_aliases" in doc


def test_the_registry_is_created_and_its_tel_lands_in_the_keystore(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert issued.registry.regk in keystore.regery.reger.tevers
    assert issued.registry.vcp.ked["t"] == coring.Ilks.vcp


def test_the_acdc_is_self_attested_by_the_hab_against_the_pinned_schema(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert issued.creder.sad["i"] == keystore.hab.pre
    assert issued.creder.sad["s"] == schemaing.DES_ALIASES_SCHEMA_SAID
    assert issued.creder.sad["ri"] == issued.registry.regk
    assert "a" in issued.creder.sad and "r" in issued.creder.sad


def test_the_tel_state_for_the_acdc_is_issued(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    state = issued.registry.tever.vcState(vci=issued.creder.said)
    assert state.et == coring.Ilks.iss


def test_both_tel_events_are_anchored_by_interaction_events_in_the_controllers_kel(keystore):
    """The vcp and the iss each get their own seal in an ixn — this is what binds TEL to KEL."""
    before = keystore.hab.kever.sner.num
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert keystore.hab.kever.sner.num == before + 2

    seals = [seal for body in kel_bodies(keystore.hab) for seal in body.get("a", [])]
    assert {"i": issued.registry.regk, "s": "0", "d": issued.registry.regd} in seals
    assert {
        "i": issued.iss_serder.pre,
        "s": "0",
        "d": issued.iss_serder.said,
    } in seals


def test_the_ids_argument_round_trips_verbatim_into_the_attribute_block(keystore):
    ids = designated_ids(keystore.hab.pre) + [f"did:web:example.com:{keystore.hab.pre}"]
    issued = assemble.issue_aliases(keystore.hab, keystore.regery, ids)
    assert issued.creder.sad["a"]["ids"] == ids


def test_the_designation_date_is_fixed_so_the_acdc_said_is_stable(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert issued.creder.sad["a"]["dt"] == assemble.DESIGNATION_DT


def test_the_designation_date_is_overridable_for_fixtures_that_need_a_second_one(keystore):
    issued = assemble.issue_aliases(
        keystore.hab,
        keystore.regery,
        designated_ids(keystore.hab.pre),
        dt="2020-01-01T00:00:00.000000+00:00",
    )
    assert issued.creder.sad["a"]["dt"] == "2020-01-01T00:00:00.000000+00:00"


def test_an_empty_ids_list_still_produces_a_schema_valid_issued_acdc(keystore):
    issued = assemble.issue_aliases(keystore.hab, keystore.regery, [])
    assert issued.creder.sad["a"]["ids"] == []
    assert issued.registry.tever.vcState(vci=issued.creder.said).et == coring.Ilks.iss


def test_every_artifact_issue_aliases_produces_carries_protocol_v1(keystore):
    """Constraint qbqfst, artifact by artifact: icp, ixn, vcp, iss and the ACDC are all v1."""
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    for serder in (
        keystore.hab.kever.serder,
        issued.registry.vcp,
        issued.iss_serder,
        issued.anc_serder,
    ):
        assert serder.pvrsn == Vrsn_1_0
    assert issued.creder.pvrsn == Vrsn_1_0

    stream = keri_api.publication_stream(keystore.hab, keystore.regery, issued.creder)
    assert set(keri_api.version_strings(stream)) <= keri_api.ACCEPTED_VERSION_STRINGS


def test_the_version_guard_passes_a_v1_event_through_unchanged(keystore):
    serder = keystore.hab.kever.serder
    assert assemble._v1(serder) is serder


def test_the_version_guard_refuses_an_event_keripy_derived_as_v2(tmp_path):
    """The three keripy calls that take no version argument are only checkable, not pinnable.

    This proves the check is real: hand it the v2 event this keripy line produces by default
    and it must refuse, so a change to keripy's derivation chain fails here rather than in a
    published stream no 1.2.x parser can read.
    """
    with keri_api.open_keystore("v2", tmp_path, salt_raw=CONTROLLER_SALT) as hby:
        unpinned = hby.makeHab(name="v2", icount=1, isith="1", ncount=1, nsith="1")
        assert unpinned.kever.serder.pvrsn == Vrsn_2_0
        with pytest.raises(AssertionError) as excinfo:
            assemble._v1(unpinned.kever.serder)
    assert "qbqfst" in str(excinfo.value)


def test_a_second_registry_in_the_same_keystore_gets_its_own_name_and_key(keystore):
    """Fixtures issue more than once per keystore; registry names must not collide."""
    first = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre), regname="one"
    )
    second = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre), regname="two"
    )
    assert first.registry.regk != second.registry.regk


def test_revoking_moves_the_tel_state_to_revoked_and_anchors_another_interaction(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    sn_before = keystore.hab.kever.sner.num

    revoked = assemble.revoke_aliases(keystore.hab, keystore.regery, issued)

    assert revoked.registry.tever.vcState(vci=issued.creder.said).et == coring.Ilks.rev
    assert keystore.hab.kever.sner.num == sn_before + 1
    assert revoked.rev_serder.pvrsn == Vrsn_1_0
    assert revoked.creder.said == issued.creder.said
    assert revoked.rev_serder.ked["t"] == coring.Ilks.rev


def test_the_revocation_event_is_anchored_by_a_seal_in_the_kel(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    revoked = assemble.revoke_aliases(keystore.hab, keystore.regery, issued)

    seals = [seal for body in kel_bodies(keystore.hab) for seal in body.get("a", [])]
    assert {
        "i": revoked.rev_serder.pre,
        "s": "1",
        "d": revoked.rev_serder.said,
    } in seals


def test_a_revoked_stream_still_contains_only_v1_version_strings(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assemble.revoke_aliases(keystore.hab, keystore.regery, issued)
    stream = keri_api.publication_stream(keystore.hab, keystore.regery, issued.creder)
    assert set(keri_api.version_strings(stream)) <= keri_api.ACCEPTED_VERSION_STRINGS


# ------------------------------------------------- the ingest side: emit_stream (embuup)


def emitted(knob, tmp_path):
    """A fixture's stream, ingested, and the `keri.cesr` re-assembled from what was accepted."""
    stream, facts = builders.KNOBS[knob](tmp_path)
    did = did_module.parse(facts["did_webs"])
    with ingest.ingest(stream, did) as verified:
        return assemble.emit_stream(verified), stream, facts


def saids(stream):
    return [frame.said for frame in ingest.walk(stream).frames]


def key_state(kever):
    """Everything the current key state commits to, as comparable values.

    Deliberately not the whole `KeyStateRecord`: that carries the first-seen ordinal and the
    datetime keripy stamped when *this* database saw the event, which are properties of an
    ingestion rather than of the key state a document rests on.
    """
    return (
        kever.sner.num,
        [verfer.qb64 for verfer in kever.verfers],
        kever.tholder.sith,
        [diger.qb64 for diger in kever.ndigers],
        kever.ntholder.sith,
        list(kever.wits),
        kever.toader.num,
        kever.delpre,
    )


def test_the_emitted_stream_carries_every_frame_the_submission_did(tmp_path):
    """`embuup`: the hosted artifact is re-assembled by replay from the scratch database, so it
    is a normalized equivalent of the submission rather than a copy of it — same messages, in
    the reference's re-ingestable order, byte-for-byte different in the first-seen replay
    couples keripy stamps on the way out."""
    emitted_stream, submitted, _ = emitted("base", tmp_path)

    assert saids(emitted_stream) == saids(submitted)
    assert keri_api.bodies(emitted_stream) == keri_api.bodies(submitted)


def test_the_emitted_stream_is_not_the_submitted_bytes(tmp_path):
    """The point of the constraint: nothing downstream can reach around the audit by copying
    input to output. `Verified` does not even carry the submitted bytes, and this asserts the
    output is genuinely re-derived rather than incidentally identical."""
    emitted_stream, submitted, _ = emitted("base", tmp_path)

    assert emitted_stream != submitted


def test_the_emitted_stream_orders_frames_the_way_the_reference_emits_them(tmp_path):
    """KEL first, then the reply records, then per credential its registry TEL, its own TEL and
    the ACDC — `dws/core/artifacting.py`'s `generate_artifacts` order, which is what the GLEIF
    resolver re-ingests."""
    emitted_stream, _, _ = emitted("endpoints", tmp_path)

    assert [frame.ilk for frame in ingest.walk(emitted_stream).frames] == [
        "icp",
        "ixn",
        "ixn",
        "rpy",
        "rpy",
        "rpy",
        "rpy",
        "vcp",
        "iss",
        None,  # an ACDC has no `t` field, which is how the walk names one
    ]


def test_a_delegated_publication_replays_its_delegators_kel_first(tmp_path):
    """A delegate's own events cannot be verified before the delegator's, so `Hab.replay`'s
    recipe — `cloneDelegation` and then the AID's own first-seen log — is what the emission
    follows."""
    emitted_stream, _, facts = emitted("delegated", tmp_path)
    principals = [frame.principal for frame in ingest.walk(emitted_stream).frames]

    assert principals[0] == facts["delegator_aid"]
    assert facts["aid"] in principals
    assert principals.index(facts["delegator_aid"]) < principals.index(facts["aid"])


def test_the_emitted_reply_records_are_the_ones_the_audit_accepted(tmp_path):
    """Two signature shapes, both re-assembled from stored state: a location scheme is signed
    by its own non-transferable endpoint provider (a single cigar), and a role authorization is
    signed by the transferable controller (a transferable indexed-signature group)."""
    emitted_stream, _, facts = emitted("endpoints", tmp_path)
    replies = [body for body in keri_api.bodies(emitted_stream) if body.get("t") == "rpy"]

    assert [body["r"] for body in replies] == [
        "/loc/scheme",
        "/loc/scheme",
        "/end/role/add",
        "/end/role/add",
    ]
    assert {body["a"]["eid"] for body in replies} == {facts["mailbox_aid"], facts["agent_aid"]}


def test_the_emitted_stream_carries_only_v1_json_version_strings(tmp_path):
    """Constraint qbqfst on the emission path (design oracle 3)."""
    for knob in ("base", "delegated", "deactivated", "endpoints"):
        emitted_stream, _, _ = emitted(knob, tmp_path / knob)
        assert set(keri_api.version_strings(emitted_stream)) <= keri_api.ACCEPTED_VERSION_STRINGS


def test_every_attachment_group_in_an_emitted_stream_is_a_v1_counter(tmp_path):
    """The other half of the version oracle, and the one a body-only check would miss: a bare
    `hab.interact` on this keripy line emits v2 attachment counters onto a v1 body, and every
    deployed 1.2.x parser drops the frame. Each frame's attachment is read here with the v1
    code table explicitly, so a v2 counter fails to parse rather than shipping."""
    emitted_stream, _, _ = emitted("endpoints", tmp_path)

    for frame in keri_api.frames(emitted_stream):
        counter = counting.Counter(qb64b=frame.attachments, version=Vrsn_1_0)
        assert counter.code in counting.CtrDex_1_0
        assert counter.code not in (
            counting.CtrDex_2_0.ControllerIdxSigs,
            counting.CtrDex_2_0.TransIdxSigGroups,
            counting.CtrDex_2_0.TransLastIdxSigGroups,
        )


@pytest.mark.parametrize("knob", ["base", "delegated", "deactivated"])
def test_the_emitted_stream_re_ingests_to_the_same_state_and_the_same_document(knob, tmp_path):
    """Round-trip identity (design oracle 2), the strength rung: whatever the emission drops,
    reorders or fails to sign shows up here without any per-field assertion having to have
    anticipated it. What is hosted must verify to exactly what was verified."""
    stream, facts = builders.KNOBS[knob](tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as first:
        emitted_stream = assemble.emit_stream(first)
        original_frames = {frame.said for frame in first.frames}
        original_doc = document.derive_document(first, did)
        original_state = key_state(first.hby.kevers[did.aid])

    with ingest.ingest(emitted_stream, did) as second:
        assert {frame.said for frame in second.frames} == original_frames
        assert key_state(second.hby.kevers[did.aid]) == original_state
        assert document.derive_document(second, did) == original_doc
        assert second.acdc.said == first.acdc.said


def test_a_round_tripped_stream_still_carries_its_endpoints(tmp_path):
    """The reply records are the part most easily lost in re-assembly: they are signed
    separately, BADA-accepted separately, and belong to no KEL. Round-tripping the endpoints
    fixture proves the services survive the trip, not just the key state."""
    stream, facts = builders.endpoints(tmp_path)
    did = did_module.parse(facts["did_webs"])

    with ingest.ingest(stream, did) as first:
        emitted_stream = assemble.emit_stream(first)
        original_doc = document.derive_document(first, did)

    with ingest.ingest(emitted_stream, did) as second:
        assert document.derive_document(second, did) == original_doc
        assert len(original_doc["service"]) == 2


# ------------------------------------------ the keystore side as a fixture/demo entry point


def minted(tmp_path, *args):
    """Run `python -m didwebs.assemble` in process and return (stream bytes, printed DID)."""
    stream = tmp_path / "publication.cesr"
    code = assemble.main(
        ["--keystore", str(tmp_path / "ks"), "--out", str(stream), *args]
    )
    assert code == 0
    return stream, code


def test_the_keystore_entry_point_mints_an_aid_and_a_publishable_stream(tmp_path, capsys):
    """docs/design.md §Modules: fixtures and demos make a stream this way, and the product's
    only verb consumes one. The stream it writes must therefore pass our own ingest."""
    capsys.readouterr()
    stream, _ = minted(tmp_path, "--domain", "labs.bakobo.com")
    did = capsys.readouterr().out.strip()

    assert did.startswith("did:webs:labs.bakobo.com:")
    with ingest.ingest(stream.read_bytes(), did_module.parse(did)) as verified:
        assert did.endswith(verified.aid)
        assert verified.acdc.attrib["ids"] == [
            f"did:web:labs.bakobo.com:{verified.aid}",
            did,
        ]


def test_the_minted_did_can_carry_a_port(tmp_path, capsys):
    capsys.readouterr()
    stream, _ = minted(tmp_path, "--domain", "labs.bakobo.com", "--port", "8443")
    did = capsys.readouterr().out.strip()

    assert did.startswith("did:webs:labs.bakobo.com%3A8443:")
    with ingest.ingest(stream.read_bytes(), did_module.parse(did)) as verified:
        assert f"did:web:labs.bakobo.com%3A8443:{verified.aid}" in verified.acdc.attrib["ids"]


def test_the_keystore_entry_point_keeps_its_keystore_where_it_was_told_to(tmp_path, capsys):
    """A demo must never write into the operator's home keystore: keripy's registry database
    defaults to ~/.keri/reg, and only an explicit head directory keeps a run self-contained."""
    capsys.readouterr()
    minted(tmp_path, "--domain", "labs.bakobo.com")

    keystore = tmp_path / "ks" / "keri"
    assert sorted(item.name for item in keystore.iterdir()) == ["db", "ks", "reg"]
    assert (keystore / "reg" / "didwebs").is_dir()  # the registry, not ~/.keri/reg/didwebs


def test_the_minted_stream_carries_only_v1_json_version_strings(tmp_path, capsys):
    capsys.readouterr()
    stream, _ = minted(tmp_path, "--domain", "labs.bakobo.com")

    assert set(keri_api.version_strings(stream.read_bytes())) <= keri_api.ACCEPTED_VERSION_STRINGS
