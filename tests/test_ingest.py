"""didwebs.ingest — the post-parse audit that defines ingest success.

keripy's Parser is a stream processor, not a validator: it catches per-frame ``ValidationError``s
and resumes (``keri/core/parsing.py`` at the estate pin, the ``except (ValidationError,
Exception)`` arm — "we don't flush rest of stream just resume"). "Parsed without error" is
therefore vacuous, so every assertion here is about *observed database state* after ingest, never
about whether the parser raised.

The fixtures come from ``tests/builders.py`` by knob name, and every negative asserts the exact
error-code string.
"""

from __future__ import annotations

import glob
from pathlib import Path

import builders
import keri_api
import pytest
from bakobo.errors import BakoboError

from didwebs import did as did_module
from didwebs import ingest

# --------------------------------------------------------------------------------- helpers


def claimed(facts) -> did_module.WebsDid:
    """The did:webs DID a fixture's stream claims to back."""
    return did_module.parse(facts["did_webs"])


def fixture(knob, tmp_path):
    return builders.KNOBS[knob](tmp_path)


def ilks(walk) -> list:
    return [frame.ilk for frame in walk.frames]


def temp_stores() -> set:
    """Every keripy temporary store directory currently sitting in /tmp."""
    return set(glob.glob("/tmp/keri_*"))


def keri_api_reply(tmp_path):
    """A ``/loc/scheme`` reply signed by the base fixture's own controller.

    ``builders`` emits no replies — a phase-1 fixture has no witnesses and no endpoint roles for
    them to describe — so the one reply frame the reply-accounting oracle needs is minted here,
    from a keystore rebuilt on the same fixed salt and therefore the same AID.
    """
    with keri_api.scratch("base", tmp_path / "reply") as (hby, _):
        hab = keri_api.make_hab(hby, "controller")
        return bytes(
            hab.makeLocScheme(url="http://witness.example.com:5642/", scheme="http",
                              gvrsn=keri_api.V1)
        )


# ------------------------------------------------------------------- unit 1: the frame walk


def test_walk_of_a_valid_publication_stream_yields_every_frame_in_order(tmp_path):
    """Six frames: three KEL events, the registry vcp, the credential iss, then the ACDC."""
    stream, facts = fixture("base", tmp_path)
    walk = ingest.walk(stream)

    assert walk.failure is None
    assert ilks(walk) == ["icp", "ixn", "ixn", "vcp", "iss", None]
    assert [frame.proto for frame in walk.frames] == ["KERI"] * 5 + ["ACDC"]
    assert {frame.kind for frame in walk.frames} == {"JSON"}
    assert walk.frames[0].said == facts["aid"]
    assert walk.frames[-1].said == facts["acdc_said"]
    assert walk.frames[3].principal == facts["regk"]


def test_walk_records_the_principal_each_frame_is_about(tmp_path):
    """KEL frames are about their AID, TEL frames about their registry/credential, ACDCs about
    their issuer — the vocabulary the third-party sweep and the accounting audit both index on."""
    stream, facts = fixture("base", tmp_path)
    walk = ingest.walk(stream)

    kel = [frame for frame in walk.frames if frame.ilk in ("icp", "ixn")]
    assert {frame.principal for frame in kel} == {facts["aid"]}
    assert walk.frames[-1].principal == facts["aid"]  # ACDC principal is its issuer
    assert walk.frames[-1].regid == facts["regk"]


def test_walk_of_an_empty_stream_yields_no_frames_and_no_failure(tmp_path):
    walk = ingest.walk(b"")

    assert walk.frames == ()
    assert walk.failure is None


def test_walk_of_garbage_fails_as_a_format_problem(tmp_path):
    walk = ingest.walk(b"not a cesr stream at all, just prose")

    assert walk.frames == ()
    assert walk.failure.fault == "format"


def test_walk_of_a_stream_cut_mid_frame_fails_as_a_format_problem(tmp_path):
    """A short read is unwalkable, not merely incomplete: the frame's own size says so."""
    stream, _ = fixture("base", tmp_path)
    walk = ingest.walk(stream[:150])

    assert walk.frames == ()
    assert walk.failure.fault == "format"


def test_walk_keeps_the_frames_before_a_failure(tmp_path):
    """The prefix that walked is retained, so attribution can see how far the stream got."""
    stream, _ = fixture("cbor_frame", tmp_path)
    walk = ingest.walk(stream)

    assert ilks(walk) == ["icp", "ixn", "ixn", "vcp", "iss", None]
    assert walk.failure is not None


def test_walk_classifies_a_cbor_frame_as_an_unsupported_serialization(tmp_path):
    """CBOR is inside protocol v1 and outside the accepted JSON-only set (SKP-F5)."""
    stream, _ = fixture("cbor_frame", tmp_path)
    walk = ingest.walk(stream)

    assert walk.failure.fault == "serialization"
    assert walk.failure.kind == "CBOR"


def test_walk_classifies_a_v2_frame_as_a_format_problem(tmp_path):
    """A v2 body in a v1-genus stream: the pinned parser cannot read it at all (qbqfst)."""
    stream, _ = fixture("v2_frame", tmp_path)
    walk = ingest.walk(stream)

    assert walk.failure.fault == "format"
    assert walk.failure.kind is None


def test_walk_of_a_v1_json_body_with_unreadable_attachments_is_a_format_problem(tmp_path):
    """The body reads, the attachments do not. Nothing is wrong with the serialization, so
    calling it one would send the submitter to re-encode a stream that is already JSON."""
    stream, _ = fixture("base", tmp_path)
    body_only = ingest.walk(stream).frames[0].serder.size
    walk = ingest.walk(stream[:body_only] + b"@@@@@@@@")

    assert walk.frames == ()
    assert walk.failure == ingest.WalkFailure(fault="format", kind=None)


def test_walk_of_a_truncated_stream_succeeds_because_a_prefix_is_still_walkable(tmp_path):
    """Truncation is not a walk failure — the inception event is a complete, well-formed frame."""
    stream, facts = fixture("truncated", tmp_path)
    walk = ingest.walk(stream)

    assert walk.failure is None
    assert ilks(walk) == ["icp"]
    assert walk.frames[0].said == facts["aid"]


# ------------------------------------------------------- unit 1: the pre-parse rejection gates


def test_a_cbor_frame_fails_the_serialization_gate(tmp_path):
    stream, facts = fixture("cbor_frame", tmp_path)

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), ingest.walk(stream))

    assert caught.value.code == "e.feature.unsupported.serialization.f"


def test_a_v2_frame_fails_the_format_gate(tmp_path):
    stream, facts = fixture("v2_frame", tmp_path)

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), ingest.walk(stream))

    assert caught.value.code == "e.input.format.stream.f"


def test_a_garbled_stream_fails_the_format_gate(tmp_path):
    _, facts = fixture("base", tmp_path)
    walk = ingest.walk(b"not a cesr stream at all, just prose")

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), walk)

    assert caught.value.code == "e.input.format.stream.f"


def test_an_empty_stream_fails_the_format_gate(tmp_path):
    """Nothing to account for is a rejection, not a vacuous pass (fail closed, ledger #16)."""
    _, facts = fixture("base", tmp_path)

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), ingest.walk(b""))

    assert caught.value.code == "e.input.format.stream.f"


def test_a_format_fault_outranks_a_serialization_fault(tmp_path):
    """Brief §2.6's pinned precedence: format wins, so a stream that is both unreadable and
    wrongly serialized reports the coarser problem."""
    cbor, facts = fixture("cbor_frame", tmp_path)
    walk = ingest.walk(cbor)
    both = ingest.Walk(walk.frames, ingest.WalkFailure(fault="format", kind="CBOR"))

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), both)

    assert caught.value.code == "e.input.format.stream.f"


def test_a_valid_stream_passes_the_gate(tmp_path):
    stream, facts = fixture("base", tmp_path)

    assert ingest.require_supported(claimed(facts), ingest.walk(stream)) is None


def test_the_gate_rejects_a_walked_frame_whose_serialization_is_not_json(tmp_path):
    """A v1 CBOR frame with v1 attachments would walk cleanly; the per-frame kind check is what
    stops it, not the walk failure that this keripy line happens to produce first."""
    stream, facts = fixture("base", tmp_path)
    walk = ingest.walk(stream)
    doctored = ingest.Walk(
        (walk.frames[0].replace(kind="CBOR"), *walk.frames[1:]), None
    )

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), doctored)

    assert caught.value.code == "e.feature.unsupported.serialization.f"


def test_the_gate_rejects_a_walked_frame_whose_protocol_version_is_not_v1(tmp_path):
    stream, facts = fixture("base", tmp_path)
    walk = ingest.walk(stream)
    doctored = ingest.Walk((walk.frames[0].replace(major=2), *walk.frames[1:]), None)

    with pytest.raises(BakoboError) as caught:
        ingest.require_supported(claimed(facts), doctored)

    assert caught.value.code == "e.input.format.stream.f"


def test_every_parser_call_site_pins_the_v1_cesr_genus():
    """Constraint qbqfst's parse-side leg: the genus default is v2, and a v1 stream fed to a
    v2-genus parser yields nothing at all — no exception, no diagnostic (design §Shape)."""
    text = Path(ingest.__file__).read_text(encoding="utf-8")
    sites = [line for line in text.splitlines() if "Parser(" in line or ".parse(" in line]

    assert sites, "expected at least one parser call site to pin"
    for site in sites:
        assert "version=V1" in site or "version=V1" in text.split(site)[1][:400]


def test_keri_api_smoke_ingest_is_not_wired_into_the_product_path():
    """tests/keri_api.py's smoke_ingest is a fixture oracle with no audit; ingest must not use it."""
    text = Path(ingest.__file__).read_text(encoding="utf-8")

    assert "keri_api" not in text
    assert "smoke_ingest" not in text


# ------------------------------------------------- unit 2: the scratch state and its lifetime


def forge_signature(stream):
    """A copy of ``stream`` with one byte of the *second* frame's controller signature flipped.

    Built here rather than taken from ``builders.tampered_sig``: that knob mutates
    ``frame.end - 1``, which on a replayed KEL is the last byte of the first-seen replay couple's
    datetime, not a signature (see the fixture-defect test below). The signature bytes are located
    through keripy's own extraction — ``msgParsator`` hands back the ``Siger`` — so no offset
    arithmetic is guessed. The second frame is chosen because a forged *inception* leaves the AID
    with no key state at all, and attribution has nothing to check the signature against.
    """
    sig = ingest.walk(stream).frames[1].sigers[0].qb64
    at = stream.index(sig.encode()) + len(sig) // 2
    replacement = b"B" if stream[at : at + 1] != b"B" else b"C"
    return stream[:at] + replacement + stream[at + 1 :]


def loaded(stream):
    """A scratch state with ``stream`` ingested and every escrow drained to a fixpoint."""
    scratch = ingest.open_scratch()
    scratch.load(stream)
    return scratch


def test_a_scratch_state_ingests_a_valid_stream_into_key_and_transaction_state(tmp_path):
    """The v1 parse-side pin proves itself here: under the v2 genus default this stream would
    produce no kevers entry at all, silently (design §Shape)."""
    stream, facts = fixture("base", tmp_path)

    with loaded(stream) as scratch:
        assert facts["aid"] in scratch.hby.kevers
        assert scratch.hby.kevers[facts["aid"]].sner.num == facts["kel_sn"]
        assert facts["regk"] in scratch.regery.reger.tevers
        assert scratch.regery.reger.saved.get(keys=(facts["acdc_said"],)) is not None


def test_two_scratch_states_share_no_lmdb_state(tmp_path):
    """Per-call temporary databases: the second ingestion sees nothing of the first."""
    base, base_facts = fixture("base", tmp_path / "one")
    other, other_facts = fixture("attacker_acdc", tmp_path / "two")

    with loaded(base) as first, loaded(other) as second:
        assert base_facts["aid"] in first.hby.kevers
        assert other_facts["attacker_aid"] not in first.hby.kevers
        assert base_facts["regk"] not in second.regery.reger.tevers
        assert first.hby.db.path != second.hby.db.path


def test_closing_a_scratch_state_leaves_no_temporary_directory_behind(tmp_path):
    """keripy clears the leaf of a temp store's path and leaves the mkdtemp root standing, so
    ingest removes the roots itself; a suite that ran otherwise would litter /tmp per ingestion."""
    stream, _ = fixture("base", tmp_path)
    before = temp_stores()

    scratch = loaded(stream)
    assert temp_stores() > before
    scratch.close()

    assert temp_stores() == before


def test_closing_a_scratch_state_twice_is_harmless(tmp_path):
    stream, _ = fixture("base", tmp_path)
    scratch = loaded(stream)
    scratch.close()

    assert scratch.close() is None


def test_the_context_manager_closes_the_scratch_state_on_the_way_out(tmp_path):
    stream, _ = fixture("base", tmp_path)
    before = temp_stores()

    with loaded(stream) as scratch:
        assert scratch.hby.db.opened

    assert temp_stores() == before


def test_escrow_drains_iterate_to_a_fixpoint(tmp_path):
    """A delegated AID needs two passes. keripy's ``processEscrows`` runs out-of-order *before*
    partial-delegation, so on the first pass the delegate's interaction events cannot resolve —
    their inception is still escrowed — and a single drain leaves the stream half-ingested."""
    stream, facts = fixture("delegated", tmp_path)

    with loaded(stream) as scratch:
        assert scratch.passes > 1
        assert scratch.hby.kevers[facts["aid"]].sner.num == facts["kel_sn"]
        assert facts["regk"] in scratch.regery.reger.tevers
        assert scratch.regery.reger.saved.get(keys=(facts["acdc_said"],)) is not None


# --------------------------------------------------------- unit 2: whose frames may appear


def test_a_delegated_stream_carrying_its_delegator_passes_the_delegator_gate(tmp_path):
    stream, facts = fixture("delegated", tmp_path)
    walked = ingest.walk(stream)

    assert ingest.delegators(claimed(facts), walked) == frozenset({facts["delegator_aid"]})
    assert ingest.require_delegator(claimed(facts), walked) is None


def test_a_delegated_stream_without_its_delegator_is_rejected(tmp_path):
    """Phase 1 does no network I/O: an absent delegator KEL is an error, never a fetch."""
    stream, facts = fixture("delegated:no-delegator", tmp_path)

    with pytest.raises(BakoboError) as caught:
        ingest.require_delegator(claimed(facts), ingest.walk(stream))

    assert caught.value.code == "e.input.missing.delegator.f"


def test_an_undelegated_stream_has_no_delegators(tmp_path):
    stream, facts = fixture("base", tmp_path)

    assert ingest.delegators(claimed(facts), ingest.walk(stream)) == frozenset()


def test_a_valid_publication_stream_carries_no_third_party_frames(tmp_path):
    stream, facts = fixture("base", tmp_path)

    assert ingest.require_no_third_party(claimed(facts), ingest.walk(stream)) is None


def test_a_stranger_kel_in_the_stream_is_rejected(tmp_path):
    """No third-party chaff in a publication. keripy accepts the stranger's events happily — the
    sweep is didwebs policy, not a keripy verdict, which is why the test proves both halves."""
    stream, facts = fixture("third_party", tmp_path)
    walked = ingest.walk(stream)

    with loaded(stream) as scratch:
        stranger_frames = [f for f in walked.frames if f.principal == facts["third_party_aid"]]
        assert stranger_frames
        assert all(ingest.accepted(scratch, frame) for frame in stranger_frames)

    with pytest.raises(BakoboError) as caught:
        ingest.require_no_third_party(claimed(facts), walked)

    assert caught.value.code == "e.proof.stream.frame.f"


def test_an_attackers_kel_backing_an_acdc_in_the_stream_reaches_the_authorization_check(tmp_path):
    """KRT-F1's fixture must not be rejected a step too early. The attacker's KEL is what anchors
    the registry the attacker's ACDC rides, so the sweep admits it as evidence *for* that ACDC and
    lets the issuer-binding post-condition deliver the verdict."""
    stream, facts = fixture("attacker_acdc", tmp_path)

    assert ingest.require_no_third_party(claimed(facts), ingest.walk(stream)) is None
    assert facts["attacker_aid"] != facts["aid"]


def test_a_transaction_event_about_an_unknown_registry_is_third_party(tmp_path):
    """A TEL frame's principal is its registry or credential identifier, so the sweep compares it
    against those, never against an AID."""
    stream, facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    doctored = ingest.Walk(
        tuple(f.replace(principal="EStranger") if f.ilk == "iss" else f for f in walked.frames),
        None,
    )

    with pytest.raises(BakoboError) as caught:
        ingest.require_no_third_party(claimed(facts), doctored)

    assert caught.value.code == "e.proof.stream.frame.f"


def test_the_sweep_lets_a_reply_frame_through_to_the_accounting_audit(tmp_path):
    """Replies are swept by accounting (BADA-accepted or not), not by principal."""
    stream, facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    doctored = ingest.Walk(
        (walked.frames[0].replace(ilk="rpy", principal="EStranger"), *walked.frames[1:]), None
    )

    assert ingest.require_no_third_party(claimed(facts), doctored) is None


# --------------------------------------------------------------- unit 2: the accounting audit


def test_every_frame_of_a_valid_stream_is_accounted_accepted(tmp_path):
    stream, facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)

    with loaded(stream) as scratch:
        assert ingest.account_frames(scratch, walked) == ()
        assert ingest.audit(scratch, claimed(facts), walked) is None


def test_a_truncated_stream_accounts_cleanly_because_its_one_frame_was_accepted(tmp_path):
    """Truncation removes frames; it does not leave an unaccounted one. The rejection comes from
    the authorization post-conditions, not from accounting."""
    stream, facts = fixture("truncated", tmp_path)
    walked = ingest.walk(stream)

    with loaded(stream) as scratch:
        assert ingest.account_frames(scratch, walked) == ()
        assert ingest.audit(scratch, claimed(facts), walked) is None


def test_a_dropped_frame_is_caught_by_accounting_not_published_around(tmp_path):
    """SPC-F1: the appended event is well formed, correctly signed, and escrowed out of order
    forever. A pipeline that published "everything accepted" would drop it silently."""
    stream, facts = fixture("dropped_frame_candidate", tmp_path)
    walked = ingest.walk(stream)

    with loaded(stream) as scratch:
        unaccounted = ingest.account_frames(scratch, walked)
        assert [frame.sn for frame in unaccounted] == [facts["orphan_sn"]]
        assert scratch.escrow_saids("ooes") == {frame.said for frame in unaccounted}

        with pytest.raises(BakoboError) as caught:
            ingest.audit(scratch, claimed(facts), walked)

    assert caught.value.code == "e.proof.stream.frame.f"


# ------------------------------------------------------------------ unit 2: the escrow audit


def test_a_forked_submission_is_rejected_as_a_key_event_log_conflict(tmp_path):
    """SKP-F2/SEC-F2. Two valid interaction events at the same sequence number in one submission.
    First-seen-wins is not an acceptable resolution for a stream we are asked to publish.

    The audit inspects real database state rather than pattern-matching the fixture: it asserts
    that keripy accepted a *different* event at that sequence number, that the losing branch is
    genuinely absent from the first-seen log, and that the conflict is what the audit reports.
    """
    stream, facts = fixture("forked_kel", tmp_path)
    walked = ingest.walk(stream)

    with loaded(stream) as scratch:
        unaccounted = ingest.account_frames(scratch, walked)
        assert len(unaccounted) == 1
        loser = unaccounted[0]
        assert loser.sn == int(facts["fork_sn"])
        winner = scratch.hby.db.kels.getLast(keys=facts["aid"], on=loser.sn)
        assert winner is not None and winner != loser.said
        assert ingest.duplicitous(scratch, walked) == {loser.said}

        with pytest.raises(BakoboError) as caught:
            ingest.audit(scratch, claimed(facts), walked)

    assert caught.value.code == "e.state.conflict.kel.f"


def test_the_likely_duplicitous_escrow_is_dead_on_this_keripy_line(tmp_path):
    """A defect record, not a preference. ``Kevery.escrowLDEvent`` calls ``self.db.addLde``, and
    ``Baser`` at the estate pin defines no such method: the ``AttributeError`` surfaces as
    "No kevery to process so dropped msg" and the Parser swallows it. ``db.ldes`` therefore never
    fills, which is why the duplicity audit reads the accepted key event log as well.

    Delete this test — and the accounting-side half of :func:`ingest.duplicitous` — when the pin
    moves to a keripy that defines ``addLde``.
    """
    stream, _ = fixture("forked_kel", tmp_path)

    with loaded(stream) as scratch:
        assert scratch.escrow_saids("ldes") == set()


def test_the_duplicity_audit_reads_the_likely_duplicitous_escrow_too(tmp_path):
    """The design's stated mechanism, exercised against a planted escrow entry so that it is
    covered today and fires by itself once keripy's ``addLde`` defect is fixed."""
    stream, facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)

    with loaded(stream) as scratch:
        planted = walked.frames[1].said
        scratch.hby.db.ldes.add(keys=facts["aid"], on=1, val=planted.encode())

        assert planted in ingest.duplicitous(scratch, walked)

        with pytest.raises(BakoboError) as caught:
            ingest.audit(scratch, claimed(facts), walked)

    assert caught.value.code == "e.state.conflict.kel.f"


def test_a_forged_controller_signature_is_attributed_to_the_signature(tmp_path):
    """SKP-F2's tamper oracle. No escrow is populated for a signature that fails to verify — the
    event is simply dropped — so attribution verifies the frame's own signatures against the
    accepted key state, with keripy's ``verifySigs`` and the Kever's own threshold."""
    stream, facts = fixture("base", tmp_path)
    forged = forge_signature(stream)
    walked = ingest.walk(forged)

    with loaded(forged) as scratch:
        unaccounted = ingest.account_frames(scratch, walked)
        assert unaccounted, "the forged event must not be in accepted state"
        assert scratch.escrow_saids("pses") == set()  # keripy escrows nothing for a bad sig

        with pytest.raises(BakoboError) as caught:
            ingest.audit(scratch, claimed(facts), walked)

    assert caught.value.code == "e.proof.stream.sig.f"


def test_the_tampered_sig_fixture_does_not_tamper_a_signature(tmp_path):
    """A defect record against ``builders.tampered_sig`` (STOP-and-report, brief §2).

    The knob mutates ``frame.end - 1``. On a replayed KEL a frame's attachments end with the
    first-seen replay couple, so that offset is the last byte of a datetime, not of a signature —
    and the datetime is not covered by any signature, so the stream ingests cleanly. The knob's
    own test (``tests/test_builders.py``) asserts only that the byte lies in the attachments, so
    it passes while its name and the module docstring both claim "inside a signature".

    Delete this test and point the signature oracle back at the knob once it is fixed.
    """
    stream, facts = fixture("tampered_sig", tmp_path)
    parent = facts["parent_stream"]
    walked = ingest.walk(parent)
    signatures = [siger.qb64 for frame in walked.frames for siger in frame.sigers]
    at = facts["tampered_offset"]

    assert not any(
        parent.index(sig.encode()) <= at < parent.index(sig.encode()) + len(sig)
        for sig in signatures
    )
    with loaded(stream) as scratch:
        assert ingest.account_frames(scratch, ingest.walk(stream)) == ()
        assert ingest.audit(scratch, claimed(facts), ingest.walk(stream)) is None


def test_attribution_of_an_unaccounted_transaction_event_falls_through_to_the_frame(tmp_path):
    """Attribution never inspects signatures on a frame that carries none."""
    stream, _facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    tel = next(frame for frame in walked.frames if frame.ilk == "iss")

    with loaded(stream) as scratch:
        assert ingest.attribute(scratch, tel).code == "e.proof.stream.frame.f"


def test_attribution_of_an_event_for_an_aid_with_no_key_state_falls_through(tmp_path):
    """Nothing to check a signature against, so the residue code, not a guess (ledger #16)."""
    stream, _facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    orphaned = walked.frames[1].replace(principal="E" + "A" * 43)

    with loaded(stream) as scratch:
        assert ingest.attribute(scratch, orphaned).code == "e.proof.stream.frame.f"


def test_attribution_maps_each_escrow_kind_to_its_own_leaf(tmp_path):
    """The escrow-to-code table, exercised against planted entries: the distinctions the error
    taxonomy asserts have to be observable, and each leaf needs a test to be discharged."""
    stream, facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    frame = walked.frames[1]

    with loaded(stream) as scratch:
        scratch.hby.db.pdes.add(keys=facts["aid"], on=1, val=frame.said.encode())
        assert ingest.attribute(scratch, frame).code == "e.proof.stream.seal.f"

    with loaded(stream) as scratch:
        scratch.regery.reger.taes.add(keys=facts["regk"], on=0, val=frame.said.encode())
        assert ingest.attribute(scratch, frame).code == "e.proof.stream.anchor.f"

    with loaded(stream) as scratch:
        scratch.hby.db.pses.add(keys=facts["aid"], on=1, val=frame.said.encode())
        assert ingest.attribute(scratch, frame).code == "e.proof.stream.sig.f"

    with loaded(stream) as scratch:
        acdc = walked.frames[-1]
        scratch.regery.reger.cmse.pin(keys=(acdc.said,), val=acdc.serder)
        assert ingest.attribute(scratch, acdc).code == "e.proof.stream.sig.f"


def test_a_reply_record_is_accounted_when_it_is_accepted(tmp_path):
    """Reply frames are accounted through the BADA-accepted reply store, not through the KEL."""
    stream, _facts = fixture("base", tmp_path)
    reply = keri_api_reply(tmp_path)
    with_reply = stream + reply
    walked = ingest.walk(with_reply)
    rpy = [frame for frame in walked.frames if frame.ilk == "rpy"]

    assert len(rpy) == 1
    with loaded(with_reply) as scratch:
        assert ingest.accepted(scratch, rpy[0])
        assert ingest.account_frames(scratch, walked) == ()


def test_an_unaccepted_reply_record_is_unaccounted(tmp_path):
    stream, _facts = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    fake = walked.frames[0].replace(ilk="rpy", said="E" + "A" * 43)

    with loaded(stream) as scratch:
        assert not ingest.accepted(scratch, fake)


def test_a_message_class_this_build_does_not_recognize_is_never_accounted(tmp_path):
    """Fail closed: an ilk the audit has no oracle for cannot be treated as accepted."""
    stream, _ = fixture("base", tmp_path)
    walked = ingest.walk(stream)
    exotic = walked.frames[0].replace(ilk="exn")

    with loaded(stream) as scratch:
        assert not ingest.accepted(scratch, exotic)
