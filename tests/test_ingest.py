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
