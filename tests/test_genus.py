"""The CESR-genus oracle, and the blind spot it exists to cover (constraint ``qbqfst``).

The pin has two independent axes. ``keri_api.version_strings`` reads the *protocol* version off
each event body and ``assemble._v1`` checks ``serder.pvrsn``; neither sees the CESR *genus* of
the attachment counters, which is chosen separately and by a different keripy default. The first
test below is the demonstration: one stream, tampered only in its counter, that the
version-string oracle still passes and the genus oracle refuses.

That is not a hypothetical. The 2026-08-28 pin-bump attempt (tick ``~3vol``) produced the same
shape for real — ``keri.app.signing.serialize`` stopped hardcoding the v1 ``-I``
SealSourceTriples counter and began deriving the genus from keripy's global default, emitting a
v2 ``-S`` SealSourceCouples while every body stayed ``KERI10JSON``.
"""

from __future__ import annotations

import builders
import keri_api
import pytest
from keri.core.counting import Codens, Counter
from keri.kering import Vrsn_1_0, Vrsn_2_0

#: The one v1 counter a didwebs publication stream carries that has a different spelling in the
#: v2 table, so swapping it changes the genus and nothing else.
V1_SEAL_SOURCE = Counter(Codens.SealSourceTriples, count=1, version=Vrsn_1_0).qb64b
V2_SEAL_SOURCE = Counter(Codens.SealSourceCouples, count=1, version=Vrsn_2_0).qb64b


@pytest.fixture(scope="module")
def base_stream(tmp_path_factory):
    stream, _ = builders.base(tmp_path_factory.mktemp("genus"))
    return stream


def test_the_two_spellings_really_are_different_genera():
    """Guards the tamper below: if these ever coincided, every test here would pass vacuously."""
    assert V1_SEAL_SOURCE != V2_SEAL_SOURCE
    assert Counter(qb64b=V1_SEAL_SOURCE, version=Vrsn_1_0).code
    with pytest.raises(Exception, match="Unsupported code"):
        Counter(qb64b=V2_SEAL_SOURCE, version=Vrsn_1_0)


def test_a_generated_stream_reads_end_to_end_under_genus_v1(base_stream):
    assert keri_api.v1_genus_violation(base_stream) is None


def test_only_the_two_serialization_knobs_declare_a_deliberate_genus_violation(tmp_path):
    """The exclusion is data on the fixture, not a list of names here (the toolkit's existing
    idiom for ``deliberate_version_strings``), and this pins which fixtures may claim it.

    ``truncated`` is deliberately absent. It stops early on a frame boundary rather than
    mid-frame, so it reads cleanly and ingest refuses it by frame accounting — a different axis,
    and the distinction is why this oracle is about genus rather than about completeness.
    """
    declaring = {
        knob
        for knob in builders.KNOBS
        if builders.KNOBS[knob](tmp_path / knob).facts["deliberate_genus_violation"]
    }
    assert declaring == {"v2_frame", "cbor_frame"}


def test_a_v2_counter_is_caught_even_though_every_body_stays_v1(base_stream):
    """The whole point of the second oracle, as one assertion.

    The tampered stream is byte-identical to a good one except for a single counter, so every
    version string in it is still KERI10JSON/ACDC10JSON — the protocol-axis oracle passes it.
    """
    assert base_stream.count(V1_SEAL_SOURCE) == 1
    tampered = base_stream.replace(V1_SEAL_SOURCE, V2_SEAL_SOURCE, 1)

    assert set(keri_api.version_strings(tampered)) <= keri_api.ACCEPTED_VERSION_STRINGS
    violation = keri_api.v1_genus_violation(tampered)
    assert violation is not None
    assert "-S" in violation


def test_the_violation_says_which_frame_reading_stopped_on(base_stream):
    """A report that only said "not v1" would send a reader back to the whole stream.

    The offset is where the *frame* began, not where the counter sits inside it — the stream is
    walked one message at a time, so what the oracle can name is the message keripy refused.
    That is the useful unit anyway: a counter offset points into the middle of an attachment,
    and the frame is the thing an emitter would go and look at.
    """
    tampered = base_stream.replace(V1_SEAL_SOURCE, V2_SEAL_SOURCE, 1)
    counter_at = base_stream.index(V1_SEAL_SOURCE)

    violation = keri_api.v1_genus_violation(tampered)

    frame_at = int(violation.split("stopped at byte ")[1].split(" of ")[0])
    assert 0 < frame_at < counter_at
    assert base_stream[frame_at:].startswith(b'{"v":"ACDC10JSON')
    assert str(len(base_stream)) in violation


def test_an_empty_stream_has_no_genus_violation():
    """Vacuous but not a failure: emptiness is ingest's to refuse, with its own code."""
    assert keri_api.v1_genus_violation(b"") is None


def test_garbage_is_a_violation_rather_than_a_hang():
    """The oracle must be total on hostile input — no exception escaping, and no loop that
    makes no progress."""
    assert keri_api.v1_genus_violation(b"not a CESR stream at all") is not None
