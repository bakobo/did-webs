"""The stream door: size before shape before meaning (constraint ``adyiw2mm``).

What these assert is deliberately narrow. The door decides *how many* bytes, never what they
mean — a stream of pure garbage passes it, and ``ingest`` refuses that stream a moment later with
a code of its own. A door that also judged meaning would be a second, weaker verifier that could
drift from the real one.
"""

from __future__ import annotations

import pytest
from bakobo.errors import BakoboError

from didwebs import bounds, errors
from didwebs.did import parse as parse_did

DID = parse_did("did:webs:labs.bakobo.com:EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP")


def write(path, size: int):
    path.write_bytes(b"x" * size)
    return path


def test_a_stream_at_the_bound_is_admitted(tmp_path):
    """The bound is inclusive: exactly ``limit`` bytes is a submission, not an overage."""
    path = write(tmp_path / "keri.cesr", bounds.STREAM.limit)
    assert bounds.open_stream(path, DID) == b"x" * bounds.STREAM.limit


def test_a_stream_one_byte_past_the_bound_is_refused(tmp_path):
    path = write(tmp_path / "keri.cesr", bounds.STREAM.limit + 1)

    with pytest.raises(BakoboError) as caught:
        bounds.open_stream(path, DID)

    assert caught.value.code == errors.STREAM_TOO_LARGE.code
    assert caught.value.retryable is False


def test_the_refusal_names_the_bound_without_echoing_the_submission(tmp_path):
    """input-handling.md rubric 6: the reader needs the bound and what to do, not their own
    payload back."""
    path = write(tmp_path / "keri.cesr", bounds.STREAM.limit + 1)

    with pytest.raises(BakoboError) as caught:
        bounds.open_stream(path, DID)

    message = str(caught.value)
    assert str(bounds.STREAM.limit) in message
    assert DID.compose() in message
    assert "xxxx" not in message


def test_an_ordinary_stream_is_returned_whole(tmp_path):
    path = write(tmp_path / "keri.cesr", 1024)
    assert bounds.open_stream(path, DID) == b"x" * 1024


def test_an_empty_stream_passes_the_door_and_is_ingests_problem(tmp_path):
    """The door is a size check only. Emptiness already has an attributed code
    (``e.input.format.stream.f``, ``ingest.require_supported``), and a second refusal here would
    be two codes for one condition."""
    path = write(tmp_path / "keri.cesr", 0)
    assert bounds.open_stream(path, DID) == b""


class _Endless:
    """A handle with more bytes behind it than the bound, which answers exactly what it is asked.

    Stands in for the thing rubric 3 is about: something whose real length the door must never
    depend on knowing.
    """

    def __init__(self):
        self.asked: list[int] = []

    def read(self, size=-1):
        self.asked.append(size)
        return b"x" * (size if size >= 0 else bounds.STREAM.limit * 4)


def test_the_door_asks_for_one_byte_past_the_bound_and_no_more():
    """rubric 3: 'a length check that first reads the whole thing' is not a bound. One read, for
    ``limit + 1``, so the process never holds more than that however much is on the other end."""
    handle = _Endless()

    with pytest.raises(BakoboError) as caught:
        bounds.read_bounded(handle, bounds.STREAM, DID)

    assert handle.asked == [bounds.STREAM.limit + 1]
    assert caught.value.code == errors.STREAM_TOO_LARGE.code


def test_a_missing_file_raises_oserror_rather_than_a_refusal(tmp_path):
    """The door does not classify an invocation mistake as a submission it refused; the CLI maps
    that to EX_USAGE."""
    with pytest.raises(OSError):
        bounds.open_stream(tmp_path / "absent.cesr", DID)


def test_every_door_is_registered(tmp_path):
    """``DOORS`` is what the census reads, so a door missing from it is a door the completeness
    test cannot see."""
    assert bounds.STREAM in bounds.DOORS
    assert all(door.limit > 0 for door in bounds.DOORS)
    assert len({door.kind for door in bounds.DOORS}) == len(bounds.DOORS)


def test_every_door_has_a_range_code_and_an_opener():
    """The three things a door's kind names must actually exist, or a refusal would assemble a
    code string at runtime -- which the error-codes standard forbids."""
    for door in bounds.DOORS:
        assert door.kind in errors.TOO_LARGE
        assert errors.TOO_LARGE[door.kind].code == f"e.input.range.{door.kind}.f"
        assert callable(getattr(bounds, f"open_{door.kind}"))
