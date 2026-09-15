"""didwebs.bounds — the door everything crosses through.

Every byte this process reads from outside arrives through an opener here, and is bounded before
it is parsed (constraint ``adyiw2mm``; dev/standards/input-handling.md). Size first, then shape,
then meaning: the frame walk, the signature verification and the ownership audit in
:mod:`didwebs.ingest` are all judgments about what bytes *mean*, and none of them starts if the
submission is simply too large.

**The door decides how many, never what it means.** :func:`open_stream` will admit a stream of
random bytes, an empty file, or a KEL that forks itself, and ``ingest`` then refuses each with an
attributed code of its own. That separation is deliberate: a door that also judged meaning would
be a second, weaker verifier that could drift from the real one, and two refusals for one
condition is worse than one.

**One number, not two.** There is no frame-count cap and no per-frame cap to go with the byte
bound. Every CESR frame carries a version string and a body, so bounding the bytes already bounds
how many frames can be in them; a separately chosen frame count would be an opinion about what a
legitimate publication contains, which is exactly what a flood guard must not be.

**The number is a flood guard.** It is not an estimate of what a real publication weighs and
should not be tuned as though it were. A did:webs publication stream is one AID's KEL, its
registry TELs and a designated-aliases ACDC; KERI events run from a few hundred bytes to a few
kB, so the bound below is thousands of rotations and orders of magnitude above any submission
anyone has a reason to send.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from didwebs import errors
from didwebs.did import WebsDid

__all__ = [
    "DOORS",
    "MAX_STREAM_BYTES",
    "STREAM",
    "Door",
    "open_stream",
    "read_bounded",
]

_MIB = 1024 * 1024


@dataclass(frozen=True)
class Door:
    """One named entrance, for one kind of input, carrying that kind's bound.

    Attributes:
        kind: the artifact this door admits. Also names the opener (``open_<kind>``) and the
            trailing descriptor of the range code the door raises, so the three cannot drift.
        limit: the most bytes that may cross, in bytes.
    """

    kind: str
    limit: int


#: The controller's CESR publication stream: a KEL, its registry TELs, and the designated-aliases
#: ACDC. Matches the sibling did-webvh's bound for the same artifact.
STREAM = Door("stream", 8 * _MIB)

#: Every door. The census test and :mod:`didwebs.errors` are both read from this rather than from
#: a list kept by hand, so adding a door is one edit and forgetting to register one is a failure.
DOORS = (STREAM,)

#: The stream door's bound, named separately because operators and tests refer to it directly.
MAX_STREAM_BYTES = STREAM.limit


def read_bounded(handle: BinaryIO, door: Door, did: WebsDid) -> bytes:
    """Read at most ``door.limit`` bytes from ``handle``, refusing anything longer.

    Reads one byte past the bound and refuses on the overage, so the process never holds more
    than ``limit + 1`` however much the far end has. A length check that first reads the whole
    thing is not a bound (dev/standards/input-handling.md, rubric 3), and neither is a
    ``Content-Length`` the same party chose.

    Args:
        handle: an open binary stream.
        door: the door whose bound applies.
        did: the DID being published, for the refusal message.

    Returns:
        The bytes read.

    Raises:
        bakobo.errors.BakoboError: ``e.input.range.<kind>.f`` when the input exceeds the bound.
    """
    payload = handle.read(door.limit + 1)
    if len(payload) > door.limit:
        raise errors.TOO_LARGE[door.kind](
            did=did.compose(), bound="the file", limit=door.limit
        )
    return payload


def open_stream(path: Path | str, did: WebsDid) -> bytes:
    """Admit a CESR publication stream, bounding it and nothing else.

    What the bytes mean is :mod:`didwebs.ingest`'s judgment, made against the AID's own key
    state. This door exists so that judgment is reached with a bounded amount of memory in hand.

    Args:
        path: the submitted stream file.
        did: the DID being published, for the refusal message.

    Returns:
        The submitted bytes.

    Raises:
        OSError: the file could not be opened. Deliberately not converted into a refusal — a
            path that is not there is a mistake in the invocation, not a submission this
            pipeline considered and declined, and the CLI reports the two differently.
        bakobo.errors.BakoboError: ``e.input.range.stream.f`` past the bound.
    """
    with open(path, "rb") as handle:  # door: the only read for this kind
        return read_bounded(handle, STREAM, did)
