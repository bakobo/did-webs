"""The post-parse audit — the definition of ingest success.

**Why this module exists.** keripy's ``Parser`` is a stream processor, not a validator. At the
estate pin it catches per-frame ``ValidationError``s, logs them, and resumes
(``keri/core/parsing.py``, the ``except (ValidationError, Exception)`` arm: *"we don't flush rest
of stream just resume"*). A forged signature, a duplicitous event, or a rejected reply therefore
leaves no exception behind — only a gap in the database. "Parsed without error" says nothing, so
ingest success is defined here, by auditing what keripy actually accepted, and hosted artifacts
are re-derived from that accepted state rather than copied from submitted bytes (constraint
``embuup``).

**The three named steps**, in the design's own vocabulary (docs/design.md, ``didwebs/ingest.py``):

1. :func:`walk` — *frame accounting*, pre-parse half. Every message in the submitted stream is
   extracted with keripy's own primitives, never a regex, so the pipeline knows exactly what it
   was asked to publish. :func:`require_supported` then enforces the JSON-only, protocol-v1
   restriction, and :func:`require_delegator` / :func:`require_no_third_party` enforce whose
   frames may appear at all.
2. :func:`account_frames` — *the accounting audit*, post-parse half: every walked frame must be
   in accepted state, and :func:`attribute` maps any that is not to an error code by reading the
   scratch database's escrows.
3. :func:`authorize` — *the authorization post-conditions* on the designated-aliases ACDC.

**The v1 pin extends to parsing** (constraint ``qbqfst``, design §Shape). ``Parser`` carries its
own CESR genus version, defaulting to v2, and a valid v1 stream fed to a v2-genus parser yields
*nothing* — no exception, no diagnostic, no ``kevers`` entry. Every parser construction and every
``parse`` call below therefore passes ``version=V1`` explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from keri.core import serdering
from keri.core.parsing import Parser
from keri.kering import Kinds, Vrsn_1_0

from didwebs import errors

__all__ = [
    "Frame",
    "Walk",
    "WalkFailure",
    "require_supported",
    "walk",
]

#: The CESR genus version every parser in this module is pinned to (constraint ``qbqfst``).
V1 = Vrsn_1_0

#: The only serialization didwebs accepts — narrower than "v1" on purpose (SKP-F5).
ACCEPTED_KIND = Kinds.json

#: Protocols a publication stream may carry.
KERI = "KERI"
ACDC = "ACDC"

#: Message types that are key events, i.e. frames whose principal is an AID.
KEL_ILKS = frozenset({"icp", "rot", "ixn", "dip", "drt"})

#: Message types that are transaction events, i.e. frames whose principal is a registry or a
#: credential identifier rather than an AID.
TEL_ILKS = frozenset({"vcp", "vrt", "iss", "rev", "bis", "brv"})

#: Registry inception. Its ``ii`` field names the AID whose KEL must anchor the registry.
REGISTRY_INCEPTION = "vcp"


@dataclass(frozen=True)
class Frame:
    """One walked message: what it is, whom it is about, and the material to audit it with.

    ``serder`` and ``sigers`` are keripy objects over the *submitted* bytes. They exist for the
    duration of the audit and never reach :class:`Verified` — constraint ``embuup`` forbids
    anything downstream from reaching around the audit to raw input.
    """

    said: str
    ilk: str | None
    proto: str
    kind: str
    major: int
    principal: str
    sn: int | None
    regid: str | None
    serder: object = None
    sigers: tuple = ()

    def replace(self, **changes) -> Frame:
        """A copy with ``changes`` applied — the dataclass helper, exposed for audit tests."""
        return replace(self, **changes)


@dataclass(frozen=True)
class WalkFailure:
    """Why the walk stopped short.

    ``fault`` is ``"format"`` (the residue is not a readable v1 frame at all) or
    ``"serialization"`` (it is a readable v1 frame in a serialization this build does not
    accept). ``kind`` is the offending serialization when one could be read.
    """

    fault: str
    kind: str | None = None


@dataclass(frozen=True)
class Walk:
    """The submitted stream as this pipeline reads it: the frames it could extract, and the
    failure that stopped it, if any. A walk with frames *and* a failure is normal — the prefix
    that walked is retained so attribution can say how far the stream got."""

    frames: tuple[Frame, ...]
    failure: WalkFailure | None


def _frame(serder, sigers) -> Frame:
    """Describe one extracted message.

    The *principal* is whom the frame is about, which differs by message class: a key event is
    about its AID, a transaction event about its registry or credential identifier, and an ACDC
    about its issuer (``SerderACDC.israid``). The third-party sweep and the accounting audit both
    index on this, so it is computed once, here.
    """
    if serder.proto == ACDC:
        return Frame(
            said=serder.said,
            ilk=None,
            proto=ACDC,
            kind=serder.kind,
            major=serder.pvrsn.major,
            principal=serder.israid,
            sn=None,
            regid=serder.regid,
            serder=serder,
            sigers=tuple(sigers),
        )
    return Frame(
        said=serder.said,
        ilk=serder.ilk,
        proto=serder.proto,
        kind=serder.kind,
        major=serder.pvrsn.major,
        principal=serder.pre,
        sn=serder.sn,
        regid=None,
        serder=serder,
        sigers=tuple(sigers),
    )


def _classify(residue: bytes) -> WalkFailure:
    """Decide whether unwalkable residue is a format problem or an unsupported serialization.

    keripy's own ``Serder`` is the discriminator: if it can read a body out of the residue then
    the frame is well formed and only its serialization or protocol version is wrong; if it
    cannot, the stream is not readable at all. Deliberately not a regex — a version-string regex
    would also match a version-string-shaped substring inside a path or an attachment (SPC-F1).
    """
    try:
        serder = serdering.Serder(raw=residue)
    except Exception:  # noqa: BLE001 — any read failure means "not a readable frame"
        return WalkFailure(fault="format")
    if serder.pvrsn.major != V1.major:
        return WalkFailure(fault="format")
    if serder.kind != ACCEPTED_KIND:
        return WalkFailure(fault="serialization", kind=serder.kind)
    return WalkFailure(fault="format")


def walk(stream: bytes) -> Walk:
    """Extract every frame of ``stream``, one message at a time, with the CESR genus pinned to v1.

    This is step 1 of the audit — the pipeline's own account of what it was asked to publish,
    taken *before* keripy sees the stream, so that a frame keripy would silently drop is visible
    here rather than absent from everything (SPC-F1).

    keripy's ``Parser.msgParsator`` is the extractor. It is driven one message at a time, rather
    than through ``Parser.parse``, because ``parse`` swallows the accumulated result when a later
    frame fails to extract: the frames that *did* walk are exactly what attribution needs.
    """
    parser = Parser(framed=True, version=V1)
    ims = bytearray(stream)
    frames: list[Frame] = []
    failure = None
    while ims:
        residue = bytes(ims)
        extractor = parser.msgParsator(ims=ims, framed=True, local=False, version=V1)
        try:
            while True:
                next(extractor)
        except StopIteration as done:
            frames.append(_frame(done.value.serder, done.value.sigers))
        except Exception:  # noqa: BLE001 — keripy raises many extraction error types
            failure = _classify(residue)
            break
    return Walk(tuple(frames), failure)


def require_supported(did, walked: Walk) -> None:
    """Reject a stream this build cannot read, or reads but will not accept (design §Modules 1).

    Two faults, in the precedence the brief pins (format, then serialization): a stream that
    cannot be walked frame by frame is ``e.input.format.stream.f``, and a walkable v1 frame
    outside the JSON-only accepted set is ``e.feature.unsupported.serialization.f``. An empty
    stream is a format fault, not a vacuous pass — there is nothing to account for, and the
    audit fails closed.
    """
    faults = [] if walked.failure is None else [walked.failure]
    faults += [
        WalkFailure(fault="format")
        for frame in walked.frames
        if frame.major != V1.major
    ]
    faults += [
        WalkFailure(fault="serialization", kind=frame.kind)
        for frame in walked.frames
        if frame.kind != ACCEPTED_KIND
    ]
    if not walked.frames and walked.failure is None:
        faults.append(WalkFailure(fault="format"))

    for fault in faults:
        if fault.fault == "format":
            raise errors.STREAM_UNWALKABLE(did=did.compose())
    for fault in faults:
        raise errors.SERIALIZATION_UNSUPPORTED(did=did.compose(), kind=fault.kind)
