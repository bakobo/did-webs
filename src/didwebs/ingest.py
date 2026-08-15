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

import os
import shutil
import tempfile
from dataclasses import dataclass, field, replace
from typing import Self

from keri.app import habbing
from keri.core import eventing as keventing
from keri.core import routing, serdering
from keri.core.parsing import Parser
from keri.kering import Kinds, Vrsn_1_0
from keri.peer import exchanging
from keri.vdr import credentialing, verifying
from keri.vdr import eventing as teventing

from didwebs import errors, schemaing

__all__ = [
    "Frame",
    "Scratch",
    "Walk",
    "WalkFailure",
    "accepted",
    "account_frames",
    "attribute",
    "audit",
    "delegators",
    "duplicitous",
    "open_scratch",
    "require_delegator",
    "require_no_third_party",
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

    @property
    def is_kel(self) -> bool:
        """A key event: its principal is an AID."""
        return self.proto == KERI and self.ilk in KEL_ILKS

    @property
    def is_tel(self) -> bool:
        """A transaction event: its principal is a registry or a credential identifier."""
        return self.proto == KERI and self.ilk in TEL_ILKS

    @property
    def is_acdc(self) -> bool:
        """A credential: its principal is its issuer."""
        return self.proto == ACDC


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


# ---------------------------------------------------------------- the scratch keripy state


def _temp_root(path: str) -> str:
    """The ``mkdtemp`` directory keripy created for a store, given the store's own path.

    hio's ``Filer`` ignores ``headDirPath`` when ``temp=True`` and makes its own directory under
    the system temp dir, then on close removes only the *leaf* of the path inside it — leaving
    the ``mkdtemp`` root standing. Ingest removes the roots itself, so a run leaves no litter.
    """
    root = os.path.realpath(tempfile.gettempdir())
    node = os.path.realpath(path)
    parent = os.path.dirname(node)
    while parent not in (root, os.path.dirname(parent)):
        node, parent = parent, os.path.dirname(parent)
    return node


@dataclass
class Scratch:
    """A per-call keripy stack in its own temporary databases.

    Verified state never persists beyond a :class:`Verified`'s lifetime and no two ingestions
    share LMDB state, so a submission can neither read nor poison what an earlier one established.
    The stack is the reference recipe's (``dws/core/resolving.py``): ``Router``/``Revery`` built
    **before** the ``Kevery`` so the Kevery's reply router is set, then ``Tevery``, ``Verifier``,
    and reply routes registered on both.
    """

    hby: habbing.Habery
    regery: credentialing.Regery
    kevery: keventing.Kevery
    tevery: teventing.Tevery
    verifier: verifying.Verifier
    revery: routing.Revery
    exchanger: exchanging.Exchanger
    roots: tuple[str, ...]
    passes: int = 0
    closed: bool = field(default=False)

    def load(self, stream: bytes) -> None:
        """Parse ``stream`` into the scratch databases and drain every escrow to a fixpoint.

        The genus pin is on the ``parse`` call, not merely on the ``Habery``: without it a valid
        v1 stream yields nothing at all (constraint ``qbqfst``).

        Draining once is not enough. keripy's ``Kevery.processEscrows`` runs out-of-order
        *before* partial-delegation, so a delegated AID's interaction events cannot resolve on
        the pass that finally accepts its inception; the TEL and credential escrows then depend on
        those events in turn. The loop therefore repeats until no escrow changes.
        """
        self.hby.psr.parse(
            ims=bytearray(stream),
            kvy=self.kevery,
            tvy=self.tevery,
            vry=self.verifier,
            rvy=self.revery,
            exc=self.exchanger,
            local=False,
            version=V1,
        )
        seen = None
        while True:
            self.kevery.processEscrows()
            self.tevery.processEscrows()
            self.verifier.processEscrows()
            self.revery.processEscrowReply()
            self.passes += 1
            state = self._escrow_state()
            if state == seen:
                return
            seen = state

    def _escrow_state(self) -> tuple:
        return tuple(sorted(self.escrow_saids(name)) for name in _AUDITED_ESCROWS)

    def escrow_saids(self, name: str) -> set[str]:
        """Every message SAID sitting in the named escrow, whichever database holds it."""
        return _ESCROW_READERS[name](self)

    def close(self) -> None:
        """Close the databases and remove their temporary directories. Idempotent."""
        if self.closed:
            return
        self.closed = True
        self.regery.close()
        self.hby.close(clear=True)
        for root in self.roots:
            shutil.rmtree(root, ignore_errors=True)
        return

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_) -> None:
        self.close()


def open_scratch() -> Scratch:
    """Build a fresh scratch stack in its own temporary databases."""
    hby = habbing.Habery(name="didwebs-ingest", base="", temp=True, version=V1)
    regery = credentialing.Regery(hby=hby, name="didwebs-ingest", base="", temp=True)
    schemaing.pin_designated_aliases_schema(hby)

    router = routing.Router()
    revery = routing.Revery(db=hby.db, rtr=router)  # before the Kevery, so kvy.rvy is set
    exchanger = exchanging.Exchanger(hby=hby, handlers=[])
    kevery = keventing.Kevery(db=hby.db, rvy=revery)
    tevery = teventing.Tevery(db=hby.db, reger=regery.reger)
    verifier = verifying.Verifier(hby=hby, reger=regery.reger)
    kevery.registerReplyRoutes(router=router)  # LocScheme and EndRole records
    tevery.registerReplyRoutes(router=router)  # ACDC rpy messages

    roots = tuple(
        dict.fromkeys(
            _temp_root(store.path)
            for store in (hby.ks, hby.db, hby.cf, regery.reger)
        )
    )
    return Scratch(hby, regery, kevery, tevery, verifier, revery, exchanger, roots)


def _on_escrow(store_of, name):
    """Read a sequence-keyed escrow (``OnIoDupSuber``) as a set of SAIDs."""

    def read(scratch: Scratch) -> set[str]:
        return {str(said) for _, _, said in getattr(store_of(scratch), name).getAllItemIter()}

    return read


def _said_escrow(store_of, name):
    """Read a SAID-keyed escrow as a set of SAIDs."""

    def read(scratch: Scratch) -> set[str]:
        return {keys[0] for keys, _ in getattr(store_of(scratch), name).getTopItemIter()}

    return read


def _db(scratch: Scratch):
    return scratch.hby.db


def _reger(scratch: Scratch):
    return scratch.regery.reger


#: Every escrow the audit reads, by name. ``ldes`` is the likely-duplicitous escrow the design
#: names as the fork mechanism; it is inert on this keripy line (``Kevery.escrowLDEvent`` calls
#: ``Baser.addLde``, which the pin does not define), so :func:`duplicitous` also reads the
#: accepted key event log. Keep both: the escrow is the correct mechanism the moment keripy has it.
_ESCROW_READERS = {
    "pses": _on_escrow(_db, "pses"),
    "pwes": _on_escrow(_db, "pwes"),
    "pdes": _on_escrow(_db, "pdes"),
    "ooes": _on_escrow(_db, "ooes"),
    "ldes": _on_escrow(_db, "ldes"),
    "oots": _on_escrow(_reger, "oots"),
    "twes": _on_escrow(_reger, "twes"),
    "taes": _on_escrow(_reger, "taes"),
    "cmse": _said_escrow(_reger, "cmse"),
}

#: The escrows whose contents define whether draining has reached a fixpoint.
_AUDITED_ESCROWS = tuple(_ESCROW_READERS)

#: Escrow-to-code attribution, in order; the first escrow holding a frame names its fault.
#: Everything not listed — out-of-order, partially witnessed, and anything keripy dropped without
#: escrowing — is residue and gets ``e.proof.stream.frame.f`` (design §Error codes, ledger #16).
_ATTRIBUTION = (
    ("pses", errors.STREAM_SIG_INVALID),
    ("cmse", errors.STREAM_SIG_INVALID),
    ("pdes", errors.STREAM_SEAL_INVALID),
    ("taes", errors.STREAM_ANCHOR_INVALID),
)


# ------------------------------------------------------------ whose frames may appear at all


def delegators(did, walked: Walk) -> frozenset[str]:
    """The claimed AID's delegator chain, as the submitted stream declares it.

    Read from the ``di`` field of delegated inception events in the walk, followed transitively,
    so a delegate of a delegate names both. Phase 1 never dereferences an OOBI to discover one.
    """
    declared = {
        frame.principal: frame.serder.ked["di"]
        for frame in walked.frames
        if frame.ilk == "dip"
    }
    chain: set[str] = set()
    pending = [did.aid]
    while pending:
        aid = pending.pop()
        parent = declared.get(aid)
        if parent is not None and parent not in chain:
            chain.add(parent)
            pending.append(parent)
    return frozenset(chain)


def require_delegator(did, walked: Walk) -> None:
    """Refuse a delegated AID whose delegator's key event log is not in the submission.

    Checked here, before keripy sees the stream, and not from the escrow audit: without the
    delegator's KEL the delegated inception lands in the partial-delegation escrow, which the
    attribution map would report as a seal fault. The honest fault is that the submission is
    incomplete, and phase 1 will not fetch the rest.
    """
    present = {frame.principal for frame in walked.frames if frame.is_kel}
    for delegator in delegators(did, walked):
        if delegator not in present:
            raise errors.DELEGATOR_MISSING(aid=did.aid, delegator=delegator)


def _is_third_party(frame: Frame, aids, registries, credentials) -> bool:
    """Whether ``frame`` is about someone other than the claimed AID's publication.

    An AID is admitted when it is the claimed AID, somewhere in its delegator chain, or the
    issuer of a registry the stream itself carries. That last clause is what lets an
    attacker-issued alias ACDC reach the authorization post-conditions, where the issuer-binding
    check names the real fault (KRT-F1), instead of being turned away here as chaff and reported
    as a frame the pipeline could not place.
    """
    if frame.is_kel or frame.is_acdc:
        return frame.principal not in aids
    if frame.is_tel:
        return frame.principal not in registries and frame.principal not in credentials
    return False  # replies and anything else are swept by accounting, not by principal


def require_no_third_party(did, walked: Walk) -> None:
    """Refuse a publication stream carrying frames about anyone else (design §Modules 1)."""
    aids = {did.aid, *delegators(did, walked)}
    aids |= {
        frame.serder.ked["ii"]
        for frame in walked.frames
        if frame.ilk == REGISTRY_INCEPTION
    }
    registries = {frame.principal for frame in walked.frames if frame.ilk == REGISTRY_INCEPTION}
    credentials = {frame.said for frame in walked.frames if frame.is_acdc}

    for frame in walked.frames:
        if _is_third_party(frame, aids, registries, credentials):
            raise errors.STREAM_FRAME_REJECTED(frame=frame.said)


# ------------------------------------------------------------------- the accounting audit


def _reply_accepted(scratch: Scratch, frame: Frame) -> bool:
    """Whether a reply record was BADA-accepted rather than left in the reply escrow."""
    if scratch.hby.db.rpys.get(keys=(frame.said,)) is None:
        return False
    escrowed = {saider.qb64 for _, saider in scratch.hby.db.rpes.getTopItemIter()}
    return frame.said not in escrowed


def accepted(scratch: Scratch, frame: Frame) -> bool:
    """Whether keripy put ``frame`` into accepted state, by message class.

    A key event is accepted when it is in the first-seen log (``db.fons``) — deliberately not
    ``db.evts``, which also holds escrowed events that may never be first-seen. A transaction
    event is accepted when the registry's or credential's TEL carries it at its own sequence
    number. A credential is accepted when it is saved *and* its TEL state exists. Anything else
    is not accepted: an unrecognized message class fails closed.
    """
    if frame.is_kel:
        return scratch.hby.db.fons.get(keys=(frame.principal, frame.said)) is not None
    if frame.is_tel:
        return scratch.regery.reger.tels.get(keys=frame.principal, on=frame.sn) == frame.said
    if frame.is_acdc:
        return scratch.regery.reger.saved.get(keys=(frame.said,)) is not None
    if frame.ilk == "rpy":
        return _reply_accepted(scratch, frame)
    return False


def account_frames(scratch: Scratch, walked: Walk) -> tuple[Frame, ...]:
    """The walked frames keripy did **not** accept.

    This is the invariant that makes a silently dropped frame visible: every frame the submitter
    sent is either in accepted state or is named here, and a named frame stops the publication.
    """
    return tuple(frame for frame in walked.frames if not accepted(scratch, frame))


def duplicitous(scratch: Scratch, walked: Walk) -> set[str]:
    """SAIDs in the submission that conflict with an event already accepted at the same place.

    Two sources, unioned. keripy's likely-duplicitous escrow is the design's stated mechanism.
    The accepted key event log is the one that actually fires at the estate pin, where
    ``escrowLDEvent`` raises ``AttributeError`` on a ``Baser.addLde`` that does not exist and the
    Parser swallows it — so a fork is dropped without a trace in ``ldes``.
    """
    found = set(scratch.escrow_saids("ldes"))
    for frame in walked.frames:
        if not frame.is_kel:
            continue
        winner = scratch.hby.db.kels.getLast(keys=frame.principal, on=frame.sn)
        if winner is not None and str(winner) != frame.said:
            found.add(frame.said)
    return found


def _signature_fails(scratch: Scratch, frame: Frame) -> bool:
    """Whether ``frame``'s controller signatures fail against the AID's accepted key state.

    keripy escrows a partially *signed* event but simply drops one whose signature does not
    verify, so no escrow attributes a forged signature and the audit has to ask directly. The
    question is asked with keripy's own ``verifySigs`` and the Kever's own threshold, against the
    key state the next event must satisfy. A rotation carries its own new keys and is out of
    scope here; it falls through to the residue code rather than being guessed at.
    """
    if not (frame.is_kel and frame.sigers):
        return False
    if frame.principal not in scratch.hby.kevers:
        return False
    kever = scratch.hby.kevers[frame.principal]
    _, indices = keventing.verifySigs(
        raw=frame.serder.raw, sigers=list(frame.sigers), verfers=kever.verfers
    )
    return not kever.tholder.satisfy(indices)


def attribute(scratch: Scratch, frame: Frame):
    """The error a single unaccounted frame earns, read off the scratch database's escrows."""
    for name, code in _ATTRIBUTION:
        if frame.said in scratch.escrow_saids(name):
            return code(frame=frame.said)
    if _signature_fails(scratch, frame):
        return errors.STREAM_SIG_INVALID(frame=frame.said)
    return errors.STREAM_FRAME_REJECTED(frame=frame.said)


def audit(scratch: Scratch, did, walked: Walk) -> None:
    """Raise the error the accounting and escrow audits attribute, if the stream earns one.

    Precedence is the brief's: the fork verdict outranks the per-frame proof leaves, because a
    submission that forks its own KEL is not a stream with one bad frame in it.
    """
    conflicts = duplicitous(scratch, walked)
    if conflicts:
        raise errors.KEL_FORKED(aid=did.aid)
    for frame in account_frames(scratch, walked):
        raise attribute(scratch, frame)
