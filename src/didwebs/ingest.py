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
   was asked to publish. :func:`require_supported` then enforces the JSON-only restriction and the
   version rules of a mixed-version stream (decision ``8686h4tf``), and :func:`require_delegator` / :func:`require_no_third_party` enforce whose
   frames may appear at all.
2. :func:`account_frames` — *the accounting audit*, post-parse half: every walked frame must be
   in accepted state, and :func:`attribute` maps any that is not to an error code by reading the
   scratch database's escrows.
3. :func:`authorize` — *the authorization post-conditions* on the designated-aliases ACDC.
4. :func:`require_ownership` — *the ownership post-condition*: once the publication is
   authorized, every accepted frame must belong to the claimed AID's estate. This is what makes
   :func:`~didwebs.assemble.emit_stream` a total function of accepted state, so that every
   hosted ``keri.cesr`` re-ingests cleanly through this same pipeline.

**The genus pin extends to parsing** (constraint ``qbqfst``, design §Shape). ``Parser`` carries
its own CESR genus version, defaulting to v2, and a valid v1 stream fed to a v2-genus parser
yields *nothing* — no exception, no diagnostic, no ``kevers`` entry. Every parser construction
and every ``parse`` call below therefore passes the genus the stream opens in explicitly
(:func:`stream_version`), and a genus-version counter in the stream switches it from there.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
from dataclasses import dataclass, field, replace
from typing import Self

from bakobo.errors import BakoboError
from keri import kering
from keri.acdc import regeventing
from keri.app import habbing
from keri.core import Blinder, BlindState, counting, routing, serdering
from keri.core import eventing as keventing
from keri.core.parsing import Parser
from keri.kering import Kinds, ShortageError, Vrsn_1_0, Vrsn_2_0
from keri.peer import exchanging
from keri.vdr import credentialing, verifying
from keri.vdr import eventing as teventing

from didwebs import errors, schemaing

# Imported under a distinct name so the constraint-qbqfst grep for parser call sites in
# this module turns up CESR stream parsing only, never DID-string parsing.
from didwebs.did import parse as parse_did

__all__ = [
    "AccountedFrame",
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
    "endpoint_providers",
    "ingest",
    "open_scratch",
    "owned",
    "owns_reply",
    "require_complete_v1",
    "require_delegator",
    "require_monotonic",
    "require_no_third_party",
    "require_ownership",
    "require_supported",
    "stream_version",
    "vet_registries",
    "walk",
]

#: The CESR genus version every v1 parser in this module is pinned to (constraint ``qbqfst``).
V1 = Vrsn_1_0

#: The protocol and genus version of a v2 publication (decision ``0plkq8s8``). A stream opens in
#: the genus :func:`stream_version` reads off it, and each message may be either version so long
#: as its body and its genus agree (decision ``8686h4tf``).
V2 = Vrsn_2_0

#: The genus-version counters that switch a stream into v2, and back into v1.
GENUS_V2 = bytes(counting.Counter.makeGVC(version=V2))
GENUS_V1 = bytes(counting.Counter.makeGVC(version=V1))

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

#: v1 transaction events whose principal is the registry itself, not a credential.
REGISTRY_V1_ILKS = frozenset({REGISTRY_INCEPTION, "vrt"})

#: A v2 registry's inception and its blindable update: ACDC-protocol messages, the only registry
#: events a v2 publication may carry (decision ``3kn6drgf``). A rip's ``i`` names its issuer.
REGISTRY_V2_INCEPTION = "rip"
REGISTRY_V2_UPDATE = "bup"
REGISTRY_V2_ILKS = frozenset({REGISTRY_V2_INCEPTION, REGISTRY_V2_UPDATE})

#: v2 registry events this build recognizes and refuses. ``upd`` is in the ACDC spec's table and
#: not in WebOfTrust keripy's (decision ``0plkq8s8``); recognizing it is what lets the refusal
#: name it instead of reporting an unplaceable frame.
REGISTRY_V2_REFUSED = frozenset({"upd"})

#: A signed assertion about somebody's key state, endpoints or credentials.
REPLY = "rpy"

#: The two reply routes a did:webs publication is made of (spec ``#### Mailbox Service
#: Endpoint`` / ``#### Agent Service Endpoint``). ``/end/role`` names the controller it binds in
#: ``a.cid``; ``/loc/scheme`` names the endpoint that declares its own URL in ``a.eid``.
END_ROLE = "/end/role"
LOC_SCHEME = "/loc/scheme"


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
    schema: str | None = None
    serder: object = None
    sigers: tuple = ()
    disclosures: tuple = ()
    #: The major version of the CESR genus the message was read under. A body of any other
    #: version is a message inconsistent in itself (decision ``8686h4tf``, rule 1).
    genus: int = 1

    def replace(self, **changes) -> Frame:
        """A copy with ``changes`` applied — the dataclass helper, exposed for audit tests."""
        return replace(self, **changes)

    @property
    def is_kel(self) -> bool:
        """A key event: its principal is an AID."""
        return self.proto == KERI and self.ilk in KEL_ILKS

    @property
    def is_tel(self) -> bool:
        """A transaction event: its principal is a registry or a credential identifier.

        In v1 these are KERI-protocol messages; in v2 they are ACDC-protocol registry events,
        whose principal is always the registry.
        """
        if self.proto == KERI:
            return self.ilk in TEL_ILKS
        return self.proto == ACDC and self.ilk in REGISTRY_V2_ILKS | REGISTRY_V2_REFUSED

    @property
    def is_acdc(self) -> bool:
        """A credential: its principal is its issuer."""
        return self.proto == ACDC and not self.is_tel

    @property
    def registry(self) -> str | None:
        """The registry a registry-scoped event belongs to, or None for any other frame.

        A credential's own transaction events (v1 ``iss``, ``rev``) are not registry-scoped:
        their principal is the credential.
        """
        if self.proto == KERI:
            return self.principal if self.ilk in REGISTRY_V1_ILKS else None
        return self.regid if self.is_tel else None


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
    #: The genus the stream opens in, which is what the scratch keystore is pinned to. Each
    #: frame records the genus it was actually read under.
    opening: object = V1


def _frame(serder, sigers, disclosures=(), genus=1) -> Frame:
    """Describe one extracted message.

    The *principal* is whom the frame is about, which differs by message class: a key event is
    about its AID, a transaction event about its registry or credential identifier, and an ACDC
    about its issuer (``SerderACDC.israid``). The third-party sweep and the accounting audit both
    index on this, so it is computed once, here.
    """
    if serder.proto == ACDC and serder.ilk in REGISTRY_V2_ILKS | REGISTRY_V2_REFUSED:
        regid = serder.said if serder.ilk == REGISTRY_V2_INCEPTION else serder.sad.get("rd")
        return Frame(
            said=serder.said,
            ilk=serder.ilk,
            proto=ACDC,
            kind=serder.kind,
            major=serder.pvrsn.major,
            principal=regid,
            sn=int(serder.sad.get("n", "0"), 16),
            regid=regid,
            serder=serder,
            disclosures=tuple(disclosures),
            genus=genus,
        )
    if serder.proto == ACDC:
        return Frame(
            said=serder.said,
            ilk=serder.ilk,
            proto=ACDC,
            kind=serder.kind,
            major=serder.pvrsn.major,
            principal=serder.israid,
            sn=None,
            regid=serder.regid,
            schema=serder.schema,
            serder=serder,
            sigers=tuple(sigers),
            disclosures=tuple(disclosures),
            genus=genus,
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
        genus=genus,
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


def stream_version(stream: bytes):
    """The genus ``stream`` opens in: V2 when it opens with the v2 genus-version counter, V1
    otherwise (decision ``8686h4tf``).

    A v2 stream announces itself, so nothing outside the bytes chooses. A stream with no counter
    opens in v1 because that is what every deployed publication is. A genus-version counter
    anywhere after that switches the genus for the messages that follow, and a body read under
    a genus of another version fails the walk or the version gate as a format fault, never
    silently.
    """
    return V2 if stream.startswith(GENUS_V2) else V1


def _final_frame(residue: bytes, genus):  # ~3rz6
    """A v2 frame with no attachment at the very end of the stream, or None.

    keripy's extractor reads a body, then peeks for an attachment group and raises
    ``ShortageError`` at end of stream, so an unattached last frame can never be extracted.
    v2 registry events and credentials routinely carry no attachment, so the residue is read as
    one whole body instead, and accepted only when it is exactly one and is read in genus v2,
    whether ``genus`` was already v2 or a counter in the residue switches to it.
    """
    if residue.startswith(GENUS_V2):
        body = residue.removeprefix(GENUS_V2)
    elif genus == V2:
        body = residue
    else:
        return None
    try:
        # An ACDC's SAID is computed over its most compact form, which only SerderACDC knows.
        klas = serdering.SerderACDC if kering.smell(body).proto == ACDC else serdering.SerderKERI
        serder = klas(raw=body)
    except Exception:  # noqa: BLE001 — any read failure means "not one whole frame"
        return None
    if serder.size != len(body) or serder.pvrsn.major != V2.major:
        return None
    return serder


def walk(stream: bytes) -> Walk:
    """Extract every frame of ``stream``, one message at a time, with the CESR genus pinned to
    the stream's own version (:func:`stream_version`).

    This is step 1 of the audit — the pipeline's own account of what it was asked to publish,
    taken *before* keripy sees the stream, so that a frame keripy would silently drop is visible
    here rather than absent from everything (SPC-F1).

    keripy's ``Parser.msgParsator`` is the extractor. It is driven one message at a time, rather
    than through ``Parser.parse``, because ``parse`` swallows the accumulated result when a later
    frame fails to extract: the frames that *did* walk are exactly what attribution needs.
    """
    opening = stream_version(stream)
    genus = opening
    parser = Parser(framed=True, version=opening)
    ims = bytearray(stream)
    frames: list[Frame] = []
    failure = None
    while ims:
        residue = bytes(ims)
        extractor = parser.msgParsator(ims=ims, framed=True, local=False, version=genus)
        try:
            while True:
                next(extractor)
        except StopIteration as done:
            # A genus-version counter mid-stream is consumed with the message after it, so every
            # completed extraction yields a message (the genus_per_artifact fixture holds this).
            # keripy keeps the switch on the parser, and so does the walk: it lasts until the
            # next counter (decision 8686h4tf, rule 3).
            genus = parser.version  # ~5zz7
            message = done.value
            if message.nests:
                # keripy extracts a message nested in an attachment group into `nests` and
                # processes nothing in it, so it would vanish from every account (panel CSR-F2).
                failure = WalkFailure(fault="format")
                break
            try:
                frames.append(
                    _frame(message.serder, message.sigers, message.bsqs, genus=genus.major)
                )
            except (ValueError, TypeError):  # a SAID-valid registry event whose `n` is not hex
                failure = WalkFailure(fault="format")
                break
        except ShortageError:
            last = _final_frame(residue, genus)
            if last is None:
                failure = _classify(residue)
            else:
                try:
                    frames.append(_frame(last, (), genus=V2.major))
                except (ValueError, TypeError):
                    failure = WalkFailure(fault="format")
            break
        except Exception:  # noqa: BLE001 — keripy raises many extraction error types
            failure = _classify(residue)
            break
    return Walk(tuple(frames), failure, opening)


def _mismatched_registry(walked: Walk) -> tuple[Frame, int] | None:
    """The first credential whose registry the stream carries in another protocol version, with
    that version, or None (decision ``8686h4tf``, rule 4)."""
    registries: dict[str, set[int]] = {}
    for frame in walked.frames:
        if frame.registry is not None:
            registries.setdefault(frame.registry, set()).add(frame.major)
    for frame in walked.frames:
        if not frame.is_acdc:
            continue
        other = registries.get(frame.regid, set()) - {frame.major}
        if other:
            return frame, min(other)
    return None


def require_supported(did, walked: Walk) -> None:
    """Reject a stream this build cannot read, or reads but will not accept (design §Modules 1).

    Two faults, in the precedence the brief pins (format, then serialization): a stream that
    cannot be walked frame by frame is ``e.input.format.stream.f``, and a walkable v1 frame
    outside the JSON-only accepted set is ``e.feature.unsupported.serialization.f``. An empty
    stream is a format fault, not a vacuous pass — there is nothing to account for, and the
    audit fails closed.

    A message whose body is not the version of the genus it was read under is a format fault:
    it is inconsistent in itself, and it is also what a genus switch with no counter before it
    looks like (decision ``8686h4tf``, rules 1 and 3). After those, a credential naming a
    registry of another version (rule 4). Rule 2 is judged after parsing, by
    :func:`require_monotonic`, because only keripy can say which events a KEL keeps.
    """
    faults = [] if walked.failure is None else [walked.failure]
    faults += [
        WalkFailure(fault="format")
        for frame in walked.frames
        if frame.major != frame.genus
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
    for frame in walked.frames:
        if frame.proto == ACDC and frame.ilk in REGISTRY_V2_REFUSED:
            raise errors.REGISTRY_EVENT_UNSUPPORTED(frame=frame.said, ilk=frame.ilk)
    if (mismatched := _mismatched_registry(walked)) is not None:
        frame, registry_version = mismatched
        raise errors.CREDENTIAL_REGISTRY_VERSION(
            credential=frame.said, version=frame.major, regid=frame.regid,
            registry_version=registry_version,
        )


# ---------------------------------------------------------------- the scratch keripy state


def _temp_root(store) -> str:
    """The ``mkdtemp`` directory keripy created for ``store``, which ingest must remove itself.

    hio's ``Filer`` ignores ``headDirPath`` when ``temp=True`` and makes its own directory under
    the store class's ``TempHeadDir``, then on close removes only the *leaf* of the path inside
    it — leaving the ``mkdtemp`` root standing. Ingest removes the roots itself, so a run leaves
    no litter.

    The head comes off the store rather than from ``tempfile.gettempdir()`` (constraint
    ``l7ws7hdt``): it is the directory that store's own ``mkdtemp`` call used, so the walk is
    exact wherever keripy has been configured to put its stores. Deriving it from the process's
    temp directory instead was a latent hazard — a store under ``/tmp/pytest-of-<user>/...``
    would have yielded ``/tmp/pytest-of-<user>`` as the directory to delete.

    Raises:
        RuntimeError: ``store`` does not sit under its own temp head, so no root can be
            identified. Fails closed rather than returning an ancestor for removal.
    """
    head = pathlib.Path(os.path.realpath(store.TempHeadDir))
    node = pathlib.Path(os.path.realpath(store.path))
    if head not in node.parents:
        raise RuntimeError(
            f"the keripy store at {store.path} sits outside its own temporary head {head}, so "
            "the directory to remove cannot be identified; refusing to guess at an ancestor"
        )
    return str(head / node.relative_to(head).parts[0])


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
    version: object = V1
    passes: int = 0
    closed: bool = field(default=False)
    #: v2 only: each vetted registry by its SAID (decision ``3kn6drgf``), and the SAIDs of the
    #: registry events and credentials that vetting accepted. keripy never processes these
    #: frames, so this is what "accepted" means for them.
    registries: dict = field(default_factory=dict)
    vetted: set = field(default_factory=set)

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
            version=self.version,
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


def open_scratch(version=V1) -> Scratch:
    """Build a fresh scratch stack in its own temporary databases, pinned to ``version``."""
    # Two further parsers are built indirectly and do not show up in a grep of this module:
    # ``Habery`` constructs ``hby.psr`` from its ``version``, and ``Regery`` constructs its own
    # from ``hby.version``. Passing the version here is what pins both (constraint qbqfst).
    hby = habbing.Habery(name="didwebs-ingest", base="", temp=True, version=version)
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
            _temp_root(store)
            for store in (hby.ks, hby.db, hby.cf, regery.reger)
        )
    )
    return Scratch(hby, regery, kevery, tevery, verifier, revery, exchanger, roots, version)


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
#: ~6ks5 a rotation short of witness receipts sits in ``pwes``, which is unlisted here, so it
#: earns the residue code. That is honest but unhelpfully vague — it *is* a rotation waiting for
#: receipts, and saying so needs either phase 2's TOAD work or a shared ``e.state.pending.witness.r``.
#: It no longer misreports as a signature failure: see ``_signature_fails``.
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
    aids |= {
        frame.serder.sad["i"]
        for frame in walked.frames
        if frame.proto == ACDC and frame.ilk == REGISTRY_V2_INCEPTION
    }
    registries = {
        frame.principal
        for frame in walked.frames
        if frame.ilk in (REGISTRY_INCEPTION, REGISTRY_V2_INCEPTION)
    }
    credentials = {frame.said for frame in walked.frames if frame.is_acdc}

    for frame in walked.frames:
        if _is_third_party(frame, aids, registries, credentials):
            raise errors.THIRD_PARTY_FRAME(frame=frame.said, principal=frame.principal)


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
    if frame.proto == ACDC and frame.major == V2.major:
        return frame.said in scratch.vetted
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

    **A first-seen frame is never a fork**, and that exemption is the whole of decision
    ``vo6rnxve``. Two events at one sequence number are two different situations, and only the
    validator's own rules tell them apart: keripy either refuses the second one — the losing
    branch of a duplicitous submission, which never reaches the first-seen log — or accepts it
    as *superseding* the first under KERI's recovery rules, which is what a controller rotating
    to its unexposed pre-rotated keys after a live key exploit produces. Comparing every walked
    frame's SAID against the winner at its ``sn`` cannot see the difference: the superseded
    event is still an accepted, first-seen frame whose SAID is not the winner's, so a legitimate
    recovery was refused as a fork. Reading ``fons`` first asks keripy the question it has
    already answered, and leaves the conflict verdict to the frames it would not accept.
    """
    found = set(scratch.escrow_saids("ldes"))
    for frame in walked.frames:
        if not frame.is_kel or accepted(scratch, frame):
            continue
        winner = scratch.hby.db.kels.getLast(keys=frame.principal, on=frame.sn)
        if winner is not None and str(winner) != frame.said:
            found.add(frame.said)
    return found


#: Event types signed by keys the event itself announces rather than by the accepted key state.
#: A rotation's signatures are made with the *new* keys it rotates to, so checking them against
#: the current Kever's verfers is asking the wrong question and always gets "no valid signature"
#: for an answer.
_ROTATION_ILKS = frozenset({"rot", "drt"})


def _signature_fails(scratch: Scratch, frame: Frame) -> bool:
    """Whether ``frame``'s controller signatures fail against the AID's accepted key state.

    keripy escrows a partially *signed* event but simply drops one whose signature does not
    verify, so no escrow attributes a forged signature and the audit has to ask directly. The
    question is asked with keripy's own ``verifySigs`` and the Kever's own threshold, against the
    key state the next event must satisfy.

    A rotation is excluded, because the question does not apply to it: it carries its own new
    keys, and the accepted key state still holds the old ones. This exclusion was the docstring's
    stated intent from the start and was not in the code, so *every* unaccounted rotation — one
    escrowed out of order, one short of witness receipts (tick ``~6ks5``), one waiting on a
    delegation — was reported as a forged signature. That is a diagnosis pointing at the
    controller's keys for a stream whose signatures are fine, which is worse than saying less:
    a rotation now falls through to the residue code, the same one an unaccounted interaction
    event in the same position already earned.
    """
    if not (frame.is_kel and frame.sigers):
        return False
    if frame.ilk in _ROTATION_ILKS:
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


@dataclass(frozen=True)
class VettedRegistry:
    """A v2 registry as ``regeventing.vet`` verified it, with the disclosure of every update.

    ``record`` is keripy's verdict on the chain. ``updates`` and ``blinders`` run in step and in
    sequence order; a blinder is the disclosure the stream carried for that update, and None
    where it carried none, which ``vetBinds`` allows only before the latest non-vacuous update.
    """

    record: object  # keri.acdc.regeventing.RegStateRecord
    rip: object
    updates: tuple
    blinders: tuple
    #: The credential the head binds, when vetting accepted it; None for a registry that binds
    #: nothing this build accepts (a spare registry, or one whose credential was refused).
    credential: object = None

    @property
    def in_force(self) -> int:
        """The position in ``record.anchors`` of the event whose state is in force: the latest
        non-vacuous update, as ``vetBinds`` reads it. Asked only of a registry whose head binds a
        credential, which has one (``record.anchors`` puts the inception at 0)."""
        return max(
            position
            for position, blinder in enumerate(self.blinders, start=1)
            if blinder is not None and (blinder.acdc or blinder.state)
        )


#: keripy's registry-chain refusals that are about anchoring in the issuer's KEL.
_ANCHOR_FAULTS = (kering.MissingAnchorError, kering.MisanchorError, kering.RootSealError)


def _disclosures(walked: Walk) -> list:
    """Every blinded-state disclosure the stream carries, each occurrence kept.

    A disclosure is a BlindedStateQuadruples block, and the ACDC spec lets it ride on any
    message, the update itself or the ACDC (spec-body.md:2062), several to a group. So they are
    collected from every frame and handed to keripy's ``vetBinds``, which matches them to updates
    by BLID and requires exactly one per update it reads. Duplicates are kept so that it can
    refuse them as it would for anyone else.
    """
    return [
        Blinder(clan=BlindState, qb64=b"".join(item.qb64b for item in crew))
        for frame in walked.frames
        for crew in frame.disclosures
    ]


def _bound_target(updates, disclosures) -> str | None:
    """The credential the latest non-vacuous update discloses, or None if no update does.

    Read newest first, as ``vetBinds`` reads them; an update with no disclosure stops the search,
    since ``vetBinds`` will then refuse the registry for exactly that reason.
    """
    for update in sorted(updates, key=lambda f: f.sn, reverse=True):
        blinder = disclosures.get(update.serder.sad["b"])
        if blinder is None:
            return None
        if blinder.acdc or blinder.state:
            return blinder.acdc
    return None


def first_seen(db, pre: str):
    """Every event of ``pre``'s accepted KEL in first-seen order, as ``(fn, serder)``.

    Read from the event store rather than through ``db.clonePreIter``, which serializes every
    event's attachments in one genus and skips, without a word, any event it cannot serialize in
    it -- which a KEL that migrated from v1 to v2 can be (decision ``8686h4tf``).
    """
    for _, fn, dig in db.fels.getAllItemIter(keys=pre, on=0):
        yield fn, db.evts.get(keys=(pre, dig))


def _kel_seals(scratch: Scratch, issuer: str) -> list[list]:
    """The seal list of every event in ``issuer``'s accepted KEL, read once.

    Completeness asks the same KEL about many transaction logs; reading it per log made the
    check quadratic in a stream far below the byte bound (hostile pass on PR #12).
    """
    out = []
    for _, serder in first_seen(scratch.hby.db, issuer):
        seals = serder.sad.get("a") or []
        out.append(seals if isinstance(seals, list) else [])
    return out


#: Text that could be a v1 TEL event's sequence number: any hex. keripy writes lowercase without
#: leading zeros, but accepts a TEL event spelled otherwise (e.g. "01") when its seal matches it
#: as text, so the check errs wide and fails closed (fix-diff pass on PR #12).
_V1_TEL_SN = re.compile(r"[0-9a-fA-F]+")


def _v1_anchor(seals: list) -> tuple[str, str] | None:
    """``(log, digest)`` when an event's seals can anchor a v1 transaction event, else None.

    keripy's v1 ``Tever.verifyAnchor`` accepts only an event whose ``a`` holds exactly one seal,
    a full ``{i, s, d}`` (``vdr/eventing.py``); anything else anchors nothing (``4f74sjd8``).
    """
    if len(seals) != 1 or not isinstance(seals[0], dict):
        return None
    seal = seals[0]
    if not all(isinstance(seal.get(key), str) for key in ("i", "s", "d")):
        return None
    # verifyAnchor compares `s` with the TEL event's own sequence number as text; an `s` that is
    # not hex can match no event (Copilot on PR #12), any hex one might.
    if not _V1_TEL_SN.fullmatch(seal["s"]):
        return None
    return seal["i"], seal["d"]


@dataclass(frozen=True)
class AnchorIndex:
    """A KEL's possible transaction-event anchors, indexed once by the log they could anchor.

    ``by_log`` maps a log identifier to the digests sealed under it. ``unattributed`` holds
    digests sealed with no identifier at all (a bare SAID, or a ``{d}`` seal), which v2's
    digest-only matching lets anchor an event of any log; v1 never accepts such a seal.
    """

    by_log: dict
    unattributed: frozenset

    def for_log(self, regid: str) -> set[str]:
        """Every digest that could anchor an event of ``regid``."""
        return set(self.by_log.get(regid, ())) | self.unattributed


def _anchor_index(kel_seals: list[list], version) -> AnchorIndex:
    """Index a KEL's seals by the log each could anchor, in one pass (decisions ``3kn6drgf``,
    ``4f74sjd8``). Scanning every seal per log was quadratic in a stream far below the byte bound
    (fix-diff pass on PR #12).

    The two versions match anchors differently, and this follows each. keripy's v2 verifier
    matches by digest alone (``regeventing.sealDigests``: a bare SAID, or any mapping's ``d``), so
    a bare digest, a ``{d}`` seal and a seal whose ``i`` is the log are all candidates, while a seal
    naming another identifier is that identifier's claim. v1's accepts only an event's single full
    seal (:func:`_v1_anchor`).
    """
    by_log: dict[str, set[str]] = {}
    unattributed: set[str] = set()
    for seals in kel_seals:
        if version == V2:
            for seal in seals:
                if isinstance(seal, str):
                    unattributed.add(seal)
                elif isinstance(seal, dict) and isinstance(seal.get("d"), str):
                    if "i" not in seal:
                        unattributed.add(seal["d"])
                    elif isinstance(seal["i"], str):  # ~666h foreign-i seals count for that i only
                        by_log.setdefault(seal["i"], set()).add(seal["d"])
        elif (anchor := _v1_anchor(seals)) is not None:
            by_log.setdefault(anchor[0], set()).add(anchor[1])
    return AnchorIndex(by_log, frozenset(unattributed))


def vet_registries(scratch: Scratch, walked: Walk) -> None:
    """Verify every v2 registry the stream carries, and record what that verification accepted.

    keripy's Parser refuses every ACDC message with an ilk, so a v2 registry never reaches a
    Tevery and nothing would ever call it accepted. Instead each registry goes to keripy's own
    issuer-registry verifier, ``keri.acdc.regeventing.vetBinds`` (``vet`` for a registry with no
    updates), against the key event log the parser *did* accept (decision ``3kn6drgf``):
    disclosures matched by BLID from anywhere in the stream, required from the head back to the
    latest non-vacuous update, and the state read from that update. A credential is accepted only
    when that update binds it mutually and it validates against the v2 schema it names.

    Then completeness, which neither verifier checks: every event of the registry that the
    issuer's KEL anchors must have been presented. An omitted revoking update would otherwise
    leave the designation reading ``issued``.

    Anything vetting does not accept stays unaccounted and is attributed by the audit, exactly
    as an escrowed v1 frame is.

    Raises:
        BakoboError: ``e.proof.stream.disclosure.f`` for an update needing a disclosure that is
            absent or does not match; ``e.proof.stream.anchor.f`` for a registry event the
            issuer's KEL does not anchor; ``e.input.missing.registry.event.f`` for an anchored
            event the stream omits; ``e.proof.stream.frame.f`` for any other chain fault.
    """
    tels = [frame for frame in walked.frames if frame.proto == ACDC and frame.is_tel]
    credentials = {frame.said: frame for frame in walked.frames if frame.is_acdc}
    occurrences = _disclosures(walked)
    disclosures = {blinder.said: blinder for blinder in occurrences}  # lookup only
    schemer = schemaing.load_designated_aliases_schema_v2()
    kels: dict[str, AnchorIndex] = {}  # each issuer's KEL, read and indexed once

    for rip in (frame for frame in tels if frame.ilk == REGISTRY_V2_INCEPTION):
        updates = sorted(
            (f for f in tels if f.ilk == REGISTRY_V2_UPDATE and f.regid == rip.said),
            key=lambda f: f.sn,
        )
        target = _bound_target(updates, disclosures)
        bound = credentials.get(target) if target else None
        try:
            if updates:
                record = regeventing.vetBinds(
                    rip.serder,
                    [update.serder for update in updates],
                    db=scratch.hby.db,
                    blinders=occurrences,
                    target=target or "",
                    acdc=bound.serder if bound is not None else None,
                )
            else:
                record = regeventing.vet(rip.serder, [], db=scratch.hby.db)
        except kering.UnverifiedBlindError as fault:
            raise errors.REGISTRY_STATE_UNPROVABLE(frame=updates[-1].said) from fault
        except _ANCHOR_FAULTS as fault:
            raise errors.STREAM_ANCHOR_INVALID(frame=rip.said) from fault
        except kering.ValidationError as fault:  # ~2gon registry duplicity lands here too
            raise errors.STREAM_FRAME_REJECTED(frame=rip.said) from fault

        presented = {rip.said, *(update.said for update in updates)}
        # Every frame the stream carries can explain a digest-only seal, not only this registry's.
        carried = {frame.said for frame in walked.frames}
        if record.issuer not in kels:
            kels[record.issuer] = _anchor_index(_kel_seals(scratch, record.issuer), V2)
        anchored = kels[record.issuer].for_log(rip.said)
        missing = anchored - presented - carried
        if missing:
            raise errors.REGISTRY_EVENT_MISSING(
                aid=record.issuer, regid=rip.said, said=min(missing)
            )

        accepted_credential = (
            bound is not None and record.binding == "mutual" and _schema_valid(schemer, bound)
        )
        scratch.registries[rip.said] = VettedRegistry(
            record,
            rip.serder,
            tuple(u.serder for u in updates),
            tuple(disclosures.get(u.serder.sad["b"]) for u in updates),
            bound.serder if accepted_credential else None,
        )
        scratch.vetted.update(presented)
        if accepted_credential:
            scratch.vetted.add(bound.said)


def _schema_valid(schemer, frame: Frame) -> bool:
    """Whether a v2 credential names the designated-aliases schema and validates against it.

    v1 never asks: keripy's Verifier validates a credential against its schema before saving it.
    Nothing saves a v2 credential, so the check is ours, and a credential under any other schema
    is not one this build can accept.
    """
    if frame.schema != schemer.said:
        return False
    try:
        return bool(schemer.verify(frame.serder.raw))
    except kering.ValidationError:
        return False


def require_complete_v1(scratch: Scratch, did, walked: Walk) -> None:
    """Refuse a stream that omits a v1 transaction event its own KEL anchors (``4f74sjd8``).

    keripy's Tevery judges only the events presented, so a stream that leaves out the ``rev``
    revoking its designation reads as issued. For every transaction log the stream presents --
    a registry or a credential -- every event the claimed AID's accepted KEL seals must be in it.
    Logs the stream does not present are not asked about: a controller may issue credentials it
    is not publishing. Only v1 logs are asked here, under v1's anchor rule, whatever version the
    KEL events sealing them are; :func:`vet_registries` asks the same of v2 registries under
    theirs (decision ``8686h4tf``).

    Raises:
        BakoboError: ``e.input.missing.registry.event.f``, naming the first omitted event.
    """
    logs = [frame for frame in walked.frames if frame.is_tel and frame.major == V1.major]
    if not logs:
        return
    presented = {frame.said for frame in logs}
    index = _anchor_index(_kel_seals(scratch, did.aid), V1)
    for log in sorted({frame.principal for frame in logs}):
        missing = index.for_log(log) - presented
        if missing:
            raise errors.REGISTRY_EVENT_MISSING(aid=did.aid, regid=log, said=min(missing))


def require_monotonic(scratch: Scratch, walked: Walk) -> None:
    """Refuse a KEL whose protocol version decreases (decision ``8686h4tf``, rule 2).

    Judged over the KEL keripy accepted, one event per sequence number, the one that stands
    there: a superseded event is not part of the log's history going forward. Judging every
    walked event instead let one interaction signed with an exposed key in v2, superseded by
    the controller's v1 recovery rotation, force the controller into v2 for good (panel SEC-F1).

    Raises:
        BakoboError: ``e.rule.kel.version.regressed.f``, naming the first event that regresses.
    """
    db = scratch.hby.db
    for aid in dict.fromkeys(frame.principal for frame in walked.frames if frame.is_kel):
        kever = scratch.hby.kevers.get(aid)
        if kever is None:
            continue  # nothing accepted; accounting attributes it
        prior = 0
        for sn in range(kever.sner.num + 1):
            serder = db.evts.get(keys=(aid, db.kels.getLast(keys=aid, on=sn)))
            if serder.pvrsn.major < prior:
                raise errors.KEL_VERSION_REGRESSED(
                    aid=aid, said=serder.said, sn=sn, version=serder.pvrsn.major, prior=prior
                )
            prior = max(prior, serder.pvrsn.major)


def audit(scratch: Scratch, did, walked: Walk) -> None:
    """Raise the error the accounting and escrow audits attribute, if the stream earns one.

    Precedence is the brief's: the fork verdict outranks the per-frame proof leaves, because a
    submission that forks its own KEL is not a stream with one bad frame in it. v2 registries are
    vetted after the fork verdict and before accounting, since vetting is what makes their frames
    accountable at all. Each log is judged in its own version, so a stream that carries both
    kinds gets both checks, and one that carries one kind finds the other a no-op.
    """
    conflicts = duplicitous(scratch, walked)
    if conflicts:
        raise errors.KEL_FORKED(aid=did.aid)
    require_monotonic(scratch, walked)
    vet_registries(scratch, walked)
    for frame in account_frames(scratch, walked):
        raise attribute(scratch, frame)
    require_complete_v1(scratch, did, walked)


# ------------------------------------------------- the authorization post-conditions


#: TEL states that mean a credential no longer authorizes anything.
REVOKED_ILKS = frozenset({"rev", "brv"})

_DID_WEBS = "did:webs:"
_DID_WEB = "did:web:"


def anchored_in(scratch: Scratch, did, regid: str) -> bool:
    """Whether ``regid``'s registry is the claimed AID's, anchored in the claimed AID's own KEL.

    Two legs, and both are needed. The registry inception names its issuer in ``ii``, which
    keripy keeps as ``Tever.pre``; and the seal that commits the inception must sit in a *first
    seen* event of the claimed AID's key event log. An ACDC riding a different KEL's registry
    fails one or the other, and is treated as absent (KRT-F1).
    """
    tever = scratch.regery.reger.tevers.get(regid)
    if tever is None or tever.pre != did.aid:
        return False
    inception = scratch.regery.reger.tels.get(keys=regid, on=0)
    _, anchor = scratch.regery.reger.ancs.get(keys=(regid, inception))
    return scratch.hby.db.fons.get(keys=(did.aid, anchor.qb64)) is not None


def _designated(entry: str):
    """An ``a.ids`` entry as ``(method, WebsDid)``, or None when it designates something else.

    Membership is decided over the normalized parse, never over raw strings: percent-encoding is
    case-insensitive and host names are too, so a designation can cover a DID without matching it
    byte for byte, and comparing strings would reject an authorization the controller did give
    (KRT-F5). An entry that is not a did:web(s) identifier, or does not parse as one, designates
    nothing here — it is not an error, it simply cannot cover the claimed DID.
    """
    for method in (_DID_WEBS, _DID_WEB):
        if entry.startswith(method):
            try:
                return method, parse_did(_DID_WEBS + entry[len(method) :])
            except BakoboError:
                return None
    return None


def _covers(did, creder) -> bool:
    """Whether the credential designates both spellings of the claimed identifier.

    Resolution step 4, read conservatively: the did:web form is a separate identifier that a
    separate hosted artifact rests on, so a designation of one form does not authorize the other.
    ``a.ids`` is indexed directly because the pinned schema makes the attribute block and its
    ``ids`` array mandatory, and keripy validates the credential against that schema before
    saving it.
    """
    designated = {
        parsed
        for parsed in (_designated(entry) for entry in creder.attrib["ids"])
        if parsed is not None
    }
    return (_DID_WEBS, did) in designated and (_DID_WEB, did) in designated


@dataclass(frozen=True)
class _Designation:
    """A designated-aliases credential of the claimed AID, as its own version's engine left it.

    ``creder`` is the accepted copy: the one keripy saved for v1, and for v2, where nothing in
    keripy saves a credential, the walked ``acm`` that vetting bound to a vetted registry head --
    every byte of it checked against what the issuer's KEL anchors (constraint ``embuup``).
    ``anchored_at`` is the sequence number of the KEL event anchoring the registry event that put
    its state in force, which is what designations are ordered by (decision ``7p6j5kde``).
    """

    creder: object
    revoked: bool
    anchored_at: int


def _designation(scratch: Scratch, did, frame: Frame) -> _Designation | None:
    """``frame`` as a designation of the claimed AID, or None when it is someone else's or rides
    a registry the claimed AID did not anchor (KRT-F1)."""
    if frame.principal != did.aid:
        return None
    if frame.major == V2.major:
        registry = scratch.registries.get(frame.regid)
        if (
            registry is None
            or registry.record.issuer != did.aid
            or frame.said not in scratch.vetted
        ):
            return None
        # vet gives the disclosed state no meaning (regeventing.py, vet); the policy is ours, and
        # anything but `issued` fails closed (decision 3kn6drgf).
        return _Designation(
            frame.serder,
            registry.record.state != "issued",  # ~6grg
            registry.record.anchors[registry.in_force][0],
        )
    if not anchored_in(scratch, did, frame.regid):
        return None
    # Never inferred from the Verifier having saved it: keripy saves revoked credentials by
    # design and says so in a comment (verifying.py, processCredential). SEC-F4.
    state = scratch.regery.reger.tevers[frame.regid].vcState(vci=frame.said)
    return _Designation(
        scratch.regery.reger.creds.get(keys=(frame.said,)),
        state is None or state.et in REVOKED_ILKS,
        state.a["s"] if state is not None else 0,
    )


def authorize(scratch: Scratch, did, walked: Walk) -> tuple:
    """Every designated-aliases credential that authorizes this publication, in the order their
    identifiers are published (design §Modules 3; decision ``7p6j5kde``).

    A publication is authorized by any designation that is the claimed AID's, unrevoked, and
    covering both spellings of the DID, whatever its version and wherever it sits in the stream.
    Evaluated only on an otherwise fully accepted stream. When none qualifies, the error names
    the furthest any candidate got, in the design's order: absent, then not the claimed AID's,
    then revoked, then out of scope -- so an unrevoked designation that does not cover the DID
    earns out of scope even beside a revoked one that would have.

    What is returned is every valid, unrevoked designation of the claimed AID, including any
    that do not cover this DID: they still authorize the identifiers they name, which the
    document reflects. They are ordered by the sequence number of the KEL event that put each in
    force, then by SAID, so two resolvers order them alike.
    """
    schemas = {
        schemaing.load_designated_aliases_schema().said,  # SAID recomputed at every load
        schemaing.DES_ALIASES_SCHEMA_V2_SAID,
    }
    candidates = [frame for frame in walked.frames if frame.is_acdc and frame.schema in schemas]
    if not candidates:
        raise errors.ALIAS_ACDC_MISSING(did=did.compose())

    granted = [
        (frame, designation)
        for frame in candidates
        if (designation := _designation(scratch, did, frame)) is not None
    ]
    if not granted:
        raise errors.ALIAS_GRANT_MISSING(did=did.compose())

    standing = sorted(
        (designation for _, designation in granted if not designation.revoked),
        key=lambda designation: (designation.anchored_at, designation.creder.said),
    )
    if not standing:
        raise errors.ALIAS_ACDC_REVOKED(said=granted[0][0].said)
    if not any(_covers(did, designation.creder) for designation in standing):
        raise errors.ALIAS_GRANT_SCOPE(did=did.compose())
    return tuple(designation.creder for designation in standing)


# ------------------------------------------------- the ownership post-condition (step 4)


def endpoint_providers(scratch: Scratch, walked: Walk, aids) -> frozenset[str]:
    """Every AID the estate has made an endpoint of, read from accepted state.

    Two sources, because did:webs establishes an endpoint role two ways and ``document.py``
    projects services from both (design §Modules). A mailbox or an agent is authorized by an
    ``/end/role/add`` reply naming it in ``a.eid``; that authorization is what makes the
    provider's own ``/loc/scheme`` reply part of this publication rather than somebody else's
    endpoint advertisement. A **witness** is not authorized that way at all — the witness role is
    established by the KEL's own ``b`` list — so a witness's ``/loc/scheme`` reply arrives with no
    role record behind it, and a predicate that demanded one would refuse every witnessed
    publication this pipeline is ever sent.
    """
    providers = {
        wit for aid in aids if aid in scratch.hby.kevers for wit in scratch.hby.kevers[aid].wits
    }
    for frame in walked.frames:
        record = _reply_record(scratch, frame)
        if record is None:
            continue
        attributes = record.ked["a"]
        if record.ked["r"].startswith(END_ROLE) and attributes.get("cid") in aids:
            providers.add(attributes.get("eid"))
    return frozenset(providers)


def _reply_record(scratch: Scratch, frame: Frame):
    """The reply keripy accepted for ``frame``, or None — accepted state, never submitted bytes."""
    if frame.ilk != REPLY:
        return None
    return scratch.hby.db.rpys.get(keys=(frame.said,))


def owns_reply(scratch: Scratch, frame: Frame, aids, providers) -> bool:
    """Whether an accepted reply record is the estate's own (design §Modules, audit step 4).

    Two routes, and only two. A ``/end/role`` reply belongs to the controller it names in
    ``a.cid``. A ``/loc/scheme`` reply is signed by the *endpoint*, not by the controller — it
    says "this is where I am", so only the endpoint's own key can make it — and it belongs to
    this publication when the endpoint is one the estate made an endpoint of (see
    :func:`endpoint_providers`), or is a member of the estate declaring its own location. Any
    other route fails closed: the predicate has no rule that places it, so it is not this
    publication's to host (ledger #16).
    """
    record = _reply_record(scratch, frame)
    if record is None:
        return False
    attributes = record.ked["a"]
    if record.ked["r"].startswith(END_ROLE):
        return attributes.get("cid") in aids
    if record.ked["r"].startswith(LOC_SCHEME):
        return attributes.get("eid") in aids or attributes.get("eid") in providers
    return False


def _subject(scratch: Scratch, frame: Frame) -> str:
    """Whom an unowned frame is about, for the refusal's own account of it.

    The walk records a reply's principal as None — keripy's ``rpy`` messages carry no ``i`` field
    — so a reply names its subject from the accepted record instead: the controller it binds
    (``a.cid``) for a role authorization, the endpoint it locates (``a.eid``) for a location
    scheme.
    """
    record = _reply_record(scratch, frame)
    if record is None:
        return frame.principal
    attributes = record.ked["a"]
    return attributes.get("cid") or attributes.get("eid")


def owned(scratch: Scratch, did, frame: Frame, aids, providers) -> bool:
    """Whether one accepted frame belongs to the claimed AID's estate.

    Placed entirely from **accepted state** plus the walk's own account of what each frame is —
    never from the submitted bytes, which the audit has already finished with. By message class:

    * a key event belongs to the estate when its AID is the claimed one or in its delegator chain;
    * a credential belongs to its issuer, which must be the claimed AID — its *subject* is
      irrelevant, which is the whole of KRT-F1 restated as a hosting rule;
    * a transaction event's principal is a registry or a credential identifier, so a registry
      event is placed by its ``Tever.pre`` and a credential event by the issuer of the credential
      keripy saved under that identifier;
    * a reply is placed by :func:`owns_reply`.

    Anything else fails closed. This runs on frames the accounting audit already accepted, so an
    unplaceable frame is a class this build has no hosting rule for, not a malformed one.
    """
    if frame.is_kel:
        return frame.principal in aids
    if frame.is_acdc:
        return frame.principal == did.aid
    if frame.proto == ACDC and frame.is_tel:
        registry = scratch.registries.get(frame.regid)
        return registry is not None and registry.record.issuer == did.aid
    if frame.is_tel:
        tever = scratch.regery.reger.tevers.get(frame.principal)
        if tever is not None:
            return tever.pre == did.aid
        creder = scratch.regery.reger.creds.get(keys=(frame.principal,))
        return creder is not None and creder.israid == did.aid
    if frame.ilk == REPLY:
        return owns_reply(scratch, frame, aids, providers)
    return False


def require_ownership(scratch: Scratch, did, walked: Walk) -> None:
    """Refuse a publication carrying an accepted frame that is not the claimed AID's own.

    **Audit step 4** (design §Modules, added 2026-08-15). Step 1's third-party sweep deliberately
    admits the issuer of any credential the stream carries, so that an attacker-issued alias ACDC
    reaches the issuer-binding post-condition and is refused for the right reason (KRT-F1). That
    admission is a hole while it stands: a stranger's *whole* publication — KEL, registry,
    self-attested credential — rides in on its own registry inception, every frame verifies, and
    the claimed AID's authorization is untouched. Before this step existed such a submission was
    accepted, and :func:`~didwebs.assemble.emit_stream` would host the stranger's registry,
    credential log and ACDC under Bakobo's domain.

    Run **after** :func:`authorize`, deliberately: the attacker-ACDC case is unowned as well as
    unauthorized, and the issuer-binding verdict is the sharper of the two.

    **Rejection, not pruning.** Emitting the submission minus the stranger's frames would publish
    "minus a frame", which is exactly what frame accounting exists to forbid (SPC-F1); and the
    submitter, not Bakobo, decides what a publication contains. The invariant this buys is that
    ``emit_stream`` is a total function of accepted state, so every hosted ``keri.cesr``
    re-ingests cleanly through this same pipeline.

    Raises:
        BakoboError: ``e.rule.stream.third-party.f`` — the same rule step 1 enforces, since it is
            the same norm: a publication stream carries only what it is publishing.
    """
    aids = {did.aid, *delegators(did, walked)}
    providers = endpoint_providers(scratch, walked, aids)
    for frame in walked.frames:
        if not owned(scratch, did, frame, aids, providers):
            raise errors.THIRD_PARTY_FRAME(frame=frame.said, principal=_subject(scratch, frame))


# ------------------------------------------------------------------------ verified state


@dataclass(frozen=True)
class AccountedFrame:
    """One frame of the submission, accounted accepted. Identifiers only — no submitted bytes."""

    said: str
    ilk: str | None
    principal: str
    #: The frame's protocol major version, which is the genus it is hosted in.
    major: int = 1


@dataclass(frozen=True)
class Verified:
    """A publication stream that passed the whole audit, and the accepted state it produced.

    **Lifetime.** ``Verified`` owns live keripy handles on temporary databases, so it must be
    closed: use it as a context manager, or call :meth:`close` (idempotent). Closing drops the
    verified state — deliberately, since it is scratch, not a store — and removes the temporary
    directories, which keripy leaves standing on its own.

    **What it does not carry** (constraint ``embuup``): the submitted bytes, in any form. The
    credential is the one read back out of the scratch database after keripy saved it, and
    ``frames`` records identifiers rather than message bodies, so nothing downstream can reach
    around the audit to raw input.
    """

    did: object
    aid: str
    #: Every valid, unrevoked designated-aliases credential of the AID, in the order
    #: :func:`authorize` gives them (decision ``7p6j5kde``).
    designations: tuple
    frames: tuple[AccountedFrame, ...]
    scratch: Scratch

    @property
    def ids(self) -> list[str]:
        """The identifiers the designations authorize: each designation's ``a.ids`` in order,
        designations in order, every identifier once (decision ``7p6j5kde``)."""
        return list(
            dict.fromkeys(entry for creder in self.designations for entry in creder.attrib["ids"])
        )

    @property
    def registries(self) -> dict:
        """The vetted v2 registries, by SAID, with every update's disclosure."""
        return self.scratch.registries

    @property
    def hby(self) -> habbing.Habery:
        """The scratch keystore holding the accepted key and reply state."""
        return self.scratch.hby

    @property
    def regery(self) -> credentialing.Regery:
        """The scratch registry database holding the accepted TEL and credential state."""
        return self.scratch.regery

    def close(self) -> None:
        """Release the verified state and its temporary databases. Idempotent."""
        return self.scratch.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_) -> None:
        self.close()


def ingest(stream: bytes, did) -> Verified:
    """Verify a publication stream against the DID it claims to back.

    The pipeline, in order: walk the stream, refuse what this build cannot read or will not
    accept, refuse a submission that is incomplete or carries someone else's frames, ingest into
    a scratch keripy stack, audit that every walked frame reached accepted state, check the
    authorization post-conditions on the designated-aliases credential, and finally require that
    every accepted frame is the claimed AID's own to publish.

    Raises:
        BakoboError: the first attributed failure. Success is defined by the audit, never by the
            parser declining to raise.

    Returns:
        Verified: the accepted state, which the caller must close.
    """
    walked = walk(stream)
    require_supported(did, walked)
    require_no_third_party(did, walked)
    require_delegator(did, walked)

    scratch = open_scratch(walked.opening)
    try:
        scratch.load(stream)
        audit(scratch, did, walked)
        designations = authorize(scratch, did, walked)
        require_ownership(scratch, did, walked)
    except BaseException:
        scratch.close()
        raise

    return Verified(
        did=did,
        aid=did.aid,
        designations=designations,
        frames=tuple(
            AccountedFrame(
                said=frame.said, ilk=frame.ilk, principal=frame.principal, major=frame.major
            )
            for frame in walked.frames
        ),
        scratch=scratch,
    )
