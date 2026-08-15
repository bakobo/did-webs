"""Two roles, one emitter — the keystore side that issues, and the ingest side that publishes.

**Keystore side.** ``issue_aliases`` and ``revoke_aliases`` create a
credential registry, issue the self-attested designated-aliases ACDC against the pinned schema,
and anchor both TEL events in the controller's KEL with interaction events. Per decision
``avuwzl`` this issuance code exists only for keystores we control — tests, demos, and
fixtures. It is deliberately not a product verb: nothing in the publication pipeline calls it,
and a customer's keystore is never ours to write to.

**Ingest side (``emit_stream``).** ``emit_stream(verified) -> bytes`` re-assembles
``keri.cesr`` by replay *from the scratch database's accepted state* — never from the submitted
bytes (constraint ``embuup``). It is the hosted-artifact path, and it shares this module
because both roles emit the same wire shapes.

Protocol v1 is pinned explicitly at every call that constructs an event (constraint
``qbqfst``). On this keripy line (2.0.0-dev6) the version default is v2 and it is chosen *per
call site* — ``interact`` does not inherit the version of the KEL it extends — so an omitted
argument silently injects a v2 frame that every deployed 1.2.x parser drops. Three keripy
entry points take no version argument at all and derive it instead:

* ``Registry.issue`` / ``Registry.revoke`` — from ``registry.versionSerder.pvrsn`` (the vcp).
* ``Credentialer.create`` — from the same registry serder.

For those three the pin is asserted rather than passed: :func:`_v1` checks the derived version
immediately, so a keripy change that flips the derivation fails here rather than downstream in
a stream nobody can read. (``signing.serialize`` hardcodes v1 internally and needs neither.)
"""

from __future__ import annotations

from dataclasses import dataclass

from hio.base import doing
from hio.help import decking
from keri.app import grouping, habbing, signing
from keri.core import coring, eventing, serdering
from keri.db.dbing import fetchTsgs
from keri.kering import Vrsn_1_0
from keri.vdr import credentialing, verifying

from didwebs import schemaing

#: The protocol version every event this module constructs carries. Never omit it.
V1 = Vrsn_1_0

#: Designation timestamp. Fixed, not wall-clock, so a fixture's ACDC SAID is stable across runs.
DESIGNATION_DT = "2025-07-24T16:21:40.802473+00:00"

#: Default registry name when a caller issues only once per keystore.
DEFAULT_REGISTRY_NAME = "aliases"


@dataclass(frozen=True)
class Issued:
    """What an issuance produced, for a caller that must anchor, assert, or publish it."""

    registry: credentialing.Registry
    creder: serdering.SerderACDC
    iss_serder: serdering.SerderKERI
    anc_serder: serdering.SerderKERI


@dataclass(frozen=True)
class Revoked:
    """What a revocation produced. ``creder`` is the credential whose TEL now reads ``rev``."""

    registry: credentialing.Registry
    creder: serdering.SerderACDC
    rev_serder: serdering.SerderKERI
    anc_serder: serdering.SerderKERI


def _v1(serder):
    """Return ``serder`` after asserting keripy derived protocol v1 for it (``qbqfst``).

    Used where keripy's API accepts no version argument, so the pin can only be checked. A
    failure here means the derivation chain changed upstream, not that a caller forgot a
    keyword.
    """
    if serder.pvrsn != V1:
        raise AssertionError(
            f"keripy derived protocol {serder.pvrsn} for a {serder.ked['t']} event; "
            f"didwebs requires {V1} (constraint qbqfst)"
        )
    return serder


class _Issuance:
    """The keripy issuance machinery, wired the way the interop spike proved out.

    ``Registrar`` and ``Credentialer`` complete asynchronously through escrows, so a Doist runs
    their Doers until the registry and the credential report complete. This mirrors
    ``.ignored/spike-keripy-interop/gen_stream.py``, which is the runnable evidence that the
    recipe works on this keripy line.
    """

    def __init__(self, hby: habbing.Habery, regery: credentialing.Regery):
        self.regery = regery
        self.counselor = grouping.Counselor(hby=hby)
        self.registrar = credentialing.Registrar(
            hby=hby, rgy=regery, counselor=self.counselor
        )
        self.verifier = verifying.Verifier(hby=hby, reger=regery.reger)
        self.credentialer = credentialing.Credentialer(
            hby=hby, rgy=regery, registrar=self.registrar, verifier=self.verifier
        )
        self.doist = doing.Doist(limit=1.0, tock=0.03125, real=True)
        self.deeds = self.doist.enter(
            doers=[
                habbing.HaberyDoer(habery=hby),
                self.counselor,
                self.registrar,
                self.credentialer,
                credentialing.RegeryDoer(rgy=regery),
            ]
        )

    def drain(self):
        """Advance the Doers one tick and drain the escrows they feed."""
        self.doist.recur(deeds=self.deeds + decking.deque([]))
        self.verifier.processEscrows()
        self.regery.processEscrows()


def _anchor(hab: habbing.Hab, serder) -> serdering.SerderKERI:
    """Commit a TEL event's seal to the controller's KEL with a v1-pinned interaction event."""
    seal = eventing.SealEvent(serder.pre, serder.ked["s"], serder.said)._asdict()
    return serdering.SerderKERI(raw=bytes(hab.interact(data=[seal], version=V1)))


def issue_aliases(
    hab: habbing.Hab,
    regery: credentialing.Regery,
    ids: list[str],
    *,
    dt: str = DESIGNATION_DT,
    regname: str = DEFAULT_REGISTRY_NAME,
    nonce: str | None = None,
) -> Issued:
    """Issue ``hab``'s self-attested designated-aliases ACDC listing ``ids``.

    Creates a backerless credential registry (``vcp``), anchors it in ``hab``'s KEL, issues the
    ACDC against the pinned designated-aliases schema, and anchors the issuance (``iss``) too.
    The ACDC is self-attested: no recipient, so the issuer's own authorization is the whole
    claim, which is exactly what a designation of one's own aliases is.

    Args:
        hab: the controller doing the designating. Its KEL carries both anchors.
        regery: the credential registry database to create the registry in.
        ids: the DIDs to designate, verbatim, in order.
        dt: designation timestamp. Fixed by default so fixtures are byte-stable.
        regname: registry name, unique within ``regery``.
        nonce: optional registry nonce, for fixtures that need two distinct registries from
            otherwise identical inputs.
    """
    schemaing.pin_designated_aliases_schema(regery.hby)
    machinery = _Issuance(regery.hby, regery)

    registry = regery.makeRegistry(
        name=regname, prefix=hab.pre, noBackers=True, nonce=nonce, version=V1
    )
    reg_anchor = _anchor(hab, registry.vcp)
    machinery.registrar.incept(iserder=registry.vcp, anc=reg_anchor)
    while not machinery.registrar.complete(pre=registry.regk, sn=0):
        machinery.drain()

    creder = _v1(
        machinery.credentialer.create(
            regname=registry.name,
            recp=None,
            schema=schemaing.DES_ALIASES_SCHEMA_SAID,
            source=None,
            rules=schemaing.read_designated_aliases_rules(),
            data={"d": "", "dt": dt, "ids": list(ids)},
        )
    )
    iss_serder = _v1(registry.issue(said=creder.said, dt=dt))
    iss_anchor = _anchor(hab, iss_serder)
    machinery.credentialer.issue(creder, iss_serder)
    machinery.registrar.issue(creder, iss_serder, iss_anchor)
    while not machinery.credentialer.complete(said=creder.said):
        machinery.drain()

    return Issued(registry, creder, iss_serder, iss_anchor)


# --------------------------------------------------- the ingest side: the hosted keri.cesr


#: An accounted frame with no message type is an ACDC: a credential carries no ``t`` field, so
#: the walk that produced :class:`~didwebs.ingest.AccountedFrame` had no ilk to record.
CREDENTIAL = None

REPLY = "rpy"


def _reply_bytes(db, said: str) -> bytes:
    """Re-assemble one BADA-accepted reply record from the state keripy stored for it.

    A port of ``Hab.loadLocScheme``/``loadEndRole``, keyed by SAID rather than by walking the
    endpoint tables: the audit already named exactly which replies were accepted, so there is
    nothing to search for. Two signature shapes reach here — a non-transferable endpoint
    provider signs its own location scheme with a single cigar, while a transferable controller
    signs a role authorization with an indexed-signature group — and keripy's ``messagize``
    re-attaches whichever was stored, with the CESR genus pinned to v1 (``qbqfst``).
    """
    serder = db.rpys.get(keys=(said,))
    cigars = db.scgs.get(keys=(said,))
    tsgs = fetchTsgs(db=db.tsgs, diger=coring.Saider(qb64=said))

    cigar = None
    if len(cigars) == 1:
        verfer, cigar = cigars[0]
        cigar.verfer = verfer

    return bytes(
        eventing.messagize(
            serder=serder, cigars=[cigar] if cigar else [], tsgs=tsgs, gvrsn=V1
        )
    )


def _tel_bytes(reger, pre: str) -> bytes:
    """Clone a transaction event log — a registry's or a credential's — from accepted state.

    ``Reger.clonePreIter`` takes no genus argument on this keripy line; it emits v1 attachment
    counters unconditionally (``keri/vdr/eventing.py``, ``cloneTvt``).
    """
    msgs = bytearray()
    for msg in reger.clonePreIter(pre=pre):
        msgs.extend(msg)
    return bytes(msgs)


def emit_stream(verified) -> bytes:
    """Re-assemble the hosted ``keri.cesr`` for a verified publication (constraint ``embuup``).

    **Every byte is replayed out of the scratch database**, which holds only what keripy
    accepted and the post-parse audit accounted for. The submitted bytes are never written —
    :class:`~didwebs.ingest.Verified` does not carry them — so a frame keripy silently dropped,
    a fork branch it refused, or a reply it left in escrow cannot reach the artifact tree. The
    hosted stream is therefore a normalized equivalent of the controller's submission, not a
    byte-identical copy of it.

    The order is the reference's (``dws/core/artifacting.py``, ``generate_artifacts``), which
    is what the deployed did:webs ecosystem re-ingests: the key event log with the delegator's
    replayed first, then the accepted reply records, then for each accepted credential its
    registry's transaction log, its own, and the credential itself.

    Args:
        verified: the state an :func:`~didwebs.ingest.ingest` produced. Must still be open.

    Returns:
        bytes: the ``keri.cesr`` artifact.
    """
    hby = verified.hby
    db = hby.db
    reger = verified.regery.reger
    kever = hby.kevers[verified.aid]

    msgs = bytearray()
    # `Hab.replay`'s recipe, driven on the database because a published AID is never a local
    # Hab: a delegate's events cannot be verified before its delegator's.
    for msg in db.cloneDelegation(kever=kever, gvrsn=V1):
        msgs.extend(msg)
    for msg in db.clonePreIter(pre=verified.aid, fn=0, gvrsn=V1):
        msgs.extend(msg)

    for frame in verified.frames:
        if frame.ilk == REPLY:
            msgs.extend(_reply_bytes(db, frame.said))

    creders = [
        reger.creds.get(keys=(frame.said,))
        for frame in verified.frames
        if frame.ilk is CREDENTIAL
    ]
    # Registries first, each once — a credential's transaction log means nothing without the
    # registry's, and two credentials may share one. For the single-credential publication
    # phase 1 produces this is byte-for-byte the reference's interleaved order.
    for regid in dict.fromkeys(creder.regid for creder in creders):
        msgs.extend(_tel_bytes(reger, regid))
    for creder in creders:
        msgs.extend(_tel_bytes(reger, creder.said))
        prefixer, seqner, saider = reger.cancs.get(keys=(creder.said,))
        msgs.extend(signing.serialize(creder, prefixer, seqner, saider))

    return bytes(msgs)


def revoke_aliases(
    hab: habbing.Hab,
    regery: credentialing.Regery,
    issued: Issued,
    *,
    dt: str = DESIGNATION_DT,
) -> Revoked:
    """Revoke a previously issued designated-aliases ACDC and anchor the ``rev`` in the KEL.

    The keystore-side counterpart of the `revoked_acdc` negative oracle: after this, the
    credential is still *saved* and still verifies, and only a direct ``Tever.vcState`` query
    reveals that it no longer authorizes anything (docs/design.md, authorization
    post-conditions).
    """
    machinery = _Issuance(regery.hby, regery)
    registry = issued.registry

    rev_serder = _v1(registry.revoke(said=issued.creder.said, dt=dt))
    rev_anchor = _anchor(hab, rev_serder)
    machinery.registrar.revoke(issued.creder, rev_serder, rev_anchor)
    while not machinery.registrar.complete(pre=issued.creder.said, sn=1):
        machinery.drain()

    return Revoked(registry, issued.creder, rev_serder, rev_anchor)
