"""In-process keripy helpers for didwebs tests — keystores, v1-pinned Habs, stream assembly.

Attribution: adapted from the GLEIF did:webs-resolver reference implementation
(``tests/conftest.py`` and ``tests/keri_api.py``, GLEIF-IT/did-webs-resolver, Apache-2.0) and
from the interop spike harness at ``.ignored/spike-keripy-interop/gen_stream.py``, which is the
runnable proof that this recipe drives *this* keripy line.

Adaptations from the reference, which targets keri 1.2.13:

* **Protocol v1 is pinned explicitly at every call that constructs an event** (constraint
  ``qbqfst``). On keripy 2.0.0-dev6 the default is v2 and it is chosen *per call site*, not
  inherited from the Hab's key state, so an unpinned ``interact`` would inject a v2 event into
  a v1 KEL. See :data:`V1` and every use of it below.
* **``SerderACDC.regi`` is ``.regid``** on this line (spike REPORT §"2.0-dev API differences").
* The reference's witness/delegation Doers (``Dipper``, ``DipSealer``, ``WitnessReceiptor`` …)
  are dropped. didwebs phase-1 fixtures have no witnesses, so delegation approval is the
  synchronous three-step dance in :func:`approve_delegation` rather than a Doist pipeline.
* Keystores are temp stores. keripy ignores ``headDirPath`` for them (hio substitutes its own
  ``mkdtemp`` under ``/tmp``) and close removes only the leaf, so :func:`scratch` removes the
  stranded roots itself; salts are fixed so AIDs are stable across runs.

Nothing here constructs the *ingest-side* stream: ``didwebs.assemble.emit_stream`` (a later
brief) re-assembles a stream from verified state in a scratch database. :func:`publication_stream`
is the keystore-side counterpart — what a controller's own keystore would publish.
"""

from __future__ import annotations

import json
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from keri import core, kering
from keri.app import habbing, signing
from keri.app.habbing import openHby
from keri.core import coring, serdering
from keri.db import dbing
from keri.kering import Vrsn_1_0
from keri.vdr import credentialing

#: The protocol version every event in a didwebs fixture carries. Never omit it.
V1 = Vrsn_1_0

#: Version strings a didwebs publication stream is allowed to contain (design §Test strategy 3).
ACCEPTED_VERSION_STRINGS = frozenset({"KERI10JSON", "ACDC10JSON"})

#: Domain every fixture DID is minted under. No DNS lookup ever happens.
DOMAIN = "labs.bakobo.com"

#: Fixed 16-byte salt seeds. Salter requires exactly 16 bytes; every one below is 16 characters,
#: and a fixed seed is what makes a fixture's AIDs identical from run to run.
CONTROLLER_SALT = b"didwebs-fixtures"
ATTACKER_SALT = b"didwebs-attacker"
THIRD_PARTY_SALT = b"didwebs-3rdparty"
DELEGATOR_SALT = b"didwebs-delegatr"
FOREIGN_SALT = b"didwebs-foreigna"
MAILBOX_SALT = b"didwebs-mailboxx"
AGENT_SALT = b"didwebs-agentaid"

#: Endpoint roles a did:webs document projects a service for, and the URLs the fixtures declare
#: (spec ``#### Mailbox Service Endpoint`` / ``#### Agent Service Endpoint``). No DNS lookup and
#: no connection ever happens; these are values in signed reply records.
MAILBOX_ROLE = kering.Roles.mailbox
AGENT_ROLE = kering.Roles.agent
MAILBOX_URL = "http://mailbox.example.com:5635/"
AGENT_URL = "http://agent.example.com:5636/"

#: Fixed registry nonce. ``keri.vdr.eventing.incept`` defaults ``nonce`` to a fresh random
#: ``Salter().qb64``, so a registry's identifier — and therefore the ACDC SAID that references
#: it — is different on every run unless the nonce is pinned. Fixtures pin it; the library
#: does not, because the nonce exists precisely to make two real registries distinct.
REGISTRY_NONCE = core.Salter(raw=b"didwebs-registry").qb64


def salt(raw: bytes) -> str:
    """A deterministic qb64 salt from a fixed 16-byte seed."""
    return core.Salter(raw=raw).qb64


def did_web(aid: str, domain: str = DOMAIN, port: str | None = None) -> str:
    """The did:web form of a did:webs DID, as ``a.ids`` must also carry it."""
    return f"did:web:{domain}{f'%3a{port}' if port else ''}:{aid}"


def did_webs(aid: str, domain: str = DOMAIN, port: str | None = None) -> str:
    """The did:webs form."""
    return f"did:webs:{domain}{f'%3a{port}' if port else ''}:{aid}"


def designated_ids(aid: str, domain: str = DOMAIN, port: str | None = None) -> list[str]:
    """Both spellings of one AID's DID — what a well-formed designation covers."""
    return [did_web(aid, domain, port), did_webs(aid, domain, port)]


@contextmanager
def open_keystore(name: str, tmp_path, *, salt_raw: bytes):
    """Open a scratch Habery under ``tmp_path``, cleared on exit."""
    with openHby(
        name=name, salt=salt(salt_raw), temp=True, headDirPath=str(tmp_path)
    ) as hby:
        yield hby


def _temp_root(path: str) -> str:
    """The ``mkdtemp`` root under ``/tmp`` that keripy's close leaves standing.

    keripy ignores ``headDirPath`` for temp stores (hio ``Filer.remake`` substitutes its own
    ``mkdtemp``) and its close removes only the store's leaf directory, stranding the root
    (worker D's finding, 2026-08-15). Same walk as ``didwebs.ingest``'s scratch teardown.
    """
    p = Path(path)
    while p.parent != Path("/tmp"):
        p = p.parent
    return str(p)


@contextmanager
def scratch(name: str, tmp_path, *, salt_raw: bytes = CONTROLLER_SALT):
    """Yield ``(hby, regery)``; closed on exit, with the leaked temp roots removed."""
    roots: tuple[str, ...] = ()
    try:
        with open_keystore(name, tmp_path, salt_raw=salt_raw) as hby:
            regery = open_regery(hby)
            roots = tuple(
                dict.fromkeys(
                    _temp_root(store.path)
                    for store in (hby.ks, hby.db, hby.cf, regery.reger)
                )
            )
            try:
                yield hby, regery
            finally:
                regery.close()
    finally:
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def make_hab(hby: habbing.Habery, name: str, **kwa) -> habbing.Hab:
    """Make a Hab with protocol v1 pinned (``qbqfst``); ``kwa`` may override any default."""
    params = {"icount": 1, "isith": "1", "ncount": 1, "nsith": "1", "transferable": True}
    params.update(kwa)
    return hby.makeHab(name=name, version=V1, **params)


def open_regery(hby: habbing.Habery, name: str | None = None) -> credentialing.Regery:
    """Open a temporary credential registry database bound to ``hby``."""
    return credentialing.Regery(
        hby=hby, name=name if name is not None else hby.name, base=hby.base, temp=True
    )


def kel_bytes(hab: habbing.Hab, *, with_delegator: bool = True) -> bytes:
    """Replay a Hab's KEL as CESR bytes, with the CESR genus pinned to v1.

    ``Hab.replay`` prepends the delegator's KEL for a delegated AID (``cloneDelegation``).
    ``with_delegator=False`` clones only this AID's own events — the fixture shape a
    delegated-without-delegator negative oracle needs.
    """
    if with_delegator:
        return bytes(hab.replay(pre=hab.pre, gvrsn=V1))
    msgs = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre, fn=0, gvrsn=V1):
        msgs.extend(msg)
    return bytes(msgs)


def tel_bytes(regery: credentialing.Regery, pre: str) -> bytes:
    """Clone a TEL (registry or credential) as CESR bytes.

    ``Reger.clonePreIter`` takes no genus argument on this line; it emits v1 attachment
    counters unconditionally (``keri/vdr/eventing.py`` ``cloneTvt``).
    """
    msgs = bytearray()
    for msg in regery.reger.clonePreIter(pre=pre):
        msgs.extend(msg)
    return bytes(msgs)


def acdc_bytes(regery: credentialing.Regery, creder) -> bytes:
    """Serialize an ACDC with its source-seal attachment, as a publication stream carries it.

    ``signing.serialize`` hardcodes ``Vrsn_1_0`` for the attachment counter on this line
    (``keri/app/signing.py:14``), so there is no version to pin here.
    """
    prefixer, seqner, saider = regery.reger.cancs.get(keys=(creder.said,))
    return bytes(signing.serialize(creder, prefixer, seqner, saider))


def registry_id(creder) -> str:
    """The ACDC's registry identifier. ``SerderACDC.regi`` was renamed ``.regid`` on this line."""
    return creder.regid


def endpoint_replies(hab, providers) -> bytes:
    """The reply records that establish ``providers`` as endpoints of ``hab``.

    Each provider is a ``(provider_hab, role, url)`` triple. Every location scheme is signed by
    the provider itself — a ``/loc/scheme`` reply says "this is where *I* am", so only the
    provider's own key can make it — and every ``/end/role/add`` is signed by the controller,
    which is what authorizes that provider in that role. All location schemes come first, then
    all role authorizations, so a consuming stream reads the way the reference emits.
    """
    msgs = bytearray()
    for provider, _role, url in providers:
        msgs.extend(provider.makeLocScheme(url=url, scheme="http", version=V1, gvrsn=V1))
    for provider, role, _url in providers:
        msgs.extend(hab.makeEndRole(eid=provider.pre, role=role, version=V1, gvrsn=V1))
    return bytes(msgs)


def publication_stream(
    hab, regery, creder=None, *, with_delegator: bool = True, replies: bytes = b""
) -> bytes:
    """Assemble a did:webs publication stream: KEL, replies, then registry TEL, credential TEL,
    ACDC.

    This is the order ``dws/core/artifacting.py`` emits and the order the GLEIF resolver
    re-ingests, as the interop spike confirmed end to end. ``replies`` is empty by default:
    phase-1 fixtures have no witnesses and no endpoint roles, so the reference recipe's
    ``/loc/scheme`` and ``/end/role`` replies have nothing to describe unless a fixture
    (``builders.endpoints``) supplies them.
    """
    stream = bytearray(kel_bytes(hab, with_delegator=with_delegator))
    stream.extend(replies)
    if creder is not None:
        stream.extend(tel_bytes(regery, registry_id(creder)))
        stream.extend(tel_bytes(regery, creder.said))
        stream.extend(acdc_bytes(regery, creder))
    return bytes(stream)


# --------------------------------------------------------------------------- stream walking


@dataclass(frozen=True)
class Frame:
    """One message in a CESR stream: its body, its attachments, and where they start."""

    start: int
    body_end: int
    end: int
    version_string: str
    raw: bytes

    @property
    def body(self) -> bytes:
        return self.raw[self.start : self.body_end]

    @property
    def attachments(self) -> bytes:
        return self.raw[self.body_end : self.end]


def version_strings(stream: bytes) -> list[str]:
    """Every protocol/kind version string in the stream, in order, e.g. ``KERI10JSON``.

    Uses keripy's own version-string regex (``kering.Rever``), which matches both the v1
    (``KERI10JSON000123_``) and v2 (``KERICAACAAJSONAAEt.``) forms, so a v2 frame is *detected*
    here rather than being invisible.
    """
    found = []
    for match in kering.Rever.finditer(stream):
        groups = match.groupdict()
        if groups["proto2"] is not None:
            found.append(
                f"{groups['proto2'].decode()}"
                f"{groups['pmajor2'].decode()}{groups['pminor2'].decode()}"
                f"{groups['gmajor2'].decode()}{groups['gminor2'].decode()}"
                f"{groups['kind2'].decode()}"
            )
        else:
            found.append(
                f"{groups['proto1'].decode()}{groups['major1'].decode()}"
                f"{groups['minor1'].decode()}{groups['kind1'].decode()}"
            )
    return found


def frames(stream: bytes) -> list[Frame]:
    """Split an all-v1 stream into frames (body + trailing attachments).

    Only v1 field-map serializations are handled: the version string carries the body size, and
    a frame's attachments run to the start of the next frame. Streams carrying a deliberately
    foreign frame (the ``v2_frame`` and ``cbor_frame`` knobs) are built by concatenation rather
    than by round-tripping through this walker.
    """
    starts = []
    for match in kering.Rever.finditer(stream):
        if match.groupdict()["size1"] is None:
            raise ValueError("frames() handles v1 version strings only")
        size = int(match.groupdict()["size1"], 16)
        body_start = stream.rindex(b"{", 0, match.start())
        starts.append((body_start, body_start + size))

    out = []
    for index, (body_start, body_end) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(stream)
        vs = version_strings(stream[body_start:body_end])[0]
        out.append(Frame(body_start, body_end, end, vs, stream))
    return out


def bodies(stream: bytes) -> list[dict]:
    """The parsed JSON body of every frame in an all-v1 JSON stream."""
    return [json.loads(frame.body) for frame in frames(stream)]


# --------------------------------------------------------------------------- smoke ingest


def smoke_ingest(stream: bytes, aid: str, tmp_path, *, name: str = "smoke") -> dict:
    """Parse a stream into a fresh keystore and report what landed. **Not** the pipeline.

    This is the spike harness's resolver-side oracle (``ingest_stream.py``, itself
    ``dws.core.resolving.save_cesr``) ported to this keripy line, and it exists for one purpose:
    to prove a fixture is genuinely ingestable rather than merely well shaped. It does none of
    the work ``didwebs.ingest`` will do — no frame accounting, no escrow audit, no error
    attribution, no authorization post-conditions — so it must never be mistaken for, or grow
    into, the product path.

    Returns a dict of observations: whether the AID reached key state, at what sequence number,
    whether the registry reached transaction state, whether the ACDC was saved, and the
    credential's TEL state.

    **The v1 pin extends to parsing, which constraint ``qbqfst`` does not currently say.**
    ``Parser.parse`` takes its own CESR genus ``version``, defaulting to v2 like every other
    call site on this line. Without ``version=V1`` a perfectly valid v1 stream parses to
    *nothing* — no exception, no diagnostic, the AID simply never reaches ``hby.kevers``, which
    is the same silent-drop failure the spike observed in the opposite direction. Any ingest
    path built on this keripy line must pin the genus at ``parse`` as well as at ``replay``.
    """
    from keri.core import eventing, routing
    from keri.peer import exchanging
    from keri.vdr import eventing as teventing
    from keri.vdr import verifying

    with scratch(name, tmp_path, salt_raw=CONTROLLER_SALT) as (hby, regery):
        from didwebs import schemaing

        schemaing.pin_designated_aliases_schema(hby)

        router = routing.Router()
        revery = routing.Revery(db=hby.db, rtr=router)
        exchanger = exchanging.Exchanger(hby=hby, handlers=[])
        kevery = eventing.Kevery(db=hby.db, rvy=revery)
        tevery = teventing.Tevery(db=hby.db, reger=regery.reger)
        verifier = verifying.Verifier(hby=hby, reger=regery.reger)
        kevery.registerReplyRoutes(router=router)
        tevery.registerReplyRoutes(router=router)

        hby.psr.parse(
            ims=bytearray(stream),
            kvy=kevery,
            tvy=tevery,
            vry=verifier,
            rvy=revery,
            exc=exchanger,
            local=False,
            version=V1,
        )
        kevery.processEscrows()
        tevery.processEscrows()
        verifier.processEscrows()
        revery.processEscrowReply()

        observed = {
            "aid_in_kevers": aid in hby.kevers,
            "kel_sn": hby.kevers[aid].sner.num if aid in hby.kevers else None,
            "registries": set(regery.reger.tevers),
            "saved_credentials": set(),
            "vc_states": {},
        }
        for keys, _ in regery.reger.saved.getTopItemIter():
            observed["saved_credentials"].add(keys[0] if isinstance(keys, tuple) else keys)
        for regk in observed["registries"]:
            for vci in observed["saved_credentials"]:
                state = regery.reger.tevers[regk].vcState(vci=vci)
                if state is not None:
                    observed["vc_states"][vci] = state.et
        return observed


# ----------------------------------------------------------------------------- delegation


def approve_delegation(delegator: habbing.Hab, delegate_pre: str, hby: habbing.Habery) -> dict:
    """Anchor a delegated inception seal in the delegator's KEL, v1 pinned.

    The reference drives this through ``Anchorer``/``DipSealer``/``WitnessReceiptor`` Doers
    because it assumes a witness network. Without witnesses the whole approval is one anchoring
    interaction event plus an escrow drain.
    """
    seal = delegable_seal(hby, delegate_pre)
    delegator.interact(data=[seal], version=V1)
    hby.kvy.processEscrows()
    return seal


def delegable_seal(hby: habbing.Habery, delegate_pre: str) -> dict:
    """The ``(i, s, d)`` seal for a delegate's inception, from key state or from escrow."""
    if delegate_pre in hby.kevers:
        kever = hby.kevers[delegate_pre]
        return {"i": delegate_pre, "s": coring.Number(num=0).numh, "d": kever.serder.said}
    for (pre, sn), edig in hby.db.delegables.getItemIter():
        if pre != delegate_pre:
            continue
        raw = hby.db.getEvt(dbing.dgKey(pre, edig))
        serder = serdering.SerderKERI(raw=bytes(raw))
        return {"i": serder.pre, "s": serder.snh, "d": serder.said}
    raise LookupError(f"no delegable inception event found for {delegate_pre}")
