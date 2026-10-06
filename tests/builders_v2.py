"""KERI protocol v2 publication streams: one valid base, and one knob per refusal.

The v2 counterpart of :mod:`builders`, and held to the same rule: no frame is hand-serialized.
Every message is real keripy output from a scratch keystore, and a knob changes the *assembly*
(which messages go in, in what order, with which attachments), never a message's bytes. So a
refusal a test observes is the pipeline refusing a real stream, not a parser choking on a
forgery the builder made up.

Every knob returns a :class:`builders.Fixture` whose facts carry ``expected_code`` for the
negative matrix, or ``None`` for a stream that must publish.
"""

from __future__ import annotations

import builders
import keri_api
from keri.acdc import Registrar, acdcmap, messaging
from keri.core import Blinder, counting, serdering
from keri.core.eventing import messagize

from didwebs import assemble, schemaing

V2 = keri_api.V2
GENUS = bytes(counting.Counter.makeGVC(version=V2))
STRANGER_SALT = b"didwebs-stranger"


def _issued(hby, rgy, name="controller", ids=None, **kwa):
    """A v2 controller and its issued designation, reproducible given the fixture constants."""
    hab = keri_api.make_hab_v2(hby, name)
    issued = assemble.issue_aliases_v2(
        hab,
        rgy,
        ids if ids is not None else keri_api.designated_ids(hab.pre),
        uuid=keri_api.REGISTRY_UUID,
        salt=keri_api.BLIND_SALT,
        stamp=keri_api.REGISTRY_STAMP,
        **kwa,
    )
    return hab, issued


def _kel(hab, *, drop_last: int = 0) -> bytes:
    """``hab``'s KEL as published, optionally without its last ``drop_last`` events."""
    events = list(hab.db.clonePreIter(pre=hab.pre, fn=0, gvrsn=V2))
    if drop_last:
        events = events[:-drop_last]
    return b"".join(bytes(event) for event in events)


def _facts(knob, hab, issued, expected_code=None, **extra):
    return builders._facts(
        knob,
        hab.pre,
        schema_said=issued.acdc.schema,
        acdc_said=issued.acdc.said,
        regk=issued.rip.said,
        ids=list(issued.acdc.attrib["ids"]),
        kel_sn=hab.kever.sner.num,
        expected_code=expected_code,
        **extra,
    )


def base(tmp_path) -> builders.Fixture:
    """A complete, valid v2 publication: KEL, ACDC, registry with its disclosed update."""
    with keri_api.scratch_v2("base", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        return builders.Fixture(assemble.keystore_stream_v2(hab, issued), _facts("base", hab, issued))


def revoked(tmp_path) -> builders.Fixture:
    """The designation, then a second update disclosing ``revoked``."""
    with keri_api.scratch_v2("revoked", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        issued = assemble.revoke_aliases_v2(
            hab, rgy, issued, salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP
        )
        stream = assemble.keystore_stream_v2(hab, issued)
        return builders.Fixture(
            stream, _facts("revoked", hab, issued, "e.state.revoked.alias-acdc.f")
        )


def undisclosed(tmp_path) -> builders.Fixture:
    """The update published bare, without its BlindedStateQuadruples group (3kn6drgf)."""
    with keri_api.scratch_v2("undisclosed", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        stream = GENUS + _kel(hab) + issued.acdc.raw + issued.rip.raw + issued.bup.raw
        return builders.Fixture(
            stream, _facts("undisclosed", hab, issued, "e.proof.stream.disclosure.f")
        )


def misdisclosed(tmp_path) -> builders.Fixture:
    """The update carrying a well-formed disclosure of a *different* blinded state: it claims
    ``issued`` for this credential, under a salt the issuer never used, so its BLID is not the
    one the anchored ``bup`` commits to."""
    with keri_api.scratch_v2("misdisclosed", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        forged = Blinder.blind(
            sn=1, acdc=issued.acdc.said, state="issued", salt=keri_api.REGISTRY_NONCE
        )
        bup = messagize(issued.bup, bonds=[forged.data], framed=False, gvrsn=V2)
        stream = GENUS + _kel(hab) + issued.acdc.raw + issued.rip.raw + bytes(bup)
        return builders.Fixture(
            stream, _facts("misdisclosed", hab, issued, "e.proof.stream.disclosure.f")
        )


def upd_update(tmp_path) -> builders.Fixture:
    """The registry updated with ``upd``, anchored and otherwise valid. Our keripy pin accepts
    it; WebOfTrust keripy main does not, so neither do we (0plkq8s8)."""
    with keri_api.scratch_v2("upd", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        upd = messaging.update(
            issued.rip.said,
            issued.bup.said,
            issued.acdc.said,
            "issued",
            sn=2,
            stamp=keri_api.REGISTRY_STAMP,
        )
        hab.interact(data=[{"i": issued.rip.said, "s": upd.sad["n"], "d": upd.said}], version=V2)
        stream = assemble.keystore_stream_v2(hab, issued) + upd.raw
        return builders.Fixture(
            stream, _facts("upd_update", hab, issued, "e.feature.unsupported.registry.event.f")
        )


def unanchored(tmp_path) -> builders.Fixture:
    """The KEL published without the interaction event that anchors the update."""
    with keri_api.scratch_v2("unanchored", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        stream = (
            GENUS
            + _kel(hab, drop_last=1)
            + issued.acdc.raw
            + assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)
        )
        return builders.Fixture(
            stream, _facts("unanchored", hab, issued, "e.proof.stream.anchor.f")
        )


def without_acdc(tmp_path) -> builders.Fixture:
    """A v2 KEL and registry, and no designation."""
    with keri_api.scratch_v2("without", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        stream = GENUS + _kel(hab)
        return builders.Fixture(
            stream, _facts("without_acdc", hab, issued, "e.input.missing.alias-acdc.f")
        )


def scope_miss(tmp_path) -> builders.Fixture:
    """A valid designation of the controller's AID under a different host."""
    with keri_api.scratch_v2("scope", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "controller")
        ids = keri_api.designated_ids(hab.pre, domain="elsewhere.example")
        issued = assemble.issue_aliases_v2(
            hab, rgy, ids, uuid=keri_api.REGISTRY_UUID, salt=keri_api.BLIND_SALT,
            stamp=keri_api.REGISTRY_STAMP,
        )
        return builders.Fixture(
            assemble.keystore_stream_v2(hab, issued),
            _facts("scope_miss", hab, issued, "e.grant.scope.alias.f"),
        )


def attacker_acdc(tmp_path) -> builders.Fixture:
    """A stranger's valid v2 designation naming the victim's DID, riding the victim's KEL.

    Every frame verifies; the stranger's registry is anchored in the stranger's own KEL. What
    fails is the issuer binding, which is the refusal the test expects (KRT-F1)."""
    with keri_api.scratch_v2("victim", tmp_path / "victim") as (vhby, _):
        victim = keri_api.make_hab_v2(vhby, "controller")
        victim_kel = _kel(victim)
        victim_ids = keri_api.designated_ids(victim.pre)
    with keri_api.scratch_v2("attacker", tmp_path / "attacker", salt_raw=STRANGER_SALT) as (
        hby,
        rgy,
    ):
        attacker, issued = _issued(hby, rgy, name="attacker", ids=victim_ids)
        stream = (
            GENUS
            + victim_kel
            + _kel(attacker)
            + issued.acdc.raw
            + assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)
        )
        facts = _facts("attacker_acdc", attacker, issued, "e.grant.missing.alias.f")
    facts.update(aid=victim.pre, did_webs=keri_api.did_webs(victim.pre),
                 did_web=keri_api.did_web(victim.pre), attacker=attacker.pre)
    return builders.Fixture(stream, facts)


def stranger_bundle(tmp_path) -> builders.Fixture:
    """A valid v2 publication with a stranger's whole valid publication appended."""
    with keri_api.scratch_v2("stranger", tmp_path / "stranger", salt_raw=STRANGER_SALT) as (
        hby,
        rgy,
    ):
        stranger, theirs = _issued(hby, rgy, name="stranger")
        appended = _kel(stranger) + theirs.acdc.raw + assemble.registry_v2_bytes(
            theirs.rip, theirs.bups, theirs.blinders
        )
    fixture = base(tmp_path / "trunk")
    facts = {**fixture.facts, "knob": "stranger_bundle",
             "expected_code": "e.rule.stream.third-party.f"}
    return builders.Fixture(fixture.stream + appended, facts)


def mixed_versions(tmp_path) -> builders.Fixture:
    """A valid v2 publication with a valid v1 one appended: one stream, two major versions
    (8686h4tf)."""
    v1 = builders.base(tmp_path / "v1")
    fixture = base(tmp_path / "v2")
    facts = {**fixture.facts, "knob": "mixed_versions", "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(fixture.stream + v1.stream, facts)


def _custom_credential(hby, rgy, *, schema, attribute):
    """A v2 registry whose disclosed head binds an ``acm`` the caller shapes: the way to put a
    credential that is not a valid designation behind a registry that is otherwise valid."""
    hab = keri_api.make_hab_v2(hby, "controller")
    registrar = Registrar(rgy=rgy)
    registry = registrar.makeRegistry(
        name="custom", prefix=hab.pre, uuid=keri_api.REGISTRY_UUID, stamp=keri_api.REGISTRY_STAMP
    )
    rip = rgy.store.event(registry.regk)
    assemble._anchor_v2(hab, registry, rip)
    acdc = acdcmap(
        israid=hab.pre, regid=registry.regk, schema=schema, attribute=attribute,
        rule=schemaing.read_designated_aliases_rules(), uuid="", pvrsn=V2, gvrsn=V2,
    )
    blinder, bup = registrar.issue(
        registry, acdc=acdc, state="issued", salt=keri_api.BLIND_SALT,
        stamp=keri_api.REGISTRY_STAMP,
    )
    assemble._anchor_v2(hab, registry, bup)
    issued = assemble.IssuedV2(registry, rip, acdc, (bup,), (blinder,))
    return hab, issued, assemble.keystore_stream_v2(hab, issued)


def foreign_schema(tmp_path) -> builders.Fixture:
    """A registry-bound credential under a schema that is not the v2 designated-aliases one:
    vetting accepts the registry and leaves the credential unaccounted."""
    with keri_api.scratch_v2("foreign", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "probe")
        ids = keri_api.designated_ids(hab.pre)
        hab, issued, stream = _custom_credential(
            hby, rgy, schema=schemaing.DES_ALIASES_SCHEMA_SAID,
            attribute={"d": "", "dt": assemble.DESIGNATION_DT, "ids": ids},
        )
        return builders.Fixture(
            stream, _facts("foreign_schema", hab, issued, "e.proof.stream.frame.f")
        )


def schema_invalid(tmp_path) -> builders.Fixture:
    """A credential naming the v2 designated-aliases schema that does not validate against it:
    the attribute block has no ``dt``."""
    with keri_api.scratch_v2("invalid", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "probe")
        ids = keri_api.designated_ids(hab.pre)
        hab, issued, stream = _custom_credential(
            hby, rgy, schema=schemaing.DES_ALIASES_SCHEMA_V2_SAID,
            attribute={"d": "", "ids": ids},
        )
        return builders.Fixture(
            stream, _facts("schema_invalid", hab, issued, "e.proof.stream.frame.f")
        )


def rip_only(tmp_path) -> builders.Fixture:
    """The credential and its registry's inception, without the update that issued it -- which
    the KEL in the same stream anchors, so the omission is visible (decision 3kn6drgf)."""
    with keri_api.scratch_v2("rip-only", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        stream = GENUS + _kel(hab) + issued.acdc.raw + issued.rip.raw
        return builders.Fixture(
            stream, _facts("rip_only", hab, issued, "e.input.missing.registry.event.f")
        )


def never_issued(tmp_path) -> builders.Fixture:
    """A credential naming a registry that was incepted and anchored but never updated: nothing
    binds it, so it is never accepted, and the accounting audit names it."""
    with keri_api.scratch_v2("never-issued", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "controller")
        registry = Registrar(rgy=rgy).makeRegistry(
            name="r", prefix=hab.pre, uuid=keri_api.REGISTRY_UUID, stamp=keri_api.REGISTRY_STAMP
        )
        rip = rgy.store.event(registry.regk)
        assemble._anchor_v2(hab, registry, rip)
        acdc = acdcmap(
            israid=hab.pre, regid=registry.regk, schema=schemaing.DES_ALIASES_SCHEMA_V2_SAID,
            attribute={"d": "", "dt": assemble.DESIGNATION_DT,
                       "ids": keri_api.designated_ids(hab.pre)},
            rule=schemaing.read_designated_aliases_rules(), pvrsn=V2, gvrsn=V2,
        )
        issued = assemble.IssuedV2(registry, rip, acdc, (), ())
        stream = GENUS + _kel(hab) + acdc.raw + rip.raw
        return builders.Fixture(
            stream, _facts("never_issued", hab, issued, "e.proof.stream.frame.f")
        )


def gapped_chain(tmp_path) -> builders.Fixture:
    """A revoked registry published without its first update: the head names a prior that
    is not there, which keripy refuses as a gapped chain."""
    with keri_api.scratch_v2("gapped", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        issued = assemble.revoke_aliases_v2(
            hab, rgy, issued, salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP
        )
        stream = (
            GENUS + _kel(hab) + issued.acdc.raw
            + assemble.registry_v2_bytes(issued.rip, issued.bups[1:], issued.blinders[1:])
        )
        return builders.Fixture(
            stream, _facts("gapped_chain", hab, issued, "e.proof.stream.frame.f")
        )


def truncated_tail(tmp_path) -> builders.Fixture:
    """A valid publication cut off inside its final attachment."""
    fixture = base(tmp_path)
    facts = {**fixture.facts, "knob": "truncated_tail", "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(fixture.stream[:-10], facts)


def garbage_tail(tmp_path) -> builders.Fixture:
    """A valid publication followed by the start of a body that never finishes."""
    fixture = base(tmp_path)
    facts = {**fixture.facts, "knob": "garbage_tail", "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(fixture.stream + b'{"v":"KERICAACAAJSON', facts)


def spare_registry(tmp_path) -> builders.Fixture:
    """A valid publication whose controller also incepted and anchored a second registry it
    never issued from. That registry is the controller's own accepted material, so it must be
    hosted, not dropped (the v1 rule, constraint embuup)."""
    with keri_api.scratch_v2("spare", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        spare = Registrar(rgy=rgy).makeRegistry(
            name="spare", prefix=hab.pre, uuid=keri_api.REGISTRY_NONCE_V2_SPARE,
            stamp=keri_api.REGISTRY_STAMP,
        )
        spare_rip = rgy.store.event(spare.regk)
        assemble._anchor_v2(hab, spare, spare_rip)
        stream = (
            GENUS + _kel(hab) + issued.acdc.raw + spare_rip.raw
            + assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)
        )
        return builders.Fixture(
            stream, _facts("spare_registry", hab, issued, spare_regk=spare_rip.said)
        )


def _delegated(tmp_path, *, include_delegator: bool):
    with keri_api.scratch_v2("delegate", tmp_path, salt_raw=keri_api.DELEGATOR_SALT) as (hby, rgy):
        delegator = keri_api.make_hab_v2(hby, "delegator")
        delegate = keri_api.make_hab_v2(hby, "delegate", delpre=delegator.pre)
        delegator.interact(data=[keri_api.delegable_seal(hby, delegate.pre)], version=V2)
        hby.kvy.processEscrows()
        issued = assemble.issue_aliases_v2(
            delegate, rgy, keri_api.designated_ids(delegate.pre), uuid=keri_api.REGISTRY_UUID,
            salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP,
        )
        if include_delegator:
            stream = assemble.keystore_stream_v2(delegate, issued)
        else:
            stream = (
                GENUS + _kel(delegate) + issued.acdc.raw
                + assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)
            )
        return stream, _facts(
            "delegated" if include_delegator else "delegated:no-delegator",
            delegate, issued,
            None if include_delegator else "e.input.missing.delegator.f",
            delegator_aid=delegator.pre,
        )


def delegated(tmp_path) -> builders.Fixture:
    """A delegated v2 AID's publication, with its delegator's KEL first."""
    return builders.Fixture(*_delegated(tmp_path, include_delegator=True))


def delegated_without_delegator(tmp_path) -> builders.Fixture:
    """The same publication without the delegator's KEL: the delegation seal is uncheckable."""
    return builders.Fixture(*_delegated(tmp_path, include_delegator=False))


def endpoints(tmp_path) -> builders.Fixture:
    """A valid publication with a mailbox and an agent, each declaring its own location and
    authorized in its role by the controller, all as v2 ``rpy`` records."""
    with keri_api.scratch_v2("endpoints", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        providers = []
        for name, salt_raw, role, url in (
            ("mailbox", keri_api.MAILBOX_SALT, keri_api.MAILBOX_ROLE, keri_api.MAILBOX_URL),
            ("agent", keri_api.AGENT_SALT, keri_api.AGENT_ROLE, keri_api.AGENT_URL),
        ):
            provider = keri_api.make_hab_v2(
                hby, name, transferable=False, salt=keri_api.salt(salt_raw)
            )
            providers.append((provider, role, url))
        replies = bytearray()
        for provider, _role, url in providers:
            replies.extend(provider.makeLocScheme(url=url, scheme="http", version=V2, gvrsn=V2))
        for provider, role, _url in providers:
            replies.extend(hab.makeEndRole(eid=provider.pre, role=role, version=V2, gvrsn=V2))
        stream = assemble.keystore_stream_v2(hab, issued, replies=bytes(replies))
        return builders.Fixture(
            stream,
            _facts(
                "endpoints", hab, issued,
                mailbox_aid=providers[0][0].pre, agent_aid=providers[1][0].pre,
                mailbox_url=keri_api.MAILBOX_URL, agent_url=keri_api.AGENT_URL,
            ),
        )


def rotated(tmp_path) -> builders.Fixture:
    """A valid publication whose controller rotated after issuing: the document must name the
    post-rotation key."""
    with keri_api.scratch_v2("rotated", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        hab.rotate(version=V2, gvrsn=V2)
        return builders.Fixture(
            assemble.keystore_stream_v2(hab, issued),
            _facts("rotated", hab, issued, current_key=hab.kever.verfers[0].qb64),
        )


def forked_kel(tmp_path) -> builders.Fixture:
    """One v2 AID, two valid interaction events at one sequence number, both submitted: two
    keystores share a salt, incept the same AID, and extend it differently."""
    with keri_api.scratch_v2("branch", tmp_path / "branch") as (bhby, _):
        branch_hab = keri_api.make_hab_v2(bhby, "controller")
        branch_hab.interact(data=[{"d": "a divergent branch"}], version=V2)
        branch = next(branch_hab.db.clonePreIter(pre=branch_hab.pre, fn=1, gvrsn=V2))
    fixture = base(tmp_path / "trunk")
    assert branch_hab.pre == fixture.facts["aid"], "the fork must be the same AID"
    facts = {**fixture.facts, "knob": "forked_kel", "expected_code": "e.state.conflict.kel.f"}
    return builders.Fixture(fixture.stream + bytes(branch), facts)


def _revoked(hby, rgy):
    hab, issued = _issued(hby, rgy)
    return hab, assemble.revoke_aliases_v2(
        hab, rgy, issued, salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP
    )


def omitted_revocation(tmp_path) -> builders.Fixture:
    """A revoked designation published without the revoking update, although the stream's own
    KEL anchors it. Every presented event verifies; what is wrong is what is missing (panel
    SEC-F1). Without a completeness check this published as ``issued``."""
    with keri_api.scratch_v2("omitted", tmp_path) as (hby, rgy):
        hab, issued = _revoked(hby, rgy)
        stream = (
            GENUS + _kel(hab) + issued.acdc.raw
            + assemble.registry_v2_bytes(issued.rip, issued.bups[:1], issued.blinders[:1])
        )
        return builders.Fixture(
            stream, _facts("omitted_revocation", hab, issued,
                           "e.input.missing.registry.event.f",
                           missing=issued.bups[1].said)
        )


def bare_seal_omitted_revocation(tmp_path) -> builders.Fixture:
    """The omitted-revocation attack with the revoking update anchored by a bare SAID, which
    keripy accepts as a seal (regeventing.sealDigests); the completeness check must too."""
    with keri_api.scratch_v2("bare-seal", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        _blinder, bup = Registrar(rgy=rgy).issue(
            issued.registry, acdc=issued.acdc, state="revoked", salt=keri_api.BLIND_SALT,
            stamp=keri_api.REGISTRY_STAMP,
        )
        # keripy's issuer-side engine will not commit an event anchored this way, but its
        # verifier (vet) accepts the seal, so the KEL alone is what a resolver would see.
        hab.interact(data=[bup.said], version=V2, gvrsn=V2)
        stream = (
            GENUS + _kel(hab) + issued.acdc.raw
            + assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)
        )
        return builders.Fixture(
            stream, _facts("bare_seal_omitted_revocation", hab, issued,
                           "e.input.missing.registry.event.f", missing=bup.said)
        )


def malformed_seal_data(tmp_path) -> builders.Fixture:
    """A valid publication whose KEL also carries an interaction with seal-shaped data keripy
    would never match (``d`` is a list). It is not an anchor, so it neither blocks publication
    nor crashes the completeness check."""
    with keri_api.scratch_v2("malformed-seal", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        hab.interact(data=[{"i": issued.rip.said, "d": []}], version=V2, gvrsn=V2)
        return builders.Fixture(
            assemble.keystore_stream_v2(hab, issued), _facts("malformed_seal_data", hab, issued)
        )


def null_sn(tmp_path) -> builders.Fixture:
    """A SAID-valid update whose ``n`` is JSON null rather than a hex string."""
    fixture = base(tmp_path)
    bup_start = fixture.stream.index(b'{"v":"ACDC', fixture.stream.index(b'"t":"bup"') - 40)
    sad = dict(serdering.SerderACDC(raw=fixture.stream[bup_start:]).sad)
    sad.update(n=None, d="")
    forged = serdering.SerderACDC(sad=sad, makify=True)
    facts = {**fixture.facts, "knob": "null_sn", "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(fixture.stream + forged.raw, facts)


def vacated(tmp_path) -> builders.Fixture:
    """The designation issued, then a vacuous update (keripy's ``Registrar.vacate``) as head.
    keripy reads the state as the latest non-vacuous update's, so this publishes as issued
    (panel GOV-F1)."""
    with keri_api.scratch_v2("vacated", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        blinder, bup = Registrar(rgy=rgy).vacate(
            issued.registry, salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP
        )
        assemble._anchor_v2(hab, issued.registry, bup)
        issued = assemble.IssuedV2(
            issued.registry, issued.rip, issued.acdc,
            (*issued.bups, bup), (*issued.blinders, blinder),
        )
        return builders.Fixture(
            assemble.keystore_stream_v2(hab, issued), _facts("vacated", hab, issued)
        )


def disclosed_on_acdc(tmp_path) -> builders.Fixture:
    """Every disclosure grouped in one -a group on the ACDC and the updates published bare,
    which ACDC spec-body.md:2062 allows (panel SPC-F2)."""
    with keri_api.scratch_v2("on-acdc", tmp_path) as (hby, rgy):
        hab, issued = _revoked(hby, rgy)
        issued = assemble.IssuedV2(
            issued.registry, issued.rip, issued.acdc, issued.bups[:1], issued.blinders[:1]
        )
        hab_kel = _kel(hab, drop_last=1)  # the revocation is not part of this publication
        acdc = messagize(issued.acdc, bonds=[b.data for b in issued.blinders], framed=False,
                         gvrsn=V2)
        stream = GENUS + hab_kel + issued.rip.raw + issued.bups[0].raw + bytes(acdc)
        return builders.Fixture(stream, _facts("disclosed_on_acdc", hab, issued))


def historical_blinder_lost(tmp_path) -> builders.Fixture:
    """Issued, then issued again; the first update's disclosure is gone. Only the head back to
    the latest non-vacuous update needs one, so this publishes (panel SKP-F1)."""
    with keri_api.scratch_v2("lost", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        blinder, bup = Registrar(rgy=rgy).issue(
            issued.registry, acdc=issued.acdc, state="issued", salt=keri_api.BLIND_SALT,
            stamp=keri_api.REGISTRY_STAMP,
        )
        assemble._anchor_v2(hab, issued.registry, bup)
        stream = (
            GENUS + _kel(hab) + issued.acdc.raw + issued.rip.raw + issued.bups[0].raw
            + bytes(messagize(bup, bonds=[blinder.data], framed=False, gvrsn=V2))
        )
        issued = assemble.IssuedV2(
            issued.registry, issued.rip, issued.acdc, (*issued.bups, bup),
            (*issued.blinders, blinder),
        )
        return builders.Fixture(stream, _facts("historical_blinder_lost", hab, issued))


def non_hex_sn(tmp_path) -> builders.Fixture:
    """A SAID-valid update whose ``n`` is not hex: unreadable as a registry event, refused as a
    format fault rather than escaping as a bare exception (panel SEC-F2)."""
    fixture = base(tmp_path)
    walked_bup = fixture.stream[fixture.stream.index(b'{"v":"ACDCCAACAAJSON', fixture.stream.index(b'"t":"bup"') - 40):]
    sad = dict(serdering.SerderACDC(raw=walked_bup).sad)
    sad.update(n="zz", d="")
    forged = serdering.SerderACDC(sad=sad, makify=True)
    facts = {**fixture.facts, "knob": "non_hex_sn", "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(fixture.stream + forged.raw, facts)


def non_hex_sn_midstream(tmp_path) -> builders.Fixture:
    """The same malformed update, followed by another frame, so the extractor completes it
    rather than stopping at end of stream."""
    fixture = non_hex_sn(tmp_path)
    base_stream = base(tmp_path / "again").stream
    start = base_stream.index(b'{"v":"ACDC', base_stream.index(b'"t":"acm"') - 40)
    acdc = serdering.SerderACDC(raw=base_stream[start:])
    facts = {**fixture.facts, "knob": "non_hex_sn_midstream"}
    return builders.Fixture(fixture.stream + acdc.raw, facts)


def empty_attachment_group(tmp_path) -> builders.Fixture:
    """An attachment-less ACDC followed by an empty attachment group (-CAA). keripy's extractor
    refuses it, so we do (panel CSR-F1)."""
    fixture = base(tmp_path)
    start = fixture.stream.index(b'"t":"acm"') - 40
    start = fixture.stream.index(b'{"v":"ACDC', start)
    acm = serdering.SerderACDC(raw=fixture.stream[start:])
    empty = bytes(counting.Counter(counting.Codens.AttachmentGroup, count=0, version=V2).qb64b)
    stream = fixture.stream[: start + acm.size] + empty + fixture.stream[start + acm.size :]
    facts = {**fixture.facts, "knob": "empty_attachment_group",
             "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(stream, facts)


def trailing_v1_body(tmp_path) -> builders.Fixture:
    """A valid v2 publication followed by one whole, attachment-less v1 credential body: the
    final-frame reader can read it, and refuses it for its version."""
    v1 = builders.base(tmp_path / "v1")
    start = v1.stream.index(b'{"v":"ACDC10')
    body = v1.stream[start : start + int(v1.stream[start + 16 : start + 22], 16)]
    fixture = base(tmp_path / "v2")
    facts = {**fixture.facts, "knob": "trailing_v1_body",
             "expected_code": "e.input.format.stream.f"}
    return builders.Fixture(fixture.stream + body, facts)


def genus_per_artifact(tmp_path) -> builders.Fixture:
    """A valid publication assembled the way heti hands out its artifacts: KEL, ACDC and
    registry each opening with its own genus-version counter. It must publish."""
    with keri_api.scratch_v2("per-artifact", tmp_path) as (hby, rgy):
        hab, issued = _issued(hby, rgy)
        stream = (
            GENUS + _kel(hab) + GENUS + issued.acdc.raw
            + GENUS + assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)
        )
        return builders.Fixture(stream, _facts("genus_per_artifact", hab, issued))


#: Every knob, by name. ``expected_code`` None means the stream must publish.
KNOBS = {
    "base": base,
    "revoked": revoked,
    "undisclosed": undisclosed,
    "misdisclosed": misdisclosed,
    "upd_update": upd_update,
    "unanchored": unanchored,
    "without_acdc": without_acdc,
    "scope_miss": scope_miss,
    "attacker_acdc": attacker_acdc,
    "stranger_bundle": stranger_bundle,
    "mixed_versions": mixed_versions,
    "foreign_schema": foreign_schema,
    "schema_invalid": schema_invalid,
    "rip_only": rip_only,
    "never_issued": never_issued,
    "gapped_chain": gapped_chain,
    "truncated_tail": truncated_tail,
    "garbage_tail": garbage_tail,
    "trailing_v1_body": trailing_v1_body,
    "genus_per_artifact": genus_per_artifact,
    "spare_registry": spare_registry,
    "delegated": delegated,
    "delegated:no-delegator": delegated_without_delegator,
    "endpoints": endpoints,
    "rotated": rotated,
    "forked_kel": forked_kel,
    "omitted_revocation": omitted_revocation,
    "bare_seal_omitted_revocation": bare_seal_omitted_revocation,
    "malformed_seal_data": malformed_seal_data,
    "null_sn": null_sn,
    "vacated": vacated,
    "disclosed_on_acdc": disclosed_on_acdc,
    "historical_blinder_lost": historical_blinder_lost,
    "non_hex_sn": non_hex_sn,
    "non_hex_sn_midstream": non_hex_sn_midstream,
    "empty_attachment_group": empty_attachment_group,
}

#: Knobs whose stream must be refused, and the exact code each must earn.
POSITIVE = (
    "base", "genus_per_artifact", "spare_registry", "delegated", "endpoints", "rotated",
    "vacated", "disclosed_on_acdc", "historical_blinder_lost", "malformed_seal_data",
)
NEGATIVE = tuple(name for name in KNOBS if name not in POSITIVE)
