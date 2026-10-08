"""Publication streams that mix KERI protocol v1 and v2: a KEL that migrates, and one knob per
refusal (decision ``8686h4tf`` as amended 2026-10-07, and ``7p6j5kde``).

Held to :mod:`builders`' rule: no frame is hand-serialized. Each message is real keripy output,
cloned in its own genus, and a knob changes only the assembly. The assembly is done here rather
than by :func:`didwebs.assemble.emit_stream`, so that ingest is tested against streams the code
under test did not write.

A stream starts in genus v1, the way ingest reads one with no leading counter, and
:func:`_runs` puts a genus-version counter wherever the genus changes (rule 3). The knobs that
break a rule break exactly that one.
"""

from __future__ import annotations

import builders
import keri_api
from keri.acdc import acdcmap
from keri.core import coring, counting, serdering
from keri.vc import proving

from didwebs import assemble, schemaing

V1 = keri_api.V1
V2 = keri_api.V2

#: A second host, so that two standing designations of one AID designate different identifiers.
SECOND_DOMAIN = "second.example"


def gvc(major: int) -> bytes:
    """The genus-version counter that switches a stream into protocol ``major``."""
    return bytes(counting.Counter.makeGVC(version=V2 if major == 2 else V1))


def _runs(pieces) -> bytes:
    """Join ``(major, bytes)`` pieces, with a genus-version counter wherever the genus changes."""
    out = bytearray()
    genus = 1
    for major, raw in pieces:
        if major != genus:
            out.extend(gvc(major))
            genus = major
        out.extend(raw)
    return bytes(out)


def kel_pieces(db, pre: str) -> list:
    """Each event of ``pre``'s KEL as ``(major, bytes)``, cloned in its own genus."""
    v1 = db.clonePreIter(pre=pre, fn=0, gvrsn=V1)
    v2 = db.clonePreIter(pre=pre, fn=0, gvrsn=V2)
    pieces = []
    for in_v1, in_v2 in zip(v1, v2, strict=True):
        major = serdering.SerderKERI(raw=bytes(in_v1)).pvrsn.major
        pieces.append((major, bytes(in_v1 if major == 1 else in_v2)))
    return pieces


def _v1_block(regery, creder) -> list:
    return [
        (1, keri_api.tel_bytes(regery, creder.regid)),
        (1, keri_api.tel_bytes(regery, creder.said)),
        (1, keri_api.acdc_bytes(regery, creder)),
    ]


def _v2_block(issued) -> list:
    return [
        (2, issued.acdc.raw),
        (2, assemble.registry_v2_bytes(issued.rip, issued.bups, issued.blinders)),
    ]


def _issue_v2(hab, rgy, ids):
    return assemble.issue_aliases_v2(
        hab, rgy, ids, uuid=keri_api.REGISTRY_UUID, salt=keri_api.BLIND_SALT,
        stamp=keri_api.REGISTRY_STAMP,
    )


def _migrated(hby, regery):
    """A v1 controller that designates in v1, then rotates into v2 and interacts there."""
    hab = keri_api.make_hab(hby, "controller")
    issued = builders._issue(hab, regery, keri_api.designated_ids(hab.pre))
    hab.rotate(version=V2, gvrsn=V2)
    hab.interact(data=[], version=V2, gvrsn=V2)
    return hab, issued


def _facts(knob, hab, expected_code=None, **extra):
    extra.setdefault("ids", keri_api.designated_ids(hab.pre))
    extra.setdefault("current_key", hab.kever.verfers[0].qb64)
    return builders._facts(
        knob, hab.pre, kel_sn=hab.kever.sner.num, expected_code=expected_code, **extra
    )


# ------------------------------------------------------------------------------- positive


def migrated_v1_designation(tmp_path) -> builders.Fixture:
    """A KEL that incepted in v1 and rotated into v2, keeping the v1 designation it issued before.
    The document must name the post-rotation key."""
    with keri_api.scratch_mixed("migrated", tmp_path) as (hby, regery, _):
        hab, issued = _migrated(hby, regery)
        stream = _runs(kel_pieces(hby.db, hab.pre) + _v1_block(regery, issued.creder))
        return builders.Fixture(
            stream,
            _facts("migrated_v1_designation", hab, acdc_said=issued.creder.said,
                   regk=issued.registry.regk),
        )


def migrated_both_designations(tmp_path) -> builders.Fixture:
    """The migrated KEL with a v2 designation issued after migration beside the standing v1 one.
    The v2 one adds a second host, so the document must reflect both (decision ``7p6j5kde``):
    v1's identifiers first, since its issuance is anchored earlier."""
    with keri_api.scratch_mixed("both", tmp_path) as (hby, regery, rgy):
        hab, v1 = _migrated(hby, regery)
        second = keri_api.designated_ids(hab.pre, domain=SECOND_DOMAIN)
        v2 = _issue_v2(hab, rgy, [*second, *keri_api.designated_ids(hab.pre)])
        stream = _runs(
            kel_pieces(hby.db, hab.pre) + _v1_block(regery, v1.creder) + _v2_block(v2)
        )
        return builders.Fixture(
            stream,
            _facts("migrated_both_designations", hab,
                   ids=[*keri_api.designated_ids(hab.pre), *second],
                   designations=[v1.creder.said, v2.acdc.said]),
        )


def credential_last_after_a_switch(tmp_path) -> builders.Fixture:
    """``migrated_both_designations`` as another producer might order it: the v2 registry, then
    the v1 logs, then the v2 credential alone and unattached at the very end. keripy cannot
    extract an attachment-less final frame (~3rz6), and here the counter switching back to v2
    is part of the residue ingest has to read whole."""
    with keri_api.scratch_mixed("last", tmp_path) as (hby, regery, rgy):
        hab, v1 = _migrated(hby, regery)
        second = keri_api.designated_ids(hab.pre, domain=SECOND_DOMAIN)
        v2 = _issue_v2(hab, rgy, [*second, *keri_api.designated_ids(hab.pre)])
        credential, registry = _v2_block(v2)
        stream = _runs(
            kel_pieces(hby.db, hab.pre) + [registry] + _v1_block(regery, v1.creder) + [credential]
        )
        assert stream.endswith(gvc(2) + v2.acdc.raw)
        return builders.Fixture(
            stream,
            _facts("credential_last_after_a_switch", hab,
                   ids=[*keri_api.designated_ids(hab.pre), *second],
                   designations=[v1.creder.said, v2.acdc.said]),
        )


def migrated_v1_revoked_v2_issued(tmp_path) -> builders.Fixture:
    """The migrated KEL revokes its v1 designation with a v2 interaction event and issues a v2
    one. v1's Tevery must read a seal in a v2 event, and the v2 designation must authorize."""
    with keri_api.scratch_mixed("reissued", tmp_path) as (hby, regery, rgy):
        hab, v1 = _migrated(hby, regery)
        assemble.revoke_aliases(hab, regery, v1)
        v2 = _issue_v2(hab, rgy, keri_api.designated_ids(hab.pre))
        stream = _runs(
            kel_pieces(hby.db, hab.pre) + _v1_block(regery, v1.creder) + _v2_block(v2)
        )
        return builders.Fixture(
            stream, _facts("migrated_v1_revoked_v2_issued", hab, designations=[v2.acdc.said])
        )


def v1_kel_v2_registry(tmp_path) -> builders.Fixture:
    """A KEL that never migrated, anchoring a v2 registry in v1 interaction events."""
    with keri_api.scratch_mixed("v1-kel-v2-reg", tmp_path) as (hby, _, rgy):
        hab = keri_api.make_hab(hby, "controller")
        v2 = _issue_v2(hab, rgy, keri_api.designated_ids(hab.pre))
        assert {major for major, _ in kel_pieces(hby.db, hab.pre)} == {1}
        stream = _runs(kel_pieces(hby.db, hab.pre) + _v2_block(v2))
        return builders.Fixture(
            stream, _facts("v1_kel_v2_registry", hab, designations=[v2.acdc.said])
        )


def v2_kel_v1_registry(tmp_path) -> builders.Fixture:
    """A v2 KEL from inception, anchoring a v1 registry and credential in v2 interaction events.
    The stream opens in v2 and switches to v1 for the transaction logs."""
    with keri_api.scratch_mixed("v2-kel-v1-reg", tmp_path) as (hby, regery, _):
        hab = keri_api.make_hab_v2(hby, "controller")
        issued = builders._issue(hab, regery, keri_api.designated_ids(hab.pre))
        assert {major for major, _ in kel_pieces(hby.db, hab.pre)} == {2}
        stream = _runs(kel_pieces(hby.db, hab.pre) + _v1_block(regery, issued.creder))
        assert stream.startswith(gvc(2))
        return builders.Fixture(
            stream, _facts("v2_kel_v1_registry", hab, acdc_said=issued.creder.said)
        )


def delegator_migrated(tmp_path) -> builders.Fixture:
    """A v1 delegate whose delegator migrated to v2 and then approved the delegate's rotation in
    a v2 interaction event."""
    with keri_api.scratch_mixed(
        "delegated", tmp_path, salt_raw=keri_api.DELEGATOR_SALT
    ) as (hby, regery, _):
        delegator = keri_api.make_hab(hby, "delegator")
        delegate = keri_api.make_hab(hby, "delegate", delpre=delegator.pre)
        keri_api.approve_delegation(delegator, delegate.pre, hby)
        delegator.rotate(version=V2, gvrsn=V2)
        issued = builders._issue(delegate, regery, keri_api.designated_ids(delegate.pre))
        # keripy accepts a local delegate's rotation at once; a stranger needs the delegator's
        # seal, which the migrated delegator makes in v2.
        delegate.rotate(version=V1)
        drt = delegate.kever.serder
        delegator.interact(
            data=[{"i": drt.pre, "s": drt.snh, "d": drt.said}], version=V2, gvrsn=V2
        )
        stream = _runs(
            kel_pieces(hby.db, delegator.pre) + kel_pieces(hby.db, delegate.pre)
            + _v1_block(regery, issued.creder)
        )
        return builders.Fixture(
            stream,
            _facts("delegator_migrated", delegate, delegator_aid=delegator.pre,
                   acdc_said=issued.creder.said),
        )


def superseded_designation(tmp_path) -> builders.Fixture:
    """Pure v1: a revoked designation first in the stream, a standing one after it, from a second
    registry. The standing one authorizes, wherever it sits (decision ``7p6j5kde``)."""
    with keri_api.scratch("superseded", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre)
        old = builders._issue(hab, regery, ids)
        assemble.revoke_aliases(hab, regery, old)
        new = builders._issue(
            hab, regery, ids, regname="second", nonce=keri_api.salt(builders.SPARE_REGISTRY_SALT)
        )
        stream = _runs(
            [(1, keri_api.kel_bytes(hab))] + _v1_block(regery, old.creder)
            + _v1_block(regery, new.creder)
        )
        return builders.Fixture(
            stream, _facts("superseded_designation", hab, designations=[new.creder.said])
        )


def moved_host(tmp_path) -> builders.Fixture:
    """Pure v1: a standing designation of an old host, then one of the host being resolved. Both
    authorize, so the document reflects the old host too, first (decision ``7p6j5kde``)."""
    with keri_api.scratch("moved", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        old_ids = keri_api.designated_ids(hab.pre, domain=SECOND_DOMAIN)
        old = builders._issue(hab, regery, old_ids)
        new = builders._issue(
            hab, regery, keri_api.designated_ids(hab.pre), regname="second",
            nonce=keri_api.salt(builders.SPARE_REGISTRY_SALT),
        )
        stream = _runs(
            [(1, keri_api.kel_bytes(hab))] + _v1_block(regery, old.creder)
            + _v1_block(regery, new.creder)
        )
        return builders.Fixture(
            stream,
            _facts("moved_host", hab, ids=[*old_ids, *keri_api.designated_ids(hab.pre)],
                   designations=[old.creder.said, new.creder.said]),
        )


# ------------------------------------------------------------------------------- negative


def backslid(tmp_path) -> builders.Fixture:
    """A KEL that rotated into v2 and then interacted in v1 again, which keripy accepts locally
    (rule 2)."""
    with keri_api.scratch_mixed("backslid", tmp_path) as (hby, regery, _):
        hab, issued = _migrated(hby, regery)
        hab.interact(data=[{"d": "back in v1"}], version=V1)
        stream = _runs(kel_pieces(hby.db, hab.pre) + _v1_block(regery, issued.creder))
        return builders.Fixture(
            stream, _facts("backslid", hab, "e.rule.kel.version.regressed.f")
        )


def switch_without_counter(tmp_path) -> builders.Fixture:
    """The migrated publication with every genus-version counter left out (rule 3)."""
    with keri_api.scratch_mixed("uncounted", tmp_path) as (hby, regery, _):
        hab, issued = _migrated(hby, regery)
        pieces = kel_pieces(hby.db, hab.pre) + _v1_block(regery, issued.creder)
        return builders.Fixture(
            b"".join(raw for _, raw in pieces),
            _facts("switch_without_counter", hab, "e.input.format.stream.f"),
        )


def body_genus_disagrees(tmp_path) -> builders.Fixture:
    """A v1 publication whose KEL keripy cloned at genus v2, behind a v2 counter: every body is v1
    and its attachments are v2 (rule 1)."""
    with keri_api.scratch("disagrees", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        issued = builders._issue(hab, regery, keri_api.designated_ids(hab.pre))
        cloned = b"".join(bytes(m) for m in hby.db.clonePreIter(pre=hab.pre, fn=0, gvrsn=V2))
        stream = (
            gvc(2) + cloned + gvc(1) + b"".join(raw for _, raw in _v1_block(regery, issued.creder))
        )
        return builders.Fixture(
            stream, _facts("body_genus_disagrees", hab, "e.input.format.stream.f")
        )


def v1_acdc_names_v2_registry(tmp_path) -> builders.Fixture:
    """A v1 designation whose ``ri`` names a v2 registry the stream carries (rule 4)."""
    with keri_api.scratch_mixed("v1-acdc-v2-reg", tmp_path) as (hby, _, rgy):
        hab = keri_api.make_hab_v2(hby, "controller")
        v2 = _issue_v2(hab, rgy, keri_api.designated_ids(hab.pre))
        creder = proving.credential(
            schema=schemaing.DES_ALIASES_SCHEMA_SAID, issuer=hab.pre,
            data={"d": "", "dt": assemble.DESIGNATION_DT,
                  "ids": keri_api.designated_ids(hab.pre)},
            status=v2.rip.said, rules=schemaing.read_designated_aliases_rules(), version=V1,
        )
        anchor = hab.kever.serder
        attached = assemble.serialize_v1(
            creder, coring.Prefixer(qb64=hab.pre), coring.Seqner(sn=anchor.sn),
            coring.Saider(qb64=anchor.said),
        )
        stream = _runs(kel_pieces(hby.db, hab.pre) + [(1, attached)] + _v2_block(v2))
        return builders.Fixture(
            stream, _facts("v1_acdc_names_v2_registry", hab,
                           "e.rule.credential.registry.version.f")
        )


def v2_acdc_names_v1_registry(tmp_path) -> builders.Fixture:
    """A v2 designation whose ``rd`` names a v1 registry the stream carries (rule 4)."""
    with keri_api.scratch_mixed("v2-acdc-v1-reg", tmp_path) as (hby, regery, _):
        hab = keri_api.make_hab(hby, "controller")
        issued = builders._issue(hab, regery, keri_api.designated_ids(hab.pre))
        acm = acdcmap(
            israid=hab.pre, regid=issued.registry.regk,
            schema=schemaing.DES_ALIASES_SCHEMA_V2_SAID,
            attribute={"d": "", "dt": assemble.DESIGNATION_DT,
                       "ids": keri_api.designated_ids(hab.pre)},
            rule=schemaing.read_designated_aliases_rules(), uuid=None, pvrsn=V2, gvrsn=V2,
        )
        stream = _runs(
            kel_pieces(hby.db, hab.pre) + [(2, acm.raw)] + _v1_block(regery, issued.creder)
        )
        return builders.Fixture(
            stream, _facts("v2_acdc_names_v1_registry", hab,
                           "e.rule.credential.registry.version.f")
        )


def migrated_v1_revoked(tmp_path) -> builders.Fixture:
    """The migrated KEL revokes its only designation, a v1 one, in a v2 interaction event."""
    with keri_api.scratch_mixed("revoked", tmp_path) as (hby, regery, _):
        hab, issued = _migrated(hby, regery)
        assemble.revoke_aliases(hab, regery, issued)
        stream = _runs(kel_pieces(hby.db, hab.pre) + _v1_block(regery, issued.creder))
        return builders.Fixture(
            stream, _facts("migrated_v1_revoked", hab, "e.state.revoked.alias-acdc.f")
        )


#: Every knob, by name. ``expected_code`` None means the stream must publish.
KNOBS = {
    "migrated_v1_designation": migrated_v1_designation,
    "migrated_both_designations": migrated_both_designations,
    "migrated_v1_revoked_v2_issued": migrated_v1_revoked_v2_issued,
    "credential_last_after_a_switch": credential_last_after_a_switch,
    "v1_kel_v2_registry": v1_kel_v2_registry,
    "v2_kel_v1_registry": v2_kel_v1_registry,
    "delegator_migrated": delegator_migrated,
    "superseded_designation": superseded_designation,
    "moved_host": moved_host,
    "backslid": backslid,
    "switch_without_counter": switch_without_counter,
    "body_genus_disagrees": body_genus_disagrees,
    "v1_acdc_names_v2_registry": v1_acdc_names_v2_registry,
    "v2_acdc_names_v1_registry": v2_acdc_names_v1_registry,
    "migrated_v1_revoked": migrated_v1_revoked,
}

POSITIVE = (
    "migrated_v1_designation", "migrated_both_designations", "migrated_v1_revoked_v2_issued",
    "credential_last_after_a_switch",
    "v1_kel_v2_registry", "v2_kel_v1_registry", "delegator_migrated", "superseded_designation", "moved_host",
)
NEGATIVE = tuple(name for name in KNOBS if name not in POSITIVE)
