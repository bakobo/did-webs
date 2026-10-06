"""The keystore side of a KERI protocol v2 publication: issue, then assemble the stream.

Decisions 0plkq8s8, 3kn6drgf and 35yl884k. What a controller we hold the keys for publishes:
a v2 KEL, the designated-aliases ACDC (an ``acm`` under the proposed v2 schema), its registry's
``rip``, and every ``bup`` carrying its BlindedStateQuadruples disclosure. The oracle throughout
is keripy's own party-side verifier, ``keri.acdc.regeventing.vet``, run over a fresh store that
has only the published bytes.
"""

from __future__ import annotations

import keri_api
import pytest
from keri.acdc import regeventing
from keri.app import habbing
from keri.core import Blinder, BlindState, counting, serdering
from keri.core.eventing import Kevery
from keri.core.parsing import Parser
from keri.kering import Ilks

from didwebs import assemble, schemaing

V2 = keri_api.V2
GENUS_V2 = bytes(counting.Counter.makeGVC(version=V2))


def _issue(tmp_path, **kwa):
    with keri_api.scratch_v2("issuer", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "controller")
        ids = keri_api.designated_ids(hab.pre)
        issued = assemble.issue_aliases_v2(
            hab, rgy, ids, uuid=keri_api.REGISTRY_UUID, salt=keri_api.BLIND_SALT,
            stamp=keri_api.REGISTRY_STAMP, **kwa
        )
        stream = assemble.keystore_stream_v2(hab, issued)
        return hab.pre, ids, issued, stream


def _messages(stream: bytes):
    """Every message in ``stream`` with its extracted attachments, genus pinned to v2."""
    ims, found = bytearray(stream), []
    parser = Parser(framed=True, version=V2)
    while ims:
        extractor = parser.msgParsator(ims=ims, framed=True, local=False, version=V2)
        try:
            while True:
                next(extractor)
        except StopIteration as done:
            if done.value is not None:
                found.append(done.value)
    return found


def _vet_from_bytes(stream: bytes):
    """Verify ``stream`` the way a stranger holding only its bytes would."""
    hby = habbing.Habery(name="stranger", base="", temp=True, version=V2)
    try:
        kevery = Kevery(db=hby.db, lax=False, local=False)
        Parser(framed=True, version=V2).parse(ims=bytearray(stream), kvy=kevery, local=False)
        messages = _messages(stream)
        rip = next(m.serder for m in messages if m.serder.ilk == Ilks.rip)
        bups = [m for m in messages if m.serder.ilk == Ilks.bup]
        acm = next(m.serder for m in messages if m.serder.ilk == Ilks.acm)
        head = max(bups, key=lambda m: int(m.serder.sad["n"], 16))
        blinder = Blinder(clan=BlindState, qb64=b"".join(item.qb64b for item in head.bsqs[0]))
        return regeventing.vet(rip, [m.serder for m in bups], db=hby.db, acdc=acm, blinder=blinder)
    finally:
        hby.close(clear=True)


def test_the_designation_is_an_acm_under_the_v2_schema_naming_its_registry(tmp_path):
    aid, ids, issued, _ = _issue(tmp_path)

    assert issued.acdc.ilk == Ilks.acm
    assert issued.acdc.pvrsn == V2
    assert issued.acdc.schema == schemaing.DES_ALIASES_SCHEMA_V2_SAID
    assert issued.acdc.sad["i"] == aid
    assert issued.acdc.sad["rd"] == issued.rip.said
    assert issued.acdc.attrib["ids"] == ids
    assert "i" not in issued.acdc.attrib, "self-attested: no issuee"
    # An absent top-level u is the ACDC spec's public variant; an empty one would make it a
    # metadata ACDC (spec-body.md:126, :168; decision 35yl884k).
    assert "u" not in issued.acdc.sad
    assert schemaing.load_designated_aliases_schema_v2().verify(issued.acdc.raw)


def test_the_registry_update_is_a_bup_whose_disclosure_says_issued(tmp_path):
    _, _, issued, _ = _issue(tmp_path)

    assert issued.bup.ilk == Ilks.bup
    assert issued.bup.sad["rd"] == issued.rip.said
    assert issued.bup.sad["b"] == issued.blinder.said
    assert issued.blinder.acdc == issued.acdc.said
    assert issued.blinder.state == "issued"


def test_the_stream_opens_with_the_v2_genus_and_carries_only_v2_bodies(tmp_path):
    _, _, _, stream = _issue(tmp_path)

    assert stream.startswith(GENUS_V2)
    assert all(m.serder.pvrsn == V2 for m in _messages(stream))


def test_every_bup_in_the_stream_carries_exactly_its_own_disclosure(tmp_path):
    """3kn6drgf: a bup without its -a group is unprovable, so the keystore never emits one."""
    _, _, issued, stream = _issue(tmp_path)

    bups = [m for m in _messages(stream) if m.serder.ilk == Ilks.bup]
    assert [m.serder.said for m in bups] == [issued.bup.said]
    disclosed = Blinder(clan=BlindState, qb64=b"".join(i.qb64b for i in bups[0].bsqs[0]))
    assert disclosed.said == issued.bup.sad["b"]


def test_the_stream_ends_on_an_attached_frame(tmp_path):
    """keripy's extractor cannot finish an attachment-less final frame (it peeks for an
    attachment and finds end of stream), so the ACDC goes before the registry and an attached
    bup comes last."""
    _, _, _, stream = _issue(tmp_path)

    assert [m.serder.ilk for m in _messages(stream)][-1] == Ilks.bup


def test_a_stranger_holding_only_the_bytes_vets_the_designation_as_issued(tmp_path):
    aid, _, issued, stream = _issue(tmp_path)

    record = _vet_from_bytes(stream)

    assert record.issuer == aid
    assert record.state == "issued"
    assert record.binding == "mutual"
    assert record.acdc == issued.acdc.said


def test_issuance_is_reproducible_given_its_nonce_salt_and_stamp(tmp_path):
    """Every SAID a fixture asserts on is fixed by its inputs. The replayed KEL is not
    byte-stable, and need not be: its first-seen couples carry the time of replay, in v1 too."""
    first = _issue(tmp_path / "one")[2]
    second = _issue(tmp_path / "two")[2]

    def saids(issued):
        return (issued.rip.said, issued.acdc.said, issued.bup.said, issued.blinder.said)

    assert saids(first) == saids(second)


def test_revocation_appends_a_bup_disclosing_revoked(tmp_path):
    with keri_api.scratch_v2("issuer", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "controller")
        issued = assemble.issue_aliases_v2(
            hab, rgy, keri_api.designated_ids(hab.pre), uuid=keri_api.REGISTRY_UUID,
            salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP,
        )
        revoked = assemble.revoke_aliases_v2(
            hab, rgy, issued, salt=keri_api.BLIND_SALT, stamp=keri_api.REGISTRY_STAMP
        )
        stream = assemble.keystore_stream_v2(hab, revoked)

    assert [b.state for b in revoked.blinders] == ["issued", "revoked"]
    assert _vet_from_bytes(stream).state == "revoked"


def test_v2_issuance_refuses_a_v1_controller(tmp_path):
    """One stream is one version (8686h4tf): a v2 registry anchored in a v1 KEL is refused at
    the source rather than published and refused at ingest."""
    with keri_api.scratch_v2("issuer", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab(hby, "controller")  # v1
        with pytest.raises(ValueError, match="protocol v2"):
            assemble.issue_aliases_v2(hab, rgy, keri_api.designated_ids(hab.pre))


def test_the_keystore_stream_is_not_a_serder_dump(tmp_path):
    """The replayed KEL carries its controller signatures: a body-only KEL would vet nothing."""
    _, _, _, stream = _issue(tmp_path)

    kel = [m for m in _messages(stream) if isinstance(m.serder, serdering.SerderKERI)]
    assert kel and all(m.sigers for m in kel)


def test_an_anchor_keripy_will_not_commit_stops_issuance(tmp_path, monkeypatch):
    """An anchored registry event keripy leaves queued would be published unprovable, so the
    keystore stops rather than carrying on with a registry nobody can vet."""
    from keri.acdc import registraring

    monkeypatch.setattr(registraring.Registry, "anchorMsg", lambda self, said, **_: False)
    with keri_api.scratch_v2("issuer", tmp_path) as (hby, rgy):
        hab = keri_api.make_hab_v2(hby, "controller")
        with pytest.raises(RuntimeError, match="did not commit"):
            assemble.issue_aliases_v2(hab, rgy, keri_api.designated_ids(hab.pre))
