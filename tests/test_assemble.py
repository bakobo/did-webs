"""Tests for didwebs.assemble's keystore side — registry, self-attested ACDC, KEL anchors.

Two contracts are under test at once. The functional one: `issue_aliases` leaves a keystore
holding an anchored registry and an issued, schema-valid designated-aliases ACDC. And the
protocol one from constraint `qbqfst`: every artifact it produces is protocol v1, because this
keripy line defaults to v2 *per call site* and a stream with one v2 frame in it is silently
dropped by every deployed 1.2.x parser.
"""

from __future__ import annotations

import json

import keri_api
import pytest
from conftest import CONTROLLER_SALT, designated_ids
from keri.core import coring
from keri.kering import Vrsn_1_0, Vrsn_2_0

from didwebs import assemble, schemaing


def kel_bodies(hab):
    """Every event in the Hab's KEL, parsed."""
    return [json.loads(frame.body) for frame in keri_api.frames(keri_api.kel_bytes(hab))]


def test_the_module_docstring_names_both_roles_so_the_split_is_discoverable():
    """The ingest-side `emit_stream` lands in a later brief; the docstring must say so."""
    doc = assemble.__doc__
    assert "emit_stream" in doc
    assert "issue_aliases" in doc


def test_the_registry_is_created_and_its_tel_lands_in_the_keystore(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert issued.registry.regk in keystore.regery.reger.tevers
    assert issued.registry.vcp.ked["t"] == coring.Ilks.vcp


def test_the_acdc_is_self_attested_by_the_hab_against_the_pinned_schema(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert issued.creder.sad["i"] == keystore.hab.pre
    assert issued.creder.sad["s"] == schemaing.DES_ALIASES_SCHEMA_SAID
    assert issued.creder.sad["ri"] == issued.registry.regk
    assert "a" in issued.creder.sad and "r" in issued.creder.sad


def test_the_tel_state_for_the_acdc_is_issued(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    state = issued.registry.tever.vcState(vci=issued.creder.said)
    assert state.et == coring.Ilks.iss


def test_both_tel_events_are_anchored_by_interaction_events_in_the_controllers_kel(keystore):
    """The vcp and the iss each get their own seal in an ixn — this is what binds TEL to KEL."""
    before = keystore.hab.kever.sner.num
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert keystore.hab.kever.sner.num == before + 2

    seals = [seal for body in kel_bodies(keystore.hab) for seal in body.get("a", [])]
    assert {"i": issued.registry.regk, "s": "0", "d": issued.registry.regd} in seals
    assert {
        "i": issued.iss_serder.pre,
        "s": "0",
        "d": issued.iss_serder.said,
    } in seals


def test_the_ids_argument_round_trips_verbatim_into_the_attribute_block(keystore):
    ids = designated_ids(keystore.hab.pre) + [f"did:web:example.com:{keystore.hab.pre}"]
    issued = assemble.issue_aliases(keystore.hab, keystore.regery, ids)
    assert issued.creder.sad["a"]["ids"] == ids


def test_the_designation_date_is_fixed_so_the_acdc_said_is_stable(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assert issued.creder.sad["a"]["dt"] == assemble.DESIGNATION_DT


def test_the_designation_date_is_overridable_for_fixtures_that_need_a_second_one(keystore):
    issued = assemble.issue_aliases(
        keystore.hab,
        keystore.regery,
        designated_ids(keystore.hab.pre),
        dt="2020-01-01T00:00:00.000000+00:00",
    )
    assert issued.creder.sad["a"]["dt"] == "2020-01-01T00:00:00.000000+00:00"


def test_an_empty_ids_list_still_produces_a_schema_valid_issued_acdc(keystore):
    issued = assemble.issue_aliases(keystore.hab, keystore.regery, [])
    assert issued.creder.sad["a"]["ids"] == []
    assert issued.registry.tever.vcState(vci=issued.creder.said).et == coring.Ilks.iss


def test_every_artifact_issue_aliases_produces_carries_protocol_v1(keystore):
    """Constraint qbqfst, artifact by artifact: icp, ixn, vcp, iss and the ACDC are all v1."""
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    for serder in (
        keystore.hab.kever.serder,
        issued.registry.vcp,
        issued.iss_serder,
        issued.anc_serder,
    ):
        assert serder.pvrsn == Vrsn_1_0
    assert issued.creder.pvrsn == Vrsn_1_0

    stream = keri_api.publication_stream(keystore.hab, keystore.regery, issued.creder)
    assert set(keri_api.version_strings(stream)) <= keri_api.ACCEPTED_VERSION_STRINGS


def test_the_version_guard_passes_a_v1_event_through_unchanged(keystore):
    serder = keystore.hab.kever.serder
    assert assemble._v1(serder) is serder


def test_the_version_guard_refuses_an_event_keripy_derived_as_v2(tmp_path):
    """The three keripy calls that take no version argument are only checkable, not pinnable.

    This proves the check is real: hand it the v2 event this keripy line produces by default
    and it must refuse, so a change to keripy's derivation chain fails here rather than in a
    published stream no 1.2.x parser can read.
    """
    with keri_api.open_keystore("v2", tmp_path, salt_raw=CONTROLLER_SALT) as hby:
        unpinned = hby.makeHab(name="v2", icount=1, isith="1", ncount=1, nsith="1")
        assert unpinned.kever.serder.pvrsn == Vrsn_2_0
        with pytest.raises(AssertionError) as excinfo:
            assemble._v1(unpinned.kever.serder)
    assert "qbqfst" in str(excinfo.value)


def test_a_second_registry_in_the_same_keystore_gets_its_own_name_and_key(keystore):
    """Fixtures issue more than once per keystore; registry names must not collide."""
    first = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre), regname="one"
    )
    second = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre), regname="two"
    )
    assert first.registry.regk != second.registry.regk


def test_revoking_moves_the_tel_state_to_revoked_and_anchors_another_interaction(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    sn_before = keystore.hab.kever.sner.num

    revoked = assemble.revoke_aliases(keystore.hab, keystore.regery, issued)

    assert revoked.registry.tever.vcState(vci=issued.creder.said).et == coring.Ilks.rev
    assert keystore.hab.kever.sner.num == sn_before + 1
    assert revoked.rev_serder.pvrsn == Vrsn_1_0
    assert revoked.creder.said == issued.creder.said
    assert revoked.rev_serder.ked["t"] == coring.Ilks.rev


def test_the_revocation_event_is_anchored_by_a_seal_in_the_kel(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    revoked = assemble.revoke_aliases(keystore.hab, keystore.regery, issued)

    seals = [seal for body in kel_bodies(keystore.hab) for seal in body.get("a", [])]
    assert {
        "i": revoked.rev_serder.pre,
        "s": "1",
        "d": revoked.rev_serder.said,
    } in seals


def test_a_revoked_stream_still_contains_only_v1_version_strings(keystore):
    issued = assemble.issue_aliases(
        keystore.hab, keystore.regery, designated_ids(keystore.hab.pre)
    )
    assemble.revoke_aliases(keystore.hab, keystore.regery, issued)
    stream = keri_api.publication_stream(keystore.hab, keystore.regery, issued.creder)
    assert set(keri_api.version_strings(stream)) <= keri_api.ACCEPTED_VERSION_STRINGS
