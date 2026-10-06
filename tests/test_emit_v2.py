"""The hosted keri.cesr for a v2 publication, and `didwebs publish` end to end.

Constraint embuup holds for v2 as for v1: what is hosted is re-derived from verified state, and
it must re-ingest through this same pipeline to the same document. Decision 3kn6drgf adds that
every hosted bup carries its disclosure, since a resolver cannot read a blinded state otherwise.
"""

from __future__ import annotations

import json
import pathlib

import builders_v2
import keri_api
import pytest
from keri.core import Blinder, BlindState
from keri.kering import Ilks
from test_issue_v2 import _messages

from didwebs import assemble, cli, document, ingest
from didwebs.did import parse as parse_did


def _claimed(facts):
    return parse_did(facts["did_webs"])


def _emitted(knob, tmp_path):
    stream, facts = builders_v2.KNOBS[knob](tmp_path)
    with ingest.ingest(stream, _claimed(facts)) as verified:
        doc = document.derive_document(verified, _claimed(facts))
        return stream, facts, doc, assemble.emit_stream(verified)


@pytest.mark.parametrize("knob", builders_v2.POSITIVE)
def test_the_hosted_stream_re_ingests_to_the_same_document(knob, tmp_path):
    _, facts, doc, emitted = _emitted(knob, tmp_path)

    with ingest.ingest(emitted, _claimed(facts)) as again:
        assert document.derive_document(again, _claimed(facts)) == doc
        assert again.acdc.said == facts["acdc_said"]


def test_the_hosted_stream_opens_with_the_v2_genus_and_ends_on_an_attached_update(tmp_path):
    _, _, _, emitted = _emitted("base", tmp_path)

    assert emitted.startswith(builders_v2.GENUS)
    assert _messages(emitted)[-1].serder.ilk == Ilks.bup


def test_every_hosted_update_carries_its_verified_disclosure(tmp_path):
    _, _, _, emitted = _emitted("base", tmp_path)

    bups = [m for m in _messages(emitted) if m.serder.ilk == Ilks.bup]
    assert bups
    for bup in bups:
        disclosed = Blinder(clan=BlindState, qb64=b"".join(i.qb64b for i in bup.bsqs[0]))
        assert disclosed.said == bup.serder.sad["b"]


def test_the_hosted_stream_normalizes_how_the_submission_was_assembled(tmp_path):
    """Submitted with a genus counter per artifact, hosted with one: the artifact is derived
    from verified state, never a copy of the submission (constraint embuup)."""
    submitted, _, _, emitted = _emitted("genus_per_artifact", tmp_path)

    assert submitted != emitted
    assert emitted.count(builders_v2.GENUS) == 1


def test_a_spare_registry_is_hosted_before_the_designations(tmp_path):
    """A registry the controller incepted and anchored but never issued from is its own
    accepted material, so it is hosted, and it goes before the designation's registry so the
    stream still ends on an attached update."""
    _, facts, _, emitted = _emitted("spare_registry", tmp_path)

    ilks = [m.serder.ilk for m in _messages(emitted)]
    rips = [m.serder.said for m in _messages(emitted) if m.serder.ilk == Ilks.rip]
    assert rips == [facts["spare_regk"], facts["regk"]]
    assert ilks[-1] == Ilks.bup


def test_publish_detects_v2_and_writes_both_artifacts(tmp_path, capsys):
    stream, facts = builders_v2.base(tmp_path / "fixture")
    path = tmp_path / "keri-in.cesr"
    path.write_bytes(stream)
    out = tmp_path / "site"

    assert cli.main(["publish", "--stream", str(path), "--did", facts["did_webs"],
                     "--out", str(out)]) == 0

    did_json, keri_cesr = (line for line in capsys.readouterr().out.splitlines())
    hosted = json.loads(pathlib.Path(did_json).read_text(encoding="utf-8"))
    assert hosted["id"] == facts["did_web"]
    with ingest.ingest(pathlib.Path(keri_cesr).read_bytes(), _claimed(facts)) as again:
        assert again.version == keri_api.V2


def test_publish_has_no_protocol_flag(tmp_path, capsys):
    """8686h4tf: the version is read from the bytes; a flag could only disagree with them."""
    assert cli.main(["publish", "--stream", "x", "--did", "did:webs:a.example:E",
                     "--out", str(tmp_path), "--protocol", "2"]) != 0
    assert "--protocol" in capsys.readouterr().err


def test_v2_endpoint_replies_become_the_same_services_v1_projects(tmp_path):
    _, facts, doc, emitted = _emitted("endpoints", tmp_path)

    assert doc["service"] == [
        {"id": f"#{facts['mailbox_aid']}/mailbox", "type": "mailbox",
         "serviceEndpoint": {"http": facts["mailbox_url"]}},
        {"id": f"#{facts['agent_aid']}/agent", "type": "agent",
         "serviceEndpoint": {"http": facts["agent_url"]}},
    ]
    assert [m.serder.ilk for m in _messages(emitted)].count("rpy") == 4


def test_a_delegated_v2_publication_hosts_its_delegators_kel_first(tmp_path):
    _, facts, _, emitted = _emitted("delegated", tmp_path)

    kel = [m.serder for m in _messages(emitted) if m.serder.ilk in ("icp", "dip", "ixn")]
    assert kel[0].ilk == "icp" and kel[0].pre == facts["delegator_aid"]
    assert any(serder.ilk == "dip" and serder.pre == facts["aid"] for serder in kel)


def test_a_rotated_v2_aid_publishes_its_current_key(tmp_path):
    _, facts, doc, _ = _emitted("rotated", tmp_path)

    assert [m["publicKeyJwk"]["kid"] for m in doc["verificationMethod"]] == [facts["current_key"]]
