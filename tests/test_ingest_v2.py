"""Ingesting a KERI protocol v2 publication stream.

Decisions 0plkq8s8 (the community's v2), 8686h4tf (the version is read from the stream; one
stream is one version) and 3kn6drgf (rip + bup, every bup disclosed). The v1 pipeline is the
model: the same walk, accounting audit, authorization and ownership steps, with the v2 registry
vetted by ``keri.acdc.regeventing.vet`` where v1 relies on keripy's Tevery and Verifier.

Every refusal is a negative requirement, so each has a fixture that supplies the bad input and
an assertion on the exact code it must earn (cc ledger #22): a missing refusal produces no
failing test of its own.
"""

from __future__ import annotations

import builders_v2
import keri_api
import pytest
from bakobo.errors import BakoboError

from didwebs import document, ingest
from didwebs.did import parse as parse_did


def _claimed(facts):
    return parse_did(facts["did_webs"])


def test_the_version_is_read_from_the_stream(tmp_path):
    v2 = builders_v2.base(tmp_path / "v2").stream
    v1 = builders_v2.builders.base(tmp_path / "v1").stream

    assert ingest.stream_version(v2) == keri_api.V2
    assert ingest.stream_version(v1) == keri_api.V1


@pytest.mark.parametrize("knob", builders_v2.POSITIVE)
def test_a_valid_v2_publication_verifies(knob, tmp_path):
    stream, facts = builders_v2.KNOBS[knob](tmp_path)

    with ingest.ingest(stream, _claimed(facts)) as verified:
        assert verified.version == keri_api.V2
        assert verified.aid == facts["aid"]
        assert verified.acdc.said == facts["acdc_said"]
        assert verified.acdc.attrib["ids"] == facts["ids"]
        doc = document.derive_document(verified, _claimed(facts))

    assert doc["id"] == facts["did_webs"]
    assert facts["did_web"] in doc["alsoKnownAs"]


def test_every_frame_of_a_valid_v2_publication_is_accounted(tmp_path):
    stream, facts = builders_v2.base(tmp_path)

    with ingest.ingest(stream, _claimed(facts)) as verified:
        ilks = [frame.ilk for frame in verified.frames]

    assert ilks.count("icp") == 1
    assert {"rip", "bup", "acm"} <= set(ilks)


@pytest.mark.parametrize("knob", builders_v2.NEGATIVE)
def test_the_v2_negative_matrix_attributes_the_exact_code(knob, tmp_path):
    stream, facts = builders_v2.KNOBS[knob](tmp_path)

    with pytest.raises(BakoboError) as caught, ingest.ingest(stream, _claimed(facts)):
        pass

    assert caught.value.code == facts["expected_code"]


def test_a_v1_stream_carrying_v2_frames_is_refused_as_a_format_fault(tmp_path):
    """The reverse of the ``mixed_versions`` knob: no v2 genus counter up front, so the stream
    is read as v1 and the appended v2 frames cannot be."""
    v1 = builders_v2.builders.base(tmp_path / "v1")
    v2 = builders_v2.base(tmp_path / "v2")

    mixed = v1.stream + v2.stream[len(builders_v2.GENUS) :]
    with pytest.raises(BakoboError) as caught, ingest.ingest(mixed, _claimed(v1.facts)):
        pass

    assert caught.value.code == "e.input.format.stream.f"


def test_a_v2_stream_whose_final_frame_carries_no_attachment_still_walks(tmp_path):
    """keripy's extractor cannot finish an attachment-less final frame. We never emit one
    (the bup goes last), but another producer may, and a valid stream must not be refused for
    its ordering."""
    stream, facts = builders_v2.base(tmp_path)
    walked = ingest.walk(stream)
    acdc = next(frame for frame in walked.frames if frame.ilk == "acm")
    reordered = stream.replace(acdc.serder.raw, b"") + acdc.serder.raw

    with ingest.ingest(reordered, _claimed(facts)) as verified:
        assert verified.acdc.said == facts["acdc_said"]


def test_the_v2_walk_records_each_registry_frame_under_its_registry(tmp_path):
    stream, facts = builders_v2.base(tmp_path)

    walked = ingest.walk(stream)
    by_ilk = {frame.ilk: frame for frame in walked.frames if frame.ilk in ("rip", "bup", "acm")}

    assert by_ilk["rip"].principal == facts["regk"]
    assert by_ilk["bup"].principal == facts["regk"]
    assert by_ilk["acm"].principal == facts["aid"]
    assert by_ilk["acm"].regid == facts["regk"]
    assert by_ilk["rip"].is_tel and by_ilk["bup"].is_tel and not by_ilk["acm"].is_tel
    assert by_ilk["acm"].is_acdc and not by_ilk["rip"].is_acdc
    assert len(by_ilk["bup"].disclosures) == 1


def test_verified_state_carries_each_vetted_registry_with_its_disclosures(tmp_path):
    """What emission re-derives keri.cesr from: keripy's verdict on the chain, and every
    update's disclosure, already checked against the BLID it commits to."""
    stream, facts = builders_v2.revoked(tmp_path)
    claimed = _claimed(facts)

    walked = ingest.walk(stream)
    with ingest.open_scratch(walked.version) as scratch:
        scratch.load(stream)
        ingest.audit(scratch, claimed, walked)
        registry = scratch.registries[facts["regk"]]

    assert registry.record.state == "revoked"
    assert [b.state for b in registry.blinders] == ["issued", "revoked"]
    assert [u.said for u in registry.updates] == [f.said for f in walked.frames if f.ilk == "bup"]


def test_a_verified_v2_publication_exposes_its_registries(tmp_path):
    stream, facts = builders_v2.base(tmp_path)

    with ingest.ingest(stream, _claimed(facts)) as verified:
        assert set(verified.registries) == {facts["regk"]}
        assert verified.registries[facts["regk"]].record.state == "issued"


def test_the_v2_anchor_index_follows_keripys_digest_only_matching():
    """keripy's v2 verifier matches an anchor by digest alone (regeventing.sealDigests). A bare
    SAID or a {d} seal could anchor any registry's event; a seal naming an identifier counts for
    that identifier only; anything that is not a string digest is not a seal at all."""
    index = ingest._anchor_index(
        [
            ["Ebare"],
            [{"d": "Edigest-only"}],
            [{"i": "Ereg", "s": "1", "d": "Enamed"}],
            [{"i": "Eother", "d": "Eelsewhere"}],
            [{"i": 7, "d": "Enot-an-identifier"}],
            [{"i": "Ereg", "d": []}],
        ],
        ingest.V2,
    )

    assert index.for_log("Ereg") == {"Ebare", "Edigest-only", "Enamed"}
    assert index.for_log("Eother") == {"Ebare", "Edigest-only", "Eelsewhere"}
    assert "Enot-an-identifier" not in index.for_log("Ereg")
