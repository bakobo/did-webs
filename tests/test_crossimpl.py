"""The cross-implementation oracle (design.md, ``Test strategy and oracles``, oracle 1; brief
F): artifacts ``didwebs`` publishes are ingested by the GLEIF reference resolver in its own
Python 3.13 venv, and its derived document agrees with ours on the documented field-level
intersection (``tests/crossimpl/compare.py``).

**Two independent things are tested here.** The comparator itself (``test_compare_*``) needs no
resolver venv at all -- it is exercised against synthetic stub documents, so its own correctness
is provable without a subprocess. The integration tests (``test_intersection_agreement``,
``test_delegated_self_expiry``) drive the real resolver in its own venv.

**Skip vs. fail** (brief F §2.5, ledger #22): locally, a missing resolver venv makes the
integration tests SKIP with the provisioning command named in the reason. In CI,
``DIDWEBS_CROSSIMPL=required`` turns that same missing-venv condition into a FAIL -- an oracle
that can silently stop running is exactly what ledger #22 is about. The comparator unit tests
carry no such guard; they always run, in every job, because they need nothing external.
"""

from __future__ import annotations

import json
import os

import builders
import pytest
from crossimpl import compare, resolver_venv, runner

from didwebs import assemble, document, ingest
from didwebs.did import parse as parse_did

#: The env var CI's `crossimpl` job sets (brief F §2.5/§2.6). Any other value, including unset,
#: means "best effort" -- skip rather than fail when the venv is missing.
REQUIRED_ENV = "DIDWEBS_CROSSIMPL"
REQUIRED_VALUE = "required"

#: Fixtures under this oracle (brief F §2.4). `delegated` is deliberately not here -- it drives
#: `test_delegated_self_expiry` only, never the intersection comparison.
ORACLE_FIXTURES = ("base", "endpoints", "deactivated")


def _venv_guard() -> None:
    """Skip, or in CI-required mode fail, when the resolver venv is not provisioned."""
    if resolver_venv.available():
        return
    reason = (
        f"resolver venv not provisioned at {resolver_venv.VENV_DIR} -- run "
        "'uv run python tests/crossimpl/resolver_venv.py provision' first"
    )
    if os.environ.get(REQUIRED_ENV) == REQUIRED_VALUE:
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture
def venv_guard():
    """Applied explicitly (never autouse) so the comparator's own unit tests below -- which need
    no venv -- are never skipped or gated by its absence."""
    _venv_guard()


# --------------------------------------------------------------------- the comparator, alone


#: A minimal but complete "ours" document: single key, no services, both DID forms designated.
_STUB_SUBJECT = "did:webs:example.com:EBIYGXusPWSVouEsi1cwgbUnhcpXbfjqjWacUOgKJRlS"
_STUB_ALIAS_WEB = "did:web:example.com:EBIYGXusPWSVouEsi1cwgbUnhcpXbfjqjWacUOgKJRlS"
_STUB_ALIAS_KERI = "did:keri:EBIYGXusPWSVouEsi1cwgbUnhcpXbfjqjWacUOgKJRlS"


def _stub_method(x: str = "abcXYZ") -> dict:
    return {
        "id": "#DKey",
        "type": "JsonWebKey",
        "controller": _STUB_SUBJECT,
        "publicKeyJwk": {"kid": "DKey", "kty": "OKP", "crv": "Ed25519", "x": x},
    }


def _stub_ours() -> dict:
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": _STUB_SUBJECT,
        "controller": _STUB_SUBJECT,
        "verificationMethod": [_stub_method()],
        "authentication": ["#DKey"],
        "assertionMethod": ["#DKey"],
        "service": [],
        "alsoKnownAs": [_STUB_ALIAS_WEB, _STUB_ALIAS_KERI],
    }


def _stub_theirs(*, x: str = "abcXYZ") -> dict:
    return {
        "id": _STUB_SUBJECT,
        "verificationMethod": [_stub_method(x=x)],
        "service": [],
        "alsoKnownAs": [_STUB_ALIAS_WEB, _STUB_SUBJECT],
    }


def test_compare_agrees_on_matching_stub_documents():
    """Two documents that differ only in the fields design.md's oracle excludes (@context,
    authentication/assertionMethod, controller, the alsoKnownAs self-entry vs. did:keri) agree
    on the documented intersection."""
    result = compare.compare(_stub_ours(), _stub_theirs(), subject_did_webs=_STUB_SUBJECT)
    assert result.ok, result.render()
    assert "id" in result.agreements
    assert "verificationMethod[].publicKeyJwk{kid,x}" in result.agreements
    assert "alsoKnownAs (documented intersection)" in result.agreements


def test_compare_flags_a_genuine_key_material_mismatch():
    """A different JWK `x` on the reference's side -- not one of the documented exclusions --
    is a real disagreement the comparator must not paper over."""
    result = compare.compare(
        _stub_ours(), _stub_theirs(x="differentXYZ"), subject_did_webs=_STUB_SUBJECT
    )
    assert not result.ok
    fields = [mismatch.field for mismatch in result.mismatches]
    assert "verificationMethod[].publicKeyJwk{kid,x}" in fields


def test_compare_flags_an_id_mismatch():
    theirs = _stub_theirs()
    theirs["id"] = "did:webs:example.com:EDifferentAID"
    result = compare.compare(_stub_ours(), theirs, subject_did_webs=_STUB_SUBJECT)
    assert not result.ok
    assert any(mismatch.field == "id" for mismatch in result.mismatches)


def test_compare_records_documented_exclusions_visibly():
    """§3.5: the exclusion list prints, reasoned, in every run's rendered output -- not only
    when a mismatch forces the reader to look."""
    result = compare.compare(_stub_ours(), _stub_theirs(), subject_did_webs=_STUB_SUBJECT)
    assert result.exclusions == compare.DOCUMENTED_EXCLUSIONS
    rendered = result.render()
    for exclusion in compare.DOCUMENTED_EXCLUSIONS:
        assert exclusion.field in rendered
        assert exclusion.reason in rendered


# ------------------------------------------------------------------ the real resolver, driven


def _emit(fixture_stream: bytes, did) -> bytes:
    """Ingest a fixture stream with our own pipeline and re-emit it the way `didwebs publish`
    would -- the resolver only ever sees a re-derived artifact, never a fixture's raw bytes
    (constraint `embuup`)."""
    with ingest.ingest(fixture_stream, did) as verified:
        return document.derive_document(verified, did), assemble.emit_stream(verified)


@pytest.mark.parametrize("knob", ORACLE_FIXTURES)
def test_intersection_agreement(knob, tmp_path, venv_guard):
    """Oracle 1, end to end: our derived document and the reference's agree on the documented
    intersection, for every fixture design.md scopes this oracle to (brief F §2.4)."""
    stream, facts = builders.KNOBS[knob](tmp_path)
    did = parse_did(facts["did_webs"])

    ours, emitted = _emit(stream, did)

    report = runner.run(
        emitted, aid=facts["aid"], did=facts["did_webs"], tmp_path=tmp_path / "resolver"
    )
    assert report["verdict"] == "INGESTED", (
        f"the reference did not cleanly ingest the {knob!r} fixture: "
        f"{report.get('error') or report.get('did_doc_error')}\n"
        f"{report.get('traceback') or report.get('did_doc_traceback', '')}"
    )

    result = compare.compare(ours, report["did_doc"], subject_did_webs=facts["did_webs"])
    print(result.render())
    assert result.ok, result.render()


def test_delegated_self_expiry(tmp_path, venv_guard):
    """A regression sensor on the reference's delegated-stream ingestion (closed tick 4jke).

    The tick's premise -- that the reference's single escrow-drain pass cannot fully ingest a
    delegated AID's stream -- was FALSIFIED here (2026-08-15): Empirically, against the pinned resolver
    (0d4f2fd) and `builders.delegated`'s stream, `save_cesr`'s single ``processEscrows()`` pass
    resolves the delegation cleanly on the first try: ``aid_in_kevers`` is True, ``kever_sn``
    matches ours exactly, and ``generate_did_doc`` returns a document. No escrow round-trip is
    needed for *this* stream shape, because ``keri_api.kel_bytes``/``Hab.replay`` always emit a
    delegate's KEL with the delegator's anchoring events first -- nothing in the stream is
    actually out of order, so the out-of-order/partial-delegation escrow interplay
    ``didwebs.ingest.Scratch.load``'s docstring describes (and that motivated the tick) never
    triggers here.

    The craftsman closed the tick on this evidence: worker D's fixpoint-drain finding stands
    for OUR 2.0-dev6 ingest stack, but the 1.2.13 reference needs no such repair for streams
    we emit, and there is no upstream issue to draft. This test stays as the sensor: if the
    reference ever stops ingesting our delegated artifacts, it fails.
    """
    stream, facts = builders.delegated(tmp_path)
    did = parse_did(facts["did_webs"])

    _, emitted = _emit(stream, did)

    report = runner.run(
        emitted, aid=facts["aid"], did=facts["did_webs"], tmp_path=tmp_path / "resolver"
    )
    assert report["verdict"] == "INGESTED", (
        "the reference no longer cleanly ingests builders.delegated's stream -- this sensor "
        "exists to catch exactly that change. report:\n" + json.dumps(report, default=str)
    )
    assert report.get("aid_in_kevers") and report.get("kever_sn") == facts["kel_sn"], (
        "the reference's key state for the delegate no longer matches ours after ingest -- "
        "report:\n" + json.dumps(report, default=str)
    )


def test_the_resolver_subprocess_strands_no_keri_temp_directory(tmp_path, venv_guard):
    """keri 1.2.13 has the same leaf-only close as the estate pin, so the resolver subprocess
    leaves four `/tmp/keri_*` roots per keystore it opens. The runner owns their removal, the
    way `keri_api.scratch` and `ingest.Scratch` do on our side of the fence."""
    import glob

    stream, facts = builders.base(tmp_path)
    did = parse_did(facts["did_webs"])
    _, emitted = _emit(stream, did)

    before = set(glob.glob("/tmp/keri_*"))
    runner.run(emitted, aid=facts["aid"], did=facts["did_webs"], tmp_path=tmp_path / "resolver")
    assert set(glob.glob("/tmp/keri_*")) == before
