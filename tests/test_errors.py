"""didwebs error registry — 17 module-scope ErrorCode literals, verbatim from docs/design.md's
reconciled table (rev 2, 2026-08-14). Identity is the contract: every test below asserts the
exact code string, per the brief's edge default (no other error codes minted in this brief)."""

from __future__ import annotations

import pytest
from bakobo.errors import BakoboError, ErrorCode

from didwebs import errors

CODES = [
    (errors.DID_INVALID, "e.input.format.did.f", {"did": "did:webs:example.com:EAbc"}),
    (errors.STREAM_UNWALKABLE, "e.input.format.stream.f", {"did": "did:webs:example.com:EAbc"}),
    (
        errors.SERIALIZATION_UNSUPPORTED,
        "e.feature.unsupported.serialization.f",
        {"did": "did:webs:example.com:EAbc", "kind": "CBOR"},
    ),
    (
        errors.ALIAS_ACDC_MISSING,
        "e.input.missing.alias-acdc.f",
        {"did": "did:webs:example.com:EAbc"},
    ),
    (
        errors.DELEGATOR_MISSING,
        "e.input.missing.delegator.f",
        {"aid": "EAbc", "delegator": "EDef"},
    ),
    (errors.STREAM_SIG_INVALID, "e.proof.stream.sig.f", {"frame": "Esig123"}),
    (errors.STREAM_SEAL_INVALID, "e.proof.stream.seal.f", {"frame": "Eseal123"}),
    (errors.STREAM_ANCHOR_INVALID, "e.proof.stream.anchor.f", {"frame": "Eanchor123"}),
    (errors.STREAM_FRAME_REJECTED, "e.proof.stream.frame.f", {"frame": "Eframe123"}),
    (errors.KEL_FORKED, "e.state.conflict.kel.f", {"aid": "EAbc"}),
    (errors.ALIAS_ACDC_REVOKED, "e.state.revoked.alias-acdc.f", {"said": "Esaid123"}),
    (
        errors.ALIAS_GRANT_MISSING,
        "e.grant.missing.alias.f",
        {"did": "did:webs:example.com:EAbc"},
    ),
    (
        errors.ALIAS_GRANT_SCOPE,
        "e.grant.scope.alias.f",
        {"did": "did:webs:example.com:EAbc"},
    ),
    (
        errors.ALIAS_AID_MISMATCH,
        "e.rule.alias.aid.mismatch.f",
        {"alias": "did:keri:EOther", "aid": "EAbc"},
    ),
    (
        errors.KEY_ALG_UNSUPPORTED,
        "e.feature.unsupported.key.alg.f",
        {"aid": "EAbc", "alg": "secp256k1"},
    ),
    (errors.THRESHOLD_UNSUPPORTED, "e.feature.unsupported.threshold.f", {"aid": "EAbc"}),
    (errors.UNKNOWN_FAILURE, "e.self.unknown.f", {}),
]

_IDS = [code for _, code, _ in CODES]


def test_registry_declares_exactly_the_17_codes_from_the_design_docs_reconciled_table():
    codes = {code for _, code, _ in CODES}
    assert len(codes) == 17
    assert codes == {
        "e.input.format.did.f",
        "e.input.format.stream.f",
        "e.feature.unsupported.serialization.f",
        "e.input.missing.alias-acdc.f",
        "e.input.missing.delegator.f",
        "e.proof.stream.sig.f",
        "e.proof.stream.seal.f",
        "e.proof.stream.anchor.f",
        "e.proof.stream.frame.f",
        "e.state.conflict.kel.f",
        "e.state.revoked.alias-acdc.f",
        "e.grant.missing.alias.f",
        "e.grant.scope.alias.f",
        "e.rule.alias.aid.mismatch.f",
        "e.feature.unsupported.key.alg.f",
        "e.feature.unsupported.threshold.f",
        "e.self.unknown.f",
    }


@pytest.mark.parametrize("entry,code,kwargs", CODES, ids=_IDS)
def test_each_entry_is_an_errorcode_with_the_exact_code_string(entry, code, kwargs):
    assert isinstance(entry, ErrorCode)
    assert entry.code == code


@pytest.mark.parametrize("entry,code,kwargs", CODES, ids=_IDS)
def test_each_entry_raises_a_bakoboerror_carrying_its_code_and_a_rendered_detail(
    entry, code, kwargs
):
    err = entry(**kwargs)
    assert isinstance(err, BakoboError)
    assert err.code == code
    assert err.detail
    assert err.retryable is False  # every code in this registry is final ("f")


@pytest.mark.parametrize("entry,code,kwargs", CODES, ids=_IDS)
def test_each_entry_refuses_a_call_missing_its_declared_args(entry, code, kwargs):
    if not kwargs:
        pytest.skip("no args declared for this code")
    with pytest.raises(ValueError):
        entry()


def test_all_codes_are_final_never_retryable():
    for _, code, _ in CODES:
        assert code.endswith(".f")
