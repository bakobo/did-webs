"""didwebs error registry — the codes themselves are the contract.

The gate below **introspects** ``didwebs.errors`` rather than restating it. An earlier version
listed seventeen codes by hand and drifted: ``e.rule.stream.third-party.f`` and
``e.self.corrupt.schema.f`` were minted, raised, and asserted elsewhere in the suite while this
file went on declaring that the registry held seventeen entries. A registry gate that has to be
edited by hand is a gate that stops being one.

So there are two halves. :data:`REGISTRY` is whatever ``didwebs.errors`` actually declares, found
by type. :data:`DESIGN_TABLE` is the set docs/design.md's reconciled table names, written out in
full because **identity is the contract**: a code's string, once shipped, never changes
(dev/standards/error-codes.md), so it is named here in the one place that would notice a rename.
The set equality between them is the gate, and every other test runs over the introspected set —
so a twentieth code is checked for its rendering, its retryability and its title the moment it is
declared, without anybody remembering to add it here.
"""

from __future__ import annotations

import inspect

import pytest
from bakobo.errors import BakoboError, ErrorCode

from didwebs import errors

#: Every :class:`ErrorCode` ``didwebs.errors`` declares, found by type at module scope — which is
#: also an assertion that they *are* module-scope literals, since nothing else would be found.
REGISTRY = {entry.code: entry for _, entry in vars(errors).items() if isinstance(entry, ErrorCode)}

#: The set docs/design.md's "Error codes" table names, verbatim. Sixteen rows, nineteen codes:
#: the table writes ``e.proof.stream.*.f`` once and names its four leaves in the same cell.
DESIGN_TABLE = frozenset(
    {
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
        "e.rule.stream.third-party.f",
        "e.feature.unsupported.key.alg.f",
        "e.feature.unsupported.threshold.f",
        "e.self.corrupt.schema.f",
        "e.self.unknown.f",
    }
)

_CODES = sorted(REGISTRY)
_WITH_ARGS = [code for code in _CODES if REGISTRY[code].args]


def values_for(entry: ErrorCode) -> dict:
    """A call satisfying ``entry``'s declared arguments, whatever they are.

    Synthesized from the declaration rather than written out per code, which is what lets the
    rendering tests below cover a code nobody has hand-listed here.
    """
    return {name: f"<{name}>" for name in entry.args}


# ------------------------------------------------------------------------------- the gate


def test_the_registry_declares_exactly_the_codes_the_design_table_names():
    """The gate, in both directions.

    A twentieth code minted in ``didwebs/errors.py`` and not added to :data:`DESIGN_TABLE` shows
    up in ``REGISTRY`` and fails this equality — because the set is *found*, not restated, so a
    new declaration cannot be invisible to it. A code named here and deleted from the module
    fails it too, which is what stops a shipped code being quietly retired. Either way the fix is
    the same and it is the right one: reconcile ``docs/design.md``'s table, then this set.
    """
    assert set(REGISTRY) == DESIGN_TABLE
    assert len(DESIGN_TABLE) == 19


def test_no_two_names_in_the_module_declare_the_same_code():
    """``REGISTRY`` is keyed by code, so a duplicate would hide inside it. Codes are globally
    unique across Bakobo; two names for one condition is a merge accident, not an alias."""
    declared = [entry for entry in vars(errors).values() if isinstance(entry, ErrorCode)]

    assert len(declared) == len(REGISTRY)


def test_the_module_docstring_states_how_many_codes_it_declares():
    """The prose and the registry are checked against each other, because the prose is what a
    reader trusts. This is the drift that happened: the docstring said seventeen for a module
    that declared nineteen."""
    doc = inspect.getdoc(errors)

    assert f"The {len(REGISTRY)} codes below" in doc


# --------------------------------------------------------- every code, found by introspection


@pytest.mark.parametrize("code", _CODES)
def test_each_entry_is_an_errorcode_carrying_its_own_exact_code_string(code):
    assert isinstance(REGISTRY[code], ErrorCode)
    assert REGISTRY[code].code == code


@pytest.mark.parametrize("code", _CODES)
def test_each_entry_raises_a_bakoboerror_carrying_its_code_and_a_rendered_detail(code):
    entry = REGISTRY[code]
    values = values_for(entry)

    err = entry(**values)

    assert isinstance(err, BakoboError)
    assert err.code == code
    assert err.detail
    for value in values.values():
        assert value in err.detail  # every declared argument reaches the prose
    assert err.retryable is False  # every code in this registry is final ("f")


@pytest.mark.parametrize("code", _CODES)
def test_each_title_is_a_complete_sentence(code):
    """The house voice: a title is a plain sentence a person can read, never a fragment and
    never "something went wrong" (dev/standards/error-handling.md)."""
    title = REGISTRY[code].title

    assert title == title.strip()
    assert title[0].isupper()
    assert title.endswith(".")


@pytest.mark.parametrize("code", _WITH_ARGS)
def test_each_entry_refuses_a_call_missing_its_declared_args(code):
    """A code's ``args`` signature is part of its contract, so an under-specified raise is a
    programming error rather than a half-rendered message. Parametrized over the codes that
    declare arguments — the one that declares none has nothing to omit."""
    with pytest.raises(ValueError):
        REGISTRY[code]()


def test_every_code_is_final_never_retryable():
    """Nothing didwebs refuses can be fixed by trying it again with the same bytes: the whole
    registry is phase-1 verdicts on a submitted stream."""
    assert all(code.endswith(".f") for code in REGISTRY)
