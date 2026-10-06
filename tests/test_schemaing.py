"""Tests for didwebs.schemaing — the pinned designated-aliases schema.

The contract under test is *fail closed on the bundled resource*: the SAID is recomputed from
the resource's own content at every load and compared against the constant pinned in
docs/design.md, so a corrupted, swapped, or hand-edited resource is refused rather than used.
"""

from __future__ import annotations

import copy
import json

import keri_api
import pytest
from bakobo.errors import BakoboError
from keri.core import scheming
from keri.kering import ValidationError

from didwebs import schemaing

PINNED_SAID = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5"


def test_the_pinned_said_constant_is_the_one_from_the_design_doc():
    assert schemaing.DES_ALIASES_SCHEMA_SAID == PINNED_SAID


def test_the_bundled_schema_resource_parses_as_json_and_self_identifies_with_the_pinned_said():
    sed = schemaing.read_designated_aliases_schema()
    assert isinstance(sed, dict)
    assert sed["$id"] == PINNED_SAID
    assert sed["credentialType"] == "DesignatedAliasesPublicAttestation"


def test_load_returns_a_schemer_whose_said_is_the_pinned_said():
    schemer = schemaing.load_designated_aliases_schema()
    assert isinstance(schemer, scheming.Schemer)
    assert schemer.said == PINNED_SAID


def test_the_said_is_recomputed_from_content_not_read_out_of_the_id_field():
    """Blanking `$id` must not change the outcome: the SAID comes from the body."""
    sed = schemaing.read_designated_aliases_schema()
    sed["$id"] = ""
    assert schemaing.verified_schemer(sed).said == PINNED_SAID


def test_a_one_byte_mutation_of_the_schema_body_is_refused(monkeypatch):
    """Oracle 3.5: mutate one byte of the loaded schema, schemaing refuses."""
    sed = schemaing.read_designated_aliases_schema()
    title = sed["title"]
    sed["title"] = title[:-1] + chr(ord(title[-1]) + 1)  # exactly one byte differs

    monkeypatch.setattr(schemaing, "read_designated_aliases_schema", lambda: sed)
    with pytest.raises(BakoboError) as excinfo:
        schemaing.load_designated_aliases_schema()
    assert excinfo.value.code == "e.self.corrupt.schema.f"


def test_the_refusal_names_the_computed_and_expected_saids():
    """The rendered detail carries both SAIDs through the code's declared args."""
    sed = schemaing.read_designated_aliases_schema()
    sed["description"] = "tampered"
    with pytest.raises(BakoboError) as excinfo:
        schemaing.verified_schemer(sed)
    rendered = str(excinfo.value)
    assert PINNED_SAID in rendered
    assert scheming.Schemer(sed=copy.deepcopy(sed)).said in rendered


def test_the_bundled_rules_resource_carries_the_four_required_clauses():
    rules = schemaing.read_designated_aliases_rules()
    assert set(rules) == {
        "d",
        "aliasDesignation",
        "usageDisclaimer",
        "issuanceDisclaimer",
        "termsOfUse",
    }
    assert rules["aliasDesignation"]["l"].startswith("The issuer of this ACDC designates")


def test_the_bundled_rules_satisfy_the_bundled_schemas_rules_block():
    """The rules block the library ships must validate against the schema it ships."""
    sed = schemaing.read_designated_aliases_schema()
    required = sed["properties"]["r"]["oneOf"][1]["required"]
    assert set(required) <= set(schemaing.read_designated_aliases_rules())


def test_pinning_puts_the_schema_where_credential_creation_will_find_it(tmp_path):
    with keri_api.scratch("pin", tmp_path) as (hby, _regery):
        schemer = schemaing.pin_designated_aliases_schema(hby)
        assert schemer.said == PINNED_SAID
        assert hby.db.schema.get(keys=(PINNED_SAID,)).said == PINNED_SAID
        assert scheming.CacheResolver(db=hby.db).resolve(PINNED_SAID) == schemer.raw


def test_pinning_is_idempotent_and_reuses_the_already_pinned_schemer(tmp_path):
    with keri_api.scratch("pin2", tmp_path) as (hby, _regery):
        first = schemaing.pin_designated_aliases_schema(hby)
        second = schemaing.pin_designated_aliases_schema(hby)
        assert first.said == second.said == PINNED_SAID
        assert scheming.CacheResolver(db=hby.db).resolve(PINNED_SAID) == first.raw


def test_the_schema_resource_is_shipped_inside_the_package_not_read_from_the_repo(tmp_path):
    """A bundled resource, per the brief — importable from the installed package."""
    from importlib import resources

    path = resources.files("didwebs").joinpath("schemas", schemaing.SCHEMA_RESOURCE)
    assert json.loads(path.read_text(encoding="utf-8"))["$id"] == PINNED_SAID


# ----------------------------------------------------- the proposed v2 schema (35yl884k)

PINNED_V2_SAID = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA"


def test_the_v2_schema_is_pinned_to_its_said():
    assert schemaing.DES_ALIASES_SCHEMA_V2_SAID == PINNED_V2_SAID
    assert schemaing.load_designated_aliases_schema_v2().said == PINNED_V2_SAID


def test_the_v2_schema_differs_from_v1_only_where_a_v2_acdc_does():
    """Decision 35yl884k's derivation, held as an oracle rather than as prose: ``ri`` is renamed
    ``rd`` in place, ``t`` (required, ``acm``) is admitted, properties take v2 field order,
    ``version`` is 2.0.0, and nothing else moves. There is no ``u``: a public attestation."""
    v1 = schemaing.read_designated_aliases_schema()
    v2 = schemaing.read_designated_aliases_schema_v2()

    assert list(v2["properties"]) == ["v", "t", "d", "i", "rd", "s", "a", "r"]
    assert v2["properties"]["rd"] == v1["properties"]["ri"]
    assert v2["properties"]["t"]["const"] == "acm"
    assert "u" not in v2["properties"]
    assert v2["required"] == ["v", "t", "d", "i", "rd", "s", "a", "r"]
    assert v2["version"] == "2.0.0"
    for field in ("v", "d", "i", "s", "a", "r"):
        assert v2["properties"][field] == v1["properties"][field]
    unchanged = set(v1) - {"$id", "version", "properties", "required"}
    assert {key: v2[key] for key in unchanged} == {key: v1[key] for key in unchanged}


def test_a_mutated_v2_schema_is_refused_naming_the_v2_pin(monkeypatch):
    sed = schemaing.read_designated_aliases_schema_v2()
    sed["description"] = "tampered"
    monkeypatch.setattr(schemaing, "read_designated_aliases_schema_v2", lambda: sed)

    with pytest.raises(BakoboError) as excinfo:
        schemaing.load_designated_aliases_schema_v2()

    assert excinfo.value.code == "e.self.corrupt.schema.f"
    assert PINNED_V2_SAID in str(excinfo.value)


def test_the_v1_schema_does_not_validate_a_v2_shaped_body_and_the_v2_one_does():
    """Why a second schema exists at all: v1 requires ``ri`` and forbids ``u``/``t``."""
    body = {
        "v": "ACDCCAACAAJSONAAAA.", "t": "acm", "d": "", "i": "E" * 44,
        "rd": "E" * 44, "s": PINNED_V2_SAID,
        "a": {"d": "", "dt": "2026-10-06T00:00:00.000000+00:00", "ids": []},
        "r": schemaing.read_designated_aliases_rules(),
    }
    raw = json.dumps(body).encode()

    with pytest.raises(ValidationError):  # keripy's verify raises rather than returning False
        schemaing.load_designated_aliases_schema().verify(raw)
    assert schemaing.load_designated_aliases_schema_v2().verify(raw)


def test_the_v2_schema_refuses_any_top_level_u():
    """A public attestation (35yl884k): an empty u is a metadata ACDC, a non-empty one private."""
    schemer = schemaing.load_designated_aliases_schema_v2()
    for u in ("", "0AAxyzNonceNonceNonceNon"):
        body = {
            "v": "ACDCCAACAAJSONAAAA.", "t": "acm", "d": "", "u": u, "i": "E" * 44,
            "rd": "E" * 44, "s": PINNED_V2_SAID,
            "a": {"d": "", "dt": "2026-10-06T00:00:00.000000+00:00", "ids": []},
            "r": schemaing.read_designated_aliases_rules(),
        }
        with pytest.raises(ValidationError):
            schemer.verify(json.dumps(body).encode())
