"""Tests for didwebs.schemaing — the pinned designated-aliases schema.

The contract under test is *fail closed on the bundled resource*: the SAID is recomputed from
the resource's own content at every load and compared against the constant pinned in
docs/design.md, so a corrupted, swapped, or hand-edited resource is refused rather than used.
"""

from __future__ import annotations

import copy
import json

import pytest
from bakobo.errors import BakoboError
from keri.app.habbing import openHby
from keri.core import scheming

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
    assert excinfo.value.code == "e.self.unknown.f"


def test_the_refusal_names_the_computed_and_expected_saids():
    """`e.self.unknown.f` declares no args, so the diagnostic rides on the chained cause."""
    sed = schemaing.read_designated_aliases_schema()
    sed["description"] = "tampered"
    with pytest.raises(BakoboError) as excinfo:
        schemaing.verified_schemer(sed)
    cause = str(excinfo.value.__cause__)
    assert PINNED_SAID in cause
    assert scheming.Schemer(sed=copy.deepcopy(sed)).said in cause


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
    with openHby(name="pin", temp=True, headDirPath=str(tmp_path)) as hby:
        schemer = schemaing.pin_designated_aliases_schema(hby)
        assert schemer.said == PINNED_SAID
        assert hby.db.schema.get(keys=(PINNED_SAID,)).said == PINNED_SAID
        assert scheming.CacheResolver(db=hby.db).resolve(PINNED_SAID) == schemer.raw


def test_pinning_is_idempotent_and_reuses_the_already_pinned_schemer(tmp_path):
    with openHby(name="pin2", temp=True, headDirPath=str(tmp_path)) as hby:
        first = schemaing.pin_designated_aliases_schema(hby)
        second = schemaing.pin_designated_aliases_schema(hby)
        assert first.said == second.said == PINNED_SAID
        assert scheming.CacheResolver(db=hby.db).resolve(PINNED_SAID) == first.raw


def test_the_schema_resource_is_shipped_inside_the_package_not_read_from_the_repo(tmp_path):
    """A bundled resource, per the brief — importable from the installed package."""
    from importlib import resources

    path = resources.files("didwebs").joinpath("schemas", schemaing.SCHEMA_RESOURCE)
    assert json.loads(path.read_text(encoding="utf-8"))["$id"] == PINNED_SAID
