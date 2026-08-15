"""The pinned designated-aliases schema, and the fail-closed load that proves it is the one.

didwebs recognizes exactly one ACDC schema — the Designated Aliases Public Attestation, SAID
``EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5`` (docs/design.md, authorization
post-conditions). The schema ships as a package resource rather than being fetched, and its
SAID is **recomputed from the resource's own bytes at every load** and compared against the
pinned constant. A resource that has been corrupted, swapped, or hand-edited therefore fails
the load instead of quietly redefining what a designated-aliases credential is (org principle
8, fail closed). Because keripy's ``Schemer`` derives the SAID from the schema body, a tampered
``$id`` cannot smuggle a mutated body past this check — only a body whose content hashes to the
pinned SAID passes.

The rules block is bundled alongside the schema because the schema's ``required`` list includes
``r``: a designated-aliases ACDC is not schema-valid without one, and
:func:`didwebs.assemble.issue_aliases` takes no rules parameter.

Attribution: the resource JSON and the load/pin pattern are adapted from the GLEIF
did:webs-resolver reference implementation (``dws/core/schemaing.py``,
``src/dws/resources/designated-aliases-public-schema.json``,
``tests/schema/rules/desig-aliases-public-schema-rules.json``; GLEIF-IT/did-webs-resolver,
Apache-2.0). Adaptations: SAID verification is unconditional and raises a didwebs error code
rather than ``kering.ConfigurationError``, and the verification is exposed separately from the
resource read so it can be exercised against arbitrary content.
"""

from __future__ import annotations

import json
from importlib import resources

from keri import kering
from keri.app import habbing
from keri.core import scheming

from didwebs import errors

#: SAID of the Designated Aliases Public Attestation schema. Pinned, never negotiated.
DES_ALIASES_SCHEMA_SAID = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5"

#: Package subdirectory holding the bundled JSON resources.
RESOURCE_DIR = "schemas"

SCHEMA_RESOURCE = "designated-aliases-public-schema.json"
RULES_RESOURCE = "desig-aliases-public-schema-rules.json"


def _read_resource(name: str) -> dict:
    """Parse a bundled JSON resource by file name."""
    path = resources.files("didwebs").joinpath(RESOURCE_DIR, name)
    return json.loads(path.read_text(encoding="utf-8"))


def read_designated_aliases_schema() -> dict:
    """Return the bundled schema as a dict, with no integrity check.

    Unverified on purpose: :func:`load_designated_aliases_schema` is the checked entry point,
    and separating the two is what lets the check be tested against mutated content.
    """
    return _read_resource(SCHEMA_RESOURCE)


def read_designated_aliases_rules() -> dict:
    """Return the bundled designated-aliases rules block as a dict."""
    return _read_resource(RULES_RESOURCE)


def verified_schemer(sed: dict) -> scheming.Schemer:
    """Return a ``Schemer`` over ``sed``, refusing anything but the pinned schema.

    Raises:
        BakoboError: ``e.self.unknown.f`` when the recomputed SAID is not the pinned one. That
            code declares no arguments, so the two SAIDs ride on a chained
            ``kering.ConfigurationError`` cause rather than in the rendered detail — the code
            is the contract, the cause is the diagnostic.
    """
    schemer = scheming.Schemer(sed=sed)
    if schemer.said != DES_ALIASES_SCHEMA_SAID:
        cause = kering.ConfigurationError(
            f"The bundled designated-aliases schema hashes to {schemer.said}, not the pinned "
            f"{DES_ALIASES_SCHEMA_SAID}; the resource has been altered."
        )
        raise errors.UNKNOWN_FAILURE() from cause
    return schemer


def load_designated_aliases_schema() -> scheming.Schemer:
    """Load and verify the bundled designated-aliases schema."""
    return verified_schemer(read_designated_aliases_schema())


def pin_designated_aliases_schema(hby: habbing.Habery) -> scheming.Schemer:
    """Make the pinned schema resolvable inside ``hby``, so ACDCs can be created against it.

    keripy resolves a credential's schema through two places, and credential creation needs
    both: the Habery's schema table (``hby.db.schema``) and the ``CacheResolver`` the credential
    verifier consults. Idempotent — an already-pinned schema is returned as is.
    """
    cache = scheming.CacheResolver(db=hby.db)
    schemer = hby.db.schema.get(keys=(DES_ALIASES_SCHEMA_SAID,))
    if schemer is None:
        schemer = load_designated_aliases_schema()
        hby.db.schema.pin(schemer.said, schemer)
    cache.add(schemer.said, schemer.raw)
    return schemer
