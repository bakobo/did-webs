"""Shared pytest fixtures for didwebs.

Attribution: the scratch-keystore and credential-issuance fixture shapes are adapted from the
GLEIF did:webs-resolver reference implementation (``tests/conftest.py``,
GLEIF-IT/did-webs-resolver, Apache-2.0). Adaptations: keripy 2.0.0-dev6 API, protocol v1 pinned
explicitly at every event-constructing call (constraint ``qbqfst``), keystores rooted in
pytest's ``tmp_path`` instead of the process-wide keripy temp directory, and fixed salts so
every AID a fixture produces is stable across runs.
"""

from __future__ import annotations

from dataclasses import dataclass

import keri_api
import pytest
from keri.app import habbing
from keri.vdr import credentialing
from keri_api import (
    CONTROLLER_SALT,
    DOMAIN,
    designated_ids,
    did_web,
    did_webs,
)

__all__ = ["CONTROLLER_SALT", "DOMAIN", "designated_ids", "did_web", "did_webs", "keystore"]


@dataclass(frozen=True)
class Keystore:
    """A scratch keystore: the Habery, its controller Hab, and a credential registry db."""

    hby: habbing.Habery
    hab: habbing.Hab
    regery: credentialing.Regery


@pytest.fixture
def keystore(tmp_path):
    """One v1-pinned transferable controller in a scratch keystore."""
    with keri_api.scratch("issuer", tmp_path, salt_raw=CONTROLLER_SALT) as (hby, regery):
        hab = keri_api.make_hab(hby, "issuer")
        yield Keystore(hby, hab, regery)
