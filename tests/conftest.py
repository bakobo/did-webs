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
from hio.base.filing import Filer
from keri.app import habbing
from keri.db.dbing import LMDBer
from keri.vdr import credentialing
from keri_api import (
    CONTROLLER_SALT,
    DOMAIN,
    designated_ids,
    did_web,
    did_webs,
)

__all__ = [
    "CONTROLLER_SALT",
    "DOMAIN",
    "contained_temp_head",
    "designated_ids",
    "did_web",
    "did_webs",
    "keystore",
]


@pytest.fixture(scope="session", autouse=True)
def contained_temp_head(tmp_path_factory):
    """Repoint keripy's temporary-store head at a directory only this run writes into.

    Constraint ``l7ws7hdt``. ``Filer.remake`` passes ``dir=self.TempHeadDir`` to ``mkdtemp``,
    and on Linux that attribute resolves to the system temp directory at import time — a
    namespace every keripy-based repo on the machine shares. Repointing it per run is what lets
    a leak oracle be a statement about *this* process instead of about ``/tmp``.

    The attribute is read at call time, so patching the classes after import is enough. Both
    classes are patched: ``LMDBer`` overrides ``TempHeadDir`` rather than inheriting it, so the
    base-class patch alone would move the keystore and config stores and leave every LMDB
    database behind.

    Autouse and session-scoped deliberately. A test that had to opt in would be a test that
    could forget, and the containment has to be in force before the first store is opened.
    """
    head = tmp_path_factory.mktemp("keri-temp-head", numbered=False)
    originals = {Filer: Filer.TempHeadDir, LMDBer: LMDBer.TempHeadDir}
    for owner in originals:
        owner.TempHeadDir = str(head)
    keri_api.TEMP_HEAD = head
    try:
        yield head
    finally:
        keri_api.TEMP_HEAD = None
        for owner, original in originals.items():
            owner.TempHeadDir = original


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
