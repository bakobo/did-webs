"""The temp-store containment contract (constraint ``l7ws7hdt``, tick ``~4nxx``).

keripy makes every temporary store with ``mkdtemp`` under its class's ``TempHeadDir`` and, on
close, removes only the leaf of the path inside it — so whoever opened the store owns removing
the root. The bug this module guards is not the removal; it is how a root gets *identified*.

Until 2026-09-15 five oracles in this suite answered that question by globbing ``/tmp/keri_*``
and comparing the set before and after an operation. That namespace belongs to keripy, not to
this repo, and sixteen bakobo repos reach it through the same hardcoded head. Measured on this
box: one concurrent keripy process churning ``/tmp/keri_*`` turns twelve green tests red, every
one of them on the glob rather than on the behavior under test.

So the suite repoints the head (see ``conftest.contained_temp_head``) and every root is derived
from the store's own ``TempHeadDir``. These tests assert the two halves of that: the head really
is repointed while tests run, and a store outside it is refused rather than walked.
"""

from __future__ import annotations

import pathlib

import keri_api
import pytest
from hio.base.filing import Filer
from keri.db.dbing import LMDBer

from didwebs import ingest


class _Store:
    """The two attributes a root walk reads off a keripy store, and nothing else."""

    def __init__(self, head, path):
        self.TempHeadDir = str(head)
        self.path = str(path)


def test_the_suite_repoints_keripys_temp_head(contained_temp_head):
    """The containment is in force for every test, which is what makes the oracles sound.

    Both classes are asserted because ``LMDBer`` overrides ``TempHeadDir`` rather than
    inheriting it, so patching the base class alone would leave every ``keri_lmdb_*`` store
    landing in the shared namespace while the ``keri_ks_``/``keri_cf_`` ones moved.
    """
    assert Filer.TempHeadDir == str(contained_temp_head)
    assert LMDBer.TempHeadDir == str(contained_temp_head)
    assert contained_temp_head.is_dir()


def test_the_contained_head_is_not_the_shared_namespace(contained_temp_head):
    """A head that resolved back to the system temp directory would pass every other test here
    while restoring the exact unsoundness this constraint removes."""
    assert contained_temp_head != pathlib.Path("/tmp")
    assert pathlib.Path("/tmp") in contained_temp_head.parents


@pytest.mark.parametrize("walk", [keri_api._temp_root, ingest._temp_root])
def test_a_root_walk_returns_the_child_of_the_head(walk, tmp_path):
    """The root is the *first* directory under the head — the one mkdtemp made — however deep
    the store's own path runs below it."""
    head = tmp_path / "head"
    root = head / "keri_lmdb_abc_test"
    store = _Store(head, root / "keri" / "db" / "didwebs-ingest")
    assert walk(store) == str(root)


@pytest.mark.parametrize("walk", [keri_api._temp_root, ingest._temp_root])
def test_a_root_walk_accepts_a_store_sitting_directly_in_the_head(walk, tmp_path):
    """The degenerate depth: the store *is* the mkdtemp directory."""
    head = tmp_path / "head"
    root = head / "keri_cf_abc_test"
    assert walk(_Store(head, root)) == str(root)


@pytest.mark.parametrize("walk", [keri_api._temp_root, ingest._temp_root])
def test_a_root_walk_refuses_a_store_outside_its_head(walk, tmp_path):
    """The failure this replaces is the dangerous one: a walk that ascends past the head and
    returns some ancestor for removal. Both walks previously climbed to a child of ``/tmp``
    whatever they were handed, so a store under ``/tmp/pytest-of-<user>/...`` would have
    yielded the whole pytest temp tree as the thing to delete."""
    head = tmp_path / "head"
    head.mkdir()
    stray = tmp_path / "elsewhere" / "keri_lmdb_abc_test" / "keri" / "db"
    with pytest.raises(RuntimeError, match="outside"):
        walk(_Store(head, stray))


@pytest.mark.parametrize("walk", [keri_api._temp_root, ingest._temp_root])
def test_a_root_walk_refuses_the_head_itself(walk, tmp_path):
    """A store whose path *is* the head has no mkdtemp root, and returning the head would hand
    a caller the container every other run's stores live in."""
    head = tmp_path / "head"
    head.mkdir()
    with pytest.raises(RuntimeError, match="outside"):
        walk(_Store(head, head))


def test_temp_stores_reads_only_the_contained_head(contained_temp_head):
    """The replacement for ``glob('/tmp/keri_*')``: a set no other process can add to."""
    planted = contained_temp_head / "keri_lmdb_planted_test"
    planted.mkdir()
    try:
        assert str(planted) in keri_api.temp_stores()
        assert all(
            str(contained_temp_head) == str(pathlib.Path(entry).parent)
            for entry in keri_api.temp_stores()
        )
    finally:
        planted.rmdir()


def test_building_a_fixture_lands_its_stores_in_the_contained_head(contained_temp_head, tmp_path):
    """End to end: the containment is not merely configured, it is where keripy actually writes.

    This is the test that would catch a keripy upgrade introducing a store class with its own
    ``TempHeadDir``, which the two assertions above cannot see.
    """
    with keri_api.scratch("contained", tmp_path) as (hby, regery):
        for store in (hby.ks, hby.db, hby.cf, regery.reger):
            assert contained_temp_head in pathlib.Path(store.path).parents
