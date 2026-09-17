"""didwebs.publish — the two hosted artifacts, written where the DID says they live.

The location is the spec's (`### Target System(s)`: the method-specific identifier's colons
become path separators, and the AID is the last segment), and the writing discipline is the
design's: write a temporary file beside the target and rename it, so a reader never sees a
half-written artifact and an update is the same operation as a first publication.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from bakobo.errors import BakoboError

from didwebs import did as did_module
from didwebs import publish

DID = "did:webs:labs.bakobo.com:EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP"
AID = "EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP"
PATHED = f"did:webs:labs.bakobo.com%3A8443:user:alice:{AID}"

DOC = {"@context": ["https://www.w3.org/ns/did/v1"], "id": DID, "controller": DID}
STREAM = b'{"v":"KERI10JSON000159_","t":"icp"}-AABAAA'


def _explode(*_args, **_kwa):
    raise OSError("no space left on device")


def published(out_root, did=DID, doc=None, stream=STREAM):
    return publish.publish(out_root, did_module.parse(did), doc or DOC, stream)


def test_the_artifacts_land_where_the_did_says_they_do(tmp_path):
    """`### Target System(s)`: the host is the web server, so the file path is everything after
    it — the path segments, then the AID, then the two file names."""
    directory = published(tmp_path)

    assert directory == tmp_path / AID
    assert json.loads((directory / "did.json").read_text(encoding="utf-8")) == DOC
    assert (directory / "keri.cesr").read_bytes() == STREAM


def test_path_segments_become_directories_and_the_port_is_not_one(tmp_path):
    """The port belongs to the host, not to the path: `did-webs-service%3a8443` addresses a
    server, and only the segments after it name directories."""
    directory = published(tmp_path, did=PATHED)

    assert directory == tmp_path / "user" / "alice" / AID
    assert (directory / "did.json").exists()


def test_the_parent_directories_are_created(tmp_path):
    directory = published(tmp_path / "does" / "not" / "exist" / "yet", did=PATHED)

    assert directory.is_dir()


def test_republishing_overwrites_both_artifacts_in_place(tmp_path):
    """`#### Update` and `#### Deactivate` are the same operation as a first publication:
    re-ingest a newer stream, regenerate, overwrite where the DID already resolves. The spec
    forbids making a published DID's resources unavailable, so nothing is ever removed."""
    published(tmp_path)
    updated = {**DOC, "alsoKnownAs": [f"did:keri:{AID}"]}

    directory = published(tmp_path, doc=updated, stream=b"newer stream")

    assert json.loads((directory / "did.json").read_text(encoding="utf-8")) == updated
    assert (directory / "keri.cesr").read_bytes() == b"newer stream"


def test_an_existing_document_is_replaced_whole_and_never_merged(tmp_path):
    """A property the write-then-rename discipline gives for free, and one a naive in-place
    write would break: a shorter document must not leave the tail of a longer one behind."""
    published(tmp_path, doc={**DOC, "service": [{"id": "#one"}, {"id": "#two"}]})

    directory = published(tmp_path, doc=DOC)

    assert json.loads((directory / "did.json").read_text(encoding="utf-8")) == DOC


def test_the_document_is_written_in_the_order_it_was_derived(tmp_path):
    """Key order is what makes two publications of the same state diff cleanly."""
    directory = published(tmp_path)

    assert list(json.loads((directory / "did.json").read_text(encoding="utf-8"))) == list(DOC)


def test_the_document_is_written_as_utf8_json_and_the_stream_as_bytes(tmp_path):
    directory = published(tmp_path, doc={**DOC, "note": "ünïcode"})

    assert "ünïcode" in (directory / "did.json").read_text(encoding="utf-8")
    assert isinstance((directory / "keri.cesr").read_bytes(), bytes)


def test_publishing_leaves_no_temporary_files_behind(tmp_path):
    directory = published(tmp_path)

    assert sorted(item.name for item in directory.iterdir()) == ["did.json", "keri.cesr"]


# ------------------------------------------------------------------------------ atomicity


def test_a_crash_while_writing_leaves_the_previous_publication_intact(tmp_path, monkeypatch):
    """The reason for the temporary file: the artifact a resolver fetches is only ever the
    old one or the new one, never a prefix of the new one."""
    published(tmp_path)
    original = (tmp_path / AID / "did.json").read_bytes()

    monkeypatch.setattr(publish.os, "replace", _explode)
    with pytest.raises(OSError):
        published(tmp_path, doc={**DOC, "id": "did:webs:other.example:" + AID})

    assert (tmp_path / AID / "did.json").read_bytes() == original
    assert sorted(item.name for item in (tmp_path / AID).iterdir()) == ["did.json", "keri.cesr"]


def test_a_crash_between_the_two_renames_leaves_two_whole_artifacts(tmp_path):
    """Two files cannot be swapped in one atomic step on a POSIX filesystem, so the guarantee
    stops at the file: each artifact is wholly old or wholly new. The stream is renamed first,
    so the surviving mix is a document backed by evidence that is newer than it — and either
    mismatch is caught by the resolver's derive-and-compare gate rather than served as truth.
    """
    published(tmp_path)
    old_document = (tmp_path / AID / "did.json").read_bytes()
    real_replace = os.replace
    calls = []

    def once(source, target):
        calls.append(Path(target).name)
        if len(calls) > 1:
            raise OSError("crash between renames")
        return real_replace(source, target)

    publish.os.replace = once
    try:
        with pytest.raises(OSError):
            published(tmp_path, doc={**DOC, "note": "newer"}, stream=b"newer stream")
    finally:
        publish.os.replace = real_replace

    assert calls == ["keri.cesr", "did.json"]
    assert (tmp_path / AID / "keri.cesr").read_bytes() == b"newer stream"
    assert (tmp_path / AID / "did.json").read_bytes() == old_document


def test_a_failed_write_removes_its_own_temporary_file(tmp_path, monkeypatch):
    """A publication that dies mid-write leaves no litter for the next one to trip over."""
    monkeypatch.setattr(publish.os, "fsync", _explode)

    with pytest.raises(OSError):
        published(tmp_path)

    assert list((tmp_path / AID).iterdir()) == []


def test_a_failure_on_the_second_artifact_removes_the_first_ones_temporary_file(
    tmp_path, monkeypatch
):
    """Both artifacts are written before either is renamed, so a failure on the second must
    take the first one's temporary file with it — nothing is published, and nothing is left."""
    real_fsync = os.fsync
    calls = []

    def second_time(fd):
        calls.append(fd)
        if len(calls) > 1:
            raise OSError("no space left on device")
        return real_fsync(fd)

    monkeypatch.setattr(publish.os, "fsync", second_time)

    with pytest.raises(OSError):
        published(tmp_path)

    assert list((tmp_path / AID).iterdir()) == []


def test_the_artifacts_are_flushed_to_disk_before_they_are_renamed(tmp_path, monkeypatch):
    """A rename of a file whose contents are still in a buffer publishes an empty artifact if
    the machine loses power, so each temporary file is fsynced before it takes the name."""
    synced = []
    monkeypatch.setattr(publish.os, "fsync", lambda fd: synced.append(fd))

    published(tmp_path)

    assert len(synced) == 2


# --------------------------------------------------------------------------- containment
#
# Constraint ``a2sbz34i``. The parser refuses a `.` or `..` segment, which is the necessary
# half; this is the sufficient half, at the join. `artifact_dir` takes `did` structurally --
# anything carrying `.path` and `.aid` -- so nothing in its own signature says the value came
# through `did.parse`. These tests hand it exactly what a parser regression, a future spec
# widening, or a caller constructing a `WebsDid` directly would hand it.


def _unparsed(path, aid=AID):
    """A DID-shaped value that never went through ``did.parse``, which is the point."""
    return did_module.WebsDid(raw="<hand-built>", host="labs.bakobo.com", port=None,
                              path=tuple(path), aid=aid)


@pytest.mark.parametrize(
    "label,path,aid",
    [
        ("a parent-directory segment", ("..",), AID),
        ("two of them", ("..", ".."), AID),
        ("one between ordinary segments", ("a", "..", "..", ".."), AID),
        ("an absolute segment", ("/etc",), AID),
        ("a parent-directory aid", (), ".."),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_a_directory_outside_the_output_root_is_refused_at_the_join(label, path, aid, tmp_path):
    served = tmp_path / "srv"
    served.mkdir()

    with pytest.raises(RuntimeError, match="outside"):
        publish.artifact_dir(served, _unparsed(path, aid))


def test_nothing_is_written_when_the_join_refuses(tmp_path):
    """Fail closed *and* clean: the refusal fires before ``mkdir``, so a refused publication
    leaves no directory behind for the next one to find."""
    served = tmp_path / "srv"
    served.mkdir()

    with pytest.raises(RuntimeError, match="outside"):
        publish.publish(served, _unparsed(("..",)), DOC, STREAM)

    assert list(tmp_path.iterdir()) == [served]
    assert list(served.iterdir()) == []


def test_the_join_accepts_an_output_root_that_does_not_exist_yet(tmp_path):
    """``publish`` creates the tree it writes into, so containment must be decidable for a root
    with no inode. A check that needed the path to exist would refuse every first publication."""
    directory = publish.artifact_dir(tmp_path / "not" / "yet", _unparsed(("user", "alice")))

    assert directory == tmp_path / "not" / "yet" / "user" / "alice" / AID


def test_the_join_accepts_a_relative_output_root(tmp_path, monkeypatch):
    """``--out`` is whatever the operator typed, and a relative path is an ordinary thing to
    type. Resolving both sides is what keeps that from reading as an escape."""
    monkeypatch.chdir(tmp_path)

    assert publish.artifact_dir("out", _unparsed(("user",))) == (tmp_path / "out/user" / AID)


def test_the_join_accepts_a_symlinked_output_root(tmp_path):
    """An operator may serve from a symlink. Resolving the root as well as the directory is what
    stops the link itself from looking like an escape."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)

    assert publish.artifact_dir(link, _unparsed(("user",))) == real / "user" / AID


# --------------------------------------------------------------- two DIDs, one directory


def test_two_dids_can_no_longer_name_one_artifact_directory(tmp_path):
    """The second, quieter half of the same defect. A `.` segment collapses in the filesystem
    but not in ``compose()``, so ``did:webs:...:a:<AID>`` and ``did:webs:...:a:.:<AID>`` were
    two distinct, separately-authorized DIDs writing one ``did.json`` -- whichever published
    second replaced the other's document with one naming a different identifier, silently.
    """
    plain = f"did:webs:labs.bakobo.com:a:{AID}"
    dotted = f"did:webs:labs.bakobo.com:a:.:{AID}"

    first = published(tmp_path, did=plain, doc={**DOC, "id": plain})

    with pytest.raises(BakoboError) as exc_info:
        published(tmp_path, did=dotted, doc={**DOC, "id": dotted})
    assert exc_info.value.code == "e.input.format.did.f"
    assert json.loads((first / "did.json").read_text(encoding="utf-8"))["id"] == plain
