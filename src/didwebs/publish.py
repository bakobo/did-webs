"""Writing the two hosted artifacts, atomically, where the DID says they live.

``### Target System(s)`` fixes the location: a did:webs DID becomes an HTTPS URL by replacing
the method-specific identifier's colons with path separators, so the artifact directory is the
DID's path segments followed by its AID, and the two files in it are ``did.json`` and
``keri.cesr``.

**Why the temporary file.** A resolver may fetch either artifact at any moment, including
while a publication is being written. Writing in place would serve a truncated document to
whoever asked during the write; writing a temporary file beside the target and renaming it
means a reader sees the old artifact or the new one and never a prefix of either. That also
makes ``#### Update`` and ``#### Deactivate`` the same operation as a first publication:
re-ingest a newer stream, regenerate, overwrite in place. Nothing is ever removed — the spec
forbids making a published DID's resources unavailable, since a resolver cannot tell a
withdrawn DID from an offline host.

**Where the guarantee stops.** Two files cannot be renamed in one atomic step on a POSIX
filesystem. Each artifact is wholly old or wholly new; a crash between the two renames leaves a
document and a stream from different publications. The stream is renamed first, so the mix that
can survive is a document backed by evidence newer than itself, and either mismatch is caught
by the resolver's derive-and-compare gate rather than served as truth.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

__all__ = ["DID_JSON", "KERI_CESR", "publish"]

DID_JSON = "did.json"
KERI_CESR = "keri.cesr"


def artifact_dir(out_root, did) -> Path:
    """The directory ``did``'s artifacts belong in, under ``out_root``.

    The host and port address the web server rather than the filesystem, so only the path
    segments and the AID become directories.
    """
    return Path(out_root).joinpath(*did.path, did.aid)


def _write(directory: Path, name: str, payload: bytes) -> Path:
    """Write ``payload`` to a temporary file in ``directory`` and return its path.

    The temporary file is created in the destination directory, not the system temp directory,
    because a rename is only atomic within one filesystem. It is flushed and fsynced before it
    is handed back: renaming a file whose contents are still buffered publishes an empty
    artifact if the machine loses power at the wrong moment.
    """
    handle, path = tempfile.mkstemp(dir=directory, prefix=f".{name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        os.unlink(path)
        raise
    return Path(path)


def publish(out_root, did, doc: dict, emitted_stream: bytes) -> Path:
    """Publish ``doc`` and ``emitted_stream`` as ``did``'s hosted artifacts.

    Args:
        out_root: the directory the DID's host serves from.
        did: the :class:`~didwebs.did.WebsDid` being published.
        doc: the DID document to write as ``did.json``. Written exactly as given, in the order
            it was derived, so two publications of the same state diff cleanly — the caller
            decides whether it is the did:webs or the did:web form (the spec's ``#### Create``
            publishes the did:web one).
        emitted_stream: the ``keri.cesr`` bytes, which constraint ``embuup`` requires to have
            been re-assembled from verified state rather than copied from a submission.

    Returns:
        Path: the artifact directory, now holding both files.
    """
    directory = artifact_dir(out_root, did)
    directory.mkdir(parents=True, exist_ok=True)

    # UTF-8 with the characters intact rather than \u-escaped ASCII: RFC 8259 makes UTF-8 the
    # encoding of a JSON text, and an escaped document is harder to diff by eye for no gain.
    payload = json.dumps(doc, ensure_ascii=False).encode("utf-8")
    document = _write(directory, DID_JSON, payload)
    try:
        stream = _write(directory, KERI_CESR, emitted_stream)
    except BaseException:
        os.unlink(document)
        raise

    try:
        os.replace(stream, directory / KERI_CESR)
        os.replace(document, directory / DID_JSON)
    except BaseException:
        for leftover in (stream, document):
            if leftover.exists():
                os.unlink(leftover)
        raise
    return directory
