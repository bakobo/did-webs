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

**Where the artifacts may not land.** That location is derived from a value a customer chose, so
every component of it is checked here, at the join, and not only in the parser that produced the
DID. Two properties, not one: the directory stays under the output root, and two DIDs that differ
never name one directory — see :func:`artifact_dir` (constraint ``a2sbz34i``).

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

from didwebs import errors

__all__ = ["DID_JSON", "KERI_CESR", "publish"]

DID_JSON = "did.json"
KERI_CESR = "keri.cesr"

#: Components that are not a directory name at all. ``.`` and ``..`` alias another directory,
#: and an empty component vanishes in a join — all three break injectivity (see
#: :func:`artifact_dir`), and ``..`` also breaks containment.
_UNSAFE_COMPONENTS = frozenset({"", ".", ".."})

#: Characters that would make one component into several, or into none. The backslash is listed
#: for a filesystem that reads it as a separator even though POSIX does not, and ``\x00``
#: because a component carrying it is not a name any filesystem will accept.
_SEPARATORS = frozenset("/\\\x00")


def artifact_dir(out_root, did) -> Path:
    """The directory ``did``'s artifacts belong in, under ``out_root``.

    The host and port address the web server rather than the filesystem, so only the path
    segments and the AID become directories.

    **Why the check is here as well as in the parser** (constraint ``a2sbz34i``). ``did.parse``
    refuses a ``.`` or ``..`` segment, which is the necessary half and where the refusal belongs:
    it is the earliest point the value is known to be wrong, and it produces an error an operator
    can act on. It is not the sufficient half. This function takes ``did`` structurally — anything
    carrying ``.path`` and ``.aid`` — so nothing in its own signature or its callers says the
    value came through the parser, and the properties it actually depends on are not "this string
    matched the ABNF". Those are different claims, in different modules, and the way they fail is
    by drifting: the spec's ``path`` production widens, or a caller constructs a
    :class:`~didwebs.did.WebsDid` directly (the test suite does), and the parser's refusal stops
    covering the sink.

    **The sink relies on two properties, and the first revision of this function checked one.**
    *Containment* is that the directory stays under ``out_root``. *Injectivity* is that two DIDs
    which differ name two directories — the ``.``-collision half of the finding, where one
    publication silently replaces another's ``did.json`` with a document naming a different
    identifier. That revision resolved the join and compared it against the root, which
    establishes containment while destroying the evidence for injectivity: ``resolve()``
    normalizes ``a/./b`` and ``a/b/../b`` to ``a/b`` *before* the comparison runs, so it was
    blind to precisely the aliasing the parser refusal had been added for. Raised by Copilot on
    PR #5 and confirmed by measurement: five component tuples were accepted and all five landed
    on one directory.

    So the check is on the components, one at a time, before anything is joined. Each must be a
    single directory name: not empty, not ``.`` or ``..``, and carrying no separator. That is
    total and syntactic — a claim about the value, which nothing can race — and containment then
    holds **by construction**, since a join of single directory names cannot leave the root.

    **Why no resolve-and-compare as well.** It would be unreachable after the above, and where it
    would *not* be unreachable it would be unsound: resolving follows symlinks, so it reads as a
    guard against a symlink planted inside the served tree, and it is not one. This function
    checks, and ``publish`` creates the directory afterwards, so anyone able to plant the symlink
    can plant it in that window. A guard that loses a race it appears to win is worse than no
    guard, and the adversary it imagines — someone with write access inside the output root —
    can already write the artifacts directly. ``out_root`` itself is still resolved, once, so a
    legitimately symlinked output directory and a relative ``--out`` both work and the returned
    path is absolute.

    The alternative considered and rejected was to require a parsed DID here — a type check, or
    re-parsing ``did.raw``. It moves the same trust one function further along without ever
    checking the properties that matter, and ``raw`` is explicitly non-authoritative.

    Raises:
        bakobo.errors.BakoboError: carrying :data:`~didwebs.errors.ARTIFACT_PATH_CORRUPT`
            (``e.self.corrupt.did.f``) for a component that is not one directory name. A
            registry code rather than a bare exception, per AGENTS.md's house standard — see that
            declaration for why the sorter is ``self`` and why it is not ``e.self.unknown.f``.
    """
    root = Path(out_root).resolve()
    for component in (*did.path, did.aid):
        if component in _UNSAFE_COMPONENTS or _SEPARATORS & set(component):
            raise errors.ARTIFACT_PATH_CORRUPT(component=repr(component), aid=did.aid)
    return root.joinpath(*did.path, did.aid)


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
