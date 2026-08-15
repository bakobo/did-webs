"""Provisions and locates the GLEIF did:webs-resolver's own venv.

**Why a second venv.** ``keri`` 2.0.0-dev6 (this project's estate pin, ``qbqfst``) declares
``Python>=3.14``; the GLEIF resolver's own ``keri>=1.2.13,<1.3`` pin declares
``Python>=3.12.6,<3.14``. The two can never share an interpreter (spike REPORT.md, "2.0-dev API
differences" #1), so the resolver is always driven as a subprocess in its own Python 3.13 venv,
never imported in-process.

**The pin.** ``GLEIF-IT/did-webs-resolver@0d4f2fd`` (design.md's ``gvimca``/``qbqfst`` decision
input, the same commit the spike harness and ``~/code/wot/did-webs-resolver`` sit at). The local
clone at that path is a READ-ONLY reference for reading source, never installed from -- this
module always installs from the pinned GitHub ref over HTTPS, so provisioning works from a bare
checkout with no local clone present, exactly like ``keri``/``bakobo-errors`` in pyproject.toml.

**Idempotent and cache-friendly** (design.md ``CI``; brief F's OPS forward form: "cache the
venv, cap the job's runtime"). :func:`provision` checks a pin-stamped marker file first and
does nothing if the venv already matches; CI restores ``.venv`` from its cache and the marker
check turns a cache hit into a no-op in well under a second.

**Where it lives.** ``tests/crossimpl/.venv`` -- gitignored by the repository's *existing*
bare ``.venv/`` rule in ``.gitignore`` (a pattern with no leading or embedded slash matches at
any depth, not only the repo root), so provisioning a second venv here needed no
``.gitignore`` edit, which is outside this brief's owned paths.

**Invocation** (ledger #19: a provisioning script must be invokable, not just importable)::

    uv run python tests/crossimpl/resolver_venv.py provision
    uv run python tests/crossimpl/resolver_venv.py freeze     # pip freeze tail, for the record
    uv run python tests/crossimpl/resolver_venv.py path       # the venv directory, for scripting

``tests/crossimpl/runner.py`` also imports :func:`python_path` and :func:`available` directly,
so the CLI and the test suite share one definition of where the venv lives and what "ready"
means.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

#: GLEIF-IT/did-webs-resolver, pinned commit (design.md `gvimca`/`qbqfst`; brief F's task 1).
RESOLVER_PIN = "0d4f2fd"
RESOLVER_SPEC = f"did-webs-resolver @ git+https://github.com/GLEIF-IT/did-webs-resolver@{RESOLVER_PIN}"

#: See the module docstring's "Where it lives" -- matched by .gitignore's bare `.venv/` rule.
VENV_DIR = HERE / ".venv"

#: Presence of this file is the idempotency check: a venv from an earlier pin is not "available".
MARKER = VENV_DIR / f".pin-{RESOLVER_PIN}"


def python_path() -> Path:
    """The interpreter inside the provisioned venv, or a path that does not exist yet."""
    return VENV_DIR / "bin" / "python"


def available() -> bool:
    """Whether a venv provisioned at the current pin is ready to drive."""
    return MARKER.exists() and python_path().exists()


def _run(cmd: list[str]) -> None:
    """Run a provisioning subprocess under ``nice`` when it is on PATH, and let its output
    reach the caller's stdout/stderr directly -- provisioning is interactive-ish (uv prints
    progress), unlike the resolver runs in :mod:`crossimpl.runner`, which are captured."""
    nice = ["nice", "-n", "19"] if shutil.which("nice") else []
    subprocess.run([*nice, *cmd], check=True)


def provision(*, force: bool = False) -> Path:
    """Build the resolver venv if it is not already there at :data:`RESOLVER_PIN`.

    Safe to call on every run: a cache hit (the common case in CI, and after the first local
    run) is one stat-and-return. ``force=True`` rebuilds even when the marker is present, for a
    developer who suspects the venv drifted from what the marker claims.
    """
    if available() and not force:
        return VENV_DIR
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    _run(["uv", "venv", "--python", "3.13", str(VENV_DIR)])
    _run(["uv", "pip", "install", "--python", str(python_path()), RESOLVER_SPEC])
    MARKER.touch()
    return VENV_DIR


def freeze() -> str:
    """``uv pip freeze`` against the provisioned venv -- the artifact M2 asks for.

    ``uv venv`` does not install ``pip`` into the venv itself (there is no ``pip`` binary to
    invoke inside it), so this shells out to ``uv pip freeze --python`` rather than
    ``<venv>/bin/python -m pip freeze``.
    """
    result = subprocess.run(
        ["uv", "pip", "freeze", "--python", str(python_path())],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["provision", "freeze", "path"])
    parser.add_argument(
        "--force", action="store_true", help="rebuild even if the pin marker is present"
    )
    args = parser.parse_args(argv)

    if args.action == "provision":
        print(provision(force=args.force))
    elif args.action == "freeze":
        if not available():
            print(f"resolver venv not provisioned at {VENV_DIR}", file=sys.stderr)
            return 1
        sys.stdout.write(freeze())
    elif args.action == "path":
        print(VENV_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
