"""Provisions and locates a venv running stock WebOfTrust/keripy main.

**Why a separate venv.** Decision ``0plkq8s8`` makes the v2 target what upstream keripy main
accepts. This project's own venv runs the bakobo fork (``bakobo/keripy@6f95d314``), and the two
cannot be installed side by side under one distribution name, so the upstream verifier is
driven as a subprocess in its own venv, never imported in-process.

**The pin.** ``WebOfTrust/keripy@624df82944a1b8ed1ab3d7b9d643a84e1c278426``. Installed from the
pinned GitHub ref over HTTPS, so provisioning works from a bare checkout with no local clone,
the same way ``tests/crossimpl/resolver_venv.py`` installs the GLEIF resolver. That commit
declares ``python_requires='~=3.14.0'``, hence the interpreter below.

**Idempotent.** :func:`provision` checks a pin-stamped marker first and does nothing if the
venv already matches, so a CI cache hit is a stat and a return.

**Where it lives.** ``tests/upstream/.venv``, gitignored by the repository's bare ``.venv/``
rule, which matches at any depth.

**Invocation**::

    uv run python tests/upstream/keripy_venv.py provision
    uv run python tests/upstream/keripy_venv.py path
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

#: WebOfTrust/keripy main, pinned (decision 0plkq8s8).
KERIPY_PIN = "624df82944a1b8ed1ab3d7b9d643a84e1c278426"
KERIPY_SPEC = f"keri @ git+https://github.com/WebOfTrust/keripy@{KERIPY_PIN}"

#: The interpreter the pinned commit's ``python_requires`` admits.
PYTHON = "3.14"

VENV_DIR = HERE / ".venv"

#: Presence of this file is the idempotency check: a venv from an earlier pin is not "available".
MARKER = VENV_DIR / f".pin-{KERIPY_PIN}"


def python_path() -> Path:
    """The interpreter inside the provisioned venv, or a path that does not exist yet."""
    return VENV_DIR / "bin" / "python"


def available() -> bool:
    """Whether a venv provisioned at the current pin is ready to drive."""
    return MARKER.exists() and python_path().exists()


def _run(cmd: list[str]) -> None:
    """Run a provisioning step under ``nice`` when it is on PATH, output uncaptured."""
    nice = ["nice", "-n", "19"] if shutil.which("nice") else []
    subprocess.run([*nice, *cmd], check=True)


def provision(*, force: bool = False) -> Path:
    """Build the upstream venv if it is not already there at :data:`KERIPY_PIN`.

    ``force=True`` rebuilds even when the marker is present.
    """
    if available() and not force:
        return VENV_DIR
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    _run(["uv", "venv", "--python", PYTHON, str(VENV_DIR)])
    _run(["uv", "pip", "install", "--python", str(python_path()), KERIPY_SPEC])
    MARKER.touch()
    return VENV_DIR


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["provision", "path"])
    parser.add_argument(
        "--force", action="store_true", help="rebuild even if the pin marker is present"
    )
    args = parser.parse_args(argv)

    if args.action == "provision":
        print(provision(force=args.force))
    else:
        print(VENV_DIR)
    return 0


if __name__ == "__main__":  # pragma: no cover - the CLI entry; main() is tested directly
    sys.exit(main())
