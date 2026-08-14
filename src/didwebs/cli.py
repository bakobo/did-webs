"""The ``didwebs`` command-line entry point — STUB.

The publish command (`didwebs publish --stream <file> --did <did> --out <dir>`, docs/design.md
§ "Modules") is not implemented yet; a later brief replaces this under TDD (this.i routes the
implication to plan session task #5). Until then, invoking the console script reports that
plainly and exits ``64`` (``EX_USAGE``) rather than doing nothing or crashing.
"""

from __future__ import annotations

import sys


def main(argv=None) -> int:
    """Report that the publish command is not yet implemented; ``argv`` is unused by the stub."""
    print("The didwebs publish command is not yet implemented.", file=sys.stderr)
    return 64
