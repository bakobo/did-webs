"""didwebs — publish did:webs DIDs for KERI-controlled AIDs on Bakobo infrastructure.

Ingests a controller-produced CESR publication stream, verifies it against the AID's key state
via keripy, and derives a hosted did:webs document from what keripy actually accepted — never
from the submitted bytes (this.i constraint embuup). Phase 1 is publish-only, host-side, with no
network I/O; see docs/design.md and this.i (goal xckiyf) for the full shape.
"""

from __future__ import annotations

__version__ = "0.0.0"
