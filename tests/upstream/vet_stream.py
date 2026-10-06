"""Vets a v2 ``keri.cesr`` with stock WebOfTrust/keripy, the way a stranger holding only its
bytes would. Runs *inside the upstream venv* that ``keripy_venv.py`` provisions.

**No import of ``didwebs`` here, ever**, nor of anything but upstream ``keri`` (and what it
brings) and the standard library. That is what makes this a check of upstream's verdict rather
than of our fork's.

The verification is upstream's own party-side verifier, ``keri.acdc.regeventing.vet``:

1. The KEL is parsed into a fresh temporary ``Habery`` by upstream's ``Parser`` and ``Kevery``,
   strict (``lax=False``) and as remote material (``local=False``).
2. Every message is walked with ``Parser.msgParsator``, genus pinned to v2.
3. For each ``rip``, every registry update in the stream naming that registry (``bup`` *and*
   ``upd`` -- the script passes along whatever the stream carries and lets upstream decide), the
   ``acm`` naming it, and the head ``bup``'s attached disclosure go to ``vet``.

Usage: ``python vet_stream.py STREAM``. On success prints one JSON line per registry,
``{"regid", "issuer", "state", "binding", "acdc"}``, and exits 0. When upstream refuses
anything, prints one JSON line ``{"error": <exception class name>, "message": ...}`` and exits
1. The caller owns the wall-clock timeout.

Set ``DIDWEBS_TEMP_HEAD`` to keep keripy's temporary stores in a directory the caller owns and
removes (constraint ``l7ws7hdt``).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from keri.acdc import regeventing
from keri.app.habbing import Habery
from keri.core import Blinder, BlindState, SerderACDC
from keri.core.eventing import Kevery
from keri.core.parsing import Parser
from keri.db.dbing import LMDBer
from keri.kering import Ilks, ShortageError, Vrsn_2_0

#: Registry update ilks handed to upstream's ``vet``. ``upd`` is here on purpose: whether an
#: ``upd`` is acceptable is upstream's call, and this oracle exists to observe it.
UPDATE_ILKS = (Ilks.bup, Ilks.upd)


class Bare:
    """A final message with no attachments, shaped like a parsed message from ``msgParsator``."""

    def __init__(self, serder):
        self.serder = serder
        self.bsqs = []


def contain_temp_stores() -> None:
    """Point keripy's temporary-store head at ``DIDWEBS_TEMP_HEAD`` when the caller names one."""
    head = os.environ.get("DIDWEBS_TEMP_HEAD")
    if head is None:
        return
    os.makedirs(head, exist_ok=True)
    from hio.base.filing import Filer

    Filer.TempHeadDir = head
    LMDBer.TempHeadDir = head


def messages(stream: bytes) -> list:
    """Every message in ``stream`` with its extracted attachments, genus pinned to v2.

    A framed extractor raises ``ShortageError`` rather than waiting for bytes, so the walk
    always terminates. upstream's extractor cannot finish a final frame that carries no
    attachments -- it peeks for one and finds end of stream -- so when the remainder is exactly
    one complete ACDC-family body, it is read as that body, unattached. Anything else short is
    upstream's refusal, and propagates.
    """
    ims, found = bytearray(stream), []
    parser = Parser(framed=True, version=Vrsn_2_0)
    while ims:
        remainder = bytes(ims)  # the extractor strips the body before it peeks for attachments
        extractor = parser.msgParsator(ims=ims, framed=True, local=False, version=Vrsn_2_0)
        try:
            while True:
                next(extractor)
        except StopIteration as done:  # returns None only when piped, which this never is
            found.append(done.value)
        except ShortageError:
            serder = SerderACDC(raw=remainder)
            if serder.size != len(remainder):
                raise
            found.append(Bare(serder))
            del ims[:]
    return found


def vet_all(stream: bytes, *, name: str = "upstream-oracle") -> list[dict]:
    """Vet every registry in ``stream`` with upstream keripy; one record per registry."""
    hby = Habery(name=name, base="", temp=True, version=Vrsn_2_0)
    try:
        kevery = Kevery(db=hby.db, lax=False, local=False)
        Parser(framed=True, version=Vrsn_2_0).parse(
            ims=bytearray(stream), kvy=kevery, local=False
        )
        found = messages(stream)
        rips = [m.serder for m in found if m.serder.ilk == Ilks.rip]
        records = []
        for rip in rips:
            updates = [
                m for m in found
                if m.serder.ilk in UPDATE_ILKS and m.serder.sad.get("rd") == rip.said
            ]
            acdc = next(
                (
                    m.serder for m in found
                    if m.serder.ilk == Ilks.acm and m.serder.sad.get("rd") == rip.said
                ),
                None,
            )
            blinder = None
            bups = [m for m in updates if m.serder.ilk == Ilks.bup]
            if bups:
                head = max(bups, key=lambda m: int(m.serder.sad["n"], 16))
                if head.bsqs:
                    blinder = Blinder(
                        clan=BlindState, qb64=b"".join(item.qb64b for item in head.bsqs[0])
                    )
            record = regeventing.vet(
                rip, [m.serder for m in updates], db=hby.db, acdc=acdc, blinder=blinder
            )
            records.append(
                {
                    "regid": record.regid,
                    "issuer": record.issuer,
                    "state": record.state,
                    "binding": record.binding,
                    "acdc": record.acdc,
                }
            )
        return records
    finally:
        hby.close(clear=True)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: vet_stream.py STREAM", file=sys.stderr)
        return 2
    contain_temp_stores()
    stream = Path(argv[0]).read_bytes()
    try:
        records = vet_all(stream)
    except Exception as exc:  # noqa: BLE001 - upstream's refusal is the datum, by class name
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
        return 1
    for record in records:
        print(json.dumps(record))
    return 0


if __name__ == "__main__":  # pragma: no cover - the CLI entry; main() runs in every test
    sys.exit(main())
