"""Vets a v2 ``keri.cesr`` with stock WebOfTrust/keripy, the way a stranger holding only its
bytes would. Runs *inside the upstream venv* that ``keripy_venv.py`` provisions.

**No import of ``didwebs`` here, ever**, nor of anything but upstream ``keri`` (and what it
brings) and the standard library. That is what makes this a check of upstream's verdict rather
than of our fork's.

The verification is upstream's own party-side verifier, ``keri.acdc.regeventing.vet``:

1. The KEL is parsed into a fresh temporary ``Habery`` by upstream's ``Parser`` and ``Kevery``,
   strict (``lax=False``) and as remote material (``local=False``), in the genus the stream
   opens in: v2 when it opens with the v2 genus-version counter, v1 otherwise. A KEL may
   migrate from v1 to v2 (didwebs decision ``8686h4tf``), and a counter anywhere in the stream
   switches the genus for what follows, which upstream's own parser honours.
2. Every message is walked with ``Parser.msgParsator`` the same way, the genus carried from
   one message to the next.
3. For each ``rip``, every registry update in the stream naming that registry (``bup`` *and*
   ``upd`` -- the script passes along whatever the stream carries and lets upstream decide), the
   ``acm`` naming it, and every disclosure the stream carries go to ``vetBinds``, the issuer-
   registry verifier keripy's own IPEX uses; a registry with no updates goes to ``vet``.

Usage: ``python vet_stream.py STREAM``. On success prints one JSON line per registry,
``{"regid", "issuer", "state", "binding", "acdc"}``, then one per key event log upstream
accepted, ``{"kel", "sn", "version"}`` with the sequence number and protocol major of its latest
event, and exits 0. When upstream refuses
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
from keri.core import Blinder, BlindState, SerderACDC, counting
from keri.core.eventing import Kevery
from keri.core.parsing import Parser
from keri.db.dbing import LMDBer
from keri.kering import Ilks, ShortageError, Vrsn_1_0, Vrsn_2_0

#: Registry update ilks handed to upstream's ``vet``. ``upd`` is here on purpose: whether an
#: ``upd`` is acceptable is upstream's call, and this oracle exists to observe it.
UPDATE_ILKS = (Ilks.bup, Ilks.upd)


class Bare:
    """A final message with no attachments, shaped like a parsed message from ``msgParsator``."""

    def __init__(self, serder):
        self.serder = serder
        self.bsqs = []


#: The counter a stream opens with when it opens in genus v2.
GENUS_V2 = bytes(counting.Counter.makeGVC(version=Vrsn_2_0))


def opening(stream: bytes):
    """The genus ``stream`` opens in: v2 behind the v2 counter, v1 otherwise."""
    return Vrsn_2_0 if stream.startswith(GENUS_V2) else Vrsn_1_0


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
    """Every message in ``stream`` with its extracted attachments, in the genus in effect.

    A framed extractor raises ``ShortageError`` rather than waiting for bytes, so the walk
    always terminates. upstream's extractor cannot finish a final frame that carries no
    attachments -- it peeks for one and finds end of stream -- so when the remainder is exactly
    one complete ACDC-family body, behind a v2 counter or not, it is read as that body,
    unattached. Anything else short is upstream's refusal, and propagates.
    """
    ims, found = bytearray(stream), []
    genus = opening(stream)
    parser = Parser(framed=True, version=genus)
    while ims:
        remainder = bytes(ims)  # the extractor strips the body before it peeks for attachments
        extractor = parser.msgParsator(ims=ims, framed=True, local=False, version=genus)
        try:
            while True:
                next(extractor)
        except StopIteration as done:  # returns None only when piped, which this never is
            genus = parser.version  # a counter before the message switched it, until the next
            found.append(done.value)
        except ShortageError:
            remainder = remainder.removeprefix(GENUS_V2)
            serder = SerderACDC(raw=remainder)
            if serder.size != len(remainder):
                raise
            found.append(Bare(serder))
            del ims[:]
    return found


def disclosures(found: list) -> list:
    """Every blinded-state disclosure carried anywhere in the stream, each occurrence kept, so
    upstream's exactly-one rule sees duplicates and refuses them as it would."""
    return [
        Blinder(clan=BlindState, qb64=b"".join(item.qb64b for item in bsq))
        for message in found
        for bsq in getattr(message, "bsqs", None) or []
    ]


def latest_target(updates: list, blinders: list) -> str:
    """The credential SAID the latest non-vacuous update discloses, or '' when none can be read
    (vetBinds then refuses the registry, which is the verdict this oracle reports)."""
    by_blid = {blinder.said: blinder for blinder in blinders}
    for update in sorted(updates, key=lambda u: int(u.sad["n"], 16), reverse=True):
        blinder = by_blid.get(update.sad.get("b"))
        if blinder is None:
            return ""
        if blinder.acdc or blinder.state:
            return blinder.acdc
    return ""


def vet_all(stream: bytes, *, name: str = "upstream-oracle") -> list[dict]:
    """Vet every registry in ``stream`` with upstream keripy; one record per registry."""
    hby = Habery(name=name, base="", temp=True, version=opening(stream))
    try:
        kevery = Kevery(db=hby.db, lax=False, local=False)
        Parser(framed=True, version=opening(stream)).parse(
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
            # Upstream's issuer-registry reading (vetBinds, as keripy's own IPEX binds issuer
            # registries): every disclosure in the stream, matched by BLID; the state is the
            # latest non-vacuous update's. A registry with no updates has no binding to read.
            blinders = disclosures(found)
            if updates:
                target = latest_target([m.serder for m in updates], blinders)
                record = regeventing.vetBinds(
                    rip, [m.serder for m in updates], db=hby.db, blinders=blinders,
                    target=target, acdc=acdc,
                )
            else:
                record = regeventing.vet(rip, [], db=hby.db)
            records.append(
                {
                    "regid": record.regid,
                    "issuer": record.issuer,
                    "state": record.state,
                    "binding": record.binding,
                    "acdc": record.acdc,
                }
            )
        for pre, kever in sorted(hby.kevers.items()):
            records.append(
                {"kel": pre, "sn": kever.sner.num, "version": kever.serder.pvrsn.major}
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
