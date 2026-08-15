"""Runs *inside the resolver's own venv* (Python 3.13, ``keri>=1.2.13,<1.3`` -- never this
project's Python 3.14 estate pin). Ported from the spike harness's resolver-side oracle,
``.ignored/spike-keripy-interop/ingest_stream.py``: same ``dws.core.resolving.save_cesr`` +
``dws.core.didding.generate_did_doc`` path, the same "exit 0, verdict in the JSON body" contract
so a resolver-side exception is data for the caller to assert on, not a process failure it has
to special-case.

**No import of ``didwebs`` or ``bakobo-errors`` here, ever.** This script's only importable
dependencies are the resolver's own (``keri``, ``dws``) -- that is what makes it a genuine
cross-implementation check rather than a mock of one. ``tests/crossimpl/runner.py`` invokes this
file as a subprocess in the venv ``resolver_venv.py`` provisions; it never runs in this
project's own interpreter.

Usage: ``python resolver_runner.py --stream PATH --aid AID --did DID [--name NAME]``. Always
exits 0 (or nonzero only if it cannot even start, e.g. a missing argument) and prints one line
of JSON: ``verdict`` is ``"INGESTED"`` (the AID reached key state and a document was derived),
``"PARTIAL"`` (the AID reached key state but no document could be derived), or ``"FAILED"``
(``save_cesr`` itself raised).
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from dws.core import didding, resolving
from keri.app.habbing import openHby
from keri.vdr import credentialing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stream", required=True, help="path to the keri.cesr bytes to ingest")
    parser.add_argument("--aid", required=True, help="the AID the stream claims to publish")
    parser.add_argument("--did", required=True, help="the did:webs DID to derive a document for")
    parser.add_argument("--name", default="crossimpl-res", help="Habery name, temp store")
    args = parser.parse_args(argv)

    stream = Path(args.stream).read_bytes()
    report: dict = {"verdict": None}

    # `temp=True` on both stores in `openHby`/`Regery` is what the spike proved keeps this
    # process off the real `~/.keri` on this keripy line (its own docstring: "Store .ks, .db,
    # and .cf in /tmp"); `tests/crossimpl/runner.py` additionally overrides HOME/XDG for this
    # subprocess as a second, independent layer (worker E's F8 incident) rather than trusting
    # that alone.
    with openHby(name=args.name, temp=True) as hby:
        rgy = credentialing.Regery(hby=hby, name=hby.name, base=hby.base, temp=True)
        try:
            resolving.save_cesr(hby=hby, rgy=rgy, kc_res=stream, aid=args.aid)
        except Exception as exc:  # noqa: BLE001 - the resolver's own failure is the datum
            report["verdict"] = "FAILED"
            report["error"] = f"{type(exc).__name__}: {exc}"
            report["traceback"] = traceback.format_exc()
        else:
            report["aid_in_kevers"] = args.aid in hby.kevers
            report["kever_sn"] = (
                hby.kevers[args.aid].sner.num if report["aid_in_kevers"] else None
            )
            report["verdict"] = "PARTIAL"
            if report["aid_in_kevers"]:
                try:
                    report["did_doc"] = didding.generate_did_doc(
                        hby, rgy, did=args.did, aid=args.aid, meta=False
                    )
                    report["verdict"] = "INGESTED"
                except Exception as exc:  # noqa: BLE001 - reported, not raised
                    report["did_doc_error"] = f"{type(exc).__name__}: {exc}"
                    report["did_doc_traceback"] = traceback.format_exc()

    print(json.dumps(report, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
