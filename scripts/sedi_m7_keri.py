"""KLI keystore adapter for the SEDI M7 localhost rehearsal.

KLI incepts and rotates the witnessed AIDs. Its VC commands currently omit the
v1 version on KEL anchors and its export defaults to v2 CESR counters, so this
adapter uses the existing didwebs issuance recipe and explicitly v1 replay.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from bakobo.errors import ErrorCode
from keri.app import signing
from keri.app.habbing import openHby
from keri.kering import Vrsn_1_0
from keri.recording import LocationRecord
from keri.vdr.credentialing import Regery

from didwebs.assemble import issue_aliases
from didwebs.did import parse as parse_did

WITNESS_OOBI_MISSING = ErrorCode(
    "e.state.missing.witness-oobi.r",
    "The witness OOBI has not been verified.",
    detail="The witness OOBI for {aid} must be verified before its transport address is used.",
    args=("aid",),
    hint="Resolve the witness OOBI with KLI and retry.",
)
ALIAS_ACDC_MISSING = ErrorCode(
    "e.state.missing.alias-acdc.r",
    "The designated-aliases credential has not been issued.",
    detail="No designated-aliases credential exists for {name} in this keystore.",
    args=("name",),
    hint="Issue the credential before exporting the publication stream.",
)
ALIAS_ACDC_AMBIGUOUS = ErrorCode(
    "e.state.conflict.alias-acdc.f",
    "The keystore contains more than one designated-aliases credential.",
    detail="The demo export for {name} cannot choose one credential without ambiguity.",
    args=("name",),
    hint="Use a fresh demo keystore with one credential per AID.",
)
DEMO_INVOCATION_INVALID = ErrorCode(
    "e.input.format.demo-invocation.f",
    "The demo command arguments are invalid.",
    detail="{problem}",
    args=("problem",),
    hint="Check the command help and supply its required arguments.",
)

WITNESSES = (
    ("BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha", 5642),
    ("BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM", 5643),
    ("BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX", 5644),
)


def seed_locations(name: str, base: str) -> None:
    """Give KLI the localhost transport addresses of verified witness OOBIs."""
    with openHby(name=name, base=base, temp=False, version=Vrsn_1_0) as hby:
        for aid, port in WITNESSES:
            if aid not in hby.kevers:
                raise WITNESS_OOBI_MISSING(aid=aid)
            hby.db.locs.pin(
                keys=(aid, "http"),
                val=LocationRecord(url=f"http://127.0.0.1:{port}/"),
            )


def issue(name: str, base: str, host: str, path_prefix: str) -> str:
    """Issue both DID spellings from one witnessed KLI AID, using v1 throughout."""
    with openHby(name=name, base=base, temp=False, version=Vrsn_1_0) as hby:
        hab = hby.habByName(name)
        regery = Regery(hby=hby, name=name, base=base)
        try:
            aid = hab.pre
            webs = f"did:webs:{host}:{path_prefix}:{aid}"
            parse_did(webs)
            ids = [webs, f"did:web:{host}:{path_prefix}:{aid}"]
            issued = issue_aliases(hab, regery, ids)
            return issued.creder.said
        finally:
            regery.close()


def export(name: str, base: str, path: Path) -> str:
    """Export the AID's KEL, TELs, and ACDC in the v1 publication order."""
    with openHby(name=name, base=base, temp=False, version=Vrsn_1_0) as hby:
        hab = hby.habByName(name)
        regery = Regery(hby=hby, name=name, base=base)
        try:
            credentials = list(regery.reger.creds.getTopItemIter())
            if not credentials:
                raise ALIAS_ACDC_MISSING(name=name)
            if len(credentials) > 1:
                raise ALIAS_ACDC_AMBIGUOUS(name=name)
            (said,), _ = credentials[0]
            creder, *_ = regery.reger.cloneCred(said=said)
            stream = bytearray()
            for msg in hby.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_1_0):
                stream.extend(msg)
            for pre in (creder.regid, creder.said):
                for msg in regery.reger.clonePreIter(pre=pre):
                    stream.extend(msg)
            prefixer, seqner, saider = regery.reger.cancs.get(keys=(creder.said,))
            stream.extend(signing.serialize(creder, prefixer, seqner, saider))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(stream)
            return hab.pre
        finally:
            regery.close()


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        super().error(str(DEMO_INVOCATION_INVALID(problem=message)))


def main() -> None:
    parser = _Parser(description=__doc__)
    parser.add_argument("command", choices=("seed", "issue", "export"))
    parser.add_argument("--name", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--host", default="dids.bakobo.com")
    parser.add_argument("--path-prefix", default="demo")
    parser.add_argument("--stream", type=Path)
    args = parser.parse_args()
    if args.command == "seed":
        seed_locations(args.name, args.base)
    elif args.command == "issue":
        print(issue(args.name, args.base, args.host, args.path_prefix))
    else:
        if args.stream is None:
            parser.error("The export command requires --stream.")
        print(export(args.name, args.base, args.stream))


if __name__ == "__main__":
    main()
