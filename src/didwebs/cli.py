"""The ``didwebs`` command line: one verb, and one operator contract.

``didwebs publish --stream <file> --did <did> --out <dir>`` runs the whole phase-1 pipeline —
ingest the submitted stream, derive the DID document, transform it to the did:web form the spec
publishes, re-assemble ``keri.cesr`` from verified state, and write both artifacts atomically.

**One verb, deliberately** (panel finding SKP-F3). Issuing a controller's designated-aliases
credential is not a product surface: Bakobo does not hold customer keys (decision ``avuwzl``),
so the keystore side stays where fixtures and demos can reach it —
``python -m didwebs.assemble`` — and never becomes something an operator can be asked to run
against a customer's DID.

**The operator contract.** Exit 0 and both artifacts exist, or a nonzero exit, nothing
published, and one line on stderr carrying the stable error code and a plain sentence.
Exit 1 means a submission was refused; exit 64 (``EX_USAGE``) means the invocation itself was
wrong and no submission was read. An internal fault reports ``e.self.unknown.f`` rather than
letting a traceback masquerade as a bad submission.

**Who is running this** (panel finding SKP-F4). In phase 1 the operator asserts that the stream
is the controller's: the pipeline establishes no submitter-to-AID binding, and none of this is
network-facing. Both must land before any submission surface exists.
"""

from __future__ import annotations

import argparse
import sys

from bakobo.errors import BakoboError

from didwebs import assemble, document, errors, ingest, publish
from didwebs.did import parse as parse_did

__all__ = ["main"]

#: ``EX_USAGE`` from sysexits.h: the command line itself was wrong.
EX_USAGE = 64

#: Any refusal of a submission. One code, because an operator scripts on the error code on
#: stderr, not on a taxonomy of exit statuses.
EX_FAILURE = 1


class _Usage(Exception):
    """A command line this program cannot act on. Never escapes :func:`main`."""


class _Parser(argparse.ArgumentParser):
    """An ``ArgumentParser`` that reports a usage error instead of exiting the process.

    argparse's own failure path calls ``sys.exit(2)``, which would make a mistyped flag look
    like an exit status this program never promises. Raising instead lets :func:`main` return
    ``EX_USAGE`` the way every other path returns a status.
    """

    def error(self, message):
        raise _Usage(message)


def _parser() -> _Parser:
    parser = _Parser(prog="didwebs", description="Publish did:webs artifacts for a KERI AID.")
    verbs = parser.add_subparsers(dest="verb", required=True)
    publishing = verbs.add_parser(
        "publish", help="verify a CESR publication stream and write did.json and keri.cesr"
    )
    publishing.add_argument(
        "--stream", required=True, help="file holding the controller's CESR publication stream"
    )
    publishing.add_argument("--did", required=True, help="the did:webs DID being published")
    publishing.add_argument(
        "--out", required=True, help="directory the DID's host serves artifacts from"
    )
    return parser


def _publish(args) -> int:
    """The pipeline, end to end. Any refusal raises; nothing partial is written."""
    try:
        with open(args.stream, "rb") as file:
            stream = file.read()
    except OSError as exc:
        raise _Usage(f"The stream file {args.stream} could not be read: {exc.strerror}.") from exc

    did = parse_did(args.did)
    with ingest.ingest(stream, did) as verified:
        doc = document.derive_document(verified, did)
        emitted = assemble.emit_stream(verified)

    # `#### Create`: what is hosted at the target system is the did:web form of the document.
    directory = publish.publish(args.out, did, document.to_did_web(doc), emitted)
    print(directory / publish.DID_JSON)
    print(directory / publish.KERI_CESR)
    return 0


def main(argv=None) -> int:
    """Run the command line and return its exit status.

    Args:
        argv: arguments after the program name. None means read ``sys.argv``.
    """
    try:
        args = _parser().parse_args(argv)
        return _publish(args)
    except _Usage as usage:
        print(usage, file=sys.stderr)
        return EX_USAGE
    except BakoboError as refused:
        print(refused, file=sys.stderr)
        return EX_FAILURE
    except Exception as fault:  # noqa: BLE001 - an unattributable fault is still ours to report
        print(errors.UNKNOWN_FAILURE(), file=sys.stderr)
        print(f"{type(fault).__name__}: {fault}", file=sys.stderr)
        return EX_FAILURE
