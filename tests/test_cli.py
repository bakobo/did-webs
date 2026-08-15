"""didwebs.cli — the one product verb, and what an operator sees when it fails.

`didwebs publish --stream <file> --did <did> --out <dir>` runs the whole pipeline: ingest the
submitted stream, derive the document, transform it to the did:web form the spec publishes,
re-assemble `keri.cesr` from verified state, and write both artifacts. There is exactly one
verb (SKP-F3): issuance is not a product surface, because Bakobo never holds customer keys.

The operator contract under test is narrow and load-bearing: exit 0 and the artifacts exist,
or a nonzero exit with the error code and a plain sentence on stderr and nothing published.
Two tests drive the *installed* console script in a subprocess (ledger #19), because a broken
`[project.scripts]` entry or a missing dependency is invisible to an in-process call.
"""

from __future__ import annotations

import json
import subprocess
import sys

import builders
import keri_api
import pytest
from test_ingest import REJECTIONS

from didwebs import cli, ingest
from didwebs import did as did_module

DOMAIN = keri_api.DOMAIN


def fixture_stream(knob, tmp_path):
    """A fixture's publication stream, written where an operator would point the CLI at it."""
    stream, facts = builders.KNOBS[knob](tmp_path / "build")
    path = tmp_path / f"{knob}.cesr"
    path.write_bytes(stream)
    return path, facts


def artifacts(out, facts):
    directory = out / facts["aid"]
    return directory / "did.json", directory / "keri.cesr"


def run(*argv):
    return cli.main(list(argv))


def only_the_command(capsys):
    """Discard whatever building a fixture printed, so a capture is the command's own output.

    keripy's Registrar narrates its escrow waits on stdout while a fixture is being issued, and
    that noise is the test harness's, not the CLI's.
    """
    capsys.readouterr()


# ---------------------------------------------------------------------------- the verb


def test_publishing_writes_both_artifacts_and_exits_zero(tmp_path, capsys):
    stream, facts = fixture_stream("base", tmp_path)
    out = tmp_path / "www"
    only_the_command(capsys)

    code = run("publish", "--stream", str(stream), "--did", facts["did_webs"], "--out", str(out))

    document, cesr = artifacts(out, facts)
    captured = capsys.readouterr()
    assert code == 0
    assert captured.err == ""
    assert str(document) in captured.out and str(cesr) in captured.out
    assert document.exists() and cesr.exists()


def test_the_published_document_is_the_did_web_form_the_spec_hosts(tmp_path):
    """`#### Create`: the resource made available at the target system is the did:web DID
    document, transformed from the derived did:webs one. A resolver of either method fetches
    this same file."""
    stream, facts = fixture_stream("base", tmp_path)
    out = tmp_path / "www"

    run("publish", "--stream", str(stream), "--did", facts["did_webs"], "--out", str(out))

    document = json.loads(artifacts(out, facts)[0].read_text(encoding="utf-8"))
    assert document["id"] == facts["did_web"]
    assert document["controller"] == facts["did_web"]
    assert facts["did_webs"] in document["alsoKnownAs"]


def test_the_published_stream_is_re_ingestable_and_agrees_with_what_went_in(tmp_path):
    """What is hosted must verify: the artifact is fed back through our own ingest, and the
    AID, the credential and the key state it establishes are the submission's."""
    stream, facts = fixture_stream("base", tmp_path)
    out = tmp_path / "www"
    run("publish", "--stream", str(stream), "--did", facts["did_webs"], "--out", str(out))

    published = artifacts(out, facts)[1].read_bytes()
    with ingest.ingest(published, did_module.parse(facts["did_webs"])) as verified:
        assert verified.aid == facts["aid"]
        assert verified.acdc.said == facts["acdc_said"]
        assert verified.hby.kevers[facts["aid"]].sner.num == facts["kel_sn"]


def test_publishing_an_update_overwrites_the_previous_artifacts(tmp_path):
    """`#### Update` and `#### Deactivate` through the operator surface: the same command with
    a newer stream replaces what is hosted, in place."""
    first, facts = fixture_stream("base", tmp_path)
    out = tmp_path / "www"
    run("publish", "--stream", str(first), "--did", facts["did_webs"], "--out", str(out))

    deactivated, dead_facts = fixture_stream("deactivated", tmp_path)
    assert dead_facts["aid"] == facts["aid"]  # same salt, same AID, a later key state
    code = run(
        "publish", "--stream", str(deactivated), "--did", facts["did_webs"], "--out", str(out)
    )

    document = json.loads(artifacts(out, facts)[0].read_text(encoding="utf-8"))
    assert code == 0
    assert document["verificationMethod"][0]["id"] != f"#{keri_api.CONTROLLER_SALT}"
    assert len(list((out / facts["aid"]).iterdir())) == 2


# --------------------------------------------------------------------- the failure contract


def test_a_stream_the_pipeline_refuses_exits_one_and_names_the_code(tmp_path, capsys):
    """OPS's contract: one line on stderr carrying the stable code and a plain sentence, exit
    1, and nothing published — a half-published DID is worse than an unpublished one."""
    stream, facts = fixture_stream("without_acdc", tmp_path)
    out = tmp_path / "www"
    only_the_command(capsys)

    code = run("publish", "--stream", str(stream), "--did", facts["did_webs"], "--out", str(out))

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert "e.input.missing.alias-acdc.f" in captured.err
    assert captured.err.strip().endswith(".") or "]" in captured.err
    assert not (out / facts["aid"]).exists()


def test_a_document_the_derivation_refuses_exits_one_too(tmp_path, capsys):
    """The failure contract covers the whole pipeline, not just ingest: a stream that verifies
    but cannot be projected into a document publishes nothing either."""
    stream, facts = fixture_stream("secp_keys", tmp_path)
    out = tmp_path / "www"

    code = run("publish", "--stream", str(stream), "--did", facts["did_webs"], "--out", str(out))

    assert code == 1
    assert "e.feature.unsupported.key.alg.f" in capsys.readouterr().err
    assert not (out / facts["aid"]).exists()


def test_a_did_that_is_not_a_did_webs_identifier_is_reported_as_such(tmp_path, capsys):
    stream, _ = fixture_stream("base", tmp_path)

    code = run("publish", "--stream", str(stream), "--did", "did:example:nope", "--out", str(tmp_path))

    assert code == 1
    assert "e.input.format.did.f" in capsys.readouterr().err


def test_an_unattributable_failure_is_reported_as_ours_not_the_submitters(
    tmp_path, capsys, monkeypatch
):
    """`e.self.unknown.f` exists so an internal fault never masquerades as a bad submission.
    The operator still gets a code and a nonzero exit rather than a traceback."""
    stream, facts = fixture_stream("base", tmp_path)

    def explode(*_args, **_kwa):
        raise RuntimeError("lmdb went away")

    monkeypatch.setattr(cli.ingest, "ingest", explode)
    code = run("publish", "--stream", str(stream), "--did", facts["did_webs"], "--out", str(tmp_path))

    captured = capsys.readouterr()
    assert code == 1
    assert "e.self.unknown.f" in captured.err
    assert "lmdb went away" in captured.err


def test_a_stream_file_that_is_not_there_is_a_usage_error(tmp_path, capsys):
    """Exit 64 is `EX_USAGE`: the operator's invocation was wrong, and nothing about the
    submission was even read. Distinct from exit 1, which means a submission was refused."""
    code = run(
        "publish",
        "--stream",
        str(tmp_path / "absent.cesr"),
        "--did",
        f"did:webs:{DOMAIN}:EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP",
        "--out",
        str(tmp_path),
    )

    captured = capsys.readouterr()
    assert code == 64
    assert "absent.cesr" in captured.err


def test_invoking_the_command_with_no_verb_is_a_usage_error(capsys):
    assert run() == 64
    assert capsys.readouterr().err.strip() != ""


def test_a_missing_required_argument_is_a_usage_error(tmp_path, capsys):
    assert run("publish", "--did", "did:webs:x") == 64
    assert "--stream" in capsys.readouterr().err


def test_an_unknown_verb_is_a_usage_error(capsys):
    assert run("resolve") == 64
    assert capsys.readouterr().err.strip() != ""


# ------------------------------------------------------- the installed entry point (#19)


@pytest.fixture(scope="module")
def keystore_stream(tmp_path_factory):
    """A publication stream produced by the keystore-side entry point, in its own process.

    `python -m didwebs.assemble` is how fixtures and demos make a stream (docs/design.md
    §Modules); it is deliberately not a console verb, because issuing a controller's
    designated-aliases credential is not something Bakobo's product does.
    """
    root = tmp_path_factory.mktemp("keystore")
    stream = root / "publication.cesr"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "didwebs.assemble",
            "--keystore",
            str(root / "ks"),
            "--domain",
            DOMAIN,
            "--out",
            str(stream),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return stream, proc.stdout.strip()


def test_the_keystore_entry_point_writes_a_stream_and_prints_its_did(keystore_stream):
    stream, did = keystore_stream

    assert did.startswith(f"did:webs:{DOMAIN}:")
    assert stream.read_bytes().startswith(b'{"v":"KERI10JSON')
    assert set(keri_api.version_strings(stream.read_bytes())) <= keri_api.ACCEPTED_VERSION_STRINGS


def test_the_installed_entry_point_publishes_end_to_end(keystore_stream, tmp_path):
    """Ledger #19: the real `didwebs` console script, in a subprocess, from a stream this
    package's own keystore side produced — so a broken script entry, a missing dependency or
    an import-time error shows up here rather than in a hand check."""
    stream, did = keystore_stream
    out = tmp_path / "www"

    proc = subprocess.run(
        ["uv", "run", "didwebs", "publish", "--stream", str(stream), "--did", did, "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    aid = did.rsplit(":", 1)[-1]
    assert proc.returncode == 0, proc.stderr
    assert (out / aid / "did.json").exists()
    assert (out / aid / "keri.cesr").exists()

    republished = (out / aid / "keri.cesr").read_bytes()
    with ingest.ingest(republished, did_module.parse(did)) as verified:
        assert verified.aid == aid


@pytest.mark.parametrize("knob,code", REJECTIONS, ids=[knob for knob, _ in REJECTIONS])
def test_no_refused_submission_leaves_an_artifact_tree_behind(knob, code, tmp_path):
    """The operator contract over the *whole* negative matrix, through the real binary.

    Two tests above establish the contract on one refusal each. This one establishes that it
    holds for every stream the pipeline refuses, whatever the reason — a bad signature, a fork, a
    stranger's publication, a serialization this build will not read. A half-published DID is
    worse than an unpublished one, and the way that would happen is a failure mode nobody wrote
    an individual test for, so the assertion is made against the matrix rather than against a
    chosen example (ledger #22).

    Driven as a subprocess rather than in process: what an operator runs is the installed console
    script, and the claim "nothing was published" is about what is on disk after that process
    exits, not about what a function returned.
    """
    stream, facts = fixture_stream(knob, tmp_path)
    out = tmp_path / "www"

    proc = subprocess.run(
        [
            "uv", "run", "didwebs", "publish",
            "--stream", str(stream), "--did", facts["did_webs"], "--out", str(out),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert proc.returncode == 1
    assert proc.stdout == ""
    assert code in proc.stderr
    assert not out.exists()  # not the AID's directory, not the output root, nothing


def test_the_installed_entry_point_reports_a_refusal_on_stderr(tmp_path):
    """The other half of the operator contract, through the real binary: exit 1, the code on
    stderr, nothing on stdout."""
    stream = tmp_path / "garbage.cesr"
    stream.write_bytes(b"not a cesr stream at all")
    did = f"did:webs:{DOMAIN}:EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP"

    proc = subprocess.run(
        ["uv", "run", "didwebs", "publish", "--stream", str(stream), "--did", did, "--out", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "e.input.format.stream.f" in proc.stderr
