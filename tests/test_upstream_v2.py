"""The upstream-keripy oracle: every v2 ``keri.cesr`` didwebs emits verifies under stock
WebOfTrust/keripy main, and the streams didwebs refuses for upstream's sake are refused there too.

Decision ``0plkq8s8`` makes the v2 target what upstream keripy main accepts, not the bakobo
fork this project's venv runs. Everything else in this suite vets with the fork, so it proves
less than it seems to about that target. Here the emitted bytes go to upstream's own
``keri.acdc.regeventing.vet``, in a venv of its own (``tests/upstream/keripy_venv.py``), via a
script that imports nothing of ours (``tests/upstream/vet_stream.py``).

**Skip vs. fail**, as in ``tests/test_crossimpl.py`` and with the same switch: a missing venv
skips locally, and ``DIDWEBS_CROSSIMPL=required`` turns it into a failure, because an oracle
that can silently stop running is no oracle. The guard and runner tests below need no venv.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import builders_v2
import pytest
from upstream import keripy_venv

from didwebs import assemble, ingest
from didwebs.did import parse as parse_did

#: The same switch `tests/test_crossimpl.py` reads, so one CI setting governs both oracles.
REQUIRED_ENV = "DIDWEBS_CROSSIMPL"
REQUIRED_VALUE = "required"

VET_STREAM = Path(keripy_venv.__file__).resolve().parent / "vet_stream.py"

#: A hung upstream process must not hang the suite.
TIMEOUT_SECONDS = 60

#: Lines of captured stderr quoted in a crash message.
TAIL_LINES = 40


class UpstreamCrashed(AssertionError):
    """The upstream process did not run to completion under its contract.

    Distinct from a refusal, which is exit 1 with a JSON ``error`` line and is data a test
    asserts on. This is a timeout, an unexpected exit status, or output the contract does not
    allow.
    """


def _venv_guard() -> None:
    """Skip, or in CI-required mode fail, when the upstream venv is not provisioned."""
    if keripy_venv.available():
        return
    reason = (
        f"upstream keripy venv not provisioned at {keripy_venv.VENV_DIR} -- run "
        "'uv run python tests/upstream/keripy_venv.py provision' first"
    )
    if os.environ.get(REQUIRED_ENV) == REQUIRED_VALUE:
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture
def venv_guard():
    """Applied explicitly, never autouse, so the guard's own tests are never gated by it."""
    _venv_guard()


def _tail(text: str) -> str:
    return "\n".join(text.splitlines()[-TAIL_LINES:])


def run_upstream(stream: bytes, tmp_path, *, python=None, script=VET_STREAM) -> dict:
    """Vet ``stream`` in the upstream venv.

    Returns ``{"records": [...]}`` when upstream accepts the stream, or ``{"error": ...,
    "message": ...}`` when it refuses it.

    Raises:
        UpstreamCrashed: the process timed out, exited other than 0 or 1, or printed something
            other than the JSON its contract promises.
    """
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    stream_path = tmp_path / "keri.cesr"
    stream_path.write_bytes(stream)
    home = tmp_path / "upstream-home"
    home.mkdir(exist_ok=True)
    stores = tmp_path / "keri-stores"
    env = {
        **os.environ,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "DIDWEBS_TEMP_HEAD": str(stores),
        "PYTHONWARNINGS": "ignore",
    }
    cmd = [str(python or keripy_venv.python_path()), str(script), str(stream_path)]
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise UpstreamCrashed(
            f"upstream vet timed out after {TIMEOUT_SECONDS}s\n{_tail(str(exc.stderr or ''))}"
        ) from exc
    finally:
        shutil.rmtree(stores, ignore_errors=True)

    def crash(reason: str) -> UpstreamCrashed:
        return UpstreamCrashed(f"{reason}\n--- stdout ---\n{_tail(proc.stdout)}\n"
                               f"--- stderr ---\n{_tail(proc.stderr)}")

    if proc.returncode not in (0, 1):
        raise crash(f"upstream vet exited {proc.returncode}")
    try:
        lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    except ValueError:
        raise crash("upstream vet printed something that is not JSON") from None
    if proc.returncode == 1:
        if len(lines) != 1 or "error" not in lines[0]:
            raise crash("upstream vet exited 1 without exactly one JSON error line")
        return lines[0]
    return {"records": lines}


def _emit(knob: str, tmp_path):
    stream, facts = builders_v2.KNOBS[knob](tmp_path / "fixture")
    with ingest.ingest(stream, parse_did(facts["did_webs"])) as verified:
        return assemble.emit_stream(verified), facts


# --------------------------------------------------------------------------- the oracle


@pytest.mark.parametrize("knob", builders_v2.POSITIVE)
def test_upstream_vets_every_emitted_v2_stream_as_issued_and_mutually_bound(
    knob, tmp_path, venv_guard
):
    emitted, facts = _emit(knob, tmp_path)

    report = run_upstream(emitted, tmp_path / "upstream")

    assert "error" not in report, f"upstream keripy refused the emitted {knob!r} stream: {report}"
    designation = [r for r in report["records"] if r["regid"] == facts["regk"]]
    assert designation, f"upstream found no designation registry in {knob!r}: {report}"
    assert designation[0] == {
        "regid": facts["regk"],
        "issuer": facts["aid"],
        "state": "issued",
        "binding": "mutual",
        "acdc": facts["acdc_said"],
    }


def test_upstream_also_refuses_a_registry_updated_with_upd(tmp_path, venv_guard):
    """didwebs refuses ``upd`` because upstream does (0plkq8s8); this is that agreement,
    observed. The refusal must be upstream rejecting the ``upd`` itself, not a parse failure
    that would refuse any trailing message."""
    stream, _ = builders_v2.upd_update(tmp_path / "fixture")

    report = run_upstream(stream, tmp_path / "upstream")

    assert report.get("error") == "ValidationError", report
    assert "Unsupported registry event type upd" in report["message"]


def test_upstream_refuses_a_misdisclosed_head(tmp_path, venv_guard):
    stream, _ = builders_v2.misdisclosed(tmp_path / "fixture")

    report = run_upstream(stream, tmp_path / "upstream")

    assert report.get("error") == "UnverifiedBlindError", report


def test_upstream_refuses_an_undisclosed_head_bound_to_its_acdc(tmp_path, venv_guard):
    """A bare ``bup`` leaves the head blinded, and nothing then binds the ACDC to it."""
    stream, _ = builders_v2.undisclosed(tmp_path / "fixture")

    report = run_upstream(stream, tmp_path / "upstream")

    assert report.get("error") == "UnverifiedBlindError", report


def test_upstream_refuses_a_stream_ending_mid_body(tmp_path, venv_guard):
    stream, _ = builders_v2.garbage_tail(tmp_path / "fixture")

    report = run_upstream(stream, tmp_path / "upstream")

    assert "error" in report, report


def test_upstream_refuses_a_final_body_trailed_by_a_partial_attachment(tmp_path, venv_guard):
    """The unattached-final-body allowance covers exactly one whole body, nothing after it."""
    stream, _ = builders_v2.upd_update(tmp_path / "fixture")

    report = run_upstream(stream + b"-", tmp_path / "upstream")

    assert report.get("error") == "ShortageError", report


def test_the_script_runs_by_hand_with_no_named_temp_head(tmp_path, venv_guard):
    """Without ``DIDWEBS_TEMP_HEAD`` the script still runs, its stores under ``TMPDIR``."""
    emitted, facts = _emit("base", tmp_path)
    stream_path = tmp_path / "keri.cesr"
    stream_path.write_bytes(emitted)
    scratch = tmp_path / "tmpdir"
    scratch.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "DIDWEBS_TEMP_HEAD"}
    env.update(TMPDIR=str(scratch), PYTHONWARNINGS="ignore")

    proc = subprocess.run(
        [str(keripy_venv.python_path()), str(VET_STREAM), str(stream_path)],
        env=env, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout.splitlines()[0])["acdc"] == facts["acdc_said"]


def test_the_script_refuses_to_run_without_exactly_one_stream(tmp_path, venv_guard):
    proc = subprocess.run(
        [str(keripy_venv.python_path()), str(VET_STREAM)],
        capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False,
    )
    assert proc.returncode == 2
    assert "usage" in proc.stderr


# ----------------------------------------------------------------- the guard, no venv needed


def test_the_guard_passes_when_the_venv_is_provisioned(monkeypatch):
    monkeypatch.setattr(keripy_venv, "available", lambda: True)
    _venv_guard()


def test_the_guard_skips_by_default_when_the_venv_is_absent(monkeypatch):
    monkeypatch.setattr(keripy_venv, "available", lambda: False)
    monkeypatch.delenv(REQUIRED_ENV, raising=False)
    with pytest.raises(pytest.skip.Exception, match="keripy_venv.py provision"):
        _venv_guard()


def test_the_guard_fails_when_required_and_the_venv_is_absent(monkeypatch):
    monkeypatch.setattr(keripy_venv, "available", lambda: False)
    monkeypatch.setenv(REQUIRED_ENV, REQUIRED_VALUE)
    with pytest.raises(pytest.fail.Exception, match="keripy_venv.py provision"):
        _venv_guard()


# ---------------------------------------------------------------- the runner, no venv needed


def _fake_script(tmp_path, body: str) -> Path:
    script = tmp_path / "fake.py"
    script.write_text(body)
    return script


def _run_fake(tmp_path, body: str) -> dict:
    import sys

    return run_upstream(
        b"x", tmp_path / "run", python=sys.executable, script=_fake_script(tmp_path, body)
    )


def test_the_runner_returns_every_record_on_success(tmp_path):
    report = _run_fake(tmp_path, 'print(\'{"regid": "a"}\')\nprint(\'{"regid": "b"}\')\n')
    assert report == {"records": [{"regid": "a"}, {"regid": "b"}]}


def test_the_runner_returns_the_refusal(tmp_path):
    report = _run_fake(
        tmp_path, 'import sys\nprint(\'{"error": "X", "message": "m"}\')\nsys.exit(1)\n'
    )
    assert report == {"error": "X", "message": "m"}


def test_the_runner_names_the_temp_head_and_removes_it(tmp_path):
    body = (
        "import os, pathlib\n"
        "head = pathlib.Path(os.environ['DIDWEBS_TEMP_HEAD'])\n"
        "head.mkdir(parents=True)\n"
        "(head / 'store').write_text('x')\n"
        "print('{}')\n"
    )
    _run_fake(tmp_path, body)
    assert not (tmp_path / "run" / "keri-stores").exists()


@pytest.mark.parametrize(
    "body, reason",
    [
        ("import sys\nsys.stderr.write('boom\\n')\nsys.exit(3)\n", "exited 3"),
        ("print('not json')\n", "not JSON"),
        ("import sys\nsys.exit(1)\n", "exactly one JSON error line"),
        ("import sys\nprint('{\"regid\": \"a\"}')\nsys.exit(1)\n", "exactly one JSON error line"),
    ],
)
def test_the_runner_treats_a_broken_contract_as_a_crash_quoting_stderr(tmp_path, body, reason):
    with pytest.raises(UpstreamCrashed, match=reason) as crashed:
        _run_fake(tmp_path, body)
    if "boom" in body:
        assert "boom" in str(crashed.value)


def test_the_runner_treats_a_timeout_as_a_crash(tmp_path, monkeypatch):
    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], TIMEOUT_SECONDS, stderr="stuck")

    monkeypatch.setattr(subprocess, "run", hang)
    with pytest.raises(UpstreamCrashed, match="timed out") as crashed:
        run_upstream(b"x", tmp_path)
    assert "stuck" in str(crashed.value)


# -------------------------------------------------------- the provisioner, no venv needed


@pytest.fixture
def scratch_venv(tmp_path, monkeypatch):
    """Point the provisioner at a scratch directory and record the commands it would run."""
    venv = tmp_path / ".venv"
    monkeypatch.setattr(keripy_venv, "VENV_DIR", venv)
    monkeypatch.setattr(keripy_venv, "MARKER", venv / f".pin-{keripy_venv.KERIPY_PIN}")
    commands = []

    def fake_run(cmd):
        commands.append(cmd)
        if cmd[1] == "venv":
            (venv / "bin").mkdir(parents=True)
            (venv / "bin" / "python").touch()

    monkeypatch.setattr(keripy_venv, "_run", fake_run)
    return venv, commands


def test_provisioning_installs_the_pinned_upstream_ref_and_stamps_the_pin(scratch_venv):
    venv, commands = scratch_venv
    assert not keripy_venv.available()

    assert keripy_venv.provision() == venv

    assert commands[0] == ["uv", "venv", "--python", "3.14", str(venv)]
    assert commands[1][-1] == (
        "keri @ git+https://github.com/WebOfTrust/keripy@624df82944a1b8ed1ab3d7b9d643a84e1c278426"
    )
    assert keripy_venv.available()


def test_provisioning_is_a_no_op_once_the_pin_is_stamped(scratch_venv):
    _, commands = scratch_venv
    keripy_venv.provision()
    commands.clear()

    keripy_venv.provision()

    assert commands == []


def test_forced_provisioning_rebuilds_from_scratch(scratch_venv):
    venv, commands = scratch_venv
    keripy_venv.provision()
    (venv / "stale").touch()
    commands.clear()

    keripy_venv.provision(force=True)

    assert len(commands) == 2
    assert not (venv / "stale").exists()


def test_the_cli_provisions_and_prints_the_path(scratch_venv, capsys):
    venv, _ = scratch_venv
    assert keripy_venv.main(["provision"]) == 0
    assert keripy_venv.main(["path"]) == 0
    assert capsys.readouterr().out.splitlines() == [str(venv), str(venv)]


@pytest.mark.parametrize(
    "nice, expected", [("/usr/bin/nice", ["nice", "-n", "19", "true"]), (None, ["true"])]
)
def test_the_real_run_helper_runs_under_nice_when_it_can(monkeypatch, nice, expected):
    calls = []
    monkeypatch.setattr(keripy_venv.shutil, "which", lambda name: nice)
    monkeypatch.setattr(keripy_venv.subprocess, "run", lambda cmd, check: calls.append(cmd))

    keripy_venv._run(["true"])

    assert calls == [expected]
