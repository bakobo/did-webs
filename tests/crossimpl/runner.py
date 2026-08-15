"""Drives ``resolver_runner.py`` as a subprocess in the resolver's own venv, from this project's
own Python 3.14 process.

**Edge defaults this module owns** (brief F, "Edge defaults"): the subprocess gets a temp
``HOME``/``XDG_*`` so it can never write into the real ``~/.keri`` (worker E's F8 incident,
defense in depth alongside ``resolver_runner.py``'s own ``temp=True`` stores); its stdout/stderr
are always captured to a file; a subprocess that does not run to completion -- nonzero exit,
timeout, or a stdout that is not the one line of JSON the runner promises -- is
:class:`ResolverCrashed`, a test **failure**, never a skip, with the log's tail quoted in the
message so a CI failure is diagnosable without re-running anything.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from crossimpl import resolver_venv

HERE = Path(__file__).resolve().parent
RESOLVER_RUNNER = HERE / "resolver_runner.py"

#: OPS forward form: "fail loudly and cheaply" -- a hung resolver subprocess must not hang CI.
TIMEOUT_SECONDS = 60

#: Lines of the captured log kept in a crash message -- enough to diagnose, not a log dump.
TAIL_LINES = 40


class ResolverCrashed(AssertionError):
    """The subprocess itself did not run to completion.

    Distinct from a normal ``verdict: "FAILED"`` report, which means ``save_cesr`` raised and
    ran to completion anyway -- that is reportable data a test asserts on. This is the process
    dying, timing out, or saying something the JSON contract does not allow, none of which any
    assertion about the resolver's *behavior* should have to anticipate.
    """


def _temp_home(tmp_path) -> dict[str, str]:
    """A scratch ``HOME`` (and every ``XDG_*`` base) for the resolver subprocess.

    keri 1.2.13's ``openHby(temp=True)`` already stores its databases under the system temp
    directory regardless of ``HOME`` (its own docstring says so, and the spike's runs confirm
    it) -- this override does not depend on that fact holding, though. It is a second,
    independent guarantee, exactly what "worker E's F8 incident" in the brief asks for: nothing
    in the resolver's dependency chain gets a real home directory to fall back to, whichever
    code path would have used one.
    """
    home = Path(tmp_path) / "resolver-home"
    home.mkdir(parents=True, exist_ok=True)
    return {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
    }


def run(stream: bytes, *, aid: str, did: str, tmp_path, name: str = "crossimpl-res") -> dict:
    """Ingest ``stream`` in the resolver's own venv; return its JSON report (see
    ``resolver_runner.py`` for the ``verdict``/``did_doc`` shape).

    Args:
        stream: the ``keri.cesr`` bytes to hand the resolver -- always ``emit_stream``'s output
            (constraint ``embuup``), never a fixture's raw submission bytes.
        aid: the AID the stream claims to publish.
        did: the did:webs DID to derive a document for.
        tmp_path: a pytest ``tmp_path`` (or any scratch directory) this call may write under.
        name: Habery name inside the resolver subprocess; distinct names let parallel test runs
            share nothing even though each subprocess's stores are ``temp=True``.

    Raises:
        ResolverCrashed: the subprocess did not run to completion.
    """
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    stream_path = tmp_path / "keri.cesr"
    stream_path.write_bytes(stream)

    env = dict(os.environ)
    env.update(_temp_home(tmp_path))

    log_path = tmp_path / "resolver-subprocess.log"
    cmd = [
        str(resolver_venv.python_path()),
        str(RESOLVER_RUNNER),
        "--stream",
        str(stream_path),
        "--aid",
        aid,
        "--did",
        did,
        "--name",
        name,
    ]
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        log_path.write_text(
            f"$ {' '.join(cmd)}\nTIMED OUT after {TIMEOUT_SECONDS}s\n"
            f"--- stdout so far ---\n{exc.stdout or ''}\n--- stderr so far ---\n{exc.stderr or ''}\n"
        )
        raise ResolverCrashed(
            f"resolver subprocess timed out after {TIMEOUT_SECONDS}s (log: {log_path})"
        ) from exc

    log_path.write_text(
        f"$ {' '.join(cmd)}\nexit: {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n"
    )

    def _crash(reason: str) -> None:
        combined = (proc.stdout + proc.stderr).splitlines()
        tail = "\n".join(combined[-TAIL_LINES:])
        raise ResolverCrashed(f"{reason} (log: {log_path})\n{tail}")

    if proc.returncode != 0:
        _crash(f"resolver subprocess exited {proc.returncode}")

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        _crash("resolver subprocess produced no output")
    try:
        return json.loads(lines[-1])
    except ValueError:
        _crash("resolver subprocess's last line of stdout was not valid JSON")
        raise  # `_crash` always raises `ResolverCrashed`; this satisfies static analysis only
