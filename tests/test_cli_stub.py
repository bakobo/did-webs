"""didwebs.cli — STUB. `main()` prints one plain-sentence line to stderr saying the publish
command is not yet implemented, and exits 64. A later brief replaces this under TDD (this.i
routes the implication to plan session task #5)."""

from __future__ import annotations

import subprocess

from didwebs import cli


def test_main_prints_a_one_line_stderr_sentence_and_returns_64(capsys):
    exit_code = cli.main([])

    captured = capsys.readouterr()
    assert exit_code == 64
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1
    assert lines[0].endswith(".")
    assert "publish" in lines[0].lower()
    assert "not" in lines[0].lower() and "implement" in lines[0].lower()


def test_main_ignores_its_argv_and_still_returns_64():
    assert cli.main(["publish", "--stream", "x", "--did", "y", "--out", "z"]) == 64


def test_installed_console_script_exits_64_with_the_same_stderr_line():
    # Install-and-invoke oracle (ledger #19): the real `didwebs` entry point, not main() called
    # in-process, so a broken [project.scripts] wiring shows up here rather than only in the
    # craftsman's manual `uv run didwebs` check.
    proc = subprocess.run(
        ["uv", "run", "didwebs"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 64
    assert proc.stdout == ""
    lines = proc.stderr.splitlines()
    assert len(lines) == 1
    assert lines[0].endswith(".")
