"""The door census.

dev/standards/input-handling.md requires one test per repo that enumerates the primitives which
bring bytes across a boundary and asserts each call site sits inside a named door or is listed as
an exemption **with a written reason**. This is that test (constraint ``adyiw2mm``).

It fails on *new* call sites, which is the whole point: a read that bypasses a door never looks
wrong when you write it, and a rule that lives only in a document is one a new call site never
hears about.

**What counts as a boundary primitive** is the list in :data:`PRIMITIVES` below. Two judgments in
it are arguable, and are stated here so a reviewer can disagree with them rather than having to
infer them:

* **Opening a file to write is not an input boundary.** ``open(path, "wb")`` brings no bytes in,
  so ``publish.py`` writing artifacts is out of scope. The mode argument is what distinguishes
  them, and a call whose mode cannot be read statically is treated as a read -- the failing
  direction, so an obfuscated mode does not buy silence.
* **``argparse`` is not itself a door, but it is where argv enters.** When a command line lands,
  its call site is expected to appear here and to be given a reason, not waved through. Listing
  ``argv`` among the primitives does not achieve that on its own: argparse reads ``sys.argv``
  inside the library, so a package that never names it has no matching call site and the rule
  silently covers nothing. ``parse_args`` is therefore a primitive in its own right -- it is the
  moment a command line becomes values this package acts on, which is what the rule is about.

Adapted from the sibling ``bakobo/did-webvh``'s census, which this standard's first
implementation was written in.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SOURCE = pathlib.Path(__file__).resolve().parent.parent / "src" / "didwebs"

#: Names whose call or attribute access brings bytes across a boundary.
PRIMITIVES = {
    "open",
    "input",
    "read_bytes",
    "read_text",
    "iterdir",
    "argv",
    "parse_args",
    "stdin",
    "environ",
    "getenv",
}

#: Modules that would put a socket in this package. Phase 1 is host-side: the pipeline ingests a
#: file the operator supplies and writes two artifacts, and reaches nothing (decision ``avuwzl``,
#: cli.py's operator contract). So the guarantee worth asserting is that none of these is
#: imported at all -- stronger than chasing call sites, and it does not misfire.
#:
#: Matched as dotted prefixes rather than top-level packages, because ``urllib`` is two libraries
#: wearing one name: ``urllib.request`` opens sockets while ``urllib.parse`` is string
#: manipulation that DID percent-encoding legitimately uses.
NETWORK_MODULES = {
    "http",
    "httpx",
    "requests",
    "socket",
    "urllib.request",
    "urllib.error",
    "aiohttp",
    "ssl",
    "ftplib",
}

#: Every boundary call site that is not itself a door, each with the reason it needs none.
#: A new entry here is a claim somebody can disagree with; that is what it is for.
EXEMPTIONS: dict[str, str] = {
    "schemaing.py:_read_resource": (
        "Reads a JSON resource bundled inside the installed package, not anything a submitter "
        "supplied: the path comes from importlib.resources and the content ships in the wheel. "
        "Its integrity is checked by SAID rather than by size -- load_designated_aliases_schema "
        "hashes it against the pinned DES_ALIASES_SCHEMA_SAID and raises e.self.corrupt.schema.f "
        "on a mismatch, which is the stronger check and the right one for our own artifact. A "
        "byte bound here would guard against this build having been tampered with, which is a "
        "condition that bound could not detect and the SAID already does."
    ),
    "cli.py:main": (
        "argparse reads sys.argv, which is the operator's own command line rather than a "
        "submission: it arrives from the shell that invoked this process, is already bounded by "
        "the kernel's ARG_MAX, and is not attacker-controlled in a phase-1 local operator "
        "command (cli.py's operator contract). The values it yields are two paths and a DID "
        "string, and each is checked where it is used -- the stream through bounds.open_stream, "
        "the DID through did.parse. This exemption is the one to revisit first if a submission "
        "surface ever puts a caller other than the operator on the other end of these values."
    ),
    "assemble.py:main": (
        "The same argv reasoning, for the keystore-side entry point. This one is further from a "
        "boundary than the CLI is: it is the fixture and demo issuer that decision avuwzl keeps "
        "out of the product surface entirely, run against keystores we own, and it is never "
        "reachable by a customer or a submitter."
    ),
}


def _write_mode(node: ast.Call) -> bool:
    """Whether this ``open`` call is opening for writing, and so brings nothing in.

    A mode that is not a plain literal returns False -- treated as a read, which is the failing
    direction, so obfuscating the mode does not exempt a call site.
    """
    mode = None
    if len(node.args) > 1:
        mode = node.args[1]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return bool(set(mode.value) & set("wax"))
    return False


def _enclosing(tree: ast.Module, target: ast.AST) -> str:
    """The name of the function a node sits in, or ``<module>``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for descendant in ast.walk(node):
                if descendant is target:
                    return node.name
    return "<module>"


def boundary_sites() -> list[tuple[str, str, int]]:
    """Every boundary call site in the package, as ``(module, function, line)``."""
    found = []
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name == "open" and _write_mode(node):
                    continue
            elif isinstance(node, ast.Attribute):
                name = node.attr
            if name in PRIMITIVES:
                found.append((path.name, _enclosing(tree, node), node.lineno))
    return found


def test_the_census_finds_something():
    """Guards the walker: a census that silently matched nothing would pass forever."""
    assert boundary_sites(), "the AST walk found no boundary primitives at all, which is wrong"


def test_every_boundary_read_is_a_door_or_an_argued_exemption():
    from didwebs import bounds

    doors = {f"open_{door.kind}" for door in bounds.DOORS} | {"_read", "read_bounded"}
    stray = [
        f"{module}:{function}:{line}"
        for module, function, line in boundary_sites()
        if function not in doors and f"{module}:{function}" not in EXEMPTIONS
    ]
    assert not stray, (
        "these call sites bring bytes across a boundary outside any door. Either move the read "
        "inside a door in bounds.py, or add it to EXEMPTIONS with a written reason: "
        f"{stray}"
    )


def test_exemptions_carry_a_real_reason():
    """An exemption with an empty or token reason is worse than no exemption list at all."""
    for site, reason in EXEMPTIONS.items():
        assert len(reason.split()) >= 8, f"{site}'s exemption is not an argument: {reason!r}"


def test_every_exemption_still_names_a_live_call_site():
    """An exemption outliving the read it excused is a standing claim nobody is checking, and it
    would silently excuse a *new* read that happened to land in the same function."""
    sites = {f"{module}:{function}" for module, function, _ in boundary_sites()}
    assert set(EXEMPTIONS) <= sites, f"stale exemptions: {set(EXEMPTIONS) - sites}"


@pytest.mark.parametrize(
    ("snippet", "expected"),
    [
        ('open("x", "wb")', True),
        ('open("x", "w")', True),
        ('open("x", mode="ab")', True),
        ('open("x", "rb")', False),
        ('open("x")', False),
        ("open(path, mode)", False),
    ],
)
def test_write_mode_detection(snippet, expected):
    """The one judgment in the walker that could silently exempt a real read."""
    call = ast.parse(snippet, mode="eval").body
    assert _write_mode(call) is expected


def test_the_package_opens_no_sockets():
    """Phase 1 publishes from a submitted file and reaches nothing (decision ``avuwzl``)."""
    offenders = []
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if any(name == m or name.startswith(f"{m}.") for m in NETWORK_MODULES):
                    offenders.append(f"{path.name}:{node.lineno} imports {name}")
    assert not offenders, (
        "phase 1 has no network I/O; a resolver phase that needs one must say so in this.i "
        f"first: {offenders}"
    )
