[![CI](https://github.com/bakobo/did-webs/actions/workflows/ci.yml/badge.svg)](https://github.com/bakobo/did-webs/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# did-webs

Publish [`did:webs`](https://github.com/trustoverip/kswg-did-method-webs-specification) DIDs
for KERI-controlled AIDs on Bakobo infrastructure. A controller-produced CESR publication stream
and the DID it claims to back go in; verified artifacts — `did.json` and `keri.cesr` — come out,
derived from what [keripy](https://github.com/WebOfTrust/keripy) actually accepted, never from
the submitted bytes.

Phase 1 is publish-only, host-side, with no network I/O. The design and its rationale live in
`this.i` (the intent tree, the source of truth) and `docs/`.

## Requirements

- Python ≥ 3.14
- [`uv`](https://docs.astral.sh/uv/)

## From a fresh clone to passing tests

```sh
uv sync
uv run pytest
```

`uv sync` installs the pinned `keri` and `bakobo-errors` packages; `uv run pytest` runs the
suite under a **100% branch-coverage gate** (`--cov-fail-under=100`).

## Command line

```sh
uv run didwebs publish --stream <keri.cesr> --did <did:webs:...> --out <dir>
```

`publish` verifies the submitted CESR stream, then writes `did.json` and `keri.cesr` into the
output directory. Refusal leaves no artifact tree behind: either both files appear or neither
does. Run `uv run didwebs publish --help` for the full argument list.

## License

Apache-2.0.
