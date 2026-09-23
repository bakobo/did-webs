# Patched Affinidi artifact check

This alternate uses the same local artifact checker as `../affinidi-check` with
the pinned private Bakobo Affinidi copies described in
[`docs/affinidi-fork.md`](../../docs/affinidi-fork.md). A cold build requires
Bakobo read access to both private Git repositories and Cargo's Git CLI mode.

From the repository root, run the saved M7 pair after Guy's rotation:

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo run --locked \
  --manifest-path tools/affinidi-check-patched/Cargo.toml -- \
  'did:webs:dids.bakobo.com:demo:ELEGG02va7qWpBiTCQfTXFwbNTk-FVWJr7nWJX2DhHy7' \
  tools/affinidi-check-patched/tests/fixtures/guy-rotated/keri.cesr \
  tools/affinidi-check-patched/tests/fixtures/guy-rotated/did.json
```

Run both saved DIDs and the two tampering checks with:

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo test --locked \
  --manifest-path tools/affinidi-check-patched/Cargo.toml
```

The checker reports failure with a symbolic error code and exit status 1. Its
success has the documented scope in `docs/affinidi-fork.md`.
