# Patched Affinidi artifact check

This alternate uses the same local artifact checker as `../affinidi-check`,
with Affinidi's KERI crates patched from the public fork described in
[`docs/affinidi-fork.md`](../../docs/affinidi-fork.md). A cold build needs no
credentials.

From the repository root, run the saved M7 pair after Guy's rotation:

```sh
cargo run --locked \
  --manifest-path tools/affinidi-check-patched/Cargo.toml -- \
  'did:webs:dids.bakobo.com:demo:ELEGG02va7qWpBiTCQfTXFwbNTk-FVWJr7nWJX2DhHy7' \
  tools/affinidi-check-patched/tests/fixtures/guy-rotated/keri.cesr \
  tools/affinidi-check-patched/tests/fixtures/guy-rotated/did.json
```

Run both saved DIDs and the two tampering checks with:

```sh
cargo test --locked \
  --manifest-path tools/affinidi-check-patched/Cargo.toml
```

The checker reports failure with a symbolic error code and exit status 1. Its
success has the documented scope in `docs/affinidi-fork.md`.
