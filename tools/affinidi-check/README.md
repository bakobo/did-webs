# Affinidi artifact check

This small binary pins `affinidi-did-webs` 0.7.0. It reads an already published
`did.json` and `keri.cesr` locally, calls Affinidi's `resolve_from_artifacts` with
**both** resources, and prints its derived DID document or its rejection. It needs
no network, proxy, TLS setup, or Affinidi checkout. Cargo downloads the pinned
crates on a cold start; `Cargo.lock` fixes their transitive versions.

From this repository's root:

```sh
nice -n 19 ionice -c 3 cargo run --locked --manifest-path tools/affinidi-check/Cargo.toml -- \
  'did:webs:dids.bakobo.com:demo:<AID>' \
  '/path/to/<AID>/keri.cesr' '/path/to/<AID>/did.json'
```

Exit code 0 means Affinidi accepted both artifacts. Exit code 1 means an invocation,
file-read, or resolver failure; stderr includes a symbolic code and Affinidi's reason.
Use a copy of each artifact to test tampering, then compare with the untampered run.
The harness does not silently omit `did.json`: Affinidi's API makes that argument
optional, but doing so would skip even its partial document check.

Run its own tests with `nice -n 19 ionice -c 3 cargo test --locked --manifest-path
tools/affinidi-check/Cargo.toml`.
