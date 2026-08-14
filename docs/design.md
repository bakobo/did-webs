# didwebs phase-1 design

Status: draft for KERI review panel (2026-08-14). Governing intent: `this.i` — goal `xckiyf`;
decisions `jo5sby` (Python on keripy), `3woefn` (Ed25519-only v1), `ecwpad` (publish-first),
`avuwzl` (non-custodial stream ingestion), `gvimca`+`qbqfst` (estate keripy, protocol v1 pinned).
Requirements background: [`scope.md`](scope.md). Spec citations are headings in
`~/code/wot/kswg-did-method-webs-specification/spec/body.md`.

## Shape

One Python package, `didwebs`, src layout, with a `didwebs` console script. Python ≥3.14. The
`keri` dependency is the estate pin — `bakobo/keripy@366d810`, same commit `witness` and `heti`
pin — with protocol v1 passed explicitly at every event-constructing and replay call site
(constraint `qbqfst`). Two API notes from the spike that differ from the GLEIF reference code:
`SerderACDC.regi` is renamed `.regid` on this line, and the GLEIF resolver requires Python
<3.14, so interop tests drive it in its own venv, never in-process.

The product surface (decision `avuwzl`) is host-side: bytes in — a controller-produced CESR
stream and the DID it claims to back — verified artifacts out. The keystore side (issue the
designated-aliases ACDC, assemble a stream) exists for keystores we control: tests, demos, and
the fixture pipeline. Phase 1 does no network I/O at all: streams arrive as files/bytes, OOBIs
are never dereferenced, and a delegated AID whose delegator KEL is not in the stream is an
error, not a fetch.

## Modules

- `didwebs/did.py` — the `WebsDid` value type. Parse/compose/validate per the spec ABNF
  (`### Method-Specific Identifier`): host, percent-encoded port, `:`-separated path segments,
  AID as final component. URL derivation (`did.json` / `keri.cesr` — `### Target System(s)`),
  and the did:web form of the same identifier. Pure functions, no keripy imports; the regex
  corpus and WSGI re-quoting lessons from the reference (`dws/core/didding.py:28-206`) inform
  the tests, not the code. The spec ABNF rejects non-transferable AIDs (scope soft spot 3); we
  implement the ABNF as written and carry the soft spot upstream.
- `didwebs/errors.py` — the error registry per `dev/standards/error-codes.md` (codes below).
- `didwebs/ingest.py` — `ingest(stream: bytes, did: WebsDid) -> Verified`. Builds a **scratch
  keripy Habery in a per-call temporary directory** — verified state never persists, and no two
  ingestions share LMDB state (the reference's shared long-lived database is the design we
  explicitly rejected; see scope, reference-impl gaps). Parser stack per the reference recipe
  (`dws/core/resolving.py:89-127`): Router/Revery **before** Kevery, Tevery, reply routes
  registered on both, escrow drains. Post-conditions, all mandatory (`#### Read (Resolve)`
  steps 3–4): the AID's key state is established; the stream carries a designated-aliases ACDC
  whose schema SAID equals the pinned `EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5` (bundled
  as a package resource and SAID-recomputed at load, the `dws/core/schemaing.py` pattern);
  the ACDC is issued and not revoked in its TEL; and its `a.ids` contains the claimed did:webs
  DID and the corresponding did:web DID (both forms, per resolution step 4 — soft spot 2 read
  conservatively). Because 1.2-line parsers silently drop frames they cannot read, ingest
  **pre-scans the stream's frame version strings and rejects anything other than
  `KERI10JSON`/`ACDC10JSON`** before parsing, so "parsed without error" can never mean
  "silently ignored half the stream".
- `didwebs/document.py` — `derive_document(v: Verified, did: WebsDid) -> dict`, pure once given
  verified state. Emits the complete document (`## DID documents`): `@context`, `id`,
  `controller` (= `id`), one `JsonWebKey`/`publicKeyJwk` verification method per current key
  (Ed25519 only, decision `3woefn`; any other CESR key code fails), `ConditionalProof2022` for
  numeric `kt > 1` and LCD-expanded fractional weights (`#### Thresholds`), `authentication` +
  `assertionMethod` (both mandatory — the reference omits them; `### Verification
  Relationships`), services projected from verified state (witness from the KEL `b` list +
  `/loc/scheme`; mailbox/agent from `/end/role/add` + `/loc/scheme`; `DelegatorOOBI` for
  delegated AIDs), and `alsoKnownAs` (always `did:keri:<aid>`, plus ACDC-authorized forms).
  `to_did_web(doc)` produces the hosted form (`### Transformation to did:web DID document`).
  Deactivation (null next keys → non-transferable key state) is detected and derivation still
  succeeds — deactivated DIDs must keep publishing (`#### Deactivate`).
- `didwebs/assemble.py` — keystore-side. `issue_aliases(hab, regery, ids)` creates the registry
  (`vcp`), issues the self-attested ACDC against the pinned schema, anchors via `ixn`;
  `assemble_stream(hab, regery) -> bytes` replays the KEL (delegator first for delegated AIDs),
  clones TEL and ACDC with `signing.serialize`, appends `rpy` location/role records — the
  re-ingestable order from `dws/core/artifacting.py:57-176`, ported to the 2.0-dev API
  (`.regid`), v1 pinned per `qbqfst`.
- `didwebs/publish.py` — `publish(out_root, did, doc, stream)`: writes
  `<out_root>/<path…>/<aid>/did.json` and `keri.cesr`, atomically (write-tempfile-rename), so
  update and deactivate are the same operation: re-ingest a newer stream, regenerate, overwrite
  in place (`#### Update`).
- `didwebs/cli.py` — two verbs. `didwebs publish --stream <file> --did <did> --out <dir>`: the
  product path, ingest→derive→publish, exit nonzero with the error code on any failure.
  `didwebs generate`: the keystore path (name/base/passcode args as keripy conventions dictate),
  for demos and fixtures. No serving verb in phase 1 (scope, phase 3).

The pipeline, end to end: `parse → ingest (verify) → derive → to_did_web → publish`. Every
artifact we host is derived from a stream we verified; the controller's submitted `did.json`,
if any, is never copied through.

## Trust boundaries

Untrusted: the stream bytes and the claimed DID. Trusted after ingest: keripy-verified key
state, TEL state, and BADA-accepted reply state in the scratch database. The principal model is
one controller per publication — how Bakobo authenticates *which customer* may submit a stream
for a given AID is a phase-3 service concern, but the artifact pipeline is already safe against
a hostile stream: everything served is derived, verification is fail-closed
(org principle 8), and nothing unverified escapes into artifacts. Witness-receipt/TOAD
enforcement (`wmoq5b`) is resolver policy — phase 2; at publish time the controller vouches for
their own stream.

## Error codes (proposed; reconcile against the bakobo/errors core registry before minting)

| Code | Condition |
|---|---|
| `e.input.format.did.f` | string is not a valid did:webs identifier |
| `e.input.format.stream.f` | CESR unparseable, or a frame's version string is outside the v1 set |
| `e.input.missing.alias-acdc.f` | stream carries no designated-aliases ACDC (absence established: we hold the whole stream) |
| `e.input.missing.delegator.f` | delegated AID but no delegator KEL in the stream |
| `e.proof.stream.f` (leaves per keripy failure) | cryptographic verification of the stream failed |
| `e.state.conflict.kel.f` | stream diverges from itself (duplicity within the submission) |
| `e.state.revoked.alias-acdc.f` | the designated-aliases ACDC is revoked |
| `e.grant.scope.alias.f` | ACDC verifies but its `a.ids` does not authorize the claimed DID (or its did:web form) |
| `e.feature.unsupported.key-alg.f` | non-Ed25519 key in current key state (decision `3woefn`) |
| `e.self.unknown.f` | unattributable internal failure |

Boundary reasoning follows the standard: a malformed stream is `input` (decidable from the
submission alone); a signature that fails against derived state is `proof`; revocation is
`state` per the settled boundary; an ACDC that verifies but doesn't cover the claimed DID is an
authorization-scope failure, `grant`.

## Test strategy and oracles

Strict TDD with the red run as a visible artifact per unit (ledger #20), 100% branch coverage
of new code. Oracles, strongest first:

1. **Cross-implementation ingest**: artifacts generated by `didwebs` are ingested by the GLEIF
   resolver (its own <3.14 venv, driving `save_cesr` + `generate_did_doc` as the spike harness
   already does) and its derived document agrees on the intersection of fields it emits
   correctly (its omissions — `@context`, relationships — and its `strip_query` defect are
   documented exclusions, not waivers).
2. **Version-string oracle**: every generated stream contains only `KERI10JSON`/`ACDC10JSON`
   frames (constraint `qbqfst` discharge).
3. **Spec worked examples** (`### Full Example`, `#### The full KERI event stream`) as golden
   fixtures for document shape; mismatches are findings against us *or the spec* — spec-side
   mismatches feed the upstream-issues drafts, not silent test adjustments.
4. **Negative oracles**, one test each (ledger #22 — negative requirements need positive
   oracles): no-ACDC stream rejected; revoked-ACDC rejected; ACDC not covering the DID
   rejected; ACDC covering did:webs but not did:web rejected; v2-frame stream rejected;
   secp256k1 key state rejected with `e.feature.unsupported.key-alg.f`; delegated AID without
   delegator KEL rejected; truncated stream (KEL prefix only, no TEL) rejected.
5. **CLI smoke** (ledger #19): the installed `didwebs` entry point runs end-to-end in a temp
   dir — generate a fixture keystore, assemble, publish, re-ingest what was published.

Test scaffolding: the in-process witness and credential-issuance helpers from the reference
(`tests/conftest.py`, `tests/keri_api.py`, Apache-2.0, adapted with attribution to the 2.0-dev
API) plus the spike harness scripts already in `.ignored/spike-keripy-interop/`.

## CI

GitHub Actions on push/PR: uv sync (keripy resolves anonymously — public repo, no App token
needed), ruff, pytest with coverage gate. Action versions on the node24 runtime (`checkout@v6`,
`setup-python@v6` family — verify each tag's runtime before writing the workflow). A second job
builds the GLEIF-resolver venv (Python 3.13) for the cross-implementation oracle.

## Explicitly not in phase 1

Resolution (phase 2, `wmoq5b` applies there), serving (phase 3), `transformKeys` re-encodings,
`versionId`, did:keri resolution, remote issuance choreography (~4spy), secp curves,
multisig *issuance* choreography (threshold derivation from key state is in; creating group
AIDs in tests is fixture work deferred until a fixture needs it).
