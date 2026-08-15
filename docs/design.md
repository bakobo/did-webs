# didwebs phase-1 design

Status: rev 2 (2026-08-14) — revised against the KERI panel run
[`../reviews/keri-review-panel-phase1-design.md`](../reviews/keri-review-panel-phase1-design.md)
(15 findings, all dispositioned; per-finding trace at the end). Governing intent: `this.i` —
goal `xckiyf`; decisions `jo5sby` (Python on keripy), `3woefn` (Ed25519-only v1), `ecwpad`
(publish-first), `avuwzl`+`embuup` (non-custodial ingestion; hosted artifacts derived, never
passthrough), `gvimca`+`qbqfst` (estate keripy, protocol v1 pinned). Requirements background:
[`scope.md`](scope.md). Spec citations are headings in
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

**The load-bearing fact about keripy** (panel root cause, SEC-F1/F2, KRT-F2, SPC-F1): the
Parser is a stream processor, not a validator. It catches per-frame `ValidationError`s —
forged signatures, likely-duplicitous events (escrowed to `ldes`), rejected replies — logs,
and resumes (`parsing.py:565-571` at the pin). "Parsed without error" is therefore vacuous.
Ingest success in this design is defined by the **post-parse audit** below, and hosted
artifacts are **re-derived from what keripy actually accepted**, never copied from submitted
bytes (constraint `embuup`).

Two keripy facts discovered building the fixture toolkit (2026-08-15) widen `qbqfst`'s
reach. First, **the v1 pin has a third call-site category: parsing.** `Parser.parse` carries
its own CESR genus `version`, defaulting to v2 — a valid v1 stream fed to a v2-genus parser
yields *nothing*: no exception, no diagnostic, no `kevers` entry. Every parser construction in
`ingest.py` therefore pins `version=Vrsn_1_0` exactly as event-constructing calls do. Second,
three keripy call sites (`Registry.issue`, `Registry.revoke`, `Credentialer.create`) accept no
version argument at all and derive it from the registry's inception; where an explicit pin is
impossible, the call is wrapped in an assertion guard (`assemble._v1()`) that refuses a non-v1
serder, and the version-string oracle backstops the whole surface.

## Modules

- `didwebs/did.py` — the `WebsDid` value type. Parse/compose/validate per the spec's MSI
  section: path segments and the AID follow the spec ABNF (normative there; the AID production
  admits only transferable digest codes — soft spot 3, carried upstream); the **host is
  validated against the RFCs the spec makes normative** — RFC 3986 `host` (including
  IP-literals) via a mature parsing library, with RFC 1035/1123 checks for reg-names — because
  the spec marks its own host charset "for illustration only" (SPC-F4). Port is
  percent-encoded (`%3A`/`%3a` both legal on the wire). **Equality and membership are defined
  over the normalized parse** — host lowercased, percent-encoding case-folded, path and AID
  case-sensitive — never over raw strings (KRT-F5); `compose()` always emits the canonical
  spelling (lowercase host, upper `%3A`) so raw-string comparers in other implementations also
  match our artifacts. URL derivation (`did.json` / `keri.cesr` — `### Target System(s)`) and
  the did:web form of the same identifier. Two distinct predicates that must never be conflated
  (KRT-F6): `has_nontransferable_code(aid)` — derivation-code test, `did.py` rejects at parse —
  and `is_abandoned(kever)` — rotated-to-null key state, detected in `document.py`, which
  accepts and keeps publishing (`#### Deactivate`). Pure functions, no keripy imports beyond
  code tables.
- `didwebs/errors.py` — the error registry per `dev/standards/error-codes.md` (codes below).
- `didwebs/ingest.py` — `ingest(stream: bytes, did: WebsDid) -> Verified`. Builds a **scratch
  keripy Habery in a per-call temporary directory** — verified state never persists, and no two
  ingestions share LMDB state. Parser stack per the reference recipe
  (`dws/core/resolving.py:89-127`): Router/Revery **before** Kevery, Tevery, Verifier, reply
  routes registered on both, escrow drains. Then the **post-parse audit**, which is the
  definition of ingest success:
  1. **Frame accounting** (SPC-F1). Before keripy parsing, the stream is walked frame-by-frame
     with keripy's own extraction primitives (Serder + attachment counters — not a regex),
     producing the list of submitted message SAIDs and kinds; only `KERI10JSON`/`ACDC10JSON`
     serializations are accepted — a deliberate JSON-only restriction, narrower than "v1"
     (SKP-F5): CBOR/MGPK v1 frames are rejected as unsupported, and an unwalkable stream
     (garbled frame, CESR-native v2 body with no version string) fails here rather than being
     silently flushed by keripy. After keripy ingest + escrow drains, every walked frame must
     be accounted **accepted**: KEL events present in the Kever's first-seen log, TEL events in
     the Tever, ACDCs saved with their TEL state, `rpy` records BADA-accepted. Any walked
     frame not in accepted state → the error attribution map below. Frames about AIDs other
     than the claimed AID and its delegator chain are rejected outright (no third-party chaff
     in a publication stream).
  2. **Escrow audit** (SEC-F2, KRT-F2). After drains, the scratch database's escrows are
     inspected and mapped to codes: non-empty likely-duplicitous escrow (`ldes`) →
     `e.state.conflict.kel.f` (intra-stream fork; first-seen-wins is *not* acceptance);
     partial/out-of-order/unverified escrows non-empty → `e.proof.stream.*` leaves per escrow
     kind (signature, delegation seal, anchor). This audit — not parser exceptions — is what
     makes the error taxonomy's distinctions observable.
  3. **Authorization post-conditions** (KRT-F1, SEC-F4). The designated-aliases ACDC must be:
     schema-pinned (SAID `EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5`, bundled resource,
     SAID-recomputed at load — the `dws/core/schemaing.py` pattern); **issued by the claimed
     AID** (`i` field of the ACDC == claimed AID); **its registry anchored in the claimed
     AID's KEL** (the `vcp`/`iss` chain reaches a seal in that KEL — an ACDC riding a
     different KEL's registry is treated as absent); **unrevoked by direct TEL state query**
     (`Tever.vcState` must return issued — never inferred from the credential Verifier having
     saved it, which it does for revoked credentials too); and its `a.ids` must contain, under
     normalized `WebsDid` equality, both the claimed did:webs DID and its did:web form
     (resolution step 4, soft spot 2 read conservatively).
- `didwebs/document.py` — `derive_document(v: Verified, did: WebsDid) -> dict`, pure once given
  verified state. Emits the complete document (`## DID documents`): `@context`, `id`,
  `controller` (= `id`), one `JsonWebKey`/`publicKeyJwk` verification method per current key
  (Ed25519 only, decision `3woefn`; any other CESR key code fails), threshold projection per
  `#### Thresholds` for the shapes the spec can express — integer `kt > 1` and a **single**
  flat weighted clause (LCD expansion) — and a **fail-closed branch for multi-clause
  (conjunctive) thresholds**, which `ConditionalProof2022` as mapped by the spec cannot
  represent: `e.feature.unsupported.threshold.f`, never a truncated projection (KRT-F3; the
  GLEIF reference truncates to clause 0 and is wrong — excluded from the oracle on this
  input, and the gap goes on the upstream issues list). `authentication` + `assertionMethod`
  (both mandatory — the reference omits them), services projected from verified state (witness
  from the KEL `b` list + `/loc/scheme`; mailbox/agent from `/end/role/add` + `/loc/scheme`;
  `DelegatorOOBI` for delegated AIDs), and `alsoKnownAs`: always `did:keri:<aid>`, plus
  ACDC-authorized entries **each of which must itself parse and carry the verified AID as its
  final component** — an entry claiming a different AID fails the publication with
  `e.rule.alias.aid.mismatch.f` (KRT-F4; the spec constrains `alsoKnownAs` to same-AID DIDs,
  and we enforce what we could otherwise only assert). `to_did_web(doc)` produces the hosted
  form. Abandoned (deactivated) AIDs derive successfully and keep publishing.
- `didwebs/assemble.py` — two roles, one emitter. Keystore-side (tests/demos/fixtures):
  `issue_aliases(hab, regery, ids)` creates the registry (`vcp`), issues the self-attested
  ACDC against the pinned schema, anchors via `ixn`. Ingest-side (**the hosted-artifact
  path**, constraint `embuup`): `emit_stream(verified) -> bytes` re-assembles `keri.cesr` by
  replay **from the scratch database's accepted state** — KEL replay (delegator first), TEL
  clone, ACDC with `signing.serialize`, accepted `rpy` records — in the reference's
  re-ingestable order (`dws/core/artifacting.py:57-176`, ported to `.regid`, v1 pinned per
  `qbqfst`). Submitted bytes are never written to the artifact tree.
- `didwebs/publish.py` — `publish(out_root, did, doc, emitted_stream)`: writes
  `<out_root>/<path…>/<aid>/did.json` and `keri.cesr`, atomically (write-tempfile-rename), so
  update and deactivate are the same operation: re-ingest a newer stream, regenerate, overwrite
  in place (`#### Update`).
- `didwebs/cli.py` — **one product verb** (SKP-F3): `didwebs publish --stream <file> --did
  <did> --out <dir>` — ingest→derive→emit→publish, exit nonzero with the error code on any
  failure. The keystore side is deliberately not a console verb: fixtures and demos invoke
  `python -m didwebs.assemble` (revisit if the onboarding survey ~4spy concludes Bakobo should
  ship issuance tooling).

The pipeline, end to end: `parse → walk/account → keripy-ingest → escrow-audit →
authorization-post-conditions → derive → to_did_web → emit_stream → publish`. Every byte we
host is derived from state keripy accepted and the audit accounted for.

## Trust boundaries

Untrusted: the stream bytes and the claimed DID. Trusted after ingest: keripy-verified key
state, TEL state, and BADA-accepted reply state in the scratch database, as bounded by the
post-parse audit. The principal model is one controller per publication — how Bakobo
authenticates *which customer* may submit a stream for a given AID is a phase-3 service
concern. In phase 1 the CLI is run by a Bakobo **operator, who asserts** the submission is the
controller's (SKP-F4 — the pipeline itself establishes no submitter-to-AID binding, and the
wording here says so honestly). Standing revisit condition, recorded: **before any
network-facing submission surface exists, both a submitter-to-AID binding and TOAD receipt
enforcement (`wmoq5b`) must land** — the artifact pipeline alone must never be exposed to
unauthenticated submissions. Verification is fail-closed (org principle 8): everything served
is derived, and nothing unverified escapes into artifacts.

## Error codes (reconciled against the bakobo/errors catalog, 2026-08-14)

Reconciliation record. No code below collides with a shipped code in the catalog
(`bakobo/errors/index.json` at `45f42ae`). Three near-neighbors are distinct conditions, and the
registry documents each boundary at the declaration: heti's `e.state.conflict.duplicity.f` is
duplicity observed across gathered evidence, while our `e.state.conflict.kel.f` is one submission
forking its own KEL; heti's `e.input.format.evidence.f` is its evidence bundle, ours is the CESR
publication stream; heti's `e.feature.unsupported.alg.f` is a request-signature algorithm, ours a
key-state key type. Two codes were renamed from rev 2's proposals by the standard's
hyphen-vs-dot rule (`key.alg` — alg is a property of the key; `alias.aid.mismatch` —
subject before predicate, as in `event.sig`); `alias-acdc` stays one hyphenated token because it
names one artifact kind, like the standard's `trans-aid`. `e.self.unknown.f` is minted here first
(catalog has no instance) with exactly the standard's meaning. The `ErrorCode` machinery comes
from `bakobo-errors`, pinned git+https at `45f42ae` (public repo, anonymous resolution in CI).

| Code | Condition |
|---|---|
| `e.input.format.did.f` | string is not a valid did:webs identifier |
| `e.input.format.stream.f` | stream cannot be walked frame-by-frame (garbled CESR, unversioned frame) |
| `e.feature.unsupported.serialization.f` | walkable v1 frame outside the JSON-only accepted set (CBOR/MGPK) |
| `e.input.missing.alias-acdc.f` | no designated-aliases ACDC in the stream (absence established: we hold and walked the whole stream) |
| `e.input.missing.delegator.f` | delegated AID but no delegator KEL in the stream |
| `e.proof.stream.*.f` (leaves per audit source: `sig`, `seal`, `anchor`, `frame`) | a walked frame not accepted by keripy — attributed via the escrow/accounting audit |
| `e.state.conflict.kel.f` | likely-duplicitous escrow non-empty: the submission forks its own KEL |
| `e.state.revoked.alias-acdc.f` | designated-aliases ACDC revoked per direct `Tever.vcState` query |
| `e.grant.missing.alias.f` | ACDC present but not the claimed AID's authorization (wrong issuer, or registry not anchored in the claimed AID's KEL) |
| `e.grant.scope.alias.f` | controller's own ACDC does not cover the claimed DID (or its did:web form) under normalized equality |
| `e.rule.alias.aid.mismatch.f` | an `a.ids` entry names a different AID than the stream verifies (spec same-AID constraint) |
| `e.feature.unsupported.key.alg.f` | non-Ed25519 key in current key state (decision `3woefn`) |
| `e.feature.unsupported.threshold.f` | multi-clause (conjunctive) `kt` — unrepresentable in `ConditionalProof2022` |
| `e.self.corrupt.schema.f` | the bundled designated-aliases schema fails SAID recomputation at load — our packaging fault, never the submitter's |
| `e.self.unknown.f` | unattributable internal failure |

Boundary reasoning follows the standard: what is decidable from the submission alone is
`input`; a walked frame keripy would not accept is `proof`; revocation is `state` per the
settled boundary; an ACDC that is not the controller's authorization, or doesn't cover the
DID, is `grant` (missing vs. scope); a well-formed, well-authorized assertion that violates a
spec norm we enforce is `rule`; capabilities nobody gets in v1 are `feature.unsupported`.

## Test strategy and oracles

Strict TDD with the red run as a visible artifact per unit (ledger #20), 100% branch coverage
of new code. Oracles, strongest first:

1. **Cross-implementation ingest**: artifacts generated by `didwebs` are ingested by the GLEIF
   resolver (its own <3.14 venv, driving `save_cesr` + `generate_did_doc` as the spike harness
   already does) and its derived document agrees on the intersection of fields it emits
   correctly. Documented exclusions, not waivers: its missing `@context`/relationships, its
   `strip_query` defect, and its clause-0 threshold truncation (KRT-F3 — on multi-clause
   inputs the reference is wrong and we fail closed instead).
2. **Round-trip identity**: `emit_stream` output re-ingested by our own `ingest` reproduces
   identical verified state and an identical derived document (the derived-artifact analogue
   of the spec's step-7 equality gate).
3. **Version-string oracle**: every emitted stream contains only `KERI10JSON`/`ACDC10JSON`
   frames (constraint `qbqfst` discharge).
4. **Spec worked examples** (`### Full Example`, `#### The full KERI event stream`) as golden
   fixtures for document shape; mismatches are findings against us *or the spec* — spec-side
   mismatches feed the upstream-issues drafts, not silent test adjustments.
5. **Negative oracles**, one test each (ledger #22):
   - no-ACDC stream rejected (`e.input.missing.alias-acdc.f`)
   - revoked-ACDC stream rejected (`e.state.revoked.alias-acdc.f`)
   - **attacker-issued alias ACDC** — victim KEL + attacker KEL + attacker-registry ACDC
     listing the victim's DID — rejected (`e.grant.missing.alias.f`) (KRT-F1)
   - ACDC not covering the claimed DID rejected; covering did:webs but not did:web rejected
     (`e.grant.scope.alias.f`)
   - `%3a`-vs-`%3A` and host-case spellings in `a.ids` **accepted** under normalized equality
     (KRT-F5 — the false-rejection direction is tested too)
   - **tampered-signature stream** rejected (`e.proof.stream.sig.f`) (SKP-F2)
   - **forked stream** — both branches of a same-sn conflict in one submission — rejected
     (`e.state.conflict.kel.f`), asserting the `ldes` audit fired (SKP-F2, SEC-F2)
   - dropped-frame stream — valid stream plus one frame keripy will reject — rejected by
     accounting, not published minus the frame (SPC-F1)
   - third-party-AID frames in the stream rejected
   - CBOR v1 frame rejected (`e.feature.unsupported.serialization.f`) (SKP-F5)
   - v2/unversioned frame rejected (`e.input.format.stream.f`)
   - secp256k1 key state rejected (`e.feature.unsupported.key.alg.f`)
   - multi-clause `kt` rejected (`e.feature.unsupported.threshold.f`), never truncated (KRT-F3)
   - `a.ids` entry with a different AID rejected (`e.rule.alias.aid.mismatch.f`) (KRT-F4)
   - delegated AID without delegator KEL rejected (`e.input.missing.delegator.f`)
   - truncated stream (KEL prefix only, no TEL) rejected
   - deactivated (rotated-to-null) AID **publishes successfully**, while a code-B AID is
     rejected at parse — one test asserting the two predicates are not conflated (KRT-F6)
6. **CLI smoke** (ledger #19): the installed `didwebs` entry point runs end-to-end in a temp
   dir — fixture keystore via `python -m didwebs.assemble`, publish, re-ingest what was
   published.

Test scaffolding: the in-process witness and credential-issuance helpers from the reference
(`tests/conftest.py`, `tests/keri_api.py`, Apache-2.0, adapted with attribution to the 2.0-dev
API) plus the spike harness scripts already in `.ignored/spike-keripy-interop/`.

## CI

GitHub Actions on push/PR: uv sync (keripy resolves anonymously — public repo, no App token
needed), ruff, pytest with coverage gate. Action versions on the node24 runtime (`checkout@v6`,
`setup-python@v6` family — verify each tag's runtime before writing the workflow). A second job
builds the GLEIF-resolver venv (Python 3.13) for the cross-implementation oracle.

## Explicitly not in phase 1

Resolution (phase 2, `wmoq5b` applies there), serving (phase 3), any network-facing submission
surface (see trust boundaries for the standing precondition), `transformKeys` re-encodings,
`versionId`, did:keri resolution, remote issuance choreography (~4spy), secp curves,
CBOR/MGPK serializations, multi-clause threshold projection (fail-closed, upstream issue),
multisig *issuance* choreography (threshold derivation from key state is in; creating group
AIDs in tests is fixture work deferred until a fixture needs it).

## Panel disposition trace (2026-08-14 run)

SEC-F1/SPC-F1 → constraint `embuup`, `emit_stream`, frame accounting, dropped-frame oracle.
SEC-F2/KRT-F2/SKP-F2 → escrow audit, error attribution map, fork + tamper oracles.
KRT-F1 → issuer-binding post-condition, `e.grant.missing.alias.f`, attacker-ACDC oracle.
KRT-F3 → fail-closed threshold branch, oracle exclusion, upstream issue (scope soft spot 15).
SEC-F4 → direct `Tever.vcState` mechanism named. KRT-F4 → same-AID enforcement +
`e.rule.alias.aid.mismatch.f`. KRT-F5 → normalized equality + canonical emission + acceptance
oracle. SPC-F4 → RFC-based host validation. KRT-F6 → two named predicates + conflation oracle.
SKP-F3 → `generate` verb dropped from the CLI. SKP-F4 → wording + standing revisit condition.
SKP-F5 → JSON-only stated as such, `e.feature.unsupported.serialization.f`. SEC-F3 was refuted
by the panel's own verifier (phase-3 concern, phased mitigation already recorded).
