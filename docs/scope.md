# did:webs implementation scope

Status: proposed (2026-08-14). Decisions ratified here move to `this.i`; this document is the
analysis behind them.

This repo implements the did:webs DID method so a Bakobo customer holding a KERI AID can
participate in W3C DID ecosystems (see `this.i`, goal `xckiyf`). This document records what the
spec requires, what the existing implementations do and fail to do, what we will build, and in
what order.

## Sources

- Spec: [trustoverip/kswg-did-method-webs-specification](https://github.com/trustoverip/kswg-did-method-webs-specification),
  v0.10.3, read at commit `2d84ef2` (2026-08-11). Local clone:
  `~/code/wot/kswg-did-method-webs-specification`. All section citations below are headings in
  `spec/body.md`.
- Reference implementation: [GLEIF-IT/did-webs-resolver](https://github.com/GLEIF-IT/did-webs-resolver)
  v0.3.7 (Python package `dws`, formerly `dkr`; keripy pinned 1.2.13; Apache-2.0), read at HEAD
  2026-08-11. Local clone: `~/code/wot/did-webs-resolver`. Supersedes the archived
  hyperledger-labs repo of the same name.
- Helper library: [GLEIF-IT/did-webs-ts](https://github.com/GLEIF-IT/did-webs-ts) v0.0.6
  (TypeScript, no KERI verification at all). Local clone: `~/code/wot/did-webs-ts`.
- Talk: Jonathan Rayback (task force co-chair), "KERI Bridge to the DID World", KERI Conference
  April 2026 — transcript at
  <https://keri.foundation/confs/2026/videos/#keri-bridge-to-the-did-world-jonathan-rayback>.

## Standards status (from the talk and spec header)

The spec is a final draft under review in the ToIP KERI Suite Working Group; the
`application/cesr` IANA media type is registered; did:webs is in final review to become a DIF
recommended DID method (it is already one of the two methods named in the joint DIF/ToIP
recommendation). Normative-cleanup commits landed through 2026-08, so churn in exactly the areas
we implement should be expected; tracking the spec is an accepted cost (`this.i` goal `xckiyf`).

## What the method requires (condensed; MUST-level unless noted)

Identifier (`### Method-Specific Identifier`): `did:webs:<host>[%3A<port>](:<path-seg>)*:<aid>`,
where the AID is always the final component and path segments use `:`, never `/`. The ABNF's
`aid` production accepts only transferable (digest-code) SAIDs — see soft spot 3.

Artifacts (`### Target System(s)`, `#### Create`): two resources derived from the DID by string
transformation — `https://<host>[:port]/<path>/<aid>/did.json` (the did:web-form DID document)
and sibling `keri.cesr` (media type `application/cesr`). `keri.cesr` must carry the full KEL
(plus any delegator's KEL events), the anchoring `ixn` events, the TEL (`vcp`/`iss`/`rev`) for
the designated-aliases ACDC, the ACDC itself, the `rpy` records for endpoints
(`/loc/scheme`, `/end/role/add`), and all interleaved CESR attachments — i.e. a stream that a
verifier can re-ingest and verify from scratch.

Designated aliases (`### Designated Aliases`): a did:webs DID does not validly resolve unless it
appears in a valid, unrevoked designated-aliases ACDC anchored (via TEL) to the KEL. This is the
method's signature feature: the controller cryptographically authorizes the host/path where the
DID lives, which no other did:web-family method offers (Rayback made this the centerpiece of the
talk). `did:keri:<aid>` must always appear in `alsoKnownAs`; other same-AID did:webs DIDs also
go in `equivalentId` metadata.

Resolution (`#### Read (Resolve)`): fetch both artifacts; verify the CESR stream under KERI
rules (fail on any verification failure or fork); confirm the designated-aliases ACDC authorizes
the DID; derive the DID document from the verified stream; transform the fetched did:web doc to
did:webs form; **fail unless derived equals transformed**. Hosted JSON is never trusted on its
own; host honesty is explicitly not assumed (`## Security Considerations`).

DID document derivation (`## DID documents`): `id` = the did:webs DID; `controller` = `id`; one
verification method per key in current key state, type `JsonWebKey` + `publicKeyJwk`
(Ed25519/secp256k1/secp256r1, CESR code stripped, `kid` = CESR string, VM `id` = `#<cesr-key>`);
for `kt > 1` or weighted thresholds an additional `ConditionalProof2022` method (`#<aid>`,
integer threshold or LCD-expanded weights); both `authentication` and `assertionMethod` required,
referencing the per-key VMs (or the conditional VM under multisig); service entries projected
from KERI state (witness from the KEL `b` list + `/loc/scheme`; mailbox/agent from
`/end/role/add` + `/loc/scheme`; `DelegatorOOBI` when the AID is delegated).

Update/Deactivate (`#### Update`, `#### Deactivate`): every KEL/TEL/rpy change obliges the
controller to regenerate and republish both artifacts in place. Deactivation = rotate to null
next keys, then republish; the artifacts must never be taken down (an offline host must remain
distinguishable from a deactivated DID).

DID parameters (`## DID Parameters`): `versionId` (build the doc from events up to sequence
number N; `versionId`/`nextVersionId` in metadata) and `transformKeys`
(JsonWebKey / Ed25519VerificationKey2020 / CesrKey re-encodings).

## Spec soft spots (raise upstream; implement defensively)

The spec-reading pass surfaced fourteen inconsistencies or gaps. The high-impact ones:

1. The designated-aliases ACDC schema (SAID `EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5`)
   appears only in examples — nothing normative fixes which schema a resolver must accept. The
   reference impl pins it as a bundled, SAID-verified resource; we should do the same and push
   for the spec to make it normative.
2. Resolution step 4 requires the ACDC to authorize both the did:webs DID **and** the
   corresponding did:web DID, but Create step 3 (and the co-chair's own talk) treat did:web
   authorization as optional. As written, a controller who skips the optional step mints a DID
   that can never resolve. Needs an upstream issue; until resolved we generate ACDCs that
   authorize both forms, and our resolver should follow whatever the spec settles on.
3. The ABNF cannot express non-transferable AIDs (code `B`), though the annex praises them for
   ephemeral use; the `path`/`host` productions also omit percent-encoding.
4. `equivalentId` is "MUST appear" in one section and "SHOULD contain" in another.
5. The mandatory `did:keri` `alsoKnownAs` entry conflicts with the rule that every `alsoKnownAs`
   identifier be ACDC-backed (no example ACDC contains a did:keri entry).
6. No `deactivated` flag is specified for `didDocumentMetadata`; deactivation is only observable
   by deriving key state.
7. Metadata properties `witnesses`, `didDocUrl`, `keriCesrUrl` appear in examples but are
   defined nowhere.

(The full list, with citations, is in the spec-read report; remaining items cover
`transformKeys` phrasing, agent-service `id` shape, versionId-vs-rpy state mixing, redirect
language, and resolution-metadata contradictions.)

Upstream engagement note: trustoverip repos are in the no-AI-posting scope — issues get drafted
as text for Daniel to post with his own hands.

## What the reference implementation teaches (and where it stops)

The GLEIF resolver is honest about being a demonstration. It genuinely does the core loop:
parses/verifies the CESR stream through keripy's Kevery/Tevery/Verifier, regenerates the
document, and deep-compares against the served `did.json`. Its keripy recipes are the most
valuable thing in it (handler-stack ordering with Revery before Kevery, reply-route
registration, escrow drains, `keri.cesr` assembly order, AEID-aware keystore open, endpoint
lookup for non-local AIDs, the bundled-schema pinning trick, the LCD threshold math). Its test
scaffolding (in-process witness, full in-process ACDC issuance, delegation approval doers) is
worth adapting wholesale.

Where it stops short of production, and where we therefore have work to do:

- **No freshness or duplicity checking.** Both artifacts come from the same untrusted server;
  nothing consults witnesses or watchers, and no witness-receipt threshold is enforced, so a
  stale-but-valid KEL prefix (i.e. pre-rotation key state) verifies clean. The spec SHOULDs
  witness/watcher fork detection; for Bakobo this is the security gap that matters most, and we
  operate witness infrastructure already.
- **Untrusted data is persisted into the resolver's long-lived LMDB** with no per-request
  isolation — a poisoning/DoS surface in a shared resolver service.
- **The generated document is incomplete**: no `@context`, no `authentication`, no
  `assertionMethod` (both spec-mandatory), no deactivation detection. (The TS library emits
  the relationships but does zero cryptographic verification, and the two GLEIF implementations
  disagree on VM type and threshold math — so "compare against the reference" is only a partial
  oracle.)
- Assorted defects: malformed controller DIDs from `strip_query()` when port/path are absent,
  silent HTTPS→HTTP fallback, 500s on non-local AIDs, TLS off by default, CORS `*`, the one
  end-to-end tamper-detection test commented out, CLI layer excluded from coverage.
- `versionId` and `transformKeys` parameters: parsed but not implemented (confirmed in the
  talk).

## Proposed scope for Bakobo's implementation

Package name and public shape to be settled at design time; strict TDD, 100% branch coverage of
new code, error codes per `dev/standards/error-codes.md` (`e.did.*` family to be designed).

In scope, phased:

1. **Generation library + CLI** — from a keripy keystore (or an imported CESR stream): compose
   the DID, issue/manage the designated-aliases ACDC (authorizing both did:webs and did:web
   forms), assemble `keri.cesr` in re-ingestable order, derive the complete DID document
   (`@context`, both verification relationships, JWK + CesrKey encodings, thresholds, services,
   delegation), emit the did:web form for hosting. Deactivation and update flows regenerate in
   place.
2. **Resolver library + service** — full `#### Read (Resolve)` algorithm with the derived-vs-
   served equality gate; scratch (per-resolution) keripy state, never a shared long-lived DB;
   witness-receipt threshold enforcement and optional watcher consultation as our
   above-reference hardening; clean `didResolutionMetadata` errors per the spec's failure
   contract; `versionId` support; universal-resolver driver container.
3. **Serving** — integration with Bakobo hosting so customer AIDs get published artifacts
   (static publication first; the dynamic per-request pattern from the reference is optional
   later). Fits alongside `bakobo/witness` operationally.
4. **Interop harness** — round-trip against the GLEIF resolver (both directions), the spec's
   worked examples as golden fixtures, plus `did-webs-ts`'s `ref/` example documents where they
   don't contradict the Python side.

Deferred until demanded: `transformKeys` re-encodings beyond JsonWebKey/CesrKey, did:keri
resolution, web-redirect/relocation handling, KRAM/BADA-RUN for non-KEL-backed extras,
secp256k1/secp256r1 (start Ed25519-only if customer AIDs are Ed25519 — confirm before design).

Out of scope: wallet/edge-agent features, ACDC credential exchange beyond the designated-aliases
attestation, did:webvh interop.

## Open questions

1. Ed25519-only at first, or all three curves from the start?
2. Does the first customer-facing deliverable prioritize the publish side (customers get
   resolvable DIDs) or the resolve side (Bakobo can verify others' DIDs)? Phasing above assumes
   publish-first.
3. Witness-receipt enforcement policy in the resolver (hard-fail vs. metadata warning) — spec
   only SHOULDs it; our default posture (fail closed) suggests hard-fail with a config escape.
