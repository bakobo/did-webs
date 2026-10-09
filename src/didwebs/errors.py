"""The didwebs error registry.

Every error this package raises is a module-scope :class:`~bakobo.errors.ErrorCode` literal —
never assembled from variables, f-strings, or a factory (dev/standards/error-codes.md, "The
registry") — so a catalog can be extracted by static analysis and an illegal code is refused at
import time rather than described in prose. Codes classify by *meaning*, never by which module
raised them (dev/standards/error-codes.md, "Minting a code"): no `didwebs`-specific component
name appears in any code.

The 29 codes below are verbatim from docs/design.md's "Error codes" table. Nineteen of them come
from that table's rev 2 (2026-08-14); `e.input.range.stream.f` was added with the stream door
(constraint `adyiw2mm`), and `e.self.corrupt.did.f` with the artifact-join containment check
(constraint `a2sbz34i`), and `e.self.corrupt.witness-replay.f` with the interop replay
(decision `t3q6azxm`), and `e.feature.unsupported.registry.event.f`,
`e.proof.stream.disclosure.f`, `e.input.missing.registry.event.f`,
`e.rule.stream.version.f` and `e.self.anchor.registry.f` with KERI protocol v2 (decisions
`0plkq8s8`, `3kn6drgf`, `8686h4tf`), and `e.rule.kel.version.regressed.f` and
`e.rule.credential.registry.version.f` when a KEL became free to migrate from v1 to v2
(`8686h4tf` as amended 2026-10-07), which also left `e.rule.stream.version.f` declared and no
longer raised. The
table carries fewer rows than codes, because `e.proof.stream.*.f` is written once and names its
five leaves — `sig`, `seal`, `anchor`, `frame`, `disclosure` — in the same cell, the audit
picking between them by which escrow held the frame or which registry check refused it.

The rev-2 nineteen were checked against the bakobo/errors catalog at the `bakobo-errors` pin —
none collides with a shipped code, and three are boundary cases against heti's near-neighbors,
called out as a comment where each is declared. `e.input.range.stream.f` is the one deliberate
cross-repo *sharing* rather than a collision; see the comment on its declaration. Identity is the
contract: a code's string, once shipped, never changes (dev/standards/error-codes.md, "A code's
meaning and `args` signature never change once shipped").

The count in the first paragraph is not decoration: `tests/test_errors.py` reads it back and
compares it against what this module actually declares, having found the registry by type rather
than by a hand-kept list. That gate exists because the hand-kept list drifted — it went on saying
seventeen while `e.rule.stream.third-party.f` and `e.self.corrupt.schema.f` were minted, raised,
and asserted elsewhere in the suite.
"""

from __future__ import annotations

from bakobo.errors import ErrorCode

DID_INVALID = ErrorCode(
    "e.input.format.did.f",
    "The string is not a valid did:webs identifier.",
    detail='"{did}" does not parse as a did:webs identifier.',
    args=("did",),
    hint="Check the did:webs method's MSI syntax for path segments and the AID production.",
)

STREAM_TOO_LARGE = ErrorCode(
    "e.input.range.stream.f",
    "The submitted publication stream is larger than this build will read.",
    detail="The stream submitted for {did} exceeds the bound on {bound}, which is {limit} "
    "bytes.",
    args=("did", "bound", "limit"),
    hint="The bound is a flood guard, far above any real publication. A submission near it is a "
    "sign something is wrong with the stream rather than with the limit.",
)
# Deliberately the same code string the sibling did-webvh declares for the same refusal: a
# submitted KERI CESR stream past the read bound, which a caller reacts to identically in both.
# The error-codes standard's rule is one code per meaning across Bakobo, and "genuinely common
# codes are defined once in the shared core registry and imported" — but bakobo/errors ships the
# ErrorCode machinery and no shared catalog module to import from, so today each repo declares
# its own. Graduating this pair into a shared registry is tick ~5cue.

#: Each door's range code, by kind, so :func:`didwebs.bounds.read_bounded` can raise the right
#: one without assembling a code string at runtime. The literal above is what a catalog
#: extractor sees; this only points at it.
TOO_LARGE = {"stream": STREAM_TOO_LARGE}

STREAM_UNWALKABLE = ErrorCode(
    "e.input.format.stream.f",
    "The publication stream cannot be walked frame by frame.",
    detail="The stream submitted for {did} contains a frame that cannot be extracted: garbled "
    "CESR, or a frame with no recognizable version string.",
    args=("did",),
    hint="Confirm the stream was produced by a CESR-conformant serializer and was not "
    "truncated in transit.",
)
# Boundary against heti's e.input.format.evidence.f: heti's code is about its own evidence
# bundle; this one is about the CESR publication stream didwebs walks (docs/design.md §
# "Error codes").

SERIALIZATION_UNSUPPORTED = ErrorCode(
    "e.feature.unsupported.serialization.f",
    "This build only accepts JSON-serialized frames.",
    detail="The stream submitted for {did} contains a {kind} frame; only KERI10JSON and "
    "ACDC10JSON serializations are accepted in v1.",
    args=("did", "kind"),
    hint="Re-serialize the stream to JSON before submitting it.",
)

ALIAS_ACDC_MISSING = ErrorCode(
    "e.input.missing.alias-acdc.f",
    "The stream carries no designated-aliases credential.",
    detail="The stream submitted for {did} was walked in full and contains no "
    "designated-aliases ACDC.",
    args=("did",),
    hint="Include the designated-aliases ACDC issued by the claimed AID in the submitted "
    "stream.",
)

DELEGATOR_MISSING = ErrorCode(
    "e.input.missing.delegator.f",
    "The delegated AID's delegator key event log is missing from the stream.",
    detail="{aid} is a delegated AID, but its delegator {delegator}'s key event log is not in "
    "the submitted stream.",
    args=("aid", "delegator"),
    hint="Include the delegator's key event log in the submission.",
)

REGISTRY_EVENT_UNSUPPORTED = ErrorCode(
    "e.feature.unsupported.registry.event.f",
    "The stream carries a registry event type this build does not accept.",
    detail="The frame {frame} is a {ilk} registry event. A protocol v2 registry here is "
    "registry inception (rip) and blindable updates (bup) only, which is what WebOfTrust "
    "keripy accepts.",
    args=("frame", "ilk"),
    hint="Record registry state with blindable updates (bup), each published with its "
    "disclosure.",
)
# Decision 0plkq8s8. `upd` is the case that motivated it: the ACDC spec still lists it, keripy
# main dropped it, so a stream depending on it is not one the reference verifier accepts.

STREAM_VERSION_MIXED = ErrorCode(
    "e.rule.stream.version.f",
    "A v2 registry cannot be anchored in a key event log of another protocol version.",
    detail="{aid} keeps a protocol {version} key event log, and a v2 registry anchored in it "
    "would make a publication stream mix versions, which this build refuses.",
    args=("aid", "version"),
    hint="Issue a v2 designation from a controller whose key event log is protocol v2, or a v1 "
    "designation from this one.",
)
# Decision 8686h4tf as first recorded, which refused any stream mixing versions. The amendment of
# 2026-10-07 allows a v1 KEL to anchor a v2 registry, so nothing raises this any more. It stays
# declared because a shipped code is never deleted or reused (dev/standards/error-codes.md), and
# it has no successor because the case it refused is now allowed.

KEL_VERSION_REGRESSED = ErrorCode(
    "e.rule.kel.version.regressed.f",
    "A key event log returns to an older KERI protocol version after a newer one.",
    detail="{aid}'s key event {said}, at sequence number {sn}, is protocol v{version}, and an "
    "earlier event of the same log is already protocol v{prior}.",
    args=("aid", "said", "sn", "version", "prior"),
    hint="Once a key event log has an event in a newer protocol version, make every later event "
    "in that version or a newer one. keripy chooses the version at each call and defaults to v2, "
    "so pass the version explicitly when you rotate or interact.",
)
# Decision 8686h4tf, rule 2. Not a cryptographic need: each event is signed in its own
# serialization. A KEL may move from v1 to v2 and never back, which catches the accidental
# flip-flopping keripy's per-call version default makes easy.

CREDENTIAL_REGISTRY_VERSION = ErrorCode(
    "e.rule.credential.registry.version.f",
    "A credential and the registry it names are different KERI protocol versions.",
    detail="The protocol v{version} credential {credential} names the registry {regid}, which the "
    "stream carries as protocol v{registry_version}.",
    args=("credential", "version", "regid", "registry_version"),
    hint="Issue a v1 credential from a v1 registry (vcp, iss) or a v2 credential from a v2 "
    "registry (rip, bup).",
)
# Decision 8686h4tf, rule 4: a v1 credential names its registry with `ri` and a vcp/iss log, a v2
# one with `rd` and a rip/bup registry. Every other combination of versions is allowed.

REGISTRY_ANCHOR_UNCOMMITTED = ErrorCode(
    "e.self.anchor.registry.f",
    "The keripy registry engine did not commit a registry event after it was anchored.",
    detail="The registry event {said} was sealed in the controller's key event log, and keripy's "
    "registry engine still did not accept the anchor, so issuance stopped rather than publish an "
    "event nobody could verify.",
    args=("said",),
    hint="This is a fault in didwebs or its keripy pin, not in your input; report it with the "
    "registry event's SAID.",
)

REGISTRY_EVENT_MISSING = ErrorCode(
    "e.input.missing.registry.event.f",
    "The stream omits a registry event its own key event log anchors.",
    detail="The key event log of {aid} anchors registry event {said} in registry {regid}, and "
    "the stream does not carry it. Registry state read without it could be stale: an omitted "
    "update may be the one that revoked the designation.",
    args=("aid", "regid", "said"),
    hint="Submit the registry's complete event log: every event the issuer's key event log "
    "anchors, with the disclosures it needs.",
)
# Decision 3kn6drgf, completeness (panel SEC-F1): verifiers check what is presented, never that
# everything anchored was presented; the KEL already in hand is what makes the gap visible.

REGISTRY_STATE_UNPROVABLE = ErrorCode(
    "e.proof.stream.disclosure.f",
    "A registry update's state cannot be proven from the stream.",
    detail="The registry update {frame} is blinded, and the stream carries no disclosure of "
    "its state, or a disclosure that does not match what the update commits to.",
    args=("frame",),
    hint="Publish every blindable update with its BlindedStateQuadruples (-a) disclosure, as "
    "the ACDC specification's public blindable mode prescribes.",
)
# Decision 3kn6drgf: a public attestation whose state is unreadable cannot authorize anything.

STREAM_SIG_INVALID = ErrorCode(
    "e.proof.stream.sig.f",
    "A frame in the stream failed signature verification.",
    detail="The frame {frame} in the submitted stream was not accepted: its signature does "
    "not verify.",
    args=("frame",),
    hint="Confirm the frame was signed by a key current in the signer's key event log.",
)

STREAM_SEAL_INVALID = ErrorCode(
    "e.proof.stream.seal.f",
    "A frame in the stream failed delegation-seal verification.",
    detail="The frame {frame} in the submitted stream was not accepted: its delegation seal "
    "does not verify against the delegator's key event log.",
    args=("frame",),
    hint="Confirm the delegator's key event log anchors the expected seal at the referenced "
    "event.",
)

STREAM_ANCHOR_INVALID = ErrorCode(
    "e.proof.stream.anchor.f",
    "A frame in the stream failed anchor verification.",
    detail="The frame {frame} in the submitted stream was not accepted: it does not anchor to "
    "the event it references.",
    args=("frame",),
    hint="Confirm the anchoring event is present in the stream and correctly seals the frame.",
)

STREAM_FRAME_REJECTED = ErrorCode(
    "e.proof.stream.frame.f",
    "A frame in the stream was rejected.",
    detail="The frame {frame} in the submitted stream was not accepted, and no more specific "
    "escrow attributed a cause.",
    args=("frame",),
    hint="Resubmit the stream after comparing it against a known-good publication.",
)

KEL_FORKED = ErrorCode(
    "e.state.conflict.kel.f",
    "The submission forks its own key event log.",
    detail="The stream submitted for {aid} produced a likely-duplicitous event: two branches "
    "of the key event log at the same sequence number.",
    args=("aid",),
    hint="Resubmit a single, non-forking key event log for this AID.",
)
# Boundary against heti's e.state.conflict.duplicity.f: heti's code is duplicity observed
# across gathered evidence from multiple sources; this one is one submission forking its own
# KEL within a single stream (docs/design.md § "Error codes").

ALIAS_ACDC_REVOKED = ErrorCode(
    "e.state.revoked.alias-acdc.f",
    "The designated-aliases credential has been revoked.",
    detail="The designated-aliases ACDC {said} is revoked, per the verified state of its "
    "registry.",
    args=("said",),
    hint="Issue a fresh designated-aliases credential before resubmitting.",
)

ALIAS_GRANT_MISSING = ErrorCode(
    "e.grant.missing.alias.f",
    "No designated-aliases credential authorizes the claimed AID.",
    detail="The designated-aliases ACDC in the stream for {did} was not issued by the claimed "
    "AID, or its registry is not anchored in the claimed AID's key event log.",
    args=("did",),
    hint="Issue the designated-aliases ACDC from the claimed AID and anchor its registry in "
    "that AID's key event log.",
)

ALIAS_GRANT_SCOPE = ErrorCode(
    "e.grant.scope.alias.f",
    "The designated-aliases credential does not cover this DID.",
    detail="The controller's designated-aliases ACDC does not list {did}, or its did:web "
    "form, among its authorized identifiers.",
    args=("did",),
    hint="Reissue the designated-aliases ACDC with this DID included among its authorized "
    "identifiers.",
)

THIRD_PARTY_FRAME = ErrorCode(
    "e.rule.stream.third-party.f",
    "The stream carries material about identifiers it is not publishing.",
    detail="The frame {frame} concerns {principal}, which is neither the claimed AID, its "
    "delegator chain, nor an issuer of a credential the stream itself carries; a publication "
    "stream may not carry third-party material.",
    args=("frame", "principal"),
    hint="Submit only the claimed AID's own key event log, registries, credentials, and "
    "endorsements.",
)
# A rule, not a proof failure: keripy accepts these frames — they verify fine. The norm "no
# third-party chaff in a publication stream" is didwebs's own (docs/design.md § Modules,
# ingest step 1), which is exactly what the `rule` descriptor names.

ALIAS_AID_MISMATCH = ErrorCode(
    "e.rule.alias.aid.mismatch.f",
    "An alsoKnownAs entry names a different AID than the stream verifies.",
    detail="The alias {alias} names an AID other than {aid}, the AID the stream verifies.",
    args=("alias", "aid"),
    hint="Only list aliases whose final path component is this same AID.",
)

KEY_ALG_UNSUPPORTED = ErrorCode(
    "e.feature.unsupported.key.alg.f",
    "This build only supports Ed25519 verification keys.",
    detail="The current key state for {aid} includes a {alg} key, which this build does not "
    "support.",
    args=("aid", "alg"),
    hint="Rotate to Ed25519 keys, or wait for a follow-on release that supports this "
    "algorithm.",
)
# Boundary against heti's e.feature.unsupported.alg.f: heti's code is about a
# request-signature algorithm; this one is about the key type in an AID's current key state
# (docs/design.md § "Error codes").

THRESHOLD_UNSUPPORTED = ErrorCode(
    "e.feature.unsupported.threshold.f",
    "This build cannot represent a multi-clause signing threshold.",
    detail="The current key state for {aid} carries a multi-clause (conjunctive) threshold, "
    "which ConditionalProof2022 cannot express.",
    args=("aid",),
    hint="Simplify to a single weighted clause, or wait for a follow-on release.",
)

ARTIFACT_PATH_CORRUPT = ErrorCode(
    "e.self.corrupt.did.f",
    "A DID reached the artifact join with a component that is not one directory name.",
    detail="The component {component} of the DID for {aid} is not a single directory name, so "
    "the artifact directory it names is not a location this package will write to.",
    args=("component", "aid"),
    hint="This is a fault in didwebs, not in your submission: didwebs.did.parse refuses these "
    "components, so a value carrying one did not come through it. Report it with the command "
    "that produced it.",
)
# `self`, not `input`, and the locus is the whole argument. The component is decidable from the
# value alone, which is normally the `input` test (dev/standards/error-codes.md, "input vs
# everything requiring a lookup"). But by the time it reaches publish.artifact_dir the value is
# not a request: did.parse is contracted to have refused it (constraint a2sbz34i), so a malformed
# component here means that contract broke inside this process. Reporting e.input.format.did.f
# would tell an operator their DID is malformed when no such DID could have reached the CLI,
# sending them to fix something that was never theirs. Same locus distinction the standard draws
# for self.config -- our own value rather than the world's.
#
# Not e.self.unknown.f either, which Copilot proposed as the alternative on PR #5: the standard
# reserves that leaf for "a failure we cannot attribute at all" (error-codes.md, on the `self`
# row), and this one is attributed precisely -- to a named component of a named DID. Borrowing
# the unattributable code for an attributable fault spends the one leaf that has to stay honest.

SCHEMA_CORRUPT = ErrorCode(
    "e.self.corrupt.schema.f",
    "The bundled credential schema does not hash to its pinned identifier.",
    detail="The designated-aliases schema shipped with this build hashes to {computed}, not "
    "the pinned {pinned}; the resource has been altered.",
    args=("computed", "pinned"),
    hint="Reinstall didwebs from a trusted distribution; this failure is in the package, not "
    "in your submission.",
)

WITNESS_REPLAY_CORRUPT = ErrorCode(
    "e.self.corrupt.witness-replay.f",
    "A verified witness signature cannot be replayed as a receipt.",
    detail="The stored witness signature for event {frame} has an invalid witness index, does "
    "not verify against the event body, or cannot be placed in its v1 replay frame.",
    args=("frame",),
    hint="Report the publication stream and this didwebs version; the accepted state could not "
    "be replayed faithfully.",
)

UNKNOWN_FAILURE = ErrorCode(
    "e.self.unknown.f",
    "An internal failure occurred that could not be attributed to a specific cause.",
)
