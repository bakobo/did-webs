"""The didwebs error registry.

Every error this package raises is a module-scope :class:`~bakobo.errors.ErrorCode` literal —
never assembled from variables, f-strings, or a factory (dev/standards/error-codes.md, "The
registry") — so a catalog can be extracted by static analysis and an illegal code is refused at
import time rather than described in prose. Codes classify by *meaning*, never by which module
raised them (dev/standards/error-codes.md, "Minting a code"): no `didwebs`-specific component
name appears in any code.

The 17 codes below are verbatim from docs/design.md's reconciled table (rev 2, 2026-08-14),
already checked against the bakobo/errors catalog at the `bakobo-errors` pin — none collides
with a shipped code, and three are boundary cases against heti's near-neighbors, called out as a
comment where each is declared. Identity is the contract: a code's string, once shipped, never
changes (dev/standards/error-codes.md, "A code's meaning and `args` signature never change once
shipped").
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
    detail="The designated-aliases ACDC {said} is revoked, per direct query of its registry's "
    "transaction event log.",
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

SCHEMA_CORRUPT = ErrorCode(
    "e.self.corrupt.schema.f",
    "The bundled credential schema does not hash to its pinned identifier.",
    detail="The designated-aliases schema shipped with this build hashes to {computed}, not "
    "the pinned {pinned}; the resource has been altered.",
    args=("computed", "pinned"),
    hint="Reinstall didwebs from a trusted distribution; this failure is in the package, not "
    "in your submission.",
)

UNKNOWN_FAILURE = ErrorCode(
    "e.self.unknown.f",
    "An internal failure occurred that could not be attributed to a specific cause.",
)
