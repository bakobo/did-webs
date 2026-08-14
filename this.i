# did-webs — Intent Tree (this.i)
#
# Source of truth for this repo's intentions and the decisions that follow. Code and docs/ are
# derived from it. Format: dhh1128/intent node tree; see bakobo/dev/methodology.md.
# Node key line:  Name = [marks...] type:   (types: goal | decision | constraint | tension | deviation)
# id: opaque base32 [a-z2-7]{6,12}, never a semantic label.  why: meets the rebuttal-surface standard.

Production did:webs implementation on KERI = goal:
  id: xckiyf
  why: >
    did-webs exists so any Bakobo customer holding a KERI AID can participate in W3C DID-based
    ecosystems (DID resolution, VC tooling) without giving up KERI's cryptographic root of trust —
    did:webs binds a web-discoverable DID to a KEL, so trust in the DID document rests on key
    events, not on the web server that happens to serve it. Rejected adopting the reference
    implementation (GLEIF-IT/did-webs-resolver) wholesale: it is a self-described demonstration,
    while Bakobo needs an operator-grade publish/serve/resolve pipeline that composes with its
    witness infrastructure. Accepted tradeoff: we own the maintenance burden of tracking a spec
    that is still moving (kswg draft, actively edited as of Aug 2026), including re-verifying our
    KEL-to-DID-document transformation whenever it changes.
  children:

    Python on keripy = decision:
      id: jo5sby
      why: >
        Chose Python on the keripy libraries over TypeScript or any from-scratch KERI stack,
        because KEL verification is the security-critical core and keripy is the battle-tested
        implementation Bakobo already operates (bakobo/witness runs a stock keripy witness) — and
        the only living reference implementation is Python-on-keripy, so conformance cross-checks
        are direct. Rejected building on GLEIF-IT/did-webs-ts: it composes DIDs but cannot verify
        a KEL. Accepted tradeoff: TypeScript-native ecosystems (browser wallets) cannot embed our
        library; they consume it as a service (resolver endpoint / universal-resolver driver)
        instead.

    Ed25519 only in v1 = decision:
      id: 3woefn
      why: >
        Support only Ed25519 verification keys at first, though the spec also defines secp256k1
        and secp256r1 transformations. Ed25519 is what KERI deployments (and Bakobo customer
        AIDs) actually use, and each extra curve adds JWK-conversion surface that must be tested
        against a spec still in normative cleanup. Rejected implementing all three up front as
        speculative coverage. Accepted tradeoff: a DID whose key state contains a secp key fails
        with a clear unsupported-key error until the follow-on, rather than degrading silently.

    Publish-first, resolve as fast follow = decision:
      id: ecwpad
      why: >
        The first deliverable is the publish side — artifact generation so customers' AIDs
        become resolvable did:webs DIDs — with our own resolver as a fast follow. Customer value
        is appearing in DID ecosystems; third parties resolve with existing tools (universal
        resolver, GLEIF demo resolver), so publishing alone is already useful. Rejected
        resolve-first (verifies others' DIDs but ships nothing customer-visible). Accepted
        tradeoff: until our resolver lands, our only end-to-end oracle for published artifacts
        is the demo-grade GLEIF resolver, which is an incomplete comparator (it omits
        spec-mandatory document properties).

    Non-custodial: the product ingests controller-produced CESR streams = decision:
      id: avuwzl
      why: >
        Bakobo does not hold customer keys, so the publish product's surface is host-side: accept
        a CESR stream the controller produced (which must already contain the designated-aliases
        ACDC only the controller's keys can issue), verify it, derive the documents, and host the
        artifacts. Rejected a custodial keystore-to-artifacts pipeline as the product surface —
        customers already operate their own agents, and custody would change Bakobo's risk
        posture, not just its API. Issuance code still exists in the library, but scoped to
        keystores we control (tests, demos). Accepted tradeoff: customer onboarding depends on
        third-party wallet/agent tooling being able to issue the designated-aliases ACDC; we
        inherit that ecosystem gap rather than papering over it with custody.
      children:

        Hosted artifacts are derived from verified state, never submitted bytes = constraint:
          id: embuup
          why: >
            The KERI panel (reviews/keri-review-panel-phase1-design.md, SEC-F1/SPC-F1,
            2026-08-14) showed keripy's Parser resumes past per-frame validation failures, so
            "the stream verified" is never a property of submitted bytes — only of the state
            keripy accepted. Passing submitted bytes through to the hosted keri.cesr would let
            unverified frames (fork branches, rejected rpy records, third-party chaff) publish
            under Bakobo's domain. Both hosted artifacts are therefore re-derived: did.json
            from derived state, keri.cesr re-assembled by replay from the scratch database,
            with a frame-accounting and escrow audit defining ingest success. Rejected
            passthrough-after-verification as unsound at the parser layer. Accepted tradeoff:
            hosted keri.cesr is a normalized equivalent, not a byte-identical copy, of the
            controller's submission.

    Interop outranks estate keripy coherence = decision:
      id: gvimca
      why: >
        Where ecosystem interoperability and estate coherence conflict, interop wins — being
        resolvable by the existing did:webs ecosystem (GLEIF resolver, universal-resolver driver,
        both on keripy 1.2.13) is the product's purpose, while the estate's bakobo/keripy pin
        (366d810, the 2.0.0-dev line, shared by witness and heti) is an internal convenience.
        Discharge check: a spike feeds a bakobo/keripy-produced stream to the GLEIF resolver; if
        it ingests cleanly we keep the estate pin, otherwise this repo pins keripy 1.2.13 and the
        divergence is recorded as a deviation here. Rejected deciding by fiat without the spike
        (the versions may interoperate fine; KERI wire compatibility is a goal of both lines).
        Accepted tradeoff: possibly two keripy versions across bakobo repos, with the mismatch
        documented rather than hidden. RESOLVED 2026-08-14: the spike passed — estate pin kept;
        see the constraint below.
      children:

        Protocol v1 pinned at every event-constructing call = constraint:
          id: qbqfst
          why: >
            The spike (.ignored/spike-keripy-interop/REPORT.md, 2026-08-14) showed bakobo/keripy
            2.0.0-dev6 emits protocol-v2 events by default and per call site — makeHab,
            interact, and replay each default to v2 independently of the kever's version —
            while the deployed did:webs ecosystem (keripy 1.2.13 parsers) silently drops v2
            frames; v2 TEL events cannot even be serialized (no vcp ilk in the v2 table). With
            Vrsn_1_0 pinned everywhere, generated streams are byte-structure-identical to a
            1.2.13 control and ingest cleanly. So: every event-constructing and replay call
            passes the v1 version explicitly, and a regression test asserts generated streams
            carry only KERI10JSON/ACDC10JSON version strings. Rejected a global pin because
            keripy offers no such choke point — the default is per-call by API design. Accepted
            tradeoff: an easy-to-forget parameter on every call, mitigated by the
            version-string oracle.

    Resolver fails below TOAD, tolerates missing receipts above it = decision:
      id: wmoq5b
      why: >
        The resolver hard-fails a stream whose witness receipts on establishment events fall
        below the controller's declared TOAD (threshold of accountable duplicity), and does NOT
        fail on receipts missing beyond that threshold. TOAD is KERI's own sufficiency bar —
        the controller's published statement of how many receipts make key state accountable —
        so demanding every listed witness's receipt would reject streams KERI itself deems
        accountable, while warn-only below TOAD would fail open (org principle 8). Accepted
        tradeoff: a resolver cannot distinguish "witness slow to receipt" from "receipt
        withheld"; below TOAD we refuse rather than guess.
