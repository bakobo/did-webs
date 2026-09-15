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

        The submitted stream crosses one named, bounded door = constraint:
          id: adyiw2mm
          why: >
            dev/standards/input-handling.md: nothing crosses a boundary unbounded, size before
            shape before meaning, and the set of doors is kept complete by a test rather than by
            memory. Until now this repo had no size axis at all — cli.py read the whole
            submitted file and handed it to ingest, and a grep for a limit found only did.py's
            RFC 1035 host and label lengths. Every check ingest makes is a judgment about what
            the bytes *mean*, and none of it starts until they are resident, which is the
            standard's named anti-pattern: verifying every signature in a stream of unbounded
            length is a more expensive way to run out of memory. So the stream enters through
            didwebs.bounds.open_stream, which reads one byte past the bound and refuses on the
            overage rather than reading the file and then measuring it, and tests/test_doors.py
            walks the package's AST so a later unguarded read fails at authoring time.

            Only a size bound, and only one door. Rejected adding a frame-count or per-frame cap
            alongside it: every CESR frame carries a version string and a body, so a byte bound
            already bounds the frame count, and a second number chosen independently would be an
            opinion about what a legitimate publication contains — which is exactly what the
            standard says a flood guard must not be. Rejected bounding inside ingest.walk, where
            the frames are: by then the bytes are in memory and the guard would be the
            "bound that only exists downstream" anti-pattern. The number is 8 MiB, matching the
            sibling did-webvh door for the same artifact: a KEL, its registry TELs and one
            designated-aliases ACDC, where events run hundreds of bytes to a few kB, so this is
            thousands of rotations and nowhere near what a real submission weighs.

            Accepted tradeoff, and it is the reason this landed before it was needed: phase 1 is
            a local operator command, so today the operator chose the file and a bound protects
            nobody from anybody. The debt belongs in the same sentence as cli.py's other phase-1
            caveat — that the pipeline establishes no submitter-to-AID binding — because both
            must be in place BEFORE any submission surface exists. An endpoint with no bound is
            a memory exhaustion an unauthenticated caller can trigger, and the door is far
            cheaper to add now than to retrofit under that deadline.

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
            tradeoff: an easy-to-forget parameter on every call, mitigated by two oracles, one
            per axis, because there are two axes and for a while only one was watched.

            The two axes, and why one oracle was never enough. The version-string oracle reads
            event-body version strings and assemble._v1 reads serder.pvrsn: both watch the
            *protocol* version. The CESR *genus* of the attachment counters is independent of
            it, and nothing watched it — so a stream could carry v1 bodies and v2 attachments
            and pass. Not theoretical: the 2026-08-28 pin-bump attempt (tick ~3vol) produced
            exactly that stream, where keri.app.signing.serialize stopped hardcoding a v1
            SealSourceTriples counter and began deriving the genus from keripy's global
            default, flipping the ACDC attachment from '-I' to a v2 '-S' SealSourceCouples
            while every event body stayed KERI10JSON. The version-string oracle passed it, and
            the first thing to notice was ingest.walk rejecting the stream as unreadable — a
            confusing report at the consuming end about a defect introduced at the emitting
            one. The genus oracle closes that: every generated stream must be readable end to
            end by a CESR consumer pinned to genus v1, which is what keripy 1.2.13 is, and a
            v2 counter raises UnexpectedCodeError where it was emitted. Rejected decoding the
            counters by hand in the toolkit — that means reimplementing a CESR walk in test
            support, and keripy's own Parser is both the correct walker and the thing the
            deployed ecosystem actually runs. Accepted tradeoff: the oracle proves the counters
            decode under CtrDex_1_0 by consuming the stream rather than by enumerating codes,
            so it reports where reading stopped rather than naming every counter it accepted.

            The pin has three call shapes, not one, and the second and third are the ones a
            reader would otherwise miss. (a) Callers that accept a version argument — makeHab,
            interact, replay, cloneDelegation, clonePreIter, Habery — are passed V1 outright.
            (b) Three keripy entry points accept no version argument and derive it instead:
            Registry.issue, Registry.revoke, and Credentialer.create all read it off the
            registry's vcp serder. There the pin can only be checked, so assemble._v1 asserts
            the derived version at the call site; a keripy change that flips the derivation
            then fails where it happened rather than downstream in a stream nobody can read.
            (c) The pin extends to *parsing*, which is a separate version axis: a Parser
            carries its own CESR genus version, also defaulting to v2 on this line, and a valid
            v1 stream fed to a v2-genus parser yields nothing at all — no exception, no
            diagnostic, no kevers entry, so the failure presents as an empty stream rather than
            a rejected one. Pinning the Habery is not sufficient, because the genus is
            re-chosen on the parse call; ingest therefore passes version=V1 to every Parser
            construction and every parse call. Rejected treating the emit-side pin as covering
            both: the two versions are independent, and only the emit side has an oracle, so
            the parse-side pin is load-bearing and invisible without this note.

    Temporary keripy stores are contained per run, never identified by a shared namespace = constraint:
      id: l7ws7hdt
      why: >
        keripy creates every temporary store with mkdtemp under the system temp directory, and
        its close removes only the leaf of the path inside it — so both ingest and the fixtures
        must remove the mkdtemp roots themselves. What this constraint settles is how a root is
        *identified*. Measured 2026-09-15: five test oracles globbed /tmp/keri_* and compared
        the set before and after an operation, which is a claim about a namespace that sixteen
        bakobo repos share, because keripy's temp head is the system temp directory and nothing
        namespaces it per project. One concurrent sibling suite reddened twelve tests here, and
        every one of them failed on the glob rather than on the behavior under test — the
        negative matrix was never mis-attributing an error code, which is what the symptom
        looked like. Worse, tests/crossimpl/runner.py did not merely read that namespace: it
        removed everything that appeared in it during its subprocess window, which against a
        concurrent keripy run deletes another repo's live store. So: a root is derived from the
        store's own TempHeadDir and refused if the store does not lie under it, the suite
        repoints that head at a per-run directory, and no oracle reads a shared namespace.
        Rejected keeping the globs and serializing suite runs across the estate — the
        unsoundness is in the oracle rather than in the scheduling, and a rule about how to run
        a suite cannot be enforced by that suite. Rejected filtering by name (globbing a
        didwebs-specific prefix) because the prefix is keripy's to choose and not ours to rely
        on. Accepted tradeoff: a keripy store opened outside the suite's own helpers now fails
        loudly instead of littering silently — the failure direction we want, but a failure
        where previously there was none.

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
