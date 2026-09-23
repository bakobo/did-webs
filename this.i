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

        A published alias carries this AID, which is what makes it self-certifying = constraint:
          id: omz5lf7e
          why: >
            The spec constrains alsoKnownAs to DIDs with the same AID, and the designated-aliases
            table admits exactly three kinds: other same-AID did:webs DIDs, same-AID did:web DIDs,
            and did:keri:<AID>. That reads as a limitation and is a safety property. An AID is a
            hash of its own inception event, so an alias carrying it is self-certifying — the
            party who can produce the stream is the only party who can name it, and there is no
            way for one controller to name a *different* party's identity in a document Bakobo
            publishes. So document.also_known_as drops an entry of any other DID method rather
            than publishing it, and raises e.rule.alias.aid.mismatch.f on a readable entry naming
            another AID; ingest tolerates the unreadable entry deliberately (KRT-F4) so the rule
            is enforced where the document is built.

            Rejected widening the alias space to name a foreign identifier — a did:webvh, did:key
            or did:scid DID — and rejected carrying the same-AID rule to the ToIP task force as a
            spec gap. That was proposed here on 2026-09-14 (.ignored/webvh-recon-2026-09-14.md,
            F7) and is refused: loosening the rule is what would introduce a vulnerability this
            method does not have. The sibling bakobo/did-webvh measured the cost on 2026-09-15.
            did:webvh does not constrain alsoKnownAs, and a binding check built there assumed a
            key appearing in a log's updateKeys proved shared control of both identifiers. It does
            not — updateKeys is a unilateral declaration by the log's own controller about who may
            write its next entry, requiring no consent and no signature from the named key — so an
            attacker could list a victim's PUBLIC key in their own log, submit the victim's PUBLIC
            KEL, and have the gate certify the linkage with no victim secret involved. Reproduced
            and confirmed. No amount of further checking recovers the property, because a
            declaration that needs no consent cannot evidence one; the same-AID rule gets it from
            the AID's derivation and costs nothing to check. Rejected, for the same reason,
            publishing an unreadable entry under a caveat: a reader of a hosted did.json sees the
            alias and not the caveat, which is org principle 8's fail-open.

            Accepted tradeoff, and it is a real loss: a controller who also controls a did:webvh
            DID cannot say so in the did:webs document Bakobo publishes. The link is expressible
            only in the other direction, from the webvh document, where the controller's own
            signature covers the assertion. Two tests hold the line rather than the docstring —
            tests/test_document.py's foreign-method drop and its foreign-AID rejection — because
            nothing else in the repo would notice the widening.

        A path segment is refused for what it means to a filesystem, and containment is
        re-checked at the join = constraint:
          id: a2sbz34i
          why: >
            The did:webs `path` production is `1*(ALPHA / DIGIT / "-" / "_" / "~" / ".")`, and
            did.py transcribed it faithfully as `^[A-Za-z0-9_~.-]+$`. That charset matches `..`.
            Every path segment becomes a directory under the output root in
            publish.artifact_dir, so `did:webs:example.com:..:..:E<AID>` parsed cleanly and
            published did.json and keri.cesr two levels ABOVE the directory the web server
            serves. Reproduced end to end on 2026-09-17 before any fix: parse succeeded, the
            artifacts landed outside the served root, and the DID composed back to itself so
            nothing downstream could notice. A second, quieter instance of the same defect: a `.`
            segment collapses in the filesystem but not in compose(), so two distinct,
            separately-authorized DIDs named one artifact directory and whichever published
            second silently replaced the other's did.json with a document naming a different
            identifier.

            So: `.` and `..` are refused by name, as are `/`, a backslash, U+0000, and leading or
            trailing whitespace; and publish.artifact_dir resolves the join and refuses a
            directory that does not lie under the output root.

            Where this came from, and the lesson that matters more than the bug. The sibling
            bakobo/webvh-gate already carried every one of these refusals, in the same function
            position — its did.py:_path_segment — and ships them as the conformance vectors
            negative-path-traversal-did and negative-pct-encoded-traversal. The two repos
            implement the same shape: a DID whose colon-separated segments become directories
            under a web root. What travelled between them was the FRAMEWORK — the value type, the
            normalized-versus-raw discipline, the door census, the error registry, the shape of
            the test file. The specific refusal did not. A framework propagates because it is
            visible in the structure of the file you are copying; a refusal propagates only if
            somebody remembers it, and nobody did. Treat a sibling's negative vectors as part of
            the thing being ported, not as its test suite.

            Rejected porting webvh-gate's percent-decode along with its refusals. There,
            webvh-path-segment is DID Core's `idchar`, which admits `pct-encoded`, so `%2e%2e` is
            a SPELLING of `..` and can only be caught after decoding exactly once; here the
            production has no pct-encoded alternative at all, so `%2e%2e` is a segment containing
            a `%` and the charset refuses it outright. Adding a decode would start accepting
            identifiers the spec does not define and would rewrite them on the way in —
            dev/standards/input-handling.md's "door that normalizes silently". A test pins the
            premise instead (test_the_path_charset_admits_no_percent), so if the spec ever gains
            pct-encoded the decode is ported at that moment rather than rediscovered from another
            traversal.

            Rejected leaving the refusal to the charset alone. `/`, backslash, U+0000 and
            whitespace are all already outside the spec's charset, so the three checks that name
            them are unreachable today and would be dead code if they ran after it. They run
            BEFORE it deliberately, which is what makes them reachable and tested, and the reason
            is that a refusal which is only an accident of how narrow a production happens to be
            disappears the day the production widens — silently, in the same edit. This spec is
            still moving (the module's own "soft spot 3" is already an argument for widening the
            AID charset), so that day is foreseeable. Refusing by name survives it.

            Rejected fixing only the parser. The parser is the necessary half and the right place
            for an operator-facing error, but it is a validator far from the sink:
            publish.artifact_dir takes `did` structurally, so nothing in its signature says the
            value came through did.parse, and the properties it depends on are not "this matched
            the ABNF". Those are different claims in different modules, and they drift. Rejected
            the narrower alternative of requiring a parsed DID at the join — a type check, or
            re-parsing did.raw — which moves the same trust one function along without ever
            checking the properties that matter, and `raw` is explicitly non-authoritative.

            THE SINK RELIES ON TWO PROPERTIES, AND THE FIRST REVISION OF THIS CONSTRAINT CHECKED
            ONE. Containment is that the directory stays under the output root. Injectivity is
            that two DIDs which differ name two directories — the `.`-collision half of the
            finding above. The first revision resolved the join and compared it against the root,
            which establishes containment while DESTROYING THE EVIDENCE for injectivity:
            Path.resolve() normalizes `a/./b` and `a/b/../b` to `a/b` before the comparison runs,
            so the sink was blind to exactly the aliasing the parser refusal had been added for.
            Copilot raised it on PR #5 and measurement confirmed it: ('a',), ('a','.'), ('.','a'),
            ('a','..','a') and ('a','b','..') were all accepted and all five landed on one
            directory. This is this constraint's own generalization — naming the checker is not
            naming the property — turned on the fix that generalization justified. A check that
            NORMALIZES BEFORE IT COMPARES cannot see an aliasing defect, because normalizing is
            what aliasing does; the check has to run on the components, before anything is joined.

            So the check is per component, before the join: each must be a single directory name
            — not empty, not `.` or `..`, carrying no separator. Total and syntactic, a claim
            about the value rather than about the filesystem, so nothing can race it. Containment
            then holds BY CONSTRUCTION, since a join of single directory names cannot leave the
            root, and is asserted as a property in the suite rather than re-checked in a branch
            no input could reach. Rejected keeping the resolve-and-compare alongside it: besides
            being unreachable, where it would NOT be unreachable it would be unsound. Resolving
            follows symlinks, so it reads as a guard against a symlink planted inside the served
            tree, and it is not one — artifact_dir checks and publish creates the directory
            afterwards, so anyone who can plant the symlink can plant it in that window. A guard
            that loses a race it appears to win is worse than no guard, and the adversary it
            imagines can already write the artifacts directly.

            The refusal carries e.self.corrupt.did.f, a registry code, not the bare RuntimeError
            the first revision used. That revision cited ingest._temp_root's bare RuntimeError as
            precedent; the citation does not hold and retiring it is worth recording. That line
            arrived on 2026-09-15, two days earlier, in the commit implementing l7ws7hdt — and
            l7ws7hdt's own `why` argues at length about how a temp root is IDENTIFIED and says
            nothing whatever about what type to raise. So the exception type there was never
            decided, only written; treating it as a convention would have laundered one unargued
            choice into a house rule, against AGENTS.md's actual standard that every error carries
            a stable symbolic code and a retryability disposition. Rejected `self` vs `input` in
            favour of `self`: the component is decidable from the value alone, which is normally
            the `input` test, but by this point the value is not a request — did.parse is
            contracted to have refused it — so reporting e.input.format.did.f would tell an
            operator their DID is malformed when no such DID could have reached the CLI. Rejected
            reusing e.self.unknown.f, which Copilot offered as the alternative: the error-codes
            standard reserves that leaf for a failure we cannot attribute AT ALL, and this one is
            attributed precisely, to a named component of a named DID. Spending the unattributable
            code on an attributable fault is what makes it stop meaning anything.

            The door census exemption for cli.py:main was rewritten in the same change, because
            it had argued the opposite and half the value here is in retiring that argument. It
            claimed argv is "not attacker-controlled in a phase-1 local operator command" and
            that the DID "is checked where it is used ... through did.parse". Both are wrong in
            ways that read as reasonable. A value can be operator-supplied and attacker-chosen at
            the same time: the DID names the CUSTOMER's AID and host, so the operator is a
            transcription step and not a source of trust, and where a value entered says nothing
            about who chose it. And naming the checker is not naming the property: did.parse
            decided ABNF conformance while the property the sink relied on was containment, which
            nothing checked — the DID was valid, checked, and unconstrained in the way that
            mattered.

            Accepted tradeoff: a controller whose deployment path legitimately contains a segment
            that is exactly `.` or `..` cannot publish it. No such deployment exists — no web
            server can serve one distinguishably — and the two dot segments are the only thing
            refused, so `v1.0`, `.well-known` and `...` all still parse. A regression test holds
            that line, because over-refusing here would be the quieter failure.

        A fork keripy reconciled is not a fork we refuse = decision:
          id: vo6rnxve
          why: >
            did:webs resolution step 3 says "If event-stream divergence or forking is detected
            ... resolution MUST fail" (spec/body.md:344-346), and there is no reconciliation
            clause anywhere in spec/. KERI's superseding recovery is a fork in KERI's own words
            — "the KEL is forked at the sn of the superseding event" (spec-body.md:1799), "when
            an event is superseded, a branch in the DAG is created" (:1788) — and it is the
            designed response to a live exploit of the current signing keys, which is the very
            thing did:webs's own Security Considerations recommend at :2398-2401. Read
            literally, the two texts together make a controller who recovers unpublishable, and
            hand an attacker who merely PROVOKES a recovery — one interaction event signed with
            a stolen key, published once — permanent denial of the DID at no further cost.

            This was not hypothetical here. An outside red-team pass (2026-09-21,
            ../didwebvh-py/.ignored/redteam/reports/webs-findings.md, findings A1/B2) traced
            this repo as the implementation that reads :344-346 at face value, and the
            recovered_kel fixture then reproduced it at runtime: keripy accepts both the
            superseded ixn and the superseding rot at sn 3, kels.getLast returns the rotation,
            the interaction is still in the first-seen log, and duplicitous() flagged it — so
            ingest refused a valid recovery with e.state.conflict.kel.f. The report reached the
            same verdict about the reference resolver from the other side: it does not implement
            the rule at all, which is more permissive than the spec requires. Two conforming
            implementations disagreeing about whether the same DID resolves is the evidence that
            the text needs fixing, and tick ~4gab carries that upstream.

            So we take the reconciliation reading. A conflict keripy itself reconciled under
            KERI's superseding acceptance rules is not a refusal; a conflict keripy would not
            accept still is. The test is membership of the first-seen log, which is keripy's
            record of the judgment it already made. Rejected implementing the superseding rules
            ourselves — A0/A1/A2 and the prior-digest check are enforced in Kever.rotate before
            anything reaches fons, and a second implementation of them in this repo would be a
            second opinion that can only disagree with the first. Rejected keeping the literal
            reading and asking the customer to republish a reconciled trunk instead: that makes
            Bakobo the reason a compromise recovery cannot be published, and a controller in the
            middle of a recovery is the party with the strongest claim on being served. Rejected
            waiting for the spec item to land first: a refusal that only fires after a key
            compromise is not a good thing to be holding.

            Accepted tradeoff: we are deliberately more permissive than one reading of a MUST,
            so a resolver that implements :344-346 literally may refuse a stream we publish.
            Nothing is gained by an attacker from the permissiveness — a superseding rotation
            has to satisfy the prior event's pre-rotation commitment, so only the controller's
            unexposed next keys can produce one — and the property we give up is one no
            implementation is known to enforce today.
          children:

            keri.cesr replays the key event log first seen, superseded events included = constraint:
              id: vctci4we
              why: >
                Neither specification says what a published keri.cesr contains after a recovery.
                KERI says both that superseded events "may be viewed or replayed in order of
                their original acceptance" (spec-body.md:1799) and that recovery repairs the KEL
                "so that future validators of the KEL will not see the compromised events"
                (:1792); did:webs requires only "the KERI event stream for the AID"
                (spec/body.md:118-125). The two readings publish different bytes and the
                divergence rule reaches a different verdict for each.

                We keep the first-seen replay emit_stream already does (db.clonePreIter), so the
                hosted stream carries both branches at the fork point. We are copying the
                reference generator: gen_kel_cesr in GLEIF's dws is `return hab.replay(pre=pre)`,
                a first-seen replay over the same clonePreIter, so this is the shape the deployed
                ecosystem receives and re-ingests, and decision gvimca says interop settles a
                question of this kind. The second reason is independent of interop and survives
                even if the ecosystem changes its mind: a first-seen replay PRESERVES the prefix
                relation that the spec's own divergence rule tests at :185-189, because the
                pre-recovery stream remains a prefix of the post-recovery one. Trunk-only
                publication inverts that — a cached pre-recovery copy is then neither a prefix
                nor a subset of what is published, and :190-192 says both the streams and the
                DIDs are invalid, permanently, with no way back since first seen is never
                unseen.

                Rejected publishing the reconciled trunk only, for that reason. Rejected making
                it a publication option: two shapes means two answers about whether one DID
                resolves, which is the interoperability defect this constraint exists to avoid,
                not a flexibility. Accepted tradeoff: the hosted stream carries an event the
                controller repudiated, and a resolver reading :344-346 literally must refuse it.
                That is vo6rnxve's conflict again, now on the wire rather than in our audit, and
                it is why ~4gab asks the editors to say normatively what keri.cesr must contain.

        Republication can break the spec's prefix rule for reply records = tension:
          id: q5qmjv3t
          why: >
            The prefix/divergence rule at spec/body.md:185-192 treats keri.cesr as append-only,
            and it is not. Per :256-262 the stream also carries KERI reply messages — Location
            Scheme and Endpoint Role Authorization — and reply state is governed by BADA, where
            a newer record REPLACES an older one at the same route rather than following it. The
            spec's own informative note concedes the shape: "Superseded, cut, nullified,
            escrowed, or otherwise unaccepted state is not projected" (:1725). emit_stream
            replays the reply records the current submission carried, so a controller who changes
            a witness URL and republishes produces a stream the previously published one is
            neither a prefix nor a subset of — and the literal rule then says both streams and
            both DIDs are invalid.

            Recorded as a tension rather than closed, because the honest fix is not ours. Tick
            ~4gab carries the upstream ask (red-team A3): scope the prefix/divergence rule to the
            KEL and TEL, where the log really is append-only, define the relation once instead of
            as "prefix" in one clause and "subset" in the next, and say what a resolver does with
            a reply record present in one stream and absent from another. Rejected carrying
            superseded reply records in the hosted stream so that every publication is a superset
            of the last: we would have to keep publication history to do it, which constraint
            embuup's per-submission scratch database deliberately does not, and the result would
            republish endpoint advertisements the controller has withdrawn — a stale mailbox or
            agent URL is exactly what BADA's replace semantics exist to retire. Rejected
            detecting it at publish time: the publish side never sees the previously published
            artifact, and a check that cannot see its own input is theatre.

            Accepted tradeoff: until the spec settles, a controller who changes an endpoint and
            republishes leaves any party holding the older stream able to reach the "both DIDs
            invalid" verdict by the literal rule, and we can neither prevent it nor observe it
            from here. The phase-2 resolver's half is smaller and is ours: scope its own
            comparison to the KEL and TEL portions.

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

    Demo DIDs use a provisional, configurable host = decision:
      id: n4fsn4v2
      why: >
        The SEDI Summit rehearsal publishes the reissuer's and Guy's AIDs under
        dids.bakobo.com/demo/<AID>, giving the summit artifacts their own path while an
        independent resolver exercises the URL shape intended for hosting. The trust-anchor
        hostname decision remains open in the interop ledger (2u2s), so the recipe takes both
        host and path prefix as inputs and defaults the prefix to demo. If either changes, both
        designated-aliases ACDCs and their did:webs DIDs must be re-minted; changing DNS or
        copying files cannot change a signed alias. Accepted tradeoff: the rehearsal proves
        interoperability for a provisional location, not authority for the final one.

    Hosted KEL replay carries witness receipt couples derived from verified signatures = decision:
      id: t3q6azxm
      why: >
        The KERI v1 wire format permits a non-transferable witness's signature to travel either
        as an indexed witness signature (-B, where the index names a witness in the event's
        witness list) or as a non-transferable receipt couple (-C, where the witness prefix is
        explicit). The pinned keripy replay emits -B from its accepted witness-signature store,
        but Affinidi did-webs 0.7.0 parses -B without counting it toward the event's witness
        threshold; its checker counts only -C. Add -C couples to hosted KEL events by mapping
        each accepted -B signature to its witness prefix and verifying that signature over the
        accepted event body before emission. Retain the original -B attachments, so keripy's
        own re-ingest still enforces the threshold and the hosted stream remains a replay of
        verified state. Reject an out-of-range index or a failed verification rather than
        inventing a receipt. This costs duplicate encoding of the same signature but does not
        add authority or require controller keys on the host. It does not solve Affinidi's
        separate rejection of keripy's -I ACDC source seal: that implementation requires an
        independently signed -F proof that the submitted credential does not provide, while
        keripy's ACDC verifier requires -I. The cold-start interop harness preserves this
        boundary as a reproducible failure until the parsers converge.

    The demo replay accepts one verified designation per AID = constraint:
      id: 52vtfve2
      why: >
        The cold-start recipe uses KLI for witnessed AIDs and this repo's v1 issuance adapter,
        because the pinned KLI VC commands emit v2 anchors and replay counters. The adapter
        uses witness OOBIs verified by KLI before assigning their localhost transport URLs,
        and exports exactly one designated-aliases credential per AID; with zero it has no
        authorization to publish, and with more than one it cannot choose which signed alias
        set the demo means. Rejected picking the first stored credential or trusting a witness
        URL before its OOBI resolves, because either would let incidental local state change
        what is published. This is a rehearsal constraint, not a new customer issuance API.
