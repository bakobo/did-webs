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
