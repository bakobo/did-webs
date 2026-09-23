# Affinidi 0.7.0 interop boundary

The cold-start checker is [`tools/affinidi-check`](../tools/affinidi-check/README.md).
This note records exactly which v1 CESR attachments the current publisher and
Affinidi read. Source references below name `trustoverip/kswg-did-method-webs-specification`
at `2d84ef2`, `GLEIF-IT/did-webs-resolver` at `0d4f2fd`, the published
`affinidi-did-webs` 0.7.0 / `affinidi-keri-core` 0.4.0 crates, and the
`keripy-1x` KERI v1 code table. The method spec requires a CESR stream and
processing under KERI rules (`spec/body.md:340-354`). It does not mandate one
attachment spelling. Its ACDC may be anchored directly in the KEL or through a
TEL anchored in the KEL (`:2487-2491`); the full example uses `vcp`, `iss`,
and KEL interaction seals (`:1416-1428`, `:1521-1574`).

| Evidence | KERI v1 framing | Our pinned keripy | Affinidi 0.7.0 |
| --- | --- | --- | --- |
| Witness receipt on a KEL event | `-B` indexed witness signature or `-C` non-transferable prefix/signature couple (`keripy-1x/src/keri/core/counting.py:55-57`; `keri/core/eventing.py:1665-1683`) | Accepts `-B`; accepted signatures are stored in `db.wigs` and replayed as `-B` (`keri/db/basing.py:1732-1741`). The hosted replay now also derives verified `-C` couples from these signatures. Its own re-ingest accepts both together. | Parses `-B` and `-C` (`affinidi-keri-core/src/parser.rs:350-363`) but counts only `-C` on the event or matching `rct` (`affinidi-did-webs/src/kel.rs:284-360`). |
| Designated-aliases ACDC proof | `-I` source seal triple or `-F` transferable indexed signature group are distinct valid v1 groups (`keripy-1x/src/keri/core/counting.py:60-63`). The method spec's full-stream example uses `-F` (`spec/body.md:3135`), while its normative rule permits TEL-mediated anchoring (`:2487-2491`). | `signing.serialize` emits `-I` (`keri/app/signing.py:12-20`); the ACDC dispatch passes the `-I` triple to `processCredential` and does not use `-F` (`keripy-1x/src/keri/core/parsing.py:1155-1162`). | V1 parser recognizes `-F` but not `-I` (`affinidi-keri-core/src/counter_table.rs:80-89`, `src/parser.rs:305-310`). Alias verification requires a `-F` group signed by the controller (`affinidi-did-webs/src/aliases.rs:136-180`), plus the `vcp`/`iss` and KEL seals (`:90-120`, `:185-239`). |

The publisher can re-encode `-B` as `-C` because the signature is already
present and maps to a named non-transferable witness. It verifies the signature
over the accepted event body before doing so. It cannot derive Affinidi's `-F`
ACDC signature from a `-I` TEL seal: that would require a new controller
signature, and the host is non-custodial (`this.i`, decision `avuwzl`). A stream
carrying only `-F` also fails this keripy pin's ACDC acceptance. Preserving our
verified-state and own re-ingest rules therefore leaves the `-I` blocker open.

In the 2026-09-23 cold run, the two complete hosted streams re-ingested through
`didwebs publish` (log `/tmp/didwebs-interop-reingest3.log`). Affinidi rejected
both complete streams at `-I` (`/tmp/didwebs-interop-affinidi-demo.log`). Removing
the ACDC **only for diagnosis** let Affinidi resolve both witnessed KELs after
the receipt change (`/tmp/didwebs-interop-affinidi-no-acdc3.log`). Those trimmed
streams are not valid did:webs publications: resolution step 4 requires the
designated-aliases ACDC (`spec/body.md:350-354`), yet Affinidi returns a document
when alias verification fails (`affinidi-did-webs/src/resolver.rs:48-68`). The same
resolver compares only the fetched document's ID and key IDs (`:71-129`) though
the method requires equality of the entire transformed DID document
(`spec/body.md:355-362`). On a diagnostic ACDC-free reissuer stream, changing
only `did.json.controller` to an attacker DID is accepted, while a changed key ID
and a changed KEL signature are refused
(`/tmp/didwebs-interop-reissuer-{tamper_controller,tamper_key,tamper_stream}.log`).

After Guy's KLI rotation, our verifier re-ingests the new stream and derives the
new key `DCComigjTwetk8AUE5Mugj0IZ8PhUwxX03cvCUvrRd8y`
(`/tmp/didwebs-interop-demo-rotate.log`,
`/tmp/didwebs-interop-rotated-reingest.log`). Affinidi's ACDC-free diagnostic
stream fails before document derivation: its `RotationEvent` requires a `c`
configuration field (`affinidi-keri-core/src/event.rs:60-110`) and `Kever`
deserializes every `rot` into it (`src/kever.rs:260-261`). KLI's normal KERI v1
rotation has no `c` (`/tmp/didwebs-interop-case-trimmed.log`; the keripy v1
serializer explicitly omits it at `keri/core/eventing.py:844-866`). This is a second
independent M7 blocker after the ACDC proof mismatch.

The GLEIF 0.3.7 comparison failure is independent of CESR framing. The spec
requires top-level `controller` (`spec/body.md:525-530`), `did:keri` in
`alsoKnownAs` (`:590-591`), and both verification relationships (`:1018-1048`).
GLEIF's constructor omits them (`src/dws/core/didding.py:334-353`), obtains
aliases only from the ACDC (`:388-396`), and its transform does not update the
top-level controller or reciprocal alias (`:472-492`). Deep equality then
returns `notVerified` (`src/dws/core/resolving.py:195-211`, `:307-320`). The
previous rehearsal logs isolate this with a GLEIF-shaped copy of the same
KERI-backed document (`/tmp/didwebs-m7-demo-compat-guy-resolve.log`).
