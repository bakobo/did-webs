# Issuing the designated-aliases ACDC with your own tooling

Bakobo does not hold your keys. The `didwebs publish` pipeline takes a CESR stream you produced and verifies it; it never signs anything on your behalf, and there is no custodial path (decision `avuwzl` in `this.i`). That is a deliberate posture, and its cost lands here: producing the stream is your job, using whatever KERI tooling you already operate. This document says exactly what the stream must contain, and how to get it out of the two toolchains most controllers have — `kli`, and KERIA driven by a Signify client.

## What the stream must contain

One file, CESR, carrying four things in this order:

1. **The claimed AID's key event log**, complete from inception. If the AID is delegated, its delegator's KEL comes first — a delegate's events cannot be verified before the events that authorize them.
2. **The registry transaction event log** — the `vcp` that incepted the credential registry, anchored in the AID's own KEL.
3. **The credential transaction event log** — the `iss` that issued the credential, likewise anchored.
4. **The designated-aliases ACDC itself**, with its proof attached.

Constraints the pipeline enforces, each of which will refuse the submission rather than publish something partial:

- **Every frame is JSON, and every frame is one protocol version.** A v1 stream carries `KERI10JSON` and `ACDC10JSON` version strings only; a KERI protocol v2 stream is described in its own section below. CBOR and MGPK are refused (`e.feature.unsupported.serialization.f`), and so is a stream mixing versions (`e.input.format.stream.f`). Prefer v1 where you have the choice: the deployed did:webs ecosystem parses v1, a v2 frame is silently dropped by every 1.2.x reader (constraint `qbqfst`), and no third-party did:webs resolver reads v2 yet.
- **The CESR attachment counters must be v1 genus too.** This is a separate axis from the version strings, and it is the one that catches people out: a stream can carry `KERI10JSON` bodies throughout and still attach counters no v1 parser can read. Recent keripy emits v2 counters by default, per call site.
- **The ACDC's proof is a source-seal triple** (the `-IAB` attachment `keri.app.signing.serialize` emits). The form shown in the did:webs specification's own worked example, a `-FAB` transferable indexed signature group, is **not** readable — by us or by any other implementation, including the reference resolver. That is an upstream defect rather than a rule of ours, but until it is fixed, a stream carrying that form will be refused.
- **The credential is self-attested, issued by the claimed AID, from a registry anchored in the claimed AID's own KEL**, and its `a.ids` must list the DID being published — both the `did:webs:` form and the corresponding `did:web:` form.
- **Nothing else.** A publication stream carries the claimed AID's own material, its delegator chain, and the issuer of a credential it carries. Another identifier's events in the same stream are refused (`e.rule.stream.third-party.f`), even when they verify perfectly.
- **8 MiB**, which is a flood guard rather than a budget. A real publication is a few kB.

The schema is pinned and not negotiable: `EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5`, the Designated Aliases Public Attestation.

## A KERI protocol v2 stream

A controller whose AID is protocol v2 publishes a v2 stream (decisions `0plkq8s8`, `3kn6drgf` and `35yl884k` in `this.i`). There is no flag: `didwebs publish` reads the version from the stream. It differs from the v1 stream above in these ways, and each one is enforced:

1. **It opens with the CESR v2 genus-version counter** (`-_AAACAA`), and every frame in it is v2. A stream mixing v1 and v2 frames is refused.
2. **The registry is a v2 ACDC registry**: a `rip` (registry inception) and blindable updates (`bup`), each anchored by a seal in the AID's own KEL. There is no `vcp` or `iss`. A `upd` update is refused (`e.feature.unsupported.registry.event.f`): the ACDC spec lists it, but WebOfTrust keripy no longer accepts it.
3. **The registry's state is disclosed**: each update's blinded state block, as a BlindedStateQuadruples (`-a`) group, on that update or grouped on the ACDC. Every update from the latest back to the latest non-vacuous one needs its disclosure; without it nobody can read whether the designation is issued or revoked, so a missing or mismatched one is refused (`e.proof.stream.disclosure.f`). keripy's `Registrar.issue` returns each update's blinder and persists none, so keep them. Use a fresh random blinding salt per registry and never reuse one: keripy derives each update's UUID from the salt and the sequence number alone, so a shared salt lets one published disclosure unblind another registry's update at the same position.
4. **The registry is complete**: every registry event your KEL anchors must be in the stream. Leaving one out is refused (`e.input.missing.registry.event.f`), because the omitted update could be the one that revoked the designation.
5. **The credential is an `acm`** under the proposed v2 designated-aliases schema, `EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA` (derived from the v1 schema as `docs/design.md` states exactly). It carries `rd` naming its registry, **no top-level `u`** (the schema refuses one: any `u` makes an ACDC a non-public variant), and no proof attachment: the anchored `bup` that binds it is its proof.
6. **Order**: KEL, any `rpy` records, the credential, then the registry with the attached `bup` last. Ingest also accepts the credential last, but some readers cannot finish an attachment-less final frame, and what we host always ends on the `bup`.

`didwebs.assemble.issue_aliases_v2` and `keystore_stream_v2` produce exactly this from a keripy keystore, and are the reference for anyone building it with other tooling.

## With `kli`

The sequence below is the reference implementation's own, from GLEIF's `did-webs-resolver` `docs/getting_started.md`, for its keripy 1.2.x line. It is **not directly usable with this repository's pinned keripy 2.0.0-dev6**: its `kli vc registry incept` and `kli vc create` omit the v1 version on KEL anchor interactions, so those events default to v2, and `kli vc export` has `--full` rather than `--chain` but replays v2 attachment counters. The SEDI M7 recipe in `scripts/sedi_m7.sh` uses KLI for witnessed AID inception and rotation, then `didwebs.assemble.issue_aliases` and an explicit v1 replay for the credential and publication stream. Assuming a compatible 1.2.x keystore and an incepted AID, the historical sequence is:

Incept a credential registry:

```
kli vc registry incept --name my-keystore --alias my-controller --registry-name dAliases
```

Resolve the schema. ACDC issuance validates against a schema the keystore can actually resolve, so this step is not optional:

```
kli oobi resolve --name my-keystore --oobi-alias designated-aliases \
  --oobi https://weboftrust.github.io/oobi/EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5
```

Issue the attestation. `--data` is a JSON file carrying `dt` and the `ids` array; `--rules` is the public schema's rules block:

```
kli vc create --name my-keystore --alias my-controller --registry-name dAliases \
  --schema EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5 \
  --data @desig-aliases-attr.json --rules @desig-aliases-public-schema-rules.json
```

Export the credential with its supporting material:

```
kli vc export --name my-keystore --alias my-controller --said <ACDC SAID> --chain
```

On the reference implementation's keripy line, `--chain` pulls in the KEL and both transaction logs alongside the ACDC. On the pinned 2.0.0-dev6 CLI, `--full` is the corresponding flag, but its output is still not a valid v1 publication stream for this pipeline because its KEL replay defaults to v2 attachment counters. Use the tested M7 adapter or another exporter that pins both protocol and CESR genus to v1.

## With KERIA and a Signify client

KERIA already exposes exactly this artifact, which is the good news in this document.

Resolve the schema first, as a **data** OOBI — KERIA refuses issuance otherwise, and says so: *"It must be loaded with data oobi before issuing credentials"* (`keria/app/credentialing.py`). Then create the registry and issue the credential through the usual Signify calls.

To export, request the credential with the CESR content type:

```
GET /credentials/{said}
Accept: application/json+cesr
```

In signify-ts that is the second argument to `get`:

```js
const stream = await client.credentials().get(said, true);
```

The response body is the file to submit. Reading KERIA's `CredentialResourceEnd.outputCred`, it emits the issuer's KEL, then the registry TEL, then the credential TEL, then the ACDC serialized with `signing.serialize` — which is the order and the proof form described above. No translation step is needed.

## Where this gets hard

These are the gaps we inherit from the ecosystem rather than ones we chose, and they are the reason this document exists at all.

**The protocol version is not yours to set, and not obviously visible.** KERIA depends on keripy unpinned, and its export path clones events without specifying a genus, so which CESR genus you get depends on which keripy your KERIA image resolved. If your submission is refused for a format or serialization reason and the JSON in it looks like plain v1, this is the first thing to check. There is no way to ask KERIA for a specific genus over the API today.

**Endpoint and witness declarations do not survive the export.** KERIA's CESR export carries key events, transaction events and the credential — it does not carry the `rpy` records that declare a witness's or an agent's URL. If your DID document needs service endpoints projected from those declarations, that material has to reach us another way, and today it does not. Tell us if you need this; it is a known shape of work rather than a surprise.

**Witnesses.** A witnessed AID's events need their receipts to travel with them. The `kli vc export --chain` path includes them because it clones from a database that has them. We have not verified the KERIA path end to end for a witnessed AID.

**The specification's own worked example does not verify.** If you are building from the spec's `keri.cesr` sample rather than from tooling output, you will produce something no implementation accepts. Build from tooling output.

## What has been verified, and what has not

Being precise about this, because the difference matters if something does not work:

- **Verified in this repository, under test**: every constraint in *What the stream must contain*. These are enforced by `didwebs` and covered by its own suite.
- **Verified by reading source**: the KERIA export endpoint's content and ordering (`keria/app/credentialing.py`, `CredentialResourceEnd.outputCred`), the signify-ts client call (`src/keri/app/credentialing.ts`), and the data-OOBI requirement for issuance.
- **Taken from the reference implementation's documentation**: the `kli` command sequence and the schema OOBI URL, both from GLEIF `did-webs-resolver` `docs/getting_started.md`.
- **Verified in the M7 rehearsal**: KLI incepted and rotated two AIDs with three local witnesses and a threshold of two; the v1 adapter issued each designated-aliases ACDC, exported its stream, and `didwebs publish` accepted both and Guy's update. The interop limits are summarized in `docs/scope.md`.
- **Not verified end to end**: the unmodified KLI VC export path or the KERIA path as a direct input to `didwebs publish`. If you hit something this document gets wrong, that is worth telling us — it means this page needs a correction, not that you did it wrong.
