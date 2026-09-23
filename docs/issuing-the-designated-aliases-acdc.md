# Issuing the designated-aliases ACDC with your own tooling

Bakobo does not hold your keys. The `didwebs publish` pipeline takes a CESR stream you produced and verifies it; it never signs anything on your behalf, and there is no custodial path (decision `avuwzl` in `this.i`). That is a deliberate posture, and its cost lands here: producing the stream is your job, using whatever KERI tooling you already operate. This document says exactly what the stream must contain, and how to get it out of the two toolchains most controllers have — `kli`, and KERIA driven by a Signify client.

## What the stream must contain

One file, CESR, carrying four things in this order:

1. **The claimed AID's key event log**, complete from inception. If the AID is delegated, its delegator's KEL comes first — a delegate's events cannot be verified before the events that authorize them.
2. **The registry transaction event log** — the `vcp` that incepted the credential registry, anchored in the AID's own KEL.
3. **The credential transaction event log** — the `iss` that issued the credential, likewise anchored.
4. **The designated-aliases ACDC itself**, with its proof attached.

Constraints the pipeline enforces, each of which will refuse the submission rather than publish something partial:

- **Every frame is JSON, protocol v1.** `KERI10JSON` and `ACDC10JSON` version strings only. CBOR and MGPK are refused (`e.feature.unsupported.serialization.f`), and so is a protocol-v2 frame (`e.input.format.stream.f`). The reason is interoperability rather than preference: the deployed did:webs ecosystem parses v1, and a v2 frame is silently dropped by every 1.2.x reader — see constraint `qbqfst`.
- **The CESR attachment counters must be v1 genus too.** This is a separate axis from the version strings, and it is the one that catches people out: a stream can carry `KERI10JSON` bodies throughout and still attach counters no v1 parser can read. Recent keripy emits v2 counters by default, per call site.
- **The ACDC's proof is a source-seal triple** (the `-IAB` attachment `keri.app.signing.serialize` emits). The form shown in the did:webs specification's own worked example, a `-FAB` transferable indexed signature group, is **not** readable — by us or by any other implementation, including the reference resolver. That is an upstream defect rather than a rule of ours, but until it is fixed, a stream carrying that form will be refused.
- **The credential is self-attested, issued by the claimed AID, from a registry anchored in the claimed AID's own KEL**, and its `a.ids` must list the DID being published — both the `did:webs:` form and the corresponding `did:web:` form.
- **Nothing else.** A publication stream carries the claimed AID's own material, its delegator chain, and the issuer of a credential it carries. Another identifier's events in the same stream are refused (`e.rule.stream.third-party.f`), even when they verify perfectly.
- **8 MiB**, which is a flood guard rather than a budget. A real publication is a few kB.

The schema is pinned and not negotiable: `EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5`, the Designated Aliases Public Attestation.

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
