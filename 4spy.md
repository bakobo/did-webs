# Customer onboarding doc: how a controller issues the designated-aliases ACDC with third-party tooling (Signify/KERIA capability survey) — inherited ecosystem gap per this.i avuwzl
kind: todo
created: 2026-08-14T18:52Z

- 2026-09-15T06:37Z DONE 2026-09-15 (4911e17): docs/issuing-the-designated-aliases-acdc.md, linked from README.

The capability survey came out better than the tick assumed. KERIA already emits EXACTLY the artifact didwebs ingests -- GET /credentials/{said} with Accept: application/json+cesr runs CredentialResourceEnd.outputCred, which clones the issuer KEL, the registry TEL, the credential TEL and then signing.serialize's the ACDC. Same order as our publication_stream, same -IAB proof form. signify-ts exposes it as client.credentials().get(said, true). No translation layer is needed, which was the main open risk.

Three inherited gaps are documented rather than papered over: (1) KERIA depends on keripy UNPINNED and outputCred clones without a gvrsn, so the CESR genus follows whatever image is deployed and cannot be requested over the API -- the likeliest cause of a mystifying refusal; (2) KERIA's export carries no rpy records, so endpoint/witness declarations do not survive it, which is real scope if a customer needs service endpoints projected; (3) the schema must be resolved as a DATA oobi first, which KERIA's own ConfigurationError message insists on.

Sources are all primary: keria/app/credentialing.py, signify-ts src/keri/app/credentialing.ts, and GLEIF did-webs-resolver docs/getting_started.md for the kli sequence and the schema OOBI URL.

HONEST LIMIT, stated in the doc's last section: neither toolchain has been run end to end into didwebs publish. Everything is test-backed, source-read, or reference-documented, and the doc says which is which. A live run of both paths would be the natural follow-on -- worth its own tick if onboarding becomes real.
