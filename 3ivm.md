# SECURITY, shipped v1 path (KERI panel SEC-F1, 2026-10-06, CONFIRMED by probe): a v1 publication stream that omits the revoking TEL event (rev/brv) while its own KEL anchors it publishes the designation as issued. keripy's Tevery/vcState judges only the TEL events presented. Same fix as v2's completeness check (decision 3kn6drgf, ingest._anchored_registry_events): refuse when the issuer's accepted KEL seals a registry/credential TEL event the stream lacks. Exploitable by whoever can submit a publication stream; phase 1 binds submitter to controller by operator assertion (design.md trust boundaries), which narrows but does not close it.
kind: todo
created: 2026-10-06T10:31Z

