# Affinidi's did:webs resolver fails open on document fields: upstream 0.7.0 and our 2-patch fork (bakobo/affinidi-keri-rs, affinidi-tdk-rs) log a designated-aliases verification failure and continue (crates/identity/did-methods/did-webs/src/resolver.rs:48-68), then check the published did.json only for identifier and key ids (:71-129). Keys and rotation verify correctly, but tampered alsoKnownAs, controller or services could be accepted. Add to the upstream issue draft /tmp/didwebs-interop-issue-affinidi.md; stage narration must claim only what it checks. Evidence: /tmp/didwebs-affinidi-fork-report.md:23-25 (was tagged F-GNH3)
kind: debt
tags: affinidi, upstream
created: 2026-09-24T21:44Z

- 2026-09-24T21:45Z Durable copies of the /tmp files cited above: /home/daniel/code/bakobo/did-webs/.ignored/summit-2026-09-24/
