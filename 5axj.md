# Attack: a served did.json with unchanged key pairs but an altered assertionMethod or authentication relationship, an added service endpoint, or a changed controller or alsoKnownAs is accepted by Affinidi's resolver, which checks only identifier and key ids (resolver.rs:71-129 in the fork). An attacker who controls the web host can redirect services or relationships without touching the KEL. Found by Codex reviewing sedi-summit-nov26#10, 2026-10-06; full review at ~/code/bakobo/did-webs/.ignored/summit-2026-10-06/codex-review-pr10-fix12.txt. Accepted as a stage limit under summit decision D-FB3N; sharpens ~6zhs.
kind: debt
tags: affinidi, upstream
created: 2026-10-06T02:05Z

