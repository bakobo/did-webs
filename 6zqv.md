# Attack: Affinidi's resolver logs a designated-aliases verification failure and resolves anyway (resolver.rs:48-68), so a did:webs with no valid designated-aliases ACDC still resolves, contrary to the spec rule recorded at docs/scope.md:50. Its alias verifier also expects an -F ACDC signature our streams don't carry, so on our artifacts the derived document always omits the did:keri alias and the top-level controller. Found by Codex reviewing sedi-summit-nov26#10, 2026-10-06; full review at ~/code/bakobo/did-webs/.ignored/summit-2026-10-06/codex-review-pr10-fix12.txt. Accepted as a stage limit under summit decision D-FB3N; sharpens ~6zhs.
kind: debt
tags: affinidi, upstream
created: 2026-10-06T02:05Z

