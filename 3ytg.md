# Attack: a served did.json with forged key bytes (publicKeyJwk x) but the KEL's key ids is accepted by Affinidi's resolver (upstream 0.7.0 and our fork), which compares only ids and key ids. The resolved document still carries the KEL's key, but a verifier that reads the served did.json directly would use the forged key. Pinned by sedi-summit-nov26 harness/tests/test_webs.py::test_affinidi_reads_no_key_bytes_from_did_json_and_this_pins_it. Found by Codex reviewing sedi-summit-nov26#10, 2026-10-06; full review at ~/code/bakobo/did-webs/.ignored/summit-2026-10-06/codex-review-pr10-fix12.txt. Accepted as a stage limit under summit decision D-FB3N; sharpens ~6zhs.
kind: debt
tags: affinidi, upstream
created: 2026-10-06T02:05Z

