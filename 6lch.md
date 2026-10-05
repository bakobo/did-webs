# Latent (Low, codex 2026-10-05): Failed witness seeding leaves earlier locations changed
kind: todo
tags: latent-defect
created: 2026-10-05T19:53Z

- 2026-10-05T19:53Z Found by a codex hostile pass on PR #7 at the commit Copilot first reviewed; Copilot never reported it. Re-checked on main 2026-10-05: still LIVE. Main-branch evidence: Called `seed_locations` with a known witness followed by a missing one. It raised `e.state.missing.witness-oobi.r`, but the first witness’s location remained pinned. Original finding: 4. Failed witness seeding leaves earlier locations changed - class: SEQUENCE - severity: Low - where: scripts/sedi_m7_keri.py:63 - reproduced: YES (Seeded one known witness followed by a missing witness; the function raised after recording the first location.) - what happens: The function mutates the keystore before checking every witness. A failed invocation therefore leaves a partial location update. Full record: ~/code/me/devenv/.ignored/review-backtest-2026-10-05/latent/did-webs-7.result.md
