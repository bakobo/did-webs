# Latent (Low, codex 2026-10-05): Incomplete proxy headers hold handler threads indefinitely
kind: todo
tags: latent-defect
created: 2026-10-05T19:53Z

- 2026-10-05T19:53Z Found by a codex hostile pass on PR #7 at the commit Copilot first reviewed; Copilot never reported it. Re-checked on main 2026-10-05: still LIVE. Main-branch evidence: Ran 20 `Tunnel.handle` calls with incomplete headers supplied through pipes. All 20 remained blocked until EOF. Original finding: 3. Incomplete proxy headers hold handler threads indefinitely - class: RESOURCE - severity: Low - where: scripts/sedi_m7_https.py:64 - reproduced: YES (Ran 20 `Tunnel.handle` calls with incomplete headers supplied through pipes; all 20 threads remained blocked until EOF.) - what happens: The byte limit only applies after each `readline` completes. A local client can keep connections open with partial headers, consuming one handler thread per connection without a timeout. Full record: ~/code/me/devenv/.ignored/review-backtest-2026-10-05/latent/did-webs-7.result.md
