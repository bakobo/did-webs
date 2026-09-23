# M7 artifact fixtures

These are the published `keri.cesr` and `did.json` files from the 2026-09-23
local SEDI M7 rehearsal run of `scripts/sedi_m7.sh`, copied byte for byte from
`/tmp/didwebs-interop-demo/artifacts/demo/`. `reissuer/` is the initial
publication for `ELXGlco2cpv7qvt8xl4VyVydpVO0KksVObTEMX4O_5Wl`;
`guy-rotated/` is Guy's publication for
`ELEGG02va7qWpBiTCQfTXFwbNTk-FVWJr7nWJX2DhHy7` after rotation. The files
contain public event, credential, and DID document material, with no secret keys.

SHA-256, in `did.json`, `keri.cesr` order:

- `guy-rotated/`: `54ae74e800355f023a736a849ed2c979c796ed25ddde0617f28f4ad92d53cce6`, `2561febaddb26d54475f1653b32fc3d8885687e07d282c82655490043911b15d`
- `reissuer/`: `9f85edf1d190e7ed483b14be2d0d3c67be5957db5df0cbfdb3fe287b98cc2b69`, `fc2d1b51c46de679a4f603b653230ecb311a7211a18dfbe811ab2b5bd13dd2f0`
