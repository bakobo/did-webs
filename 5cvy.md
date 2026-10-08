# v2 completeness counts any {d}-only or bare-string seal as a candidate anchor, even one that is not a digest at all (e.g. ixn data [{"d": "after migration"}]); keripy's sealDigests can never match such a string to an event, so this refuses publications keripy would accept. Found 2026-10-08 building mixed-version fixtures.
kind: todo
created: 2026-10-08T00:26Z

