# Cross-impl oracle: GLEIF resolver's single escrow drain cannot ingest delegated streams (out-of-order runs before partial-delegation; needs fixpoint iteration) — document as oracle exclusion and draft upstream issue
kind: todo
created: 2026-08-15T01:20Z
closed: 2026-08-15T02:28Z

- 2026-08-15T02:28Z FALSIFIED by worker F (2026-08-15): the pinned GLEIF resolver ingests builders.delegated cleanly in a single drain pass, because emit/replay order is delegator-first causal — nothing is out of order. D's fixpoint finding stands for OUR 2.0-dev6 ingest stack; the 1.2.13 reference needs no such fix for streams we emit. No upstream issue to draft. Regression sensor: tests/test_crossimpl.py::test_delegated_self_expiry
