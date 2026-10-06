# No test publishes a WITNESSED v2 AID: v2 fixtures are witnessless because in-process witnesses are not available here (same blocker as ~4geu). Evidence so far is the 2026-10-06 spike, where a heti AID with 2 witnesses at toad 2, rotated after issuance, round-tripped through equivalent ingest/emit code (keri-v2-spike branch, .ignored/kv2/heti-wit). v2 emission deliberately drops v1's receipt-couple projection, so a witnessed v2 test is the one that would catch a mistake there. Candidate: keripy indirecting.setupWitness in-process, as heti's tests/produce/witnesses.py does.
kind: todo
created: 2026-10-06T02:53Z

