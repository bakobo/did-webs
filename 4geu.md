# Receipting-Doist fixture so a witnessed AID can be built in process (keripy refuses toad=0 with witnesses; Registrar blocks awaiting receipts — worker E probes E1/E2); unblocks an end-to-end witness-service projection oracle
kind: todo
created: 2026-08-15T02:05Z

- 2026-09-15T06:34Z ATTEMPTED 2026-09-15, NOT DONE. The tick's premise is wrong in a way that matters: a 'Receipting Doist' cannot unblock this, because receipts were never the only thing being waited on. Precise gates, read off the estate pin's keripy and verified by probe:

1. keripy refusing toad=0 with witnesses is NOT a blocker here. make_hab(wits=[wit.pre], toad='1') succeeds, the icp reaches first-seen immediately, and after in-process receipting (wit.receipt -> hby.psr.parse) db.pwes is EMPTY and the anchoring ixn at sn=1 is first-seen too. The KEL side is fine.

2. The block is on the TEL side, in credentialing.Registrar. processWitnessEscrow (credentialing.py:774-801) holds the vcp in reger.tpwe until BOTH (a) len(db.wigs) == len(kever.wits) -- which in-process receipting does satisfy -- AND (b) registrar.receiptor.cues holds an entry matching {pre, sn}. That cue is raised only by keripy's own Receiptor gathering receipts over the network. Receipts arriving by any other route leave 'witnessed' False and the loop hits its continue statement forever.

3. Even past that, Registrar.complete (credentialing.py:723-738) requires reger.ctel to be set AND witPub.sent(said=pre) to be true, and WitnessPublisher.sendDo (agenting.py:632-673) only pushes that cue after building a messenger(hab, wit) client per witness and waiting for that client to go idle -- a real network send.

4. TRIED AND DID NOT WORK: interleaving real in-process receipting into _Issuance.drain, and additionally pushing synthetic cues into both registrar.receiptor.cues and registrar.witPub.cues. Registry still incomplete after 60 drains, so there is at least one further gate beyond (2b) and (3). Do not re-try cue-planting; it is a dead end.

RETARGET: what this needs is a genuinely reachable witness SERVICE, not a Doist -- a keri.app.indirecting HTTP witness bound to localhost plus a /loc/scheme reply pointing at it, so Receiptor and WitnessPublisher can both complete real round-trips. docs/scope.md already flags GLEIF's in-process witness scaffolding as 'worth adapting wholesale'; that is the thing to adapt. Retitle accordingly when someone picks it up.

Related: ~6ks5's remaining half needs this same fixture to get an end-to-end oracle.
