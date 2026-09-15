# The suite is nondeterministic, and still strands /tmp/keri_* directories
kind: todo
created: 2026-09-15T04:21Z

- 2026-09-15T04:21Z Two consecutive full runs of the SAME clean tree on 2026-09-15 gave different results: 7 failed/865 passed, then 2 failed/870 passed, out of 872 either way. Failures land in test_ingest.py::test_the_negative_matrix_attributes_the_exact_code[...] (scope_miss, revoked_acdc, tampered_sig, forked_kel, stranger_bundle vary between runs) and test_builders.py::test_building_a_fixture_leaves_no_keri_temp_directory. Every one of them PASSES when run in isolation, so it is ordering or shared state, not a broken assertion.

The leak test is the tell. It globs /tmp/keri_* before and after one builders.KNOBS['base'] call and asserts the set is unchanged, so it fails only when a build strands a NEW directory -- i.e. keri_api.scratch's removal is not covering every path a full-suite run takes, even though it covers the isolated one. Consistent with that: /tmp holds 32,017 stranded keri_* directories, ~3.4 GB of a 12 GB tmpfs, oldest 2026-09-11, newest written by the runs that produced the numbers above. So the strand is ongoing, not historical.

Worth pinning down before trusting a red suite here: right now a failure cannot be told apart from the noise, which is the expensive part -- CI's 100% branch gate is only as good as a suite that gives the same answer twice. Suggested first look: whether the leak is the cause or another symptom, by cleaning /tmp/keri_* and re-running, then by running the negative matrix alone versus after test_builders.

Found while placing the mark for ~3r4a, not in a review of this suite. Nothing here was changed to chase it.
