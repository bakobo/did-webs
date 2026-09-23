# Patched Affinidi stage checker

The stage checker uses two private, standalone Bakobo copies of Affinidi's Rust
repositories. They retain `upstream` remotes. The did:webs crate is pinned to
`bakobo/affinidi-tdk-rs` commit `f9d07b4feaaa25fab4d74c435b89f83f5011e7b6`;
that commit changes only its KERI dependencies, both pinned to
`bakobo/affinidi-keri-rs` commit `1288096b1552713e552ca42a40fa6ce6d8fdadb6`.
The original 0.7.0 checker remains at [`tools/affinidi-check`](../tools/affinidi-check/README.md),
and the alternate is at [`tools/affinidi-check-patched`](../tools/affinidi-check-patched/README.md).
The private Git dependencies require Bakobo read access on a cold build.

**Source seal (`-I`).** KERI v1 carries the designated-aliases ACDC's TEL source
seal in an `-I` attachment. The method specification permits an ACDC anchored
through a TEL (`spec/body.md:2487-2491`), and our pinned keripy emits that form.
Affinidi's 0.4.0 KERI parser did not recognize the counter, so it stopped before
checking either demo stream. Commit `1e00cbb` teaches the v1 parser to read its
bounded source seal triples as a typed attachment; it does not invent a
controller signature or treat the seal as an `-F` signature group.

**Rotation configuration.** A normal KERI v1 `rot` can omit the `c` configuration
field, as Guy's rotation does. The method requires replaying that rotation to
derive the current verification key (`spec/body.md:340-354`). Affinidi's
rotation type previously rejected it during deserialization. Commit `1288096`
defaults an absent `c` to an empty list, leaving supplied values intact.

With those two patches, the alternate checker accepts both saved M7 artifact
pairs, including Guy after rotation, and refuses the tested changed DID key and
changed KERI event. The unpatched checker still rejects the full streams at
`-I`. This is a narrow stage compatibility result: Affinidi's alias verifier
still requires an `-F` ACDC signature and its resolver suppresses that failure.
Consequently its derived document omits the published `did:keri` alias and
top-level `controller`; its document comparison checks IDs and key IDs rather
than full document equality. A successful checker exit therefore does not prove
complete did:webs document conformance. See
[`affinidi-interop.md`](affinidi-interop.md) for the evidence and source references.
