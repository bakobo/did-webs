"""The fixture toolkit — one valid publication stream, and named knobs that derange it.

:func:`base` produces a complete, valid did:webs publication stream: a controller KEL, the
registry TEL, the credential TEL, and the self-attested designated-aliases ACDC, in the order
``dws/core/artifacting.py`` emits and the GLEIF resolver re-ingests. Every other function here
takes that recipe and breaks exactly one thing, and the knob names are the vocabulary the
ingest brief's negative oracles use — do not rename them.

**Each derangement isolates one property.** An attack fixture that is also invalid for an
unrelated reason — a bad signature on the attacker's own ACDC, say — proves nothing about the
check it was built to exercise, because the pipeline would reject it a step too early. So the
attacker's credential is internally perfect and only *whose* it is is wrong; the CBOR frame is
a correctly signed event on the claimed AID's own KEL and only its serialization is wrong; and
so on. ``tests/test_builders.py`` asserts the specific observable property behind each claim.

**Every builder returns ``(stream, facts)``.** ``facts`` carries the AIDs, SAIDs and DIDs a
consuming test needs to assert against, plus ``deliberate_version_strings`` — the version
strings that fixture is knowingly wrong about, which is how the toolkit-wide qbqfst oracle
excludes the two serialization knobs without weakening itself.

**Determinism.** Salts are fixed and the designation date is fixed, so every AID, SAID and DID
is identical from run to run. The *bytes* are not: keripy stamps wall-clock first-seen replay
couples into KEL attachments, which no argument controls. Frame bodies are stable; assert on
``facts`` and on bodies, never on whole-stream equality.

**Hand-built bytes.** Three knobs concatenate frames rather than producing them through one
keystore's API, because keripy will not emit the shape from a single Hab: ``forked_kel`` and
``dropped_frame_candidate`` need two divergent histories of the same AID (built from two
keystores sharing a salt, so the AID matches), and ``tampered_sig`` mutates a signature byte
directly. No frame anywhere in this module is hand-serialized: every one is real keripy output.
"""

from __future__ import annotations

import functools
from typing import NamedTuple

import keri_api
from keri.core.coring import MtrDex
from keri.kering import Kinds, Vrsn_1_0, Vrsn_2_0

from didwebs import assemble, schemaing

SCHEMA_SAID = schemaing.DES_ALIASES_SCHEMA_SAID

#: A conjunctive threshold: two clauses, each needing both of its keys. Unrepresentable in
#: ConditionalProof2022, which is why the pipeline must fail closed rather than truncate it.
MULTI_CLAUSE_SITH = [["1/2", "1/2"], ["1/2", "1/2"]]


class Fixture(NamedTuple):
    """A publication stream and the facts a consuming test asserts against."""

    stream: bytes
    facts: dict


def _facts(knob: str, aid: str, **extra) -> dict:
    """The fact keys every fixture carries, so a consuming test never has to branch on knob."""
    facts = {
        "knob": knob,
        "aid": aid,
        "did_web": keri_api.did_web(aid),
        "did_webs": keri_api.did_webs(aid),
        "schema_said": SCHEMA_SAID,
        "acdc_said": None,
        "regk": None,
        "ids": [],
        "kel_sn": 0,
        "deliberate_version_strings": frozenset(),
    }
    facts.update(extra)
    return facts


def _issue(hab, regery, ids, **kwa):
    """Issue the designated-aliases ACDC for ``hab``, v1 pinned, with a fixed registry nonce.

    The nonce is what makes a fixture reproducible: keripy defaults it to fresh randomness, so
    without pinning it here the registry identifier — and the ACDC SAID that references it —
    would differ on every run.
    """
    kwa.setdefault("nonce", keri_api.REGISTRY_NONCE)
    return assemble.issue_aliases(hab, regery, ids, **kwa)


# --------------------------------------------------------------------------------- the base


def base(tmp_path) -> Fixture:
    """A complete, valid publication stream: KEL, registry TEL, credential TEL, ACDC.

    No ``rpy`` records appear. The reference recipe emits ``/loc/scheme`` and ``/end/role``
    replies to describe witnesses and endpoint roles; a phase-1 fixture has neither, so there
    is nothing for them to describe and their absence is correct rather than a shortcut.
    """
    with keri_api.scratch("base", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre)
        issued = _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "base",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
            ),
        )


# ------------------------------------------------------------------- absence and revocation


def without_acdc(tmp_path) -> Fixture:
    """A valid KEL whose anchors promise a credential the stream does not carry.

    The registry and credential are really issued into the keystore, and both anchor seals stay
    in the KEL — only the TEL and ACDC frames are left out of the publication. That defeats an
    implementation that infers a credential's presence from its anchor, which the weaker
    "controller never issued anything" shape would not.
    """
    with keri_api.scratch("noacdc", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre)
        _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, creder=None)
        return Fixture(
            stream, _facts("without_acdc", hab.pre, ids=ids, kel_sn=hab.kever.sner.num)
        )


def revoked_acdc(tmp_path) -> Fixture:
    """Issued, then revoked. The ACDC still verifies; only its TEL says it authorizes nothing."""
    with keri_api.scratch("revoked", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre)
        issued = _issue(hab, regery, ids)
        assemble.revoke_aliases(hab, regery, issued)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "revoked_acdc",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
                revoked=True,
            ),
        )


# ------------------------------------------------------------------------ wrong authorization


def attacker_acdc(tmp_path) -> Fixture:
    """A victim's KEL beside an attacker's, and an alias ACDC from the attacker's registry.

    The attacker's credential is impeccable on its own terms: correctly signed, issued against
    the pinned schema, anchored in the attacker's own KEL. It simply designates a DID belonging
    to somebody else. If this fixture were invalid for any *other* reason the negative oracle
    that consumes it would pass without ever reaching the issuer check.
    """
    with keri_api.scratch("victim", tmp_path) as (hby, regery):
        victim = keri_api.make_hab(hby, "victim")
        attacker = keri_api.make_hab(hby, "attacker", salt=keri_api.salt(keri_api.ATTACKER_SALT))
        ids = keri_api.designated_ids(victim.pre)
        issued = _issue(attacker, regery, ids)

        stream = bytearray(keri_api.kel_bytes(victim))
        stream.extend(keri_api.publication_stream(attacker, regery, issued.creder))
        return Fixture(
            bytes(stream),
            _facts(
                "attacker_acdc",
                victim.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=victim.kever.sner.num,
                attacker_aid=attacker.pre,
                issuer_aid=issued.creder.sad["i"],
            ),
        )


def scope_miss(tmp_path) -> Fixture:
    """The controller's own ACDC, designating DIDs on a domain that is not the claimed one."""
    with keri_api.scratch("scope", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre, domain="elsewhere.example")
        issued = _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "scope_miss",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
            ),
        )


def spelling_variants(tmp_path) -> Fixture:
    """The ACCEPTED direction: lowercase ``%3a`` and upper-case host, which must still match.

    Percent-encoding is case-insensitive and DNS host names are too, so this designation covers
    the claimed DID under normalized equality even though not one of its entries is a
    byte-for-byte match. Testing only the rejection direction would let a pipeline that
    compares raw strings look correct.
    """
    port = "8443"
    with keri_api.scratch("spelling", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre, domain=keri_api.DOMAIN.upper(), port=port)
        issued = _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "spelling_variants",
                hab.pre,
                did_web=keri_api.did_web(hab.pre, port=port).replace("%3a", "%3A"),
                did_webs=keri_api.did_webs(hab.pre, port=port).replace("%3a", "%3A"),
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
            ),
        )


def alias_foreign_aid(tmp_path) -> Fixture:
    """A designation that covers the claimed DID *and* a DID whose final component is another AID.

    The spec constrains ``alsoKnownAs`` to same-AID DIDs. The foreign entry is a real AID from a
    real keystore, not a plausible-looking string, so an implementation cannot dodge the check
    by rejecting it as malformed.
    """
    with keri_api.scratch("foreign", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        other = keri_api.make_hab(hby, "other", salt=keri_api.salt(keri_api.FOREIGN_SALT))
        foreign_alias = keri_api.did_webs(other.pre)
        ids = [*keri_api.designated_ids(hab.pre), foreign_alias]
        issued = _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "alias_foreign_aid",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
                foreign_aid=other.pre,
                foreign_alias=foreign_alias,
            ),
        )


# --------------------------------------------------------------------------- broken framing


def tampered_sig(tmp_path) -> Fixture:
    """A valid stream with one byte of one controller signature flipped.

    Hand-mutated bytes: keripy will not emit a message whose signature does not verify, so the
    only way to produce this shape is to change the signature after the fact. The mutation is a
    single byte inside the first frame's attachment group, so every message *body* — and
    therefore every SAID in the stream — is untouched, and the signature check is the only
    thing that can fail.
    """
    stream, facts = base(tmp_path)
    frame = keri_api.frames(stream)[0]
    offset = frame.end - 1  # last byte of the icp's indexed-signature group
    original = stream[offset : offset + 1]
    replacement = b"B" if original != b"B" else b"C"

    tampered = stream[:offset] + replacement + stream[offset + 1 :]
    facts = {
        **facts,
        "knob": "tampered_sig",
        "parent_stream": stream,
        "tampered_offset": offset,
    }
    return Fixture(tampered, facts)


def forked_kel(tmp_path) -> Fixture:
    """One AID, two valid interaction events at sequence number 1, both in the same submission.

    Two keystores share a salt, so both incept the identical AID; each then extends it
    differently. Both branches are correctly signed — this is duplicity, not forgery, and
    first-seen-wins is not an acceptable resolution for a stream we are asked to publish.
    """
    stream, facts = base(tmp_path / "trunk")
    with keri_api.scratch("branch", tmp_path / "branch") as (hby, _):
        hab = keri_api.make_hab(hby, "controller")
        hab.interact(data=[{"d": "a divergent branch"}], version=Vrsn_1_0)
        branch = keri_api.frames(keri_api.kel_bytes(hab))[-1]
        assert hab.pre == facts["aid"], "the fork must be the same AID, not a lookalike"
        forked = stream + branch.raw[branch.start : branch.end]

    return Fixture(
        forked, {**facts, "knob": "forked_kel", "fork_sn": "1", "parent_stream": stream}
    )


def dropped_frame_candidate(tmp_path) -> Fixture:
    """A valid stream plus one well-formed event keripy will escrow forever and never accept.

    The extra frame is a genuine, correctly signed interaction event for the claimed AID, but
    it sits several sequence numbers ahead of anything in the stream, so its prior-event digest
    resolves to nothing. keripy escrows it out of order and never first-sees it. A pipeline that
    publishes "everything that was accepted" would silently drop it; accounting must notice.
    """
    stream, facts = base(tmp_path / "trunk")
    ahead = facts["kel_sn"] + 4
    with keri_api.scratch("ahead", tmp_path / "ahead") as (hby, _):
        hab = keri_api.make_hab(hby, "controller")
        for step in range(ahead):
            hab.interact(data=[{"d": f"step {step}"}], version=Vrsn_1_0)
        orphan = keri_api.frames(keri_api.kel_bytes(hab))[-1]
        assert hab.pre == facts["aid"]
        appended = stream + orphan.raw[orphan.start : orphan.end]

    return Fixture(
        appended,
        {
            **facts,
            "knob": "dropped_frame_candidate",
            "orphan_sn": ahead,
            "parent_stream": stream,
        },
    )


def third_party(tmp_path) -> Fixture:
    """A valid stream with an unrelated AID's KEL appended — chaff in a publication."""
    stream, facts = base(tmp_path / "trunk")
    with keri_api.scratch("stranger", tmp_path / "stranger", salt_raw=keri_api.THIRD_PARTY_SALT) as (
        hby,
        _,
    ):
        stranger = keri_api.make_hab(hby, "stranger")
        appended = stream + keri_api.kel_bytes(stranger)
        stranger_aid = stranger.pre

    return Fixture(
        appended,
        {**facts, "knob": "third_party", "third_party_aid": stranger_aid, "parent_stream": stream},
    )


def cbor_frame(tmp_path) -> Fixture:
    """A v1 CBOR interaction event on the claimed AID's own KEL.

    Serialization is the only thing wrong: same AID, same protocol version, valid signature,
    correct place in the sequence. didwebs accepts JSON only — a deliberate restriction narrower
    than "v1" — and this fixture is what proves the restriction is enforced rather than assumed.
    """
    stream, facts = base(tmp_path / "trunk")
    with keri_api.scratch("cbor", tmp_path / "cbor") as (hby, _):
        hab = keri_api.make_hab(hby, "controller")
        raw = bytes(hab.interact(data=[{"d": "cbor"}], kind=Kinds.cbor, version=Vrsn_1_0))
        assert hab.pre == facts["aid"]
        appended = stream + raw

    return Fixture(
        appended,
        {
            **facts,
            "knob": "cbor_frame",
            "deliberate_version_strings": frozenset({"KERI10CBOR"}),
            "parent_stream": stream,
        },
    )


def v2_frame(tmp_path) -> Fixture:
    """A protocol-v2 interaction event on a v1 KEL — exactly the qbqfst failure mode.

    This is what one unpinned ``hab.interact`` produces on this keripy line. A 1.2.x parser does
    not recognize the frame and drops it silently, which is why the pipeline has to reject the
    submission rather than publish what survived.
    """
    stream, facts = base(tmp_path / "trunk")
    with keri_api.scratch("vtwo", tmp_path / "vtwo") as (hby, _):
        hab = keri_api.make_hab(hby, "controller")
        raw = bytes(hab.interact(data=[{"d": "vtwo"}], version=Vrsn_2_0))
        assert hab.pre == facts["aid"]
        appended = stream + raw

    return Fixture(
        appended,
        {
            **facts,
            "knob": "v2_frame",
            "deliberate_version_strings": frozenset({"KERICAACAAJSON"}),
            "parent_stream": stream,
        },
    )


def truncated(tmp_path) -> Fixture:
    """The inception event alone — a KEL prefix, with the rest of the KEL and all TEL missing."""
    stream, facts = base(tmp_path)
    icp = keri_api.frames(stream)[0]
    return Fixture(
        stream[icp.start : icp.end],
        {**facts, "knob": "truncated", "acdc_said": None, "regk": None, "parent_stream": stream},
    )


# ----------------------------------------------------------------------- unsupported shapes


def secp_keys(tmp_path) -> Fixture:
    """A complete, internally valid stream whose current key state is secp256k1, not Ed25519.

    Everything about this publication is correct except the key algorithm, which the did:webs
    verification-method mapping does not cover in v1.
    """
    with keri_api.scratch("secp", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller", icode=MtrDex.ECDSA_256k1_Seed)
        ids = keri_api.designated_ids(hab.pre)
        issued = _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        keys = keri_api.bodies(stream)[0]["k"]
        return Fixture(
            stream,
            _facts(
                "secp_keys",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
                keys=keys,
                key_alg="secp256k1",
            ),
        )


def multi_clause_kt(tmp_path) -> Fixture:
    """A conjunctive signing threshold — two weighted clauses, both of which must be satisfied.

    ``ConditionalProof2022`` as the spec maps it can express one flat weighted clause and no
    more. The reference implementation truncates to clause 0 and publishes a document that
    understates the controller's threshold; didwebs must fail closed instead, and this fixture
    is the input that distinguishes the two behaviours.
    """
    with keri_api.scratch("multi", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(
            hby,
            "controller",
            icount=4,
            isith=MULTI_CLAUSE_SITH,
            ncount=4,
            nsith=MULTI_CLAUSE_SITH,
        )
        ids = keri_api.designated_ids(hab.pre)
        issued = _issue(hab, regery, ids)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "multi_clause_kt",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
                kt=keri_api.bodies(stream)[0]["kt"],
            ),
        )


# --------------------------------------------------------------------- delegation and death


def delegated(tmp_path, *, include_delegator: bool = True) -> Fixture:
    """A delegated AID's publication, with or without its delegator's KEL in the stream.

    With the delegator included the stream is complete and publishable. Without it, the ``dip``
    still names a delegator whose key state nothing in the submission establishes, so the
    delegation seal cannot be checked and the publication must be refused — not published on
    the strength of an unverifiable claim.

    ``Hab.replay`` prepends the delegator's KEL via ``cloneDelegation``; the no-delegator
    variant clones only this AID's own events. Note the ``dip`` still *mentions* the delegator
    in its ``di`` field either way, so a test must look at frame ownership rather than at
    whether the delegator's prefix appears in the bytes.
    """
    with keri_api.scratch("delegate", tmp_path, salt_raw=keri_api.DELEGATOR_SALT) as (hby, regery):
        delegator = keri_api.make_hab(hby, "delegator")
        delegate = keri_api.make_hab(hby, "delegate", delpre=delegator.pre)
        keri_api.approve_delegation(delegator, delegate.pre, hby)

        ids = keri_api.designated_ids(delegate.pre)
        issued = _issue(delegate, regery, ids)
        stream = keri_api.publication_stream(
            delegate, regery, issued.creder, with_delegator=include_delegator
        )
        return Fixture(
            stream,
            _facts(
                "delegated" if include_delegator else "delegated:no-delegator",
                delegate.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=delegate.kever.sner.num,
                delegator_aid=delegator.pre,
                includes_delegator=include_delegator,
            ),
        )


def deactivated(tmp_path) -> Fixture:
    """A controller rotated to a null next key state — abandoned, and still publishable.

    This is a VALID stream. An abandoned AID derives a document and keeps publishing; conflating
    "deactivated" with "rejected" is the mistake this fixture exists to catch. The rotation
    happens after issuance, so the designation the document rests on is already anchored.
    """
    with keri_api.scratch("deactivated", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "controller")
        ids = keri_api.designated_ids(hab.pre)
        issued = _issue(hab, regery, ids)
        hab.rotate(ncount=0, nsith="0", version=Vrsn_1_0, gvrsn=Vrsn_1_0)
        stream = keri_api.publication_stream(hab, regery, issued.creder)
        return Fixture(
            stream,
            _facts(
                "deactivated",
                hab.pre,
                acdc_said=issued.creder.said,
                regk=issued.registry.regk,
                ids=ids,
                kel_sn=hab.kever.sner.num,
                deactivated=True,
            ),
        )


#: Every knob by name. The ingest brief's negative oracles index into this; the names are the
#: shared vocabulary and must not be renamed. ``delegated`` appears twice because the brief asks
#: for the delegated AID "with and without delegator KEL included" as one knob with two shapes.
KNOBS = {
    "base": base,
    "without_acdc": without_acdc,
    "revoked_acdc": revoked_acdc,
    "attacker_acdc": attacker_acdc,
    "scope_miss": scope_miss,
    "spelling_variants": spelling_variants,
    "tampered_sig": tampered_sig,
    "forked_kel": forked_kel,
    "dropped_frame_candidate": dropped_frame_candidate,
    "third_party": third_party,
    "cbor_frame": cbor_frame,
    "v2_frame": v2_frame,
    "secp_keys": secp_keys,
    "multi_clause_kt": multi_clause_kt,
    "delegated": delegated,
    "delegated:no-delegator": functools.partial(delegated, include_delegator=False),
    "truncated": truncated,
    "deactivated": deactivated,
    "alias_foreign_aid": alias_foreign_aid,
}
