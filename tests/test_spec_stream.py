"""The spec's own `keri.cesr`, fed through this pipeline — design oracle 4's second half.

`#### The full KERI event stream` (``~/code/wot/kswg-did-method-webs-specification/spec/body.md``
at line 3028) publishes a complete did:webs publication stream: an inception, two anchoring
interaction events, a registry inception, a credential issuance, and the designated-aliases ACDC
they authorize. It is the only stream in the specification whose *bytes* a conforming
implementation is shown, which makes it the cheapest wire-format regression oracle didwebs can
own — and the only one whose author is not us.

**This is a sensor, not a golden.** The brief asked for whichever of two honest forms reality
chose: assert acceptance and compare the derived document, or assert the precise observed failure
and say exactly what the stream contains that phase 1 cannot verify. Reality chose the second,
and the reason is narrow, specific, and worth a regression test of its own (tick ``~474z``):

    The spec's stream attaches its ACDC's proof as a **CESR transferable indexed signature
    group** (``-FAB`` — issuer prefix, sequence number, event SAID, then the issuer's indexed
    signature). keripy 2.0.0-dev6, the estate pin, routes that group to ``exts['tsgs']``, while
    its ACDC dispatch (``keri/core/parsing.py``, ``msgProcess``) reads only ``exts['ssts']`` —
    the source-seal triple that this line's own ``signing.serialize`` emits as ``-IAB``. So
    ``processACDC`` is called with ``prefixer=None``, ``saveCredential`` raises
    ``AttributeError``, and ``msgProcess`` re-raises it as *"No verifier to process so dropped
    ACDC"* — the same swallowed-``AttributeError`` shape the design already records for the dead
    ``addLde`` escrow (tick ``~3v45``). The credential is dropped without an escrow entry, so
    frame accounting reports it as ``e.proof.stream.frame.f``.

Everything else about the spec's stream verifies here: the whole KEL, both TELs, and the
credential's own signature against its issuer's key state. The last test hands the ``-FAB``
group's triple to the verifier by hand and the credential saves — which is what makes this a
finding about the parser rather than about the spec or about us.

**Not a skip and not a loosened assertion.** The rejection is asserted exactly — the code and the
offending frame — so the day the pin moves to a keripy whose ACDC dispatch reads ``tsgs``, this
test fails and gets rewritten as the acceptance golden it was meant to be.

**Where the brief's expectation did not survive contact.** It anticipated comparing the derived
document against ``tests/test_document.py``'s Full Example golden, reusing that golden's two
documented deltas. The two spec sections are different worked examples: `### Full Example`
publishes ``EEOqE46O…`` on port 7702 with a witness, and this stream publishes ``ENro7uf0…`` on
port 7676 with none. There is no derived document here to compare against that golden, even once
the parser gap closes.
"""

from __future__ import annotations

import json

import pytest
from bakobo.errors import BakoboError
from keri.core import coring, indexing
from keri.core import eventing as keventing

from didwebs import did as did_module
from didwebs import ingest

#: The spec's `#### The full KERI event stream`, verbatim (body.md line 3028). Pretty-printed
#: there for the reader; :func:`recompact` restores the bytes a controller actually submits.
SPEC_BLOCK = """\
{
    "v": "KERI10JSON00012b_",
    "t": "icp",
    "d": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "i": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "s": "0",
    "kt": "1",
    "k": [
        "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr"
    ],
    "nt": "1",
    "n": [
        "ELa775aLyane1vdiJEuexP8zrueiIoG995pZPGJiBzGX"
    ],
    "bt": "0",
    "b": [],
    "c": [],
    "a": []
}-VAn-AABAADjfOjbPu9OWce59OQIc-y3Su4kvfC2BAd_e_NLHbXcOK8-3s6do5vBfrxQ1kDyvFGCPMcSl620dLMZ4QDYlvME-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2024-04-01T17c40c48d329209p00c00{
    "v": "KERI10JSON00013a_",
    "t": "ixn",
    "d": "ED-4iQIVxwMcrTOW6fVs9oPpLTIxtqh_vcvLmE999zsU",
    "i": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "s": "1",
    "p": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "a": [
        {
            "i": "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx",
            "s": "0",
            "d": "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx"
        }
    ]
}-VAn-AABAACNra5mDg7YHFtBeXiwIGqnHkyq7F55FGNYG1wH95akjSWCb1HzNI3E05ufT0HffClDxnJF_DmAUW2SBb0EJeoO-EAB0AAAAAAAAAAAAAAAAAAAAAAB1AAG2024-04-01T17c42c37d704426p00c00{
    "v": "KERI10JSON00013a_",
    "t": "ixn",
    "d": "EBjw0a_L8M0F4xYND99dvahlrkpxODi9Wc9VzUvkhD0t",
    "i": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "s": "2",
    "p": "ED-4iQIVxwMcrTOW6fVs9oPpLTIxtqh_vcvLmE999zsU",
    "a": [
        {
            "i": "EIGWggWL2IHiUzj1P2YuPA0-Uh55LTIu14KTvVQGrfvT",
            "s": "0",
            "d": "EJQvCZQYn8oO1z3_f8qhxXjk7TcLol4G3RdHVTwfGV3L"
        }
    ]
}-VAn-AABAABo_okwAmWIYWI93EtUONZiEvsGuSRkKnj0mopX_RoXwWHZ_1V5hQ0BxcntsmAi21DbusyCmK-fHwTNtSxUSsoN-EAB0AAAAAAAAAAAAAAAAAAAAAAC1AAG2024-04-01T17c42c39d995867p00c00{
    "v": "KERI10JSON000113_",
    "t": "vcp",
    "d": "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx",
    "i": "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx",
    "ii": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "s": "0",
    "c": [
        "NB"
    ],
    "bt": "0",
    "b": [],
    "n": "AAfqHwMDdBoIWk_4Z6hvVJuhtvjA_gk8Y9bEUoP_rC_p"
}-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAABED-4iQIVxwMcrTOW6fVs9oPpLTIxtqh_vcvLmE999zsU{
    "v": "KERI10JSON0000ed_",
    "t": "iss",
    "d": "EJQvCZQYn8oO1z3_f8qhxXjk7TcLol4G3RdHVTwfGV3L",
    "i": "EIGWggWL2IHiUzj1P2YuPA0-Uh55LTIu14KTvVQGrfvT",
    "s": "0",
    "ri": "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx",
    "dt": "2023-11-13T17:41:37.710691+00:00"
}-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAACEBjw0a_L8M0F4xYND99dvahlrkpxODi9Wc9VzUvkhD0t{
    "v": "ACDC10JSON0005f2_",
    "d": "EIGWggWL2IHiUzj1P2YuPA0-Uh55LTIu14KTvVQGrfvT",
    "i": "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "ri": "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx",
    "s": "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5",
    "a": {
        "d": "EJJjtYa6D4LWe_fqtm1p78wz-8jNAzNX6aPDkrQcz27Q",
        "dt": "2023-11-13T17:41:37.710691+00:00",
        "ids": [
            "did:web:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            "did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            "did:web:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            "did:web:foo.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            "did:webs:foo.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"
        ]
    },
    "r": {
        "d": "EEVTx0jLLZDQq8a5bXrXgVP0JDP7j8iDym9Avfo8luLw",
        "aliasDesignation": {
            "l": "The issuer of this ACDC designates the identifiers in the ids field as the only allowed namespaced aliases of the issuer's AID."
        },
        "usageDisclaimer": {
            "l": "This attestation only asserts designated aliases of the controller of the AID, that the AID controlled namespaced alias has been designated by the controller. It does not assert that the controller of this AID has control over the infrastructure or anything else related to the namespace other than the included AID."
        },
        "issuanceDisclaimer": {
            "l": "All information in a valid and non-revoked alias designation assertion is accurate as of the date specified."
        },
        "termsOfUse": {
            "l": "Designated aliases of the AID must only be used in a manner consistent with the expressed intent of the AID controller."
        }
    }
}-VA0-FABENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe0AAAAAAAAAAAAAAAAAAAAAAAENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe-AABAADQOX208DAmZEPb2v0XXF0N6WgxOdOxB3AsCBJds_vbAr7v1PQBA4MWNsXc8unk5UykbB8j538XGkzLtujekvIP"""

#: The identifiers the block publishes, read off its own frames.
SPEC_AID = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"
SPEC_KEY = "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr"
SPEC_REGISTRY = "EAtQJEQMkkvlWxyfLbcLyv4kNeAI5Qsqe65vKIWnHKpx"
SPEC_ACDC = "EIGWggWL2IHiUzj1P2YuPA0-Uh55LTIu14KTvVQGrfvT"
SPEC_SCHEMA = "EN6Oh5XSD5_q2Hgu-aqpdfbVepdpYpFlgz6zvJL5b_r5"
SPEC_DID = f"did:webs:did-webs-service%3a7676:{SPEC_AID}"

#: The counter that opens the ACDC's proof. This constant is what the sensor is about.
ACDC_PROOF_CODE = b"-FAB"


def recompact(block: str) -> bytes:
    """The spec's pretty-printed block as the bytes a controller would submit.

    A CESR frame's version string carries the size of its own *compact* serialization, so the
    spec's indented JSON is not a stream any parser can read: every body has to be re-serialized
    with keripy's separators before the attachments that follow it mean anything. The round trip
    is checked rather than assumed — the first test below asserts each frame's declared size
    against the bytes produced here, which is what makes this extraction faithful rather than
    merely plausible.
    """
    decoder = json.JSONDecoder()
    stream = bytearray()
    at = block.index("{")
    while True:
        body, end = decoder.raw_decode(block, at)
        stream.extend(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode())
        at = block.find("{", end)
        stream.extend(block[end : at if at != -1 else len(block)].strip().encode())
        if at == -1:
            return bytes(stream)


def bodies(block: str) -> list[dict]:
    """Every JSON body in the block, in order."""
    decoder = json.JSONDecoder()
    found = []
    at = block.index("{")
    while at != -1:
        body, end = decoder.raw_decode(block, at)
        found.append(body)
        at = block.find("{", end)
    return found


def read_proof(stream: bytes, acdc):
    """The ACDC proof's ``(prefixer, seqner, saider, siger)``, at the fixed widths CESR v1 gives
    them: a 44-character prefix, a 24-character sequence number, a 44-character SAID, then a
    ``-AAB`` group holding one 88-character indexed signature."""
    proof = stream[stream.index(acdc.serder.raw) + len(acdc.serder.raw) :]
    assert proof.startswith(b"-VA0" + ACDC_PROOF_CODE)
    at = len(b"-VA0") + len(ACDC_PROOF_CODE)
    assert proof[at + 112 : at + 116] == b"-AAB"
    return (
        coring.Prefixer(qb64b=proof[at : at + 44]),
        coring.Seqner(qb64b=proof[at + 44 : at + 68]),
        coring.Saider(qb64b=proof[at + 68 : at + 112]),
        indexing.Siger(qb64b=proof[at + 116 : at + 204]),
    )


@pytest.fixture(scope="module")
def spec_stream() -> bytes:
    return recompact(SPEC_BLOCK)


@pytest.fixture
def spec_did():
    return did_module.parse(SPEC_DID)


# ------------------------------------------------------------------- the extraction itself


def test_the_block_recompacts_to_the_frame_sizes_it_declares(spec_stream):
    """Each frame's version string states the size of its own serialization, so a faithful
    recompaction reproduces all six exactly. A transcription slip anywhere in the 4.5 KB block
    would move a size, break a SAID, or both — which is why nothing else here has to trust the
    extraction."""
    for body in bodies(SPEC_BLOCK):
        compact = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        assert int(body["v"][10:16], 16) == len(compact), body.get("t", "ACDC")

    assert len(spec_stream) == 3805


def test_the_spec_stream_walks_as_the_six_frames_a_publication_is_made_of(spec_stream):
    walked = ingest.walk(spec_stream)

    assert walked.failure is None
    assert [frame.ilk for frame in walked.frames] == ["icp", "ixn", "ixn", "vcp", "iss", None]
    assert [frame.kind for frame in walked.frames] == ["JSON"] * 6
    assert walked.frames[0].said == SPEC_AID
    assert walked.frames[3].principal == SPEC_REGISTRY
    assert walked.frames[-1].said == SPEC_ACDC
    assert walked.frames[-1].schema == SPEC_SCHEMA  # the same schema didwebs pins


def test_the_spec_stream_passes_every_gate_before_keripy_sees_it(spec_stream, spec_did):
    """Serialization, whose frames these are, delegation: the spec's stream is a v1 JSON
    publication of one AID's own material, so no pre-parse gate has anything to say about it."""
    walked = ingest.walk(spec_stream)

    assert ingest.require_supported(spec_did, walked) is None
    assert ingest.require_no_third_party(spec_did, walked) is None
    assert ingest.require_delegator(spec_did, walked) is None


# ---------------------------------------------------- what does verify, and what does not


def test_the_spec_streams_key_and_transaction_state_verify_in_full(spec_stream):
    """Five of the six frames reach accepted state under the estate pin: the whole KEL, the
    registry inception, and the credential's issuance event. Whatever is wrong is not the spec's
    crypto, its serialization, or its ordering."""
    walked = ingest.walk(spec_stream)
    with ingest.open_scratch() as scratch:
        scratch.load(spec_stream)

        assert SPEC_AID in scratch.hby.kevers
        assert scratch.hby.kevers[SPEC_AID].sner.num == 2
        assert [verfer.qb64 for verfer in scratch.hby.kevers[SPEC_AID].verfers] == [SPEC_KEY]
        assert SPEC_REGISTRY in scratch.regery.reger.tevers
        assert scratch.regery.reger.tevers[SPEC_REGISTRY].pre == SPEC_AID
        assert scratch.regery.reger.tevers[SPEC_REGISTRY].vcState(vci=SPEC_ACDC).et == "iss"

        assert [frame.said for frame in ingest.account_frames(scratch, walked)] == [SPEC_ACDC]


def test_the_spec_streams_credential_signature_verifies_against_its_issuers_key_state(spec_stream):
    """The credential itself is sound. Its ``-FAB`` group carries the issuer's indexed signature
    over the ACDC, and that signature verifies against the key the spec's own inception event
    establishes — so the frame is not refused for anything its author did."""
    walked = ingest.walk(spec_stream)
    acdc = walked.frames[-1]
    prefixer, seqner, saider, siger = read_proof(spec_stream, acdc)

    with ingest.open_scratch() as scratch:
        scratch.load(spec_stream)
        kever = scratch.hby.kevers[SPEC_AID]
        _, indices = keventing.verifySigs(
            raw=acdc.serder.raw, sigers=[siger], verfers=kever.verfers
        )

        assert prefixer.qb64 == SPEC_AID
        assert seqner.sn == 0 and saider.qb64 == SPEC_AID  # the inception event it points at
        assert indices == [0]
        assert acdc.sigers == ()  # and yet the walk sees no signature on this frame


# ------------------------------------------------------------------------------ the sensor


def test_ingesting_the_spec_stream_is_refused_for_a_credential_proof_keripy_will_not_read(
    spec_stream, spec_did
):
    """**The sensor.** The estate pin cannot ingest the specification's own published stream.

    The exact observed failure, asserted exactly: the ACDC frame is the one frame accounting
    cannot place, and it earns the residue code because no escrow holds it — keripy drops it
    rather than escrowing it. See the module docstring for why, and tick ``~474z``.
    """
    with pytest.raises(BakoboError) as caught:
        ingest.ingest(spec_stream, spec_did)

    assert caught.value.code == "e.proof.stream.frame.f"
    assert caught.value.code_args == (SPEC_ACDC,)


def test_no_escrow_holds_the_dropped_credential_which_is_why_the_code_is_the_residue_one(
    spec_stream,
):
    """Attribution is not guessing. The credential sits in none of the audited escrows, so
    ``e.proof.stream.frame.f`` — "not accepted, and no more specific escrow attributed a cause" —
    is the honest verdict rather than a signature or anchor code it has not earned."""
    walked = ingest.walk(spec_stream)
    with ingest.open_scratch() as scratch:
        scratch.load(spec_stream)
        held = {name: scratch.escrow_saids(name) for name in ingest._AUDITED_ESCROWS}

        assert all(SPEC_ACDC not in saids for saids in held.values()), held
        assert ingest.attribute(scratch, walked.frames[-1]).code == "e.proof.stream.frame.f"


def test_the_credential_saves_the_moment_its_proof_is_handed_to_the_verifier(spec_stream):
    """The finding, isolated to one line of keripy. Handing ``processCredential`` the triple the
    ``-FAB`` group already carries — which the ACDC dispatch never reads — saves the credential
    into the same scratch database that just dropped it. Nothing about the spec's stream, this
    build's schema pin, or the audit has to change for it to verify."""
    walked = ingest.walk(spec_stream)
    acdc = walked.frames[-1]
    prefixer, seqner, saider, _ = read_proof(spec_stream, acdc)

    with ingest.open_scratch() as scratch:
        scratch.load(spec_stream)
        assert scratch.regery.reger.saved.get(keys=(SPEC_ACDC,)) is None

        scratch.verifier.processCredential(
            creder=acdc.serder, prefixer=prefixer, seqner=seqner, saider=saider
        )

        assert scratch.regery.reger.saved.get(keys=(SPEC_ACDC,)) is not None
        assert ingest.accepted(scratch, acdc)
