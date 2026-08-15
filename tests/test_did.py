"""didwebs.did — the WebsDid value type: parse/compose/validate did:webs identifiers.

Fixtures below are taken verbatim from the did:webs spec (v0.10.3 clone,
``~/code/wot/kswg-did-method-webs-specification/spec/body.md``):

* ``### Method-Specific Identifier`` (~line 21) — the ABNF, and the RFC-governs-host note.
* ``### Target System(s)`` (~line 93), including ``#### Sample did:webs URLs`` (~line 129) —
  URL derivation and the root/path/port worked examples.
* ``### Full Example`` (~line 1407) — the one did:webs identifier used in the fully annotated
  KERI event stream walkthrough: ``did:webs:did-webs-service%3a7702:EEOqE46OO...``.

Strict TDD (ledger #20): this file is written and run red — ``didwebs.did`` does not exist yet —
before ``src/didwebs/did.py`` is implemented. The red run is saved at
``/home/daniel/code/bakobo/did-webs/.ignored/red-runs/B-did.txt``.
"""

from __future__ import annotations

import dataclasses
import random

import pytest
from bakobo.errors import BakoboError

from didwebs.did import WebsDid, has_nontransferable_code, parse

# ---------------------------------------------------------------------------
# Spec fixtures
# ---------------------------------------------------------------------------

# `### Full Example`, the one did:webs DID string in that section.
FULL_EXAMPLE_DID = "did:webs:did-webs-service%3a7702:EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP"

# `#### Sample did:webs URLs` (informative, inside `### Target System(s)`).
SAMPLE_ROOT_DID = "did:webs:w3c-ccg.github.io:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR"
SAMPLE_ROOT_DOC_URL = (
    "https://w3c-ccg.github.io/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/did.json"
)
SAMPLE_ROOT_CESR_URL = (
    "https://w3c-ccg.github.io/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/keri.cesr"
)
SAMPLE_PATH_DID = (
    "did:webs:w3c-ccg.github.io:user:alice:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR"
)
SAMPLE_PATH_DOC_URL = (
    "https://w3c-ccg.github.io/user/alice/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/did.json"
)
SAMPLE_PATH_CESR_URL = (
    "https://w3c-ccg.github.io/user/alice/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/keri.cesr"
)
SAMPLE_PORT_DID = (
    "did:webs:example.com%3a3000:user:alice:EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR"
)
SAMPLE_PORT_DOC_URL = (
    "https://example.com:3000/user/alice/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/did.json"
)
SAMPLE_PORT_CESR_URL = (
    "https://example.com:3000/user/alice/EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGR/keri.cesr"
)

# compose() always emits canonical spelling (upper `%3A`); the spec's own literal text uses
# lowercase `%3a`, so the *canonical* round-trip target is not byte-identical to the fixture --
# see `test_full_example_did_round_trips_parse_compose_canonically` below.
FULL_EXAMPLE_DID_CANONICAL = FULL_EXAMPLE_DID.replace("%3a", "%3A")
SAMPLE_PORT_DID_CANONICAL = SAMPLE_PORT_DID.replace("%3a", "%3A")

FULL_EXAMPLE_AID = "EEOqE46OOSl1k1JO3ggQTGuQR3nnWE8bYjOPnJ53m8CP"

# A syntactically well-formed said-512 AID (2-char code "0D" + 86 base64url chars), used only to
# exercise the said-512 branch of the ABNF; not a real KERI digest.
SAID_512_AID = "0D" + ("A" * 86)

# code-B (Ed25519N, non-transferable, basic derivation) at said-256 length — never legal here
# per the spec's `aid = said` production (digest codes only) and KRT-F6.
NONTRANS_B_AID = "B" + ("A" * 43)


# ---------------------------------------------------------------------------
# Parse: valid shapes
# ---------------------------------------------------------------------------


def test_parse_root_form_no_path_no_port():
    d = parse("did:webs:foo.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
    assert isinstance(d, WebsDid)
    assert d.host == "foo.com"
    assert d.port is None
    assert d.path == ()
    assert d.aid == "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"


def test_parse_path_form_multiple_segments_preserves_order():
    d = parse(SAMPLE_PATH_DID)
    assert d.path == ("user", "alice")


def test_parse_port_form_extracts_digits():
    d = parse(SAMPLE_PORT_DID)
    assert d.host == "example.com"
    assert d.port == "3000"
    assert d.path == ("user", "alice")


def test_parse_said_512_aid_accepted():
    d = parse(f"did:webs:foo.com:{SAID_512_AID}")
    assert d.aid == SAID_512_AID


def test_parse_ipv6_ip_literal_host_accepted():
    d = parse("did:webs:[2001:db8::1]:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
    assert d.host == "[2001:db8::1]"


def test_parse_ipv6_ip_literal_host_with_port_accepted():
    d = parse("did:webs:[2001:db8::1]%3A8080:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
    assert d.host == "[2001:db8::1]"
    assert d.port == "8080"


def test_parse_ipv4_host_accepted():
    d = parse("did:webs:192.168.0.1:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe")
    assert d.host == "192.168.0.1"


def test_parse_raw_is_accessible_but_not_authoritative():
    raw = "did:webs:FOO.COM:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"
    d = parse(raw)
    assert d.raw == raw
    assert d.host == "foo.com"  # normalized, not the raw spelling


# ---------------------------------------------------------------------------
# KRT-F5: normalized equality/membership over host-case and percent-case
# ---------------------------------------------------------------------------


def test_percent_case_spellings_of_the_port_marker_are_equal_under_normalized_equality():
    lower = parse("did:webs:example.com%3a3000:user:alice:" + FULL_EXAMPLE_AID)
    upper = parse("did:webs:example.com%3A3000:user:alice:" + FULL_EXAMPLE_AID)
    assert lower == upper
    assert hash(lower) == hash(upper)


def test_host_case_variants_are_equal_under_normalized_equality():
    lower = parse("did:webs:example.com:" + FULL_EXAMPLE_AID)
    upper = parse("did:webs:EXAMPLE.COM:" + FULL_EXAMPLE_AID)
    assert lower == upper
    assert hash(lower) == hash(upper)


def test_membership_in_a_set_works_under_normalized_equality():
    # The `a.ids` membership check (KRT-F5): a set of authorized aliases must treat case/percent
    # variants as the same member.
    authorized = {parse("did:webs:example.com%3a3000:user:alice:" + FULL_EXAMPLE_AID)}
    claimed = parse("did:webs:EXAMPLE.COM%3A3000:user:alice:" + FULL_EXAMPLE_AID)
    assert claimed in authorized


def test_path_is_case_sensitive_under_normalized_equality():
    a = parse("did:webs:example.com:user:alice:" + FULL_EXAMPLE_AID)
    b = parse("did:webs:example.com:user:Alice:" + FULL_EXAMPLE_AID)
    assert a != b


def test_aid_is_case_sensitive_under_normalized_equality():
    other_case_aid = FULL_EXAMPLE_AID[:-1] + (
        "p" if FULL_EXAMPLE_AID[-1] == "P" else "P"
    )
    a = parse("did:webs:example.com:" + FULL_EXAMPLE_AID)
    b = parse("did:webs:example.com:" + other_case_aid)
    assert a != b


def test_equality_with_non_websdid_returns_notimplemented_and_compares_false():
    d = parse("did:webs:foo.com:" + FULL_EXAMPLE_AID)
    assert d.__eq__("not a did") is NotImplemented
    assert (d == "not a did") is False
    assert (d == 42) is False


# ---------------------------------------------------------------------------
# KRT-F6 (parse half): code-B AID rejected; has_nontransferable_code is its own predicate
# ---------------------------------------------------------------------------


def test_has_nontransferable_code_true_for_code_b():
    assert has_nontransferable_code(NONTRANS_B_AID) is True


def test_has_nontransferable_code_true_for_a_four_char_nontrans_code():
    # NonTransDex also carries 4-char codes ("1AAA" ECDSA_256k1N, "1AAC" Ed448N, "1AAI"
    # ECDSA_256r1N) alongside the 1-char "B" -- exercise the `aid[0] == "1"` branch.
    assert has_nontransferable_code("1AAA" + "A" * 40) is True


def test_has_nontransferable_code_false_for_transferable_digest_codes():
    assert has_nontransferable_code(FULL_EXAMPLE_AID) is False
    assert has_nontransferable_code(SAID_512_AID) is False


def test_has_nontransferable_code_false_for_empty_string():
    assert has_nontransferable_code("") is False


def test_code_b_aid_rejected_at_parse():
    with pytest.raises(BakoboError) as exc_info:
        parse(f"did:webs:foo.com:{NONTRANS_B_AID}")
    assert exc_info.value.code == "e.input.format.did.f"


# ---------------------------------------------------------------------------
# Every `### Full Example` DID string round-trips parse -> compose canonically
# ---------------------------------------------------------------------------


def test_full_example_did_round_trips_parse_compose_canonically():
    # The spec's literal text spells the port marker `%3a` (lowercase); compose() always emits
    # the canonical `%3A` (upper), so the round-trip target is the canonicalized fixture, not
    # the raw spec bytes -- the same DID, its canonical spelling.
    d = parse(FULL_EXAMPLE_DID)
    assert d.compose() == FULL_EXAMPLE_DID_CANONICAL
    assert parse(d.compose()) == d


@pytest.mark.parametrize(
    "raw,canonical",
    [
        (
            "did:webs:foo.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
            "did:webs:foo.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
        ),
        (SAMPLE_ROOT_DID, SAMPLE_ROOT_DID),
        (SAMPLE_PATH_DID, SAMPLE_PATH_DID),
        (SAMPLE_PORT_DID, SAMPLE_PORT_DID_CANONICAL),
        (FULL_EXAMPLE_DID, FULL_EXAMPLE_DID_CANONICAL),
    ],
)
def test_spec_worked_example_dids_round_trip_canonically(raw, canonical):
    assert parse(raw).compose() == canonical


def test_compose_emits_lowercase_host_and_uppercase_percent_colon():
    d = parse("did:webs:EXAMPLE.com%3a3000:user:alice:" + FULL_EXAMPLE_AID)
    composed = d.compose()
    assert composed == "did:webs:example.com%3A3000:user:alice:" + FULL_EXAMPLE_AID


# ---------------------------------------------------------------------------
# to_did_web()
# ---------------------------------------------------------------------------


def test_to_did_web_swaps_the_method_and_keeps_the_rest_canonical():
    d = parse(FULL_EXAMPLE_DID)
    assert d.to_did_web() == "did:web:did-webs-service%3A7702:" + FULL_EXAMPLE_AID


def test_to_did_web_normalizes_case_like_compose_does():
    d = parse("did:webs:EXAMPLE.com:" + FULL_EXAMPLE_AID)
    assert d.to_did_web() == "did:web:example.com:" + FULL_EXAMPLE_AID


# ---------------------------------------------------------------------------
# URL derivation, `### Target System(s)`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,doc_url,cesr_url",
    [
        (SAMPLE_ROOT_DID, SAMPLE_ROOT_DOC_URL, SAMPLE_ROOT_CESR_URL),
        (SAMPLE_PATH_DID, SAMPLE_PATH_DOC_URL, SAMPLE_PATH_CESR_URL),
        (SAMPLE_PORT_DID, SAMPLE_PORT_DOC_URL, SAMPLE_PORT_CESR_URL),
    ],
)
def test_url_derivation_matches_sample_did_webs_urls(raw, doc_url, cesr_url):
    d = parse(raw)
    assert d.did_json_url() == doc_url
    assert d.keri_cesr_url() == cesr_url


def test_keri_cesr_url_is_did_json_url_with_the_trailing_segment_swapped():
    d = parse(FULL_EXAMPLE_DID)
    assert d.did_json_url().endswith("/did.json")
    assert d.keri_cesr_url() == d.did_json_url()[: -len("did.json")] + "keri.cesr"


# ---------------------------------------------------------------------------
# Invalid strings raise DID_INVALID (e.input.format.did.f), assert the code string
# ---------------------------------------------------------------------------


INVALID_DIDS = [
    ("missing did:webs: prefix", "did:web:foo.com:" + FULL_EXAMPLE_AID),
    ("wrong-case prefix", "DID:WEBS:foo.com:" + FULL_EXAMPLE_AID),
    ("empty host", "did:webs::" + FULL_EXAMPLE_AID),
    ("empty path segment (double colon)", f"did:webs:foo.com::{FULL_EXAMPLE_AID}"),
    ("trailing colon after aid", "did:webs:foo.com:" + FULL_EXAMPLE_AID + ":"),
    ("literal slash in the identifier", "did:webs:foo.com/user:" + FULL_EXAMPLE_AID),
    ("no aid at all", "did:webs:foo.com"),
    ("unterminated ip-literal", "did:webs:[2001:db8::1:" + FULL_EXAMPLE_AID),
    (
        "ip-literal host followed by garbage instead of a separator",
        "did:webs:[::1]x:" + FULL_EXAMPLE_AID,
    ),
    (
        "percent-encoding inside an ip-literal",
        "did:webs:[2001:db8::%31]:" + FULL_EXAMPLE_AID,
    ),
    ("aid too short for said-256", "did:webs:foo.com:E" + "A" * 30),
    ("aid with an illegal digest code", "did:webs:foo.com:Z" + "A" * 43),
    ("aid with an illegal character", "did:webs:foo.com:E" + "A" * 42 + "!"),
    ("code-b nontransferable aid", f"did:webs:foo.com:{NONTRANS_B_AID}"),
    ("port with six digits (exceeds 1*5DIGIT)", "did:webs:foo.com%3a100000:" + FULL_EXAMPLE_AID),
    ("port with a non-digit", "did:webs:foo.com%3aabcd:" + FULL_EXAMPLE_AID),
    ("host label exceeding 63 chars", "did:webs:" + ("a" * 64) + ".com:" + FULL_EXAMPLE_AID),
    (
        "host exceeding 253 chars total",
        "did:webs:" + ".".join(["a" * 50] * 5) + ".com:" + FULL_EXAMPLE_AID,
    ),
    ("host label starting with a hyphen", "did:webs:-foo.com:" + FULL_EXAMPLE_AID),
    ("host label ending with a hyphen", "did:webs:foo-.com:" + FULL_EXAMPLE_AID),
    ("path segment with an illegal character", "did:webs:foo.com:us/er:" + FULL_EXAMPLE_AID),
    ("empty string", ""),
    ("not a did uri at all", "https://example.com/did.json"),
]


@pytest.mark.parametrize("label,raw", INVALID_DIDS, ids=[label for label, _ in INVALID_DIDS])
def test_invalid_dids_raise_did_invalid_with_the_exact_code(label, raw):
    with pytest.raises(BakoboError) as exc_info:
        parse(raw)
    assert exc_info.value.code == "e.input.format.did.f"


def test_parse_rejects_non_str_input():
    with pytest.raises(BakoboError) as exc_info:
        parse(b"did:webs:foo.com:" + FULL_EXAMPLE_AID.encode())
    assert exc_info.value.code == "e.input.format.did.f"


# ---------------------------------------------------------------------------
# Pure value type: frozen, hashable, no I/O
# ---------------------------------------------------------------------------


def test_websdid_is_frozen():
    d = parse("did:webs:foo.com:" + FULL_EXAMPLE_AID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.host = "other.com"


# ---------------------------------------------------------------------------
# Property test: parse(compose(d)) == d; normalized equality invariant under
# host-case and percent-case perturbation. Seeded generative loop (no hypothesis
# dev dependency present; plain pytest per the brief).
# ---------------------------------------------------------------------------

_SAID_256_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_SAID_256_CODES = "EFGHI"
_SAID_512_CODES = ("0D", "0E", "0F", "0G")
_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_PATH_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~."


def _random_label(rng: random.Random) -> str:
    length = rng.randint(1, 10)
    label = "".join(rng.choice(_LABEL_ALPHABET) for _ in range(length))
    # Never start/end with a hyphen so the label stays LDH-legal.
    return label.strip("-") or "a"


def _random_host(rng: random.Random) -> str:
    labels = [_random_label(rng) for _ in range(rng.randint(1, 3))]
    return ".".join(labels)


def _random_aid(rng: random.Random) -> str:
    if rng.random() < 0.5:
        code = rng.choice(_SAID_256_CODES)
        body_len = 43
    else:
        code = rng.choice(_SAID_512_CODES)
        body_len = 86
    body = "".join(rng.choice(_SAID_256_ALPHABET) for _ in range(body_len))
    return code + body


def _random_path_segment(rng: random.Random) -> str:
    length = rng.randint(1, 8)
    return "".join(rng.choice(_PATH_ALPHABET) for _ in range(length))


def _random_valid_did(rng: random.Random) -> str:
    host = _random_host(rng)
    port = f"%3a{rng.randint(1, 65535)}" if rng.random() < 0.5 else ""
    n_segments = rng.randint(0, 3)
    segments = "".join(f":{_random_path_segment(rng)}" for _ in range(n_segments))
    aid = _random_aid(rng)
    return f"did:webs:{host}{port}{segments}:{aid}"


@pytest.mark.parametrize("seed", range(200))
def test_property_parse_compose_round_trips(seed):
    rng = random.Random(seed)
    raw = _random_valid_did(rng)
    d = parse(raw)
    assert parse(d.compose()) == d


@pytest.mark.parametrize("seed", range(200))
def test_property_normalized_equality_invariant_under_case_perturbation(seed):
    rng = random.Random(seed)
    raw = _random_valid_did(rng)
    d = parse(raw)

    perturbed = raw.replace("%3a", "%3A") if "%3a" in raw else raw.replace("%3A", "%3a")
    # Perturb host case too (host is everything up to the first ':' or '%').
    prefix = "did:webs:"
    rest = perturbed[len(prefix):]
    host_end = min(
        (i for i in (rest.find(":"), rest.find("%")) if i != -1), default=len(rest)
    )
    perturbed = prefix + rest[:host_end].swapcase() + rest[host_end:]

    assert parse(perturbed) == d
