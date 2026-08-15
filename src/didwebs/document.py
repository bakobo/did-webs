"""The DID document, derived from verified state.

**Why this module exists.** Constraint ``embuup``: what Bakobo hosts is *derived* from the
state keripy accepted and the ingest audit accounted for, never copied out of the submitted
stream. :func:`derive_document` is the ``did.json`` half of that — a projection of key state,
endpoint state and the designated-aliases credential onto the document the spec's
``## DID documents`` section defines. :func:`to_did_web` then produces the hosted form.

**Spec-section mapping.** Every block below names the heading it implements, in
``~/code/wot/kswg-did-method-webs-specification/spec/body.md``, so a spec-drift audit can be
done section by section rather than by reading the whole module:

======================================  =========================================
``### DID Subject`` / ``DID Controller``  :func:`project_document`
``### Verification Methods``              :func:`verification_methods`
``#### Ed25519``                          :func:`json_web_key`
``#### Thresholds``                       :func:`threshold_method`
``### Verification Relationships``        :func:`verification_methods` (references)
``#### Witness/Mailbox/Agent Service``    :func:`services`
``#### Delegator Service Endpoint``       :func:`delegator_service`
``### Also Known As``                     :func:`also_known_as`
``#### Deactivate``                       :func:`is_abandoned`
``### Transformation to did:web ...``     :func:`to_did_web`
======================================  =========================================

**Where this is deliberately not the reference implementation.** The GLEIF resolver
(``dws/core/didding.py``) omits ``@context``, omits both verification relationships, and
truncates a conjunctive threshold to its first clause — publishing a document that understates
the controller's signing threshold (panel finding KRT-F3). This module emits all three and
fails closed on the threshold it cannot represent.
"""

from __future__ import annotations

import math
from base64 import urlsafe_b64encode

from bakobo.errors import BakoboError
from keri import kering
from keri.core.coring import MtrDex

from didwebs import errors
from didwebs.did import parse as parse_did

__all__ = [
    "CONTEXT",
    "also_known_as",
    "delegator_service",
    "derive_document",
    "is_abandoned",
    "json_web_key",
    "key_algorithm",
    "project_document",
    "services",
    "threshold_method",
    "to_did_web",
    "verification_methods",
]

#: The JSON-LD context a consumer needs to read this document as JSON-LD. ``## DID documents``
#: says a did:webs document is pure JSON and MAY carry an ``@context``; docs/design.md makes it
#: mandatory here, and the spec names no value, so this is the DID Core context and nothing
#: more. It does not define the ``JsonWebKey`` or ``ConditionalProof2022`` terms — that gap is
#: on the upstream-issues list rather than papered over with an invented URI.
CONTEXT = ["https://www.w3.org/ns/did/v1"]

#: CESR derivation codes for an Ed25519 public key. ``#### Ed25519`` names both: the decoding
#: rule is stated as "minus the leading 'B' or 'D' CESR codes".
ED25519_CODES = frozenset({MtrDex.Ed25519, MtrDex.Ed25519N})

#: Curve names for the codes this build refuses, so the error names what the spec names
#: (``#### Secp256k1``, ``#### Secp256r1``) rather than a bare CESR code.
KEY_ALGORITHMS = {
    MtrDex.ECDSA_256k1: "secp256k1",
    MtrDex.ECDSA_256k1N: "secp256k1",
    MtrDex.ECDSA_256r1: "secp256r1",
    MtrDex.ECDSA_256r1N: "secp256r1",
}

JSON_WEB_KEY = "JsonWebKey"
CONDITIONAL_PROOF = "ConditionalProof2022"
DELEGATOR_OOBI = "DelegatorOOBI"

#: The endpoint roles a service entry is projected for. Witness comes from key state; these two
#: come from Endpoint Role Authorizations. Other roles KERI defines (``controller``,
#: ``watcher``) have no did:webs service mapping in the spec and are deliberately not invented.
PROJECTED_ROLES = (kering.Roles.mailbox, kering.Roles.agent)

#: URL schemes an OOBI may be built on, in preference order.
OOBI_SCHEMES = (kering.Schemes.https, kering.Schemes.http)

_DID_WEBS = "did:webs:"
_DID_WEB = "did:web:"
_DID_KERI = "did:keri:"


# ------------------------------------------------------------------- verification methods


def key_algorithm(code: str) -> str:
    """The curve name for a CESR key code, or the code itself when this build has no name.

    Naming an unknown code as itself is the honest answer: the error says which key it could
    not use, without asserting a curve nobody verified.
    """
    return KEY_ALGORITHMS.get(code, code)


def json_web_key(verfer, did: str) -> dict:
    """One Ed25519 key as a ``JsonWebKey`` verification method (``#### Ed25519``).

    The JWK's ``x`` is the raw public key — the CESR derivation code stripped, which is what
    ``verfer.raw`` already is — in unpadded base64url.
    """
    return {
        "id": f"#{verfer.qb64}",
        "type": JSON_WEB_KEY,
        "controller": did,
        "publicKeyJwk": {
            "kid": verfer.qb64,
            "kty": "OKP",
            "crv": "Ed25519",
            "x": urlsafe_b64encode(verfer.raw).rstrip(b"=").decode(),
        },
    }


def threshold_method(tholder, methods: list, did, aid: str) -> dict | None:
    """The ``ConditionalProof2022`` method a signing threshold above one requires, or None.

    ``#### Thresholds`` can express exactly two shapes: an integer greater than one, and a
    single flat clause of fractional weights expanded over their lowest common denominator.
    Anything else — a conjunctive (multi-clause) threshold, or a clause that itself weights a
    nested set of keys — has no representation here, so it fails closed with
    ``e.feature.unsupported.threshold.f``. Projecting one clause of a conjunction, as the GLEIF
    reference does, would publish a document claiming a *lower* threshold than the controller
    committed to (KRT-F3).
    """
    if not tholder.weighted:
        if tholder.num <= 1:
            return None
        return {
            "id": f"#{aid}",
            "type": CONDITIONAL_PROOF,
            "controller": did.compose(),
            "threshold": tholder.num,
            "conditionThreshold": [method["id"] for method in methods],
        }

    clauses = tholder.thold
    if len(clauses) != 1 or any(isinstance(weight, tuple) for weight in clauses[0]):
        raise errors.THRESHOLD_UNSUPPORTED(aid=aid)

    weights = clauses[0]
    lcd = math.lcm(*[weight.denominator for weight in weights])
    return {
        "id": f"#{aid}",
        "type": CONDITIONAL_PROOF,
        "controller": did.compose(),
        "threshold": lcd,
        "conditionWeightedThreshold": [
            {"condition": method["id"], "weight": weight.numerator * lcd // weight.denominator}
            for method, weight in zip(methods, weights, strict=False)
        ],
    }


def verification_methods(kever, did) -> tuple[list, list]:
    """The document's verification methods and the references both relationships carry.

    ``### Verification Methods`` maps every key in the current key state to a method;
    ``### Verification Relationships`` then says a document MUST carry ``authentication`` and
    ``assertionMethod``, listing every key when the threshold is one and the single
    ``ConditionalProof2022`` method when it is more.

    Raises:
        BakoboError: ``e.feature.unsupported.key.alg.f`` for a key that is not Ed25519
            (decision ``3woefn``), or ``e.feature.unsupported.threshold.f`` for a threshold
            shape ``ConditionalProof2022`` cannot express.
    """
    subject = did.compose()
    methods = []
    for verfer in kever.verfers:
        if verfer.code not in ED25519_CODES:
            raise errors.KEY_ALG_UNSUPPORTED(aid=did.aid, alg=key_algorithm(verfer.code))
        methods.append(json_web_key(verfer, subject))

    conditional = threshold_method(kever.tholder, methods, did, did.aid)
    if conditional is None:
        return methods, [method["id"] for method in methods]
    return [*methods, conditional], [conditional["id"]]


# ------------------------------------------------------------------------------- services


def _urls(db, eid: str) -> dict:
    """Every URL an endpoint provider has declared, by scheme (keripy ``db.locs``).

    A nullified location — BADA's way of withdrawing an endpoint — is stored as an empty url
    and is not an endpoint any more, so it is dropped rather than published as one.
    """
    return {
        keys[1]: location.url
        for keys, location in db.locs.getTopItemIter(keys=(eid,))
        if location.url
    }


def _service(eid: str, role: str, urls: dict) -> dict:
    """One service entry: ``#<eid>/<role>``, typed by the role, endpoints keyed by scheme."""
    return {"id": f"#{eid}/{role}", "type": role, "serviceEndpoint": urls}


def _oobi(db, aid: str) -> str | None:
    """keripy's canonical controller OOBI for ``aid``, from its own declared location.

    ``{url}/oobi/{aid}/controller`` is the shape keripy itself generates
    (``keri/app/oobiing.py`` at the estate pin), https preferred over http. None when the
    verified state declares no location: phase 1 resolves nothing over the network, so an OOBI
    that cannot be derived from what was submitted cannot be published at all.
    """
    urls = _urls(db, aid)
    for scheme in OOBI_SCHEMES:
        if scheme in urls:
            return f"{urls[scheme].rstrip('/')}/oobi/{aid}/controller"
    return None


def delegator_service(db, kever, did) -> dict | None:
    """The ``DelegatorOOBI`` entry a delegated AID carries (``#### Delegator Service Endpoint``).

    The ``id`` is the SAID the delegator's anchoring seal commits to for this delegate's
    inception — the seal is located by matching on the delegate's own prefix rather than by
    taking the anchoring event's first seal, which is only correct when the delegator anchored
    nothing else in that event.

    Returns None when the AID is not delegated, when the delegator's anchoring event is not in
    verified state, or when no OOBI URL can be derived. The spec says a delegated AID MUST
    carry this entry; phase 1 cannot always satisfy that from verified state alone, and
    publishing a service endpoint we made up would be worse than omitting one.
    """
    if not kever.delpre:
        return None

    # A delegated inception's SAID is its own prefix, so the seal that commits it is
    # (i=delegate, s=0, d=delegate).
    seal = {"i": did.aid, "s": "0", "d": did.aid}
    anchoring = db.fetchLastSealingEventByEventSeal(pre=kever.delpre, seal=seal)
    if anchoring is None:
        return None

    url = _oobi(db, kever.delpre)
    if url is None:
        return None

    committed = next(item["d"] for item in anchoring.sad["a"] if item.get("i") == did.aid)
    return {"id": committed, "type": DELEGATOR_OOBI, "serviceEndpoint": url}


def services(db, kever, did) -> list:
    """Every service the verified state supports, in a stable order.

    Witnesses come from key state — ``#### Witness Service Endpoint`` is explicit that the
    witness role is established by the KEL's witness list, not by an endpoint role
    authorization — and mailbox and agent come from Endpoint Role Authorizations
    (``db.ends``), each crossed with the Location Scheme records (``db.locs``) that say where
    that provider is. An authorization with no location, or a location for a provider nobody
    authorized, projects nothing: both halves are required.
    """
    projected = []
    for eid in kever.wits:
        urls = _urls(db, eid)
        if urls:
            projected.append(_service(eid, kering.Roles.witness, urls))

    for role in PROJECTED_ROLES:
        for keys, end in db.ends.getTopItemIter(keys=(did.aid, role)):
            if not (end.allowed or end.enabled):
                continue
            urls = _urls(db, keys[2])
            if urls:
                projected.append(_service(keys[2], role, urls))

    delegator = delegator_service(db, kever, did)
    if delegator is not None:
        projected.append(delegator)
    return projected


# ---------------------------------------------------------------------------- alsoKnownAs


def _same_identifier(entry: str, did) -> tuple[str, object] | None:
    """``entry`` as ``(method, WebsDid)`` when this method can read it, else None."""
    for method in (_DID_WEBS, _DID_WEB):
        if entry.startswith(method):
            try:
                return method, parse_did(_DID_WEBS + entry[len(method) :])
            except BakoboError:
                return None
    return None


def also_known_as(ids: list, did) -> list:
    """The designated aliases this document publishes (``### Also Known As``).

    Every entry the credential designates, in the order the controller designated them, minus
    the document's own subject — which is the ``id``, not an alias of itself — plus
    ``did:keri:<aid>``, which a did:webs document MUST always provide.

    Each entry this method can parse must name the AID the stream verifies: the spec constrains
    ``alsoKnownAs`` to same-AID DIDs, and ingest deliberately tolerates entries it cannot read
    so that the rule is enforced here, where the document is built (KRT-F4). An entry of some
    other DID method is dropped rather than published: its AID binding cannot be checked, and
    publishing an unverifiable alias under Bakobo's domain would fail open.

    Raises:
        BakoboError: ``e.rule.alias.aid.mismatch.f`` when a readable entry names another AID.
    """
    aliases = []
    for entry in ids:
        designated = _same_identifier(entry, did)
        if designated is None:
            continue
        method, parsed = designated
        if parsed.aid != did.aid:
            raise errors.ALIAS_AID_MISMATCH(alias=entry, aid=did.aid)
        if method == _DID_WEBS and parsed == did:
            continue  # the subject itself
        aliases.append(entry)

    # No duplicate is possible: a `did:keri:` designation is not a did:web(s) identifier, so
    # the loop above dropped it whether or not the controller designated one.
    aliases.append(_DID_KERI + did.aid)
    return aliases


# --------------------------------------------------------------------------- the document


def is_abandoned(kever) -> bool:
    """Whether this AID has rotated to a null next key state (``#### Deactivate``).

    KRT-F6's key-state half, and the *only* abandonment predicate in this package that looks at
    key state. Its counterpart, ``did.has_nontransferable_code``, is a derivation-code test that
    rejects an identifier at parse time. Conflating them is how an implementation ends up either
    refusing to publish a deactivated DID — which the spec requires it to keep publishing,
    overwriting the artifacts in place — or accepting an identifier this method does not admit.
    """
    return not kever.ndigers


def project_document(kever, db, ids: list, did) -> dict:
    """The did:webs DID document for ``did``, projected from state.

    The seam that makes the spec's worked examples testable: they publish key state and reply
    records but no private keys, so the document they claim can be reproduced from planted
    state without a stream. :func:`derive_document` is the pipeline's entry point.

    ``### DID Subject`` fixes ``id`` as the DID being published, and ``### DID Controller``
    fixes ``controller`` as the same string. Key order is stable so two publications of the
    same state diff cleanly.
    """
    methods, references = verification_methods(kever, did)
    return {
        "@context": list(CONTEXT),
        "id": did.compose(),
        "controller": did.compose(),
        "verificationMethod": methods,
        "authentication": references,
        "assertionMethod": references,
        "service": services(db, kever, did),
        "alsoKnownAs": also_known_as(ids, did),
    }


def derive_document(verified, did) -> dict:
    """The DID document for ``did``, derived from an ingested stream's verified state.

    Pure given that state (constraint ``embuup``): the key state is what keripy accepted, the
    endpoint records are what BADA accepted, and the designations are read from the credential
    keripy saved — never from the bytes the submitter sent.

    Raises:
        BakoboError: an unsupported key algorithm or threshold shape, or an alias naming
            another AID. Each stops the publication; none of them yields a partial document.
    """
    return project_document(
        verified.hby.kevers[did.aid], verified.hby.db, verified.acdc.attrib["ids"], did
    )


def to_did_web(doc: dict) -> dict:
    """The did:web form of a did:webs DID document (``### Transformation to did:web ...``).

    Rewrites only the identifiers: the top-level ``id`` and ``controller``, every
    verification-method ``controller`` that equals the subject DID, and the reciprocal
    ``alsoKnownAs`` entry — the did:web form of the subject is replaced by the did:webs form,
    so the transformed document lists the did:webs DID as an alias of the did:web subject.
    All other content is copied through unchanged, and the input is not mutated.

    The precondition — a valid, unrevoked designated-aliases ACDC authorizing *both* forms — is
    ingest's (``e.grant.scope.alias.f``), which is why this is a total function here.
    """
    subject = doc["id"]
    web = _DID_WEB + subject[len(_DID_WEBS) :]

    transformed = dict(doc)
    transformed["id"] = web
    transformed["controller"] = web
    transformed["verificationMethod"] = [
        {**method, "controller": web} if method["controller"] == subject else dict(method)
        for method in doc["verificationMethod"]
    ]

    parsed = parse_did(subject)
    aliases = []
    replaced = False
    for entry in doc["alsoKnownAs"]:
        designated = _same_identifier(entry, parsed)
        if designated is not None and designated == (_DID_WEB, parsed):
            aliases.append(subject)
            replaced = True
        else:
            aliases.append(entry)
    if not replaced:
        # `### Also Known As`: the did:web document MUST list the did:webs form.
        aliases.insert(0, subject)
    transformed["alsoKnownAs"] = aliases
    return transformed
