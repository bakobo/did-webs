"""Field-level comparison between didwebs's derived document and the GLEIF resolver's derived
document, on the documented intersection (design.md, ``Test strategy and oracles``, oracle 1;
brief F §3: "field-level (never byte-level; our ``ensure_ascii`` differs)").

**Fields compared:** ``id``; verification-method key material (JWK ``x``, key ids); single-key
and integer (non-conjunctive) thresholds; service entries the reference *also* emits; and
``alsoKnownAs``, on its own documented intersection (see :func:`_also_known_as_intersection`).

**Fields excluded, as data with a reason each** (:data:`DOCUMENTED_EXCLUSIONS`) -- never a
silent waiver (brief F §1). The first three entries are design.md's oracle-1 list; the rest were
found reading the reference's source while building this driver, and did not appear in
design.md or the spike's REPORT -- surfaced here rather than folded in silently, per this
brief's duty to report every resolver behavior that differs from what the spike documented.

**What this module deliberately does not do** (brief F §6, TST forward form): it never consults
``didwebs``'s own source for an expected value beyond the two documents it is handed. Every
exclusion below is justified by reading ``dws.core.didding``/``dws.core.resolving`` -- the
reference's own code -- not by asserting that our answer is the right one.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "DOCUMENTED_EXCLUSIONS",
    "ComparisonResult",
    "Exclusion",
    "Mismatch",
    "compare",
]


@dataclass(frozen=True)
class Exclusion:
    """One field, or part of a field, this oracle does not require agreement on, and why."""

    field: str
    reason: str


@dataclass(frozen=True)
class Mismatch:
    """One field the comparison expected to agree on, and did not."""

    field: str
    ours: object
    theirs: object
    detail: str = ""

    def render(self) -> str:
        tail = f" -- {self.detail}" if self.detail else ""
        return f"MISMATCH  {self.field}: ours={self.ours!r} theirs={self.theirs!r}{tail}"


@dataclass(frozen=True)
class ComparisonResult:
    """What one field-level comparison found: what agreed, what did not, and what was excluded.

    ``exclusions`` is always :data:`DOCUMENTED_EXCLUSIONS` in full, printed on every run whether
    or not that run's fixture exercises the excluded field -- brief F §3.5 asks that the
    exclusion list "prints in the test output (visible, reasoned)", not only the entries a given
    run happened to touch.
    """

    agreements: tuple[str, ...]
    mismatches: tuple[Mismatch, ...]
    exclusions: tuple[Exclusion, ...]

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def render(self) -> str:
        lines = ["cross-implementation comparison:"]
        for field in self.agreements:
            lines.append(f"  AGREE     {field}")
        for excl in self.exclusions:
            lines.append(f"  EXCLUDED  {excl.field}: {excl.reason}")
        for mismatch in self.mismatches:
            lines.append(f"  {mismatch.render()}")
        return "\n".join(lines)


#: design.md oracle 1's three named exclusions, plus behaviors this driver found in
#: `dws.core.didding`/`dws.core.resolving` at the pin (0d4f2fd) that neither design.md nor the
#: spike's REPORT documents. Every entry is data, not a comment -- `render()` always prints all
#: of them, so a reader never has to trust that an exclusion was actually applied.
DOCUMENTED_EXCLUSIONS = (
    Exclusion(
        "@context",
        "the reference never emits @context at all (design.md oracle 1).",
    ),
    Exclusion(
        "authentication / assertionMethod",
        "the reference never emits either verification relationship (design.md oracle 1); "
        "didwebs makes both mandatory.",
    ),
    Exclusion(
        "verificationMethod (multi-clause threshold)",
        "the reference truncates a conjunctive kt to clause 0 and publishes an understated "
        "threshold (KRT-F3); didwebs fails closed instead, so there is no document of ours to "
        "compare on the multi_clause_kt fixture -- excluded from this oracle's fixture set "
        "entirely (brief F §2.4), not merely from this field.",
    ),
    Exclusion(
        "controller (top level)",
        "dws.core.didding.gen_did_document has no top-level `controller` key at all -- not a "
        "value mismatch, the key is absent. Found building this driver; not in design.md's "
        "oracle-1 list or the spike's REPORT.",
    ),
    Exclusion(
        "verificationMethod[].controller (strip_query)",
        "dws.core.didding.strip_query re-derives each method's `controller` from the DID string "
        "via its own regex rather than echoing the DID given to generate_did_doc verbatim "
        "(design.md oracle 1's 'strip_query defect'). didwebs fixtures carry no query string, "
        "so this is inert on the base/endpoints/deactivated fixtures, but the field is excluded "
        "on principle rather than by accident of the fixtures having nothing to trigger it.",
    ),
    Exclusion(
        "service (mailbox / agent, non-local AID)",
        "dws.core.didding.gen_service_endpoints resolves mailbox/agent roles via "
        "hab.fetchRoleUrls on a LOCAL Hab; dws.core.resolving.save_cesr -- the only ingestion "
        "path this oracle or the reference's own HTTP resolve() flow ever uses -- never creates "
        "one for the AID it just ingested, so it falls back to habs.get_role_urls, which returns "
        "witness roles only. Mailbox/agent service entries are silently absent from the "
        "reference's document regardless of what the stream declares. Found building this "
        "driver against the `endpoints` fixture; not in design.md's oracle-1 list or the "
        "spike's REPORT (the spike never exercised replies/services).",
    ),
    Exclusion(
        "alsoKnownAs (self entry / did:keri)",
        "the reference does not filter the subject's own did:webs identifier out of "
        "alsoKnownAs (didwebs treats that entry as redundant with `id` and omits it), and never "
        "emits the spec-mandatory did:keri:<aid> alias (didwebs always appends it). Found "
        "building this driver; not in design.md's oracle-1 list. See "
        "_also_known_as_intersection for how this comparison still asserts agreement on the "
        "entries both sides are capable of expressing.",
    ),
)


def _jwk_material(methods: list[dict]) -> set[tuple[str, str]]:
    """``(kid, x)`` for every ``JsonWebKey`` method -- "verification method key material (JWK
    x, key ids)" (brief F §3), the one piece of a verification method neither implementation's
    known defects touch."""
    return {
        (method["publicKeyJwk"]["kid"], method["publicKeyJwk"]["x"])
        for method in methods
        if method.get("type") == "JsonWebKey"
    }


def _threshold(methods: list[dict]) -> dict | None:
    """The ``ConditionalProof2022`` method's shape, or ``None`` for a single-key AID (kt=1,
    where neither implementation emits one at all -- itself a form of agreement)."""
    for method in methods:
        if method.get("type") == "ConditionalProof2022":
            weighted = "conditionWeightedThreshold" in method
            return {
                "threshold": method["threshold"],
                "weighted": weighted,
            }
    return None


def _service_key(entry: dict) -> tuple:
    return (entry["id"], entry["type"])


def _also_known_as_intersection(
    entries: list[str], *, drop_did_keri: bool = False, drop_self: str | None = None
) -> set[str]:
    """``entries`` reduced to the identifiers the *other* implementation is capable of
    expressing (see the ``alsoKnownAs`` :class:`Exclusion` above for why this reduction, rather
    than list equality, is the honest comparison)."""
    out = set(entries)
    if drop_did_keri:
        out = {entry for entry in out if not entry.startswith("did:keri:")}
    if drop_self is not None:
        out.discard(drop_self)
    return out


def compare(ours: dict, theirs: dict, *, subject_did_webs: str) -> ComparisonResult:
    """Compare two derived DID documents on the fields design.md's oracle 1 names.

    Args:
        ours: ``didwebs.document.derive_document``'s output (the did:webs form -- see this
            brief's assumption manifest for why the did:web-transformed form is not used here).
        theirs: the ``did_doc`` a resolver-subprocess report carries
            (``dws.core.didding.generate_did_doc`` called with the same did:webs DID).
        subject_did_webs: the did:webs DID both documents were derived for, needed to reduce
            ``alsoKnownAs`` to its documented intersection.
    """
    agreements: list[str] = []
    mismatches: list[Mismatch] = []

    if ours["id"] == theirs["id"]:
        agreements.append("id")
    else:
        mismatches.append(Mismatch("id", ours["id"], theirs["id"]))

    ours_keys = _jwk_material(ours["verificationMethod"])
    theirs_keys = _jwk_material(theirs["verificationMethod"])
    if ours_keys == theirs_keys:
        agreements.append("verificationMethod[].publicKeyJwk{kid,x}")
    else:
        mismatches.append(
            Mismatch(
                "verificationMethod[].publicKeyJwk{kid,x}",
                sorted(ours_keys),
                sorted(theirs_keys),
            )
        )

    ours_threshold = _threshold(ours["verificationMethod"])
    theirs_threshold = _threshold(theirs["verificationMethod"])
    if ours_threshold is None and theirs_threshold is None:
        agreements.append("threshold (single key -- no ConditionalProof2022 method either side)")
    elif (
        ours_threshold is not None
        and theirs_threshold is not None
        and not ours_threshold["weighted"]
        and not theirs_threshold["weighted"]
    ):
        if ours_threshold["threshold"] == theirs_threshold["threshold"]:
            agreements.append("threshold (integer)")
        else:
            mismatches.append(Mismatch("threshold (integer)", ours_threshold, theirs_threshold))
    else:
        mismatches.append(
            Mismatch(
                "threshold",
                ours_threshold,
                theirs_threshold,
                "a weighted threshold on either side is outside this oracle's fixture set "
                "(brief F §2.4 excludes multi_clause_kt entirely) -- unexpected here.",
            )
        )

    theirs_services = {_service_key(entry): entry for entry in theirs["service"]}
    ours_services = {_service_key(entry): entry for entry in ours["service"]}
    common = set(theirs_services) & set(ours_services)
    for key in sorted(common):
        if ours_services[key] == theirs_services[key]:
            agreements.append(f"service {key!r}")
        else:
            mismatches.append(Mismatch(f"service {key!r}", ours_services[key], theirs_services[key]))
    if not theirs_services:
        agreements.append("service (reference emits none to disagree with)")

    ours_aka = _also_known_as_intersection(ours["alsoKnownAs"], drop_did_keri=True)
    theirs_aka = _also_known_as_intersection(theirs["alsoKnownAs"], drop_self=subject_did_webs)
    if ours_aka == theirs_aka:
        agreements.append("alsoKnownAs (documented intersection)")
    else:
        mismatches.append(
            Mismatch(
                "alsoKnownAs (documented intersection)", sorted(ours_aka), sorted(theirs_aka)
            )
        )

    return ComparisonResult(tuple(agreements), tuple(mismatches), DOCUMENTED_EXCLUSIONS)
