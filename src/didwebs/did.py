"""didwebs.did — the WebsDid value type.

Parses, composes, and validates ``did:webs`` identifiers per the method-specific-identifier
ABNF (``### Method-Specific Identifier``) and derives the two hosting URLs
(``### Target System(s)``) in the did:webs spec (v0.10.3 clone,
``~/code/wot/kswg-did-method-webs-specification/spec/body.md``).

Pure value type: no I/O, no keripy state, no network. The only keripy import is
:data:`keri.core.coring.NonTransDex`, the derivation-code table used by
:func:`has_nontransferable_code` -- a code-table lookup, not a keripy state or object.

**Host validation.** The spec's own ABNF host character class is "for illustration only";
the RFCs are normative (RFC 3986 ``host``, including IP-literals, plus RFC 1035/1123 for
reg-names). This module uses the ``rfc3986`` PyPI package's ABNF-derived regular expressions
for the RFC 3986 productions (reg-name, IPv4address, IP-literal), then layers RFC 1035/1123
label rules (length, LDH charset, hyphen placement) on top in plain code for the reg-name
case -- exactly the split the design contract calls for.

**Normalized vs. raw (MNT).** :class:`WebsDid` stores the *normalized* parse in its comparable
fields (``host`` lowercased, the port marker's percent-case discarded entirely since it carries
no information once decoded, ``path``/``aid`` case-sensitive as spec'd) and keeps the original
input string on ``raw`` -- present for diagnostics, excluded from equality and hashing via
``field(compare=False)``. Never compare ``raw`` strings; compare :class:`WebsDid` instances.

**KRT-F6, the parse-side half.** :func:`has_nontransferable_code` is a pure derivation-code
test (keripy's :data:`~keri.core.coring.NonTransDex`), and :func:`parse` uses it to reject a
non-transferable AID (e.g. code ``B``). This is the *only* abandonment-adjacent thing this
module does: whether a *transferable* AID has since been rotated to null keys (abandoned) is
``document.py``'s predicate, over live key state -- a different question this module cannot
even ask, since it never touches keripy state. The two predicates must never be conflated.

**Soft spot 3 (carried upstream, see docs/design.md).** The spec's ``aid = said`` production
only admits self-addressing digest codes (``E F G H I 0D 0E 0F 0G``). Every one of those codes
is transferable, so the ABNF's own charset already excludes every non-transferable AID
structurally -- :func:`has_nontransferable_code` is not the only thing standing in the way of
a code-B AID (which fails :func:`parse`'s AID shape check independently). But the same charset
also excludes *transferable* basic-derivation AIDs (e.g. Ed25519 code ``D``), which is a real
identifier shape KERI supports and the spec's own ABNF has no room for. That gap belongs on the
upstream-issues list, not silently widened here: this module follows the spec ABNF exactly, so
a code-D AID is rejected too, for now.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from keri.core.coring import NonTransDex
from rfc3986 import abnf_regexp as _rfc3986_abnf

from didwebs.errors import DID_INVALID

__all__ = ["WebsDid", "has_nontransferable_code", "parse"]

_PREFIX = "did:webs:"

# --- AID (spec `aid = said`): digest self-addressing codes only, see "soft spot 3" above. ---
_SAID_256_RE = re.compile(r"^[EFGHI][A-Za-z0-9_-]{43}$")
_SAID_512_RE = re.compile(r"^0[DEFG][A-Za-z0-9_-]{86}$")

# --- path segment (spec `path = 1*(ALPHA / DIGIT / "-" / "_" / "~" / ".")`). ---
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_~.-]+$")

# --- host, RFC 3986 productions via rfc3986's ABNF-derived regex fragments. ---
_REG_NAME_RE = re.compile("^" + _rfc3986_abnf.REG_NAME + "$")
_IPV4_RE = re.compile("^" + _rfc3986_abnf.IPv4_RE + "$")
# IP-literal *without* the RFC 6874 zone-id extension: zone ids admit percent-encoded octets,
# and the brief's pinned edge default is that percent-encoding inside an IP-literal is invalid.
_IP_LITERAL_RE = re.compile(
    r"^\[(?:" + _rfc3986_abnf.IPv6_RE + "|" + _rfc3986_abnf.IPv_FUTURE_RE + r")\]$"
)

# --- RFC 1035/1123 reg-name layer: label length <=63, total <=253, LDH + hyphen placement. ---
_LDH_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAX_HOST_LEN = 253
_MAX_LABEL_LEN = 63

_PCT_TRIPLE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# --- percent-encoded port marker, spec `pct-encoded-colon = "%3A" / "%3a"`. ---
_PORT_MARKER_RE = re.compile(r"%3[Aa][0-9]*$")


class _Invalid(Exception):
    """Internal control-flow only: every raise site is caught by :func:`parse` and converted to
    :data:`~didwebs.errors.DID_INVALID`. Never escapes this module."""


def has_nontransferable_code(aid: str) -> bool:
    """Whether ``aid``'s derivation code is one of keripy's non-transferable basic-derivation
    codes (:data:`keri.core.coring.NonTransDex`) -- e.g. ``B`` (Ed25519N).

    A pure derivation-code test, nothing more: it looks only at the code prefix, never at key
    state. This is KRT-F6's parse-side predicate; ``document.py``'s ``is_abandoned`` is the
    other, unrelated, half -- see the module docstring.
    """
    if not aid:
        return False
    if aid[0] == "1":
        code = aid[:4]
    elif aid[0] == "0":
        code = aid[:2]
    else:
        code = aid[:1]
    return code in NonTransDex


def _validate_aid(aid: str) -> None:
    # KRT-F6 checked first and explicitly, ahead of the generic shape gate below: a
    # non-transferable AID is rejected *as itself*, not as an accident of also failing the
    # said-256/512 shape check (see "soft spot 3" in the module docstring for why, structurally,
    # it always would too).
    if has_nontransferable_code(aid):
        raise _Invalid("aid carries a non-transferable derivation code")
    if not (_SAID_256_RE.match(aid) or _SAID_512_RE.match(aid)):
        raise _Invalid("aid is not a valid said-256 or said-512 SAID")


def _validate_host(host: str) -> str:
    """Return the canonical (lowercased, percent-triples uppercased) form of ``host``, or raise
    :class:`_Invalid`."""
    if not host:
        raise _Invalid("empty host")

    if host.startswith("["):
        if not _IP_LITERAL_RE.match(host):
            raise _Invalid("not a valid IP-literal (or it contains percent-encoding)")
        return host.lower()

    if _IPV4_RE.match(host):
        return host

    if not _REG_NAME_RE.match(host):
        raise _Invalid("not a valid RFC 3986 reg-name")

    # RFC 1035/1123 layer on top of the RFC 3986 reg-name syntax.
    if len(host) > _MAX_HOST_LEN:
        raise _Invalid("host exceeds 253 characters")
    labels = host.split(".")
    for label in labels:
        if len(label) > _MAX_LABEL_LEN or not _LDH_LABEL_RE.match(label):
            raise _Invalid(f"label {label!r} is not a valid LDH label")

    return _PCT_TRIPLE_RE.sub(lambda m: m.group(0).upper(), host.lower())


def _extract_port_marker(span: str) -> tuple[str, str | None]:
    """Split a host(+port) span into ``(host_part, port_or_None)``.

    The marker is anchored to the end of ``span`` -- nothing legitimate follows a port in the
    grammar at this point, the caller already sliced off the trailing ``:path``/``:aid`` tail.
    A malformed marker (more than 5 digits, i.e. exceeding the spec's ``port = 1*5(DIGIT)``, or
    no digits at all) is deliberately *not* treated as a port: it is left in ``host_part``,
    where its stray ``%`` fails host validation downstream rather than silently truncating
    itself into a shorter, valid-looking port.
    """
    match = _PORT_MARKER_RE.search(span)
    if match is None:
        return span, None
    digits = match.group(0)[3:]
    if not (1 <= len(digits) <= 5):
        return span, None
    return span[: match.start()], digits


def _split(raw: str) -> tuple[str, str | None, list[str], str]:
    """Split the substring after ``did:webs:`` into ``(host, port, path_segments, aid)``, all
    still in their as-parsed (not yet canonicalized) form. Raises :class:`_Invalid`."""
    rest = raw[len(_PREFIX) :]

    if rest.startswith("["):
        end = rest.find("]")
        if end == -1:
            raise _Invalid("unterminated IP-literal host")
        span = rest[: end + 1]
        remainder = rest[end + 1 :]
        marker = re.match(r"%3[Aa][0-9]*", remainder)
        if marker:
            span += marker.group(0)
            remainder = remainder[marker.end() :]
        tail = remainder
    else:
        colon = rest.find(":")
        if colon == -1:
            raise _Invalid("missing the mandatory ':' aid separator")
        span = rest[:colon]
        tail = rest[colon:]

    host_part, port = _extract_port_marker(span)

    if not tail.startswith(":"):
        raise _Invalid("malformed identifier after the host")

    # tail starts with ':' (just checked), so split always yields >=1 element past the
    # leading empty string -- `*path_segments, aid = parts` can never fail to unpack.
    parts = tail.split(":")[1:]
    *path_segments, aid = parts
    return host_part, port, path_segments, aid


@dataclass(frozen=True)
class WebsDid:
    """A parsed, normalized ``did:webs`` identifier.

    Equality, hashing, and membership (the ``a.ids`` check, KRT-F5) are all over the normalized
    fields below -- ``host`` lowercased, the port's percent-case discarded (the marker itself is
    never retained; only its decoded digits are), ``path`` and ``aid`` case-sensitive as the
    spec requires. ``raw`` is the original input, kept for diagnostics and explicitly excluded
    from comparison/hashing: it is accessible, never authoritative.
    """

    raw: str = field(compare=False)
    host: str
    port: str | None
    path: tuple[str, ...]
    aid: str

    def _tail(self) -> str:
        port_part = f"%3A{self.port}" if self.port is not None else ""
        path_part = "".join(f":{segment}" for segment in self.path)
        return f"{self.host}{port_part}{path_part}:{self.aid}"

    def compose(self) -> str:
        """The canonical ``did:webs`` spelling: lowercase host, upper ``%3A``."""
        return "did:webs:" + self._tail()

    def to_did_web(self) -> str:
        """The ``did:web`` form of the same identifier (same host/port/path/AID)."""
        return "did:web:" + self._tail()

    def did_json_url(self) -> str:
        """The ``did.json`` hosting URL (``### Target System(s)``)."""
        authority = self.host if self.port is None else f"{self.host}:{self.port}"
        segments = "/".join((*self.path, self.aid))
        return f"https://{authority}/{segments}/did.json"

    def keri_cesr_url(self) -> str:
        """The ``keri.cesr`` hosting URL: ``did_json_url()`` with the trailing segment swapped."""
        return self.did_json_url()[: -len("did.json")] + "keri.cesr"


def parse(raw: str) -> WebsDid:
    """Parse and validate a ``did:webs`` identifier string.

    Fails closed: any deviation from the spec ABNF/RFC host rules raises
    :data:`~didwebs.errors.DID_INVALID` (code ``e.input.format.did.f``) -- never a bare
    exception, and never a partial/best-effort :class:`WebsDid`.
    """
    if not isinstance(raw, str):
        raise DID_INVALID(did=raw)

    try:
        if not raw.startswith(_PREFIX):
            raise _Invalid("missing the 'did:webs:' prefix")

        host, port, path_segments, aid = _split(raw)

        host = _validate_host(host)

        for segment in path_segments:
            if not _PATH_SEGMENT_RE.match(segment):
                raise _Invalid(f"path segment {segment!r} is not a valid path segment")

        _validate_aid(aid)
    except _Invalid as exc:
        raise DID_INVALID(did=raw) from exc

    return WebsDid(raw=raw, host=host, port=port, path=tuple(path_segments), aid=aid)
