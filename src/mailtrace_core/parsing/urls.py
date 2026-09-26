"""URL extraction, normalization and defanging. Nothing here touches the network."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import idna

from mailtrace_core.models import UrlRecord
from mailtrace_core.util.defang import defang_url

# Scheme-ful URLs plus bare "www." hosts. Deliberately permissive; we trim
# trailing punctuation afterwards.
_URL_RE = re.compile(
    r"""
    (?:(?:https?|ftp|ftps)://[^\s<>"'\]\}]+)
    |
    (?:\bwww\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?:/[^\s<>"'\]\}]*)?)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_TRAILING = ".,;:!?'\")]}>"


def _trim_trailing(raw: str) -> str:
    """Strip trailing punctuation, keeping a ')' that closes a '(' in the URL."""
    while raw and raw[-1] in _TRAILING:
        if raw[-1] == ")" and raw.count("(") >= raw.count(")"):
            break
        raw = raw[:-1]
    return raw


# Something a human would read as a link: a host with a TLD, optionally scheme'd.
_LOOKS_LIKE_URL_RE = re.compile(
    r"^\s*(?:(?:https?|ftp)://)?(?:[a-z0-9\-]+\.)+[a-z]{2,}(?:[:/?#][^\s]*)?\s*$",
    re.IGNORECASE,
)

# Broad regex to catch "http://user@host" credential-in-URL tricks and obfuscation.
_MAX_URL_LEN = 2048


def find_urls_in_text(text: str) -> list[str]:
    """Return raw URL strings found in free text, in order, without dedup."""
    out: list[str] = []
    for m in _URL_RE.finditer(text):
        raw = _trim_trailing(m.group(0))
        if raw and len(raw) <= _MAX_URL_LEN:
            out.append(raw)
    return out


def _split_host_port(netloc: str) -> tuple[str, str | None]:
    # Strip userinfo
    if "@" in netloc:
        netloc = netloc.rpartition("@")[2]
    if netloc.startswith("["):  # IPv6 literal
        end = netloc.find("]")
        return netloc[: end + 1], netloc[end + 2 :] or None
    host, _, port = netloc.partition(":")
    return host, port or None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_url(raw: str) -> tuple[str, str | None, str | None]:
    """Return ``(normalized_url, host, scheme)``.

    Adds ``http://`` to bare ``www.`` hosts, lower-cases scheme and host,
    strips a default port, and leaves path/query untouched.
    """
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return raw, None, None
    scheme = parts.scheme.lower() or None
    host, port = _split_host_port(parts.netloc)
    host = host.lower().rstrip(".")
    if port in {"80", "443"} and (scheme, port) in {("http", "80"), ("https", "443")}:
        port = None
    netloc = host + (f":{port}" if port else "")
    normalized = urlunsplit((scheme or "", netloc, parts.path or "/", parts.query, parts.fragment))
    return normalized, host or None, scheme


def decode_idn(host: str) -> tuple[bool, str | None]:
    """Return ``(is_idn, unicode_form)`` for a host that may contain punycode labels."""
    if "xn--" not in host.lower():
        return False, None
    try:
        return True, idna.decode(host)
    except (idna.IDNAError, UnicodeError, ValueError):
        return True, None


def _host_of_display(text: str) -> str | None:
    if not text or not _LOOKS_LIKE_URL_RE.match(text):
        return None
    _, host, _ = normalize_url(text.strip())
    return host


def build_url_record(
    raw: str,
    source: str,
    *,
    display_text: str | None = None,
    shorteners: list[str] | None = None,
) -> UrlRecord:
    """Build a fully-populated :class:`UrlRecord` for one URL occurrence."""
    normalized, host, scheme = normalize_url(raw)
    is_idn, unicode_host = decode_idn(host) if host else (False, None)
    shortener_set = {s.lower() for s in (shorteners or [])}
    display_mismatch = False
    if display_text is not None:
        display_host = _host_of_display(display_text)
        if display_host and host and display_host != host:
            display_mismatch = True
    return UrlRecord(
        raw=raw,
        normalized=normalized,
        defanged=defang_url(normalized),
        source=source,
        host=host,
        display_text=display_text,
        display_mismatch=display_mismatch,
        is_ip_host=bool(host and _is_ip(host)),
        is_idn=is_idn,
        unicode_host=unicode_host,
        is_shortener=bool(host and host in shortener_set),
        scheme=scheme,
    )


def registrable_domain(host: str) -> str:
    """Cheap eTLD+1 approximation without a public-suffix list.

    Handles the common two-part public suffixes (``co.uk``, ``com.au`` ...).
    Good enough for lookalike comparison; not used for security decisions.
    """
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return host.lower()
    second_level = {"co", "com", "org", "net", "gov", "edu", "ac", "gob", "or", "ne", "mil"}
    reserved_tlds = {"test", "example", "invalid", "localhost"}
    if labels[-2] in second_level and (len(labels[-1]) == 2 or labels[-1] in reserved_tlds):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
