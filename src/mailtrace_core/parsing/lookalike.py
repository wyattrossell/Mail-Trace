"""Lookalike / homoglyph domain detection against a watchlist of brands.

Comparison works on a *skeleton* of each label: lower-cased, diacritics
stripped, common confusables folded (``rn`` to ``m``, Cyrillic ``а`` to
Latin ``a``, ``0`` to ``o`` ...). A domain whose skeleton equals a brand's
but whose raw form differs is a homoglyph. Small edit distances catch typos,
and affix/subdomain checks catch ``paypal-secure.com`` and
``paypal.com.evil.net``.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from mailtrace_core.parsing.urls import decode_idn, registrable_domain

_SINGLE = {
    "0": "o",
    "1": "l",
    "|": "l",
    "!": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "b",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    # Cyrillic
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "ӏ": "l",
    "к": "k",
    "м": "m",
    "т": "t",
    "в": "b",
    "н": "h",
    "г": "r",
    "ь": "b",
    "є": "e",
    "ѵ": "v",
    # Greek
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "ν": "v",
    "ι": "i",
    "κ": "k",
    "υ": "u",
    "τ": "t",
    "ε": "e",
    "χ": "x",
    "η": "n",
    "ω": "w",
    # Misc
    "ı": "i",
    "ł": "l",
    "ø": "o",
    "đ": "d",
    "þ": "p",
    "æ": "ae",
    "ɡ": "g",
    "ɩ": "i",
    "’": "",
    "ʼ": "",
}
_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("ci", "a"), ("nn", "m"), ("lj", "u"), ("ll", "u")]


@dataclass(slots=True)
class LookalikeMatch:
    domain: str
    brand: str
    kind: str
    """``homoglyph``, ``typo``, ``affix``, ``brand-subdomain``, ``tld-swap``, ``idn``."""
    detail: str


def skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKD", label.lower())
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = "".join(_SINGLE.get(ch, ch) for ch in s)
    for pair, rep in _MULTI:
        s = s.replace(pair, rep)
    return s.replace("-", "").replace("_", "").replace(".", "")


def damerau_levenshtein(a: str, b: str) -> int:
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _label(domain: str) -> str:
    return registrable_domain(domain).split(".")[0]


def _typo_threshold(length: int) -> int:
    if length < 4:
        return 0
    if length < 8:
        return 1
    return 2


def compare_domain(domain: str, watchlist: list[str]) -> LookalikeMatch | None:
    """Return the strongest lookalike match for ``domain`` or None.

    A domain that *is* a watchlist brand, or a subdomain of one, is not a
    lookalike and returns None.
    """
    if not domain:
        return None
    host = domain.lower().strip(".")
    is_idn, unicode_host = decode_idn(host)
    if is_idn and unicode_host:
        host_cmp = unicode_host.lower()
    else:
        host_cmp = host
    reg = registrable_domain(host_cmp)
    reg_label = reg.split(".")[0]
    reg_skel = skeleton(reg_label)

    for brand in watchlist:
        brand = brand.lower().strip(".")
        brand_reg = registrable_domain(brand)
        brand_label = brand_reg.split(".")[0]
        if len(brand_label) < 3:
            continue
        # Legitimate: exact or subdomain of the brand.
        if host_cmp == brand or host_cmp.endswith("." + brand) or reg == brand_reg:
            return None

    best: LookalikeMatch | None = None
    for brand in watchlist:
        brand = brand.lower().strip(".")
        brand_reg = registrable_domain(brand)
        brand_label = brand_reg.split(".")[0]
        if len(brand_label) < 3:
            continue
        brand_skel = skeleton(brand_label)
        labels = host_cmp.split(".")

        # brand.com.evil.net or paypal.evil.net
        if brand_reg in host_cmp and not host_cmp.endswith(brand_reg):
            return LookalikeMatch(
                domain, brand, "brand-subdomain", f"'{brand_reg}' appears as a subdomain of {reg}"
            )
        if brand_label in labels[:-2] if len(labels) > 2 else False:
            return LookalikeMatch(
                domain, brand, "brand-subdomain", f"'{brand_label}' used as a subdomain label of {reg}"
            )

        if is_idn and reg_skel == brand_skel:
            return LookalikeMatch(
                domain, brand, "idn", f"punycode {host} renders as {unicode_host}, a homoglyph of {brand_reg}"
            )
        if reg_label != brand_label and reg_skel == brand_skel:
            return LookalikeMatch(
                domain, brand, "homoglyph", f"'{reg_label}' is a visual imitation of '{brand_label}'"
            )
        if reg_label == brand_label and reg != brand_reg:
            cand = LookalikeMatch(
                domain, brand, "tld-swap", f"same name as {brand_reg} under a different TLD ({reg})"
            )
            best = best or cand
            continue
        thresh = _typo_threshold(len(brand_label))
        dist = damerau_levenshtein(reg_skel, brand_skel)
        if 0 < dist <= thresh:
            cand = LookalikeMatch(
                domain, brand, "typo", f"'{reg_label}' is within {dist} edit(s) of '{brand_label}'"
            )
            if best is None or best.kind == "tld-swap":
                best = cand
            continue
        if brand_skel in reg_skel and reg_skel != brand_skel and len(brand_skel) >= 4:
            cand = LookalikeMatch(
                domain, brand, "affix", f"'{reg_label}' contains brand name '{brand_label}' with extra text"
            )
            best = best or cand
    return best
