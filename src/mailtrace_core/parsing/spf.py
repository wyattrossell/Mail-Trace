"""Minimal SPF (RFC 7208) evaluator over the :class:`Resolver` abstraction.

Supports ``all``, ``ip4``, ``ip6``, ``a``, ``mx``, ``include``, ``exists``
and the ``redirect`` modifier, with the 10-lookup limit. ``ptr`` is treated
as non-matching (deprecated by the RFC) and macros are not expanded; both
are reported in ``detail`` so the examiner knows the evaluation was partial.
"""

from __future__ import annotations

import ipaddress
import re

from mailtrace_core.enrichment.dns_lookup import DnsTempError, Resolver
from mailtrace_core.models import SpfVerification

MAX_LOOKUPS = 10
_MACRO_RE = re.compile(r"%\{")


class _Budget:
    def __init__(self) -> None:
        self.lookups = 0

    def spend(self) -> None:
        self.lookups += 1
        if self.lookups > MAX_LOOKUPS:
            raise _PermError("more than 10 DNS-querying mechanisms (RFC 7208 limit)")


class _PermError(Exception):
    pass


def fetch_spf_record(domain: str, resolver: Resolver) -> str | None:
    txts = resolver.txt(domain)
    spf = [t for t in txts if t.lower().startswith("v=spf1") and (len(t) == 6 or t[6] == " ")]
    if len(spf) > 1:
        raise _PermError(f"{domain} publishes multiple SPF records")
    return spf[0] if spf else None


def _ip_in(ip: ipaddress._BaseAddress, cidr: str, default_bits: int) -> bool:
    try:
        if "/" in cidr:
            net = ipaddress.ip_network(cidr, strict=False)
        else:
            net = ipaddress.ip_network(f"{cidr}/{default_bits}", strict=False)
    except ValueError:
        raise _PermError(f"invalid network {cidr!r}") from None
    return ip.version == net.version and ip in net


def _host_matches(
    ip: ipaddress._BaseAddress, host: str, resolver: Resolver, budget: _Budget, spec: str
) -> bool:
    """Match ip against A/AAAA of host with optional /cidr suffix in spec."""
    bits = None
    if "/" in spec:
        host_part, _, cidr = spec.partition("/")
        host = host_part or host
        try:
            bits = int(cidr.split("/")[0])
        except ValueError:
            raise _PermError(f"bad cidr in {spec!r}") from None
    addrs = resolver.aaaa(host) if ip.version == 6 else resolver.a(host)
    for a in addrs:
        try:
            if bits is None:
                if ipaddress.ip_address(a) == ip:
                    return True
            elif ip in ipaddress.ip_network(f"{a}/{bits}", strict=False):
                return True
        except ValueError:
            continue
    return False


def _evaluate(
    ip: ipaddress._BaseAddress,
    domain: str,
    resolver: Resolver,
    budget: _Budget,
    notes: list[str],
    depth: int = 0,
) -> tuple[str, str | None, str | None]:
    """Return ``(result, record, matched_mechanism)`` for domain."""
    if depth > 10:
        raise _PermError("include/redirect nesting too deep")
    record = fetch_spf_record(domain, resolver)
    if record is None:
        return "none", None, None
    terms = record.split()[1:]
    redirect: str | None = None
    for term in terms:
        if _MACRO_RE.search(term):
            notes.append(f"macro in {term!r} not expanded; treated as no match")
            continue
        if "=" in term and ":" not in term.split("=", 1)[0]:
            mod, _, val = term.partition("=")
            if mod.lower() == "redirect":
                redirect = val.lower()
            continue  # exp= and unknown modifiers are ignored
        qualifier = "+"
        if term[0] in "+-~?":
            qualifier, term = term[0], term[1:]
        name, _, arg = term.partition(":")
        name = name.lower()
        if "/" in name and not arg:  # e.g. "a/24" or "mx/24"
            name, _, cidr = name.partition("/")
            arg = "/" + cidr
        matched = False
        if name == "all":
            matched = True
        elif name == "ip4":
            matched = ip.version == 4 and _ip_in(ip, arg, 32)
        elif name == "ip6":
            matched = ip.version == 6 and _ip_in(ip, arg, 128)
        elif name == "a":
            budget.spend()
            target = arg.split("/")[0] or domain
            matched = _host_matches(ip, target, resolver, budget, arg)
        elif name == "mx":
            budget.spend()
            target = arg.split("/")[0] or domain
            cidr_spec = "/" + arg.split("/", 1)[1] if "/" in arg else ""
            for mx in resolver.mx(target)[:10]:
                if _host_matches(ip, mx, resolver, budget, cidr_spec):
                    matched = True
                    break
        elif name == "include":
            budget.spend()
            sub, _, _ = _evaluate(ip, arg.lower(), resolver, budget, notes, depth + 1)
            if sub == "none":
                raise _PermError(f"include:{arg} has no SPF record")
            matched = sub == "pass"
        elif name == "exists":
            budget.spend()
            matched = bool(resolver.a(arg))
        elif name == "ptr":
            budget.spend()
            notes.append("ptr mechanism is deprecated; treated as no match")
            matched = False
        else:
            raise _PermError(f"unknown mechanism {name!r}")
        if matched:
            result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
            return result, record, f"{qualifier}{term}"
    if redirect:
        budget.spend()
        result, _, mech = _evaluate(ip, redirect, resolver, budget, notes, depth + 1)
        if result == "none":
            raise _PermError(f"redirect={redirect} has no SPF record")
        return result, record, f"redirect={redirect} -> {mech}"
    return "neutral", record, None


def check_spf(client_ip: str | None, domain: str | None, resolver: Resolver | None) -> SpfVerification:
    """Evaluate SPF for the connecting IP against the MAIL FROM (or From) domain."""
    if resolver is None:
        return SpfVerification(domain, client_ip, "skipped", detail="DNS disabled or offline")
    if not domain:
        return SpfVerification(domain, client_ip, "skipped", detail="no sender domain available")
    if not client_ip:
        return SpfVerification(
            domain,
            client_ip,
            "skipped",
            detail="no verifiable connecting IP (trust boundary could not be established)",
        )
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return SpfVerification(domain, client_ip, "permerror", detail="invalid client IP")
    notes: list[str] = []
    budget = _Budget()
    try:
        result, record, mech = _evaluate(ip, domain.lower(), resolver, budget, notes)
    except _PermError as exc:
        return SpfVerification(domain, client_ip, "permerror", detail=str(exc))
    except DnsTempError as exc:
        return SpfVerification(domain, client_ip, "temperror", detail=f"DNS failure: {exc}")
    detail = "; ".join(notes)
    if result == "none":
        detail = "no SPF record published"
    return SpfVerification(
        domain=domain,
        client_ip=client_ip,
        result=result,
        record=record,
        detail=detail,
        matched_mechanism=mech,
    )
