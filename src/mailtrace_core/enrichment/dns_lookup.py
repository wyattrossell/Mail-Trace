"""DNS resolver abstraction.

:class:`DnsResolver` talks to real DNS through dnspython and goes through the
network choke point. :class:`StaticResolver` answers from a dict so SPF,
DKIM and DMARC evaluation can be tested fully offline with deterministic
records.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from mailtrace_core.util import netguard


class DnsTempError(RuntimeError):
    """Transient failure (timeout, SERVFAIL, network down)."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def a(self, name: str) -> list[str]: ...
    def aaaa(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[str]: ...
    def ns(self, name: str) -> list[str]: ...
    def ptr(self, ip: str) -> list[str]: ...


class StaticResolver:
    """Deterministic resolver for tests and canned demos.

    ``records`` maps ``(name_lower, rtype)`` to a list of string values.
    Names are normalised without a trailing dot.
    """

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None) -> None:
        self.records = {(k[0].lower().rstrip("."), k[1].upper()): v for k, v in (records or {}).items()}
        self.queries: list[tuple[str, str]] = []

    def _get(self, name: str, rtype: str) -> list[str]:
        key = (name.lower().rstrip("."), rtype)
        self.queries.append(key)
        vals = self.records.get(key, [])
        if vals == ["__TEMPERROR__"]:
            raise DnsTempError(f"simulated temperror for {name} {rtype}")
        return list(vals)

    def txt(self, name: str) -> list[str]:
        return self._get(name, "TXT")

    def a(self, name: str) -> list[str]:
        return self._get(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self._get(name, "AAAA")

    def mx(self, name: str) -> list[str]:
        return self._get(name, "MX")

    def ns(self, name: str) -> list[str]:
        return self._get(name, "NS")

    def ptr(self, ip: str) -> list[str]:
        return self._get(ip, "PTR")


class DnsResolver:
    """Live resolver via dnspython. Every query is a passive DNS lookup."""

    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None) -> None:
        import dns.resolver

        self._res = dns.resolver.Resolver()
        self._res.timeout = timeout
        self._res.lifetime = timeout * 2
        if nameservers:
            self._res.nameservers = nameservers

    def _query(self, name: str, rtype: str) -> list[str]:
        import dns.exception
        import dns.resolver

        netguard.require(netguard.NetCategory.DNS)
        try:
            answer = self._res.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.resolver.NoNameservers as exc:
            raise DnsTempError(str(exc)) from exc
        except dns.exception.DNSException as exc:
            raise DnsTempError(str(exc)) from exc
        out: list[str] = []
        for rdata in answer:
            if rtype == "TXT":
                out.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
            elif rtype == "MX":
                out.append(str(rdata.exchange).rstrip("."))
            elif rtype in {"PTR", "NS"}:
                out.append(str(rdata.target).rstrip("."))
            else:
                out.append(str(rdata))
        return out

    def txt(self, name: str) -> list[str]:
        return self._query(name, "TXT")

    def a(self, name: str) -> list[str]:
        return self._query(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self._query(name, "AAAA")

    def mx(self, name: str) -> list[str]:
        return self._query(name, "MX")

    def ns(self, name: str) -> list[str]:
        return self._query(name, "NS")

    def ptr(self, ip: str) -> list[str]:
        import dns.reversename

        rev = str(dns.reversename.from_address(ip))
        return self._query(rev, "PTR")


def dkim_dnsfunc(resolver: Resolver) -> Callable[..., bytes | None]:
    """Adapt a :class:`Resolver` to the ``dnsfunc(name, timeout=5)`` dkimpy expects."""

    def _fn(name: bytes | str, timeout: float = 5) -> bytes | None:
        n = name.decode() if isinstance(name, bytes) else name
        records = resolver.txt(n.rstrip("."))
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                return r.encode()
        return records[0].encode() if records else None

    return _fn
