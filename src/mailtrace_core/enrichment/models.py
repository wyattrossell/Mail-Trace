"""Data models produced by the enrichment layer.

Everything here is a plain dataclass so it serialises through
:func:`mailtrace_core.models.to_jsonable`. Each record keeps a list of
:class:`Lookup` entries saying which provider was consulted, whether it
answered, was cached, was rate limited, or was skipped and why.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class LookupStatus(enum.StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


@dataclass(slots=True)
class Lookup:
    """One provider consultation for one target."""

    provider: str
    target: str
    status: LookupStatus
    detail: str = ""
    fetched_at: str = ""
    cached: bool = False


@dataclass(slots=True)
class ReputationVerdict:
    provider: str
    target: str
    target_type: str
    """``ip``, ``domain``, ``url`` or ``hash``."""
    verdict: str
    """``malicious``, ``suspicious``, ``clean`` or ``unknown``."""
    summary: str = ""
    detail: str = ""
    link: str = ""
    fetched_at: str = ""


@dataclass(slots=True)
class IpEnrichment:
    ip: str
    roles: list[str] = field(default_factory=list)
    """Why this IP was looked up: ``origin (likely)``, ``hop 2``, ``url host a.test`` ..."""
    is_private: bool = False
    reverse_dns: list[str] = field(default_factory=list)
    asn: int | None = None
    asn_org: str | None = None
    isp: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    geo_source: str | None = None
    network_handle: str | None = None
    network_name: str | None = None
    network_cidr: str | None = None
    network_country: str | None = None
    rdap_registry: str | None = None
    abuse_contacts: list[str] = field(default_factory=list)
    hosting: bool | None = None
    vpn: bool | None = None
    proxy: bool | None = None
    tor: bool | None = None
    flag_reasons: list[str] = field(default_factory=list)
    reputation: list[ReputationVerdict] = field(default_factory=list)
    lookups: list[Lookup] = field(default_factory=list)


@dataclass(slots=True)
class DomainEnrichment:
    domain: str
    roles: list[str] = field(default_factory=list)
    registrar: str | None = None
    registrar_iana_id: str | None = None
    registrar_abuse_email: str | None = None
    registrar_abuse_phone: str | None = None
    registrant_org: str | None = None
    registrant_country: str | None = None
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    age_days: int | None = None
    is_new: bool | None = None
    """True when created fewer than :data:`NEW_DOMAIN_DAYS` days ago."""
    statuses: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    a: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    whois_source: str | None = None
    reputation: list[ReputationVerdict] = field(default_factory=list)
    lookups: list[Lookup] = field(default_factory=list)


@dataclass(slots=True)
class LegalProcessTarget:
    provider_key: str
    provider_name: str
    role: str
    """What this provider is in the case, e.g. ``originating mail provider``."""
    matched_on: str
    """The observation that produced the match, e.g. ``asn_org: GOOGLE``."""
    portal: str = ""
    email: str = ""
    phone: str = ""
    guidelines_url: str = ""
    jurisdiction: str = ""
    records_available: list[str] = field(default_factory=list)
    notes: str = ""
    verify_before_use: bool = True
    last_verified: str | None = None


@dataclass(slots=True)
class RiskFactor:
    name: str
    points: int
    max_points: int
    evidence: str
    source: str
    """``findings``, ``domain``, ``ip``, ``reputation`` or ``mitigation``."""


@dataclass(slots=True)
class RiskScore:
    score: int
    band: str
    factors: list[RiskFactor] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    computed_at: str = ""


@dataclass(slots=True)
class EnrichmentReport:
    ips: list[IpEnrichment] = field(default_factory=list)
    domains: list[DomainEnrichment] = field(default_factory=list)
    url_reputation: list[ReputationVerdict] = field(default_factory=list)
    attachment_reputation: list[ReputationVerdict] = field(default_factory=list)
    legal_targets: list[LegalProcessTarget] = field(default_factory=list)
    preservation_note: str = ""
    risk: RiskScore | None = None
    skipped: list[str] = field(default_factory=list)
    """``provider: reason`` for every provider that could not run."""
    lookups_performed: int = 0
    lookups_cached: int = 0
    started_at: str = ""
    finished_at: str = ""


NEW_DOMAIN_DAYS = 30
