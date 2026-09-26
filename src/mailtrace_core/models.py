"""Domain models shared across parsing, analysis, and reporting.

All models are plain dataclasses so they can be serialized to JSON for the CLI
and report layers without any GUI dependency. Every timestamp is timezone-aware.
Audit and intake timestamps are UTC. ``Hop.timestamp`` keeps the offset the
server wrote so clock-skew analysis can see it.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Confidence(enum.StrEnum):
    """How strongly the evidence supports a finding.

    CONFIRMED  - directly observable in the evidence (e.g. two headers differ).
    LIKELY     - strong indicator, but an innocent explanation exists.
    UNVERIFIED - suggestive only; requires corroboration before relying on it.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"


class Severity(enum.StrEnum):
    """Investigative weight of a finding. Independent of confidence."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceFormat(enum.StrEnum):
    EML = "eml"
    MSG = "msg"
    RAW_HEADERS = "raw_headers"


@dataclass(slots=True)
class Evidence:
    """A pointer to the exact artifact a finding rests on."""

    source: str
    """Where it came from, e.g. ``header:From``, ``hop:3``, ``dns:TXT:example.com``."""
    value: str
    """The observed value, verbatim or lightly trimmed."""
    note: str = ""


@dataclass(slots=True)
class Finding:
    """A single conclusion, always with a confidence label and its evidence."""

    rule_id: str
    title: str
    confidence: Confidence
    severity: Severity
    explanation: str
    evidence: list[Evidence] = field(default_factory=list)
    category: str = "general"


@dataclass(slots=True)
class Hop:
    """One ``Received:`` header, parsed. Index 0 is the origin (oldest)."""

    index: int
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    from_helo: str | None = None
    by_host: str | None = None
    by_ip: str | None = None
    protocol: str | None = None
    hop_id: str | None = None
    for_addr: str | None = None
    timestamp: datetime | None = None
    delay_seconds: float | None = None
    """Seconds since the previous hop's timestamp. Negative means out of order."""
    trusted: bool = False
    """True when added by a server we believe belongs to the recipient's side."""
    trust_reason: str = ""
    anomalies: list[str] = field(default_factory=list)


@dataclass(slots=True)
class OriginCandidate:
    """A possible originating IP, with where the claim comes from."""

    ip: str
    source: str
    confidence: Confidence
    note: str = ""
    is_private: bool = False


@dataclass(slots=True)
class AuthResult:
    """One method result taken from an ``Authentication-Results`` header."""

    authserv_id: str
    method: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)
    reason: str = ""
    raw: str = ""


@dataclass(slots=True)
class DkimVerification:
    """Outcome of independently re-verifying a DKIM signature."""

    domain: str | None
    selector: str | None
    result: str
    """``pass``, ``fail``, ``permerror``, ``temperror``, ``none``, or ``skipped``."""
    detail: str = ""
    signed_headers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SpfVerification:
    domain: str | None
    client_ip: str | None
    result: str
    """``pass``, ``fail``, ``softfail``, ``neutral``, ``none``, ``permerror``,
    ``temperror``, or ``skipped``."""
    record: str | None = None
    detail: str = ""
    matched_mechanism: str | None = None


@dataclass(slots=True)
class DmarcVerification:
    domain: str | None
    result: str
    """``pass``, ``fail``, ``none``, ``temperror``, or ``skipped``."""
    record: str | None = None
    policy: str | None = None
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    alignment_spf: str = "r"
    alignment_dkim: str = "r"
    detail: str = ""


@dataclass(slots=True)
class AuthenticationSummary:
    reported: list[AuthResult] = field(default_factory=list)
    dkim: DkimVerification | None = None
    spf: SpfVerification | None = None
    dmarc: DmarcVerification | None = None
    skipped_checks: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UrlRecord:
    raw: str
    normalized: str
    defanged: str
    source: str
    """``text``, ``html-href``, ``html-src``, ``html-action``."""
    host: str | None = None
    display_text: str | None = None
    display_mismatch: bool = False
    """True when an HTML link's visible text looks like a different URL/host."""
    is_ip_host: bool = False
    is_idn: bool = False
    unicode_host: str | None = None
    is_shortener: bool = False
    scheme: str | None = None


@dataclass(slots=True)
class AttachmentRecord:
    filename: str
    size: int
    sha256: str
    md5: str
    declared_type: str | None
    detected_type: str | None
    extension: str | None
    type_mismatch: bool
    disposition: str | None = None
    content_id: str | None = None
    is_inline: bool = False
    part_index: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower() if "@" in self.address else ""


@dataclass(slots=True)
class ParsedEmail:
    """Normalized view of one message, regardless of source format."""

    source_format: SourceFormat
    source_name: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    message_id: str | None = None
    subject: str | None = None
    date: datetime | None = None
    from_: Address | None = None
    sender: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: Address | None = None
    to: list[Address] = field(default_factory=list)
    cc: list[Address] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    origin_candidates: list[OriginCandidate] = field(default_factory=list)
    auth: AuthenticationSummary = field(default_factory=AuthenticationSummary)
    body_text: str = ""
    body_html: str = ""
    urls: list[UrlRecord] = field(default_factory=list)
    attachments: list[AttachmentRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_bytes: bytes = field(default=b"", repr=False)
    """Original RFC 5322 bytes when available (needed for DKIM re-verification)."""

    def header(self, name: str) -> str | None:
        """First header value with this name (case-insensitive), or None."""
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for k, v in self.headers if k.lower() == lname]


@dataclass(slots=True)
class CaseMeta:
    case_number: str
    examiner: str
    agency: str
    created_at: datetime
    case_id: str
    """Filesystem-safe identifier derived from the case number."""


@dataclass(slots=True)
class EvidenceItem:
    """An ingested file, with its integrity hashes."""

    item_id: str
    original_path: str
    stored_path: str
    filename: str
    size: int
    sha256: str
    md5: str
    ingested_at: datetime
    source_format: SourceFormat


@dataclass(slots=True)
class AnalysisResult:
    email: ParsedEmail
    findings: list[Finding] = field(default_factory=list)
    skipped_checks: list[str] = field(default_factory=list)
    enrichment: Any = None
    """:class:`mailtrace_core.enrichment.models.EnrichmentReport` once enrichment has run."""


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses, enums, datetimes and bytes to JSON types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            if f.name == "raw_bytes":
                continue
            out[f.name.rstrip("_")] = to_jsonable(getattr(obj, f.name))
        return out
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple | set):
        return [to_jsonable(v) for v in obj]
    return obj
