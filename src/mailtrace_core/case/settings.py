"""Per-installation settings and secret storage.

Non-secret settings live in a JSON file under ``%APPDATA%/MailTrace``.
API keys never touch that file: they go to Windows Credential Manager through
``keyring``. Everything here degrades gracefully when the backing store is
unavailable, so the core can run headless and in tests.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

KEYRING_SERVICE = "MailTrace"

DEFAULT_BRANDS: list[str] = [
    "paypal.com",
    "microsoft.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "dropbox.com",
    "docusign.com",
    "adobe.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "citi.com",
    "capitalone.com",
    "usbank.com",
    "americanexpress.com",
    "irs.gov",
    "ssa.gov",
    "usps.com",
    "ups.com",
    "fedex.com",
    "dhl.com",
    "zoom.us",
    "coinbase.com",
    "binance.com",
    "venmo.com",
    "zelle.com",
    "cash.app",
]

DEFAULT_FREE_MAIL: list[str] = [
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "aol.com",
    "icloud.com",
    "me.com",
    "mail.com",
    "protonmail.com",
    "proton.me",
    "pm.me",
    "gmx.com",
    "gmx.net",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "zoho.com",
    "tutanota.com",
    "tuta.io",
    "fastmail.com",
    "hushmail.com",
]

DEFAULT_SHORTENERS: list[str] = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "t.ly",
    "lnkd.in",
    "s.id",
    "bl.ink",
    "short.io",
    "qrco.de",
]


@dataclass(slots=True)
class Settings:
    """Everything the parser and rules need to know about the operator."""

    agency_domains: list[str] = field(default_factory=list)
    """Domains belonging to the examiner's own agency; impersonation targets."""
    trusted_recipient_domains: list[str] = field(default_factory=list)
    """Domains whose mail servers are considered recipient-side for hop trust."""
    impersonated_brands: list[str] = field(default_factory=lambda: list(DEFAULT_BRANDS))
    free_mail_domains: list[str] = field(default_factory=lambda: list(DEFAULT_FREE_MAIL))
    url_shorteners: list[str] = field(default_factory=lambda: list(DEFAULT_SHORTENERS))
    dns_enabled: bool = True
    active_features_enabled: bool = False
    """Must stay False unless the operator accepts the warning in the GUI."""
    case_base_dir: str = ""
    # --- enrichment
    enrichment_enabled: bool = True
    geoip_city_db: str = ""
    """Path to GeoLite2-City.mmdb supplied by the operator (MaxMind licence)."""
    geoip_asn_db: str = ""
    """Path to GeoLite2-ASN.mmdb supplied by the operator."""
    ipinfo_enabled: bool = True
    tor_exit_check: bool = True
    rdap_enabled: bool = True
    whois_fallback: bool = True
    reputation_enabled: bool = True
    enrichment_cache_ttl_hours: float = 24.0
    max_enrich_ips: int = 10
    max_enrich_domains: int = 20
    max_enrich_urls: int = 20
    # --- reporting
    report_agency_name: str = ""
    """Agency name on the report header; falls back to the case agency."""
    report_agency_line2: str = ""
    """Unit, address or contact line under the agency name."""
    report_logo_path: str = ""
    report_classification: str = "LAW ENFORCEMENT SENSITIVE"
    report_footer_note: str = ""
    report_default_examiner: str = ""
    """Used when a report is generated outside a case (CLI without --case)."""
    reporter_name: str = ""
    """Name/rank/agency block used to sign outgoing report drafts."""
    reporter_email: str = ""
    reporter_phone: str = ""
    # --- examiner defaults and updates
    default_examiner: str = ""
    """Pre-filled in the New Case dialog."""
    default_agency: str = ""
    update_check_enabled: bool = True
    update_skip_version: str = ""
    """A release the user chose to skip; no prompt for it again."""
    """Turn off on air-gapped machines; the check contacts api.github.com once per day."""

    @property
    def brand_watchlist(self) -> list[str]:
        """Brands plus the agency's own domains, lower-cased and de-duplicated."""
        seen: set[str] = set()
        out: list[str] = []
        for d in [*self.agency_domains, *self.impersonated_brands]:
            d = d.strip().lower().lstrip("@")
            if d and d not in seen:
                seen.add(d)
                out.append(d)
        return out


def settings_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / ".config")
    return Path(base) / "MailTrace"


def settings_path() -> Path:
    return settings_dir() / "settings.json"


def load_settings(path: Path | None = None) -> Settings:
    p = path or settings_path()
    if not p.exists():
        return Settings()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return Settings()
    s = Settings()
    for k, v in data.items():
        if hasattr(s, k) and not k.startswith("_"):
            setattr(s, k, v)
    return s


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    p = path or settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
    return p


# ------------------------------------------------------------------- secrets
def get_api_key(provider: str) -> str | None:
    """Read a key from the OS credential store. None when absent or unavailable."""
    try:
        import keyring

        return keyring.get_password(KEYRING_SERVICE, provider)
    except Exception:  # noqa: BLE001 - any backend failure means "no key"
        return None


def set_api_key(provider: str, key: str) -> bool:
    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, provider, key)
        return True
    except Exception:  # noqa: BLE001
        return False


def delete_api_key(provider: str) -> bool:
    try:
        import keyring

        keyring.delete_password(KEYRING_SERVICE, provider)
        return True
    except Exception:  # noqa: BLE001
        return False
