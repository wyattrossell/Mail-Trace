"""RDAP (RFC 9083) lookups for IP networks and domains via the rdap.org redirector.

rdap.org answers with a redirect to the authoritative registry/registrar
server, which the HTTP client follows. Registries are contacted read-only;
the sender's own infrastructure is never touched.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from mailtrace_core.enrichment.context import Context, ProviderAnswer
from mailtrace_core.enrichment.models import NEW_DOMAIN_DAYS, Lookup, LookupStatus
from mailtrace_core.util.netguard import NetCategory

RDAP_BASE = "https://rdap.org"
_TEL_RE = re.compile(r"^tel:", re.IGNORECASE)


def _vcard(entity: dict[str, Any]) -> dict[str, str]:
    """Flatten a jCard into ``{fn, email, tel, org, country}``."""
    out: dict[str, str] = {}
    arr = entity.get("vcardArray")
    if not isinstance(arr, list) or len(arr) < 2 or not isinstance(arr[1], list):
        return out
    for prop in arr[1]:
        if not isinstance(prop, list) or len(prop) < 4:
            continue
        name = str(prop[0]).lower()
        value = prop[3]
        if name == "fn" and isinstance(value, str):
            out.setdefault("fn", value)
        elif name == "email" and isinstance(value, str):
            out.setdefault("email", value)
        elif name == "tel" and isinstance(value, str):
            out.setdefault("tel", _TEL_RE.sub("", value))
        elif name == "org":
            out.setdefault("org", value if isinstance(value, str) else " ".join(map(str, value)))
        elif name == "adr":
            params = prop[1] if isinstance(prop[1], dict) else {}
            if isinstance(value, list) and len(value) >= 7 and value[6]:
                out.setdefault("country", str(value[6]))
            elif params.get("cc"):
                out.setdefault("country", str(params["cc"]))
    return out


def _walk_entities(obj: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for ent in obj.get("entities", []) or []:
        if isinstance(ent, dict):
            found.append(ent)
            found.extend(_walk_entities(ent))
    return found


def _events(obj: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for ev in obj.get("events", []) or []:
        if isinstance(ev, dict) and ev.get("eventAction") and ev.get("eventDate"):
            out.setdefault(str(ev["eventAction"]).lower(), str(ev["eventDate"]))
    return out


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    for fmt in (
        None,
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%d-%b-%Y",
        "%Y.%m.%d",
        "%d/%m/%Y",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = (
                datetime.fromisoformat(v)
                if fmt is None
                else datetime.strptime(v[:19] if fmt != "%Y-%m-%d" else v[:10], fmt)
            )
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def age_days(created: str | None, now: datetime | None = None) -> int | None:
    dt = parse_date(created)
    if dt is None:
        return None
    return max(0, ((now or datetime.now(tz=UTC)) - dt).days)


def parse_domain_rdap(data: dict[str, Any]) -> dict[str, Any]:
    ev = _events(data)
    out: dict[str, Any] = {
        "domain": (data.get("ldhName") or data.get("unicodeName") or "").lower(),
        "statuses": [str(s) for s in data.get("status", []) or []],
        "nameservers": [
            str(ns.get("ldhName", "")).lower().rstrip(".")
            for ns in data.get("nameservers", []) or []
            if isinstance(ns, dict) and ns.get("ldhName")
        ],
        "created": ev.get("registration"),
        "updated": ev.get("last changed") or ev.get("last update of rdap database"),
        "expires": ev.get("expiration"),
        "registrar": None,
        "registrar_iana_id": None,
        "registrar_abuse_email": None,
        "registrar_abuse_phone": None,
        "registrant_org": None,
        "registrant_country": None,
        "source": "rdap",
    }
    for ent in _walk_entities(data):
        roles = [str(r).lower() for r in ent.get("roles", []) or []]
        card = _vcard(ent)
        if "registrar" in roles:
            out["registrar"] = out["registrar"] or card.get("fn") or card.get("org")
            for pid in ent.get("publicIds", []) or []:
                if isinstance(pid, dict) and "registrar" in str(pid.get("type", "")).lower():
                    out["registrar_iana_id"] = str(pid.get("identifier"))
        if "abuse" in roles:
            out["registrar_abuse_email"] = out["registrar_abuse_email"] or card.get("email")
            out["registrar_abuse_phone"] = out["registrar_abuse_phone"] or card.get("tel")
        if "registrant" in roles:
            out["registrant_org"] = out["registrant_org"] or card.get("org") or card.get("fn")
            out["registrant_country"] = out["registrant_country"] or card.get("country")
    return out


def parse_ip_rdap(data: dict[str, Any]) -> dict[str, Any]:
    cidrs = data.get("cidr0_cidrs") or []
    cidr = None
    if cidrs and isinstance(cidrs[0], dict):
        c = cidrs[0]
        prefix = c.get("v4prefix") or c.get("v6prefix")
        if prefix and c.get("length") is not None:
            cidr = f"{prefix}/{c['length']}"
    if cidr is None and data.get("startAddress") and data.get("endAddress"):
        cidr = f"{data['startAddress']} - {data['endAddress']}"
    abuse: list[str] = []
    org = None
    for ent in _walk_entities(data):
        roles = [str(r).lower() for r in ent.get("roles", []) or []]
        card = _vcard(ent)
        if "abuse" in roles and card.get("email") and card["email"] not in abuse:
            abuse.append(card["email"])
        if ("registrant" in roles or "administrative" in roles) and not org:
            org = card.get("fn") or card.get("org")
    port43 = data.get("port43") or ""
    registry = None
    for name in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
        if name in port43.lower() or any(
            name in str(link.get("href", "")).lower() for link in data.get("links", []) or []
        ):
            registry = name.upper()
            break
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "cidr": cidr,
        "country": data.get("country"),
        "org": org,
        "abuse_contacts": abuse,
        "registry": registry,
        "type": data.get("type"),
    }


def _fetch(
    ctx: Context, provider: str, target: str, path: str, parser: Any
) -> tuple[dict[str, Any] | None, Lookup]:
    if ctx.http is None:
        return None, ctx.skip(provider, target, "offline")
    if not ctx.settings.rdap_enabled:
        return None, ctx.skip(provider, target, "RDAP disabled in settings")

    def call() -> ProviderAnswer:
        assert ctx.http is not None
        resp = ctx.http.get(f"{RDAP_BASE}/{path}", NetCategory.RDAP)
        if resp.status == 404:
            return ProviderAnswer(
                LookupStatus.NOT_FOUND, detail="no RDAP record / no RDAP server for this registry"
            )
        if resp.status == 429:
            return ProviderAnswer(LookupStatus.RATE_LIMITED, retry_after=resp.retry_after)
        if resp.status >= 400 or not isinstance(resp.json, dict):
            return ProviderAnswer(LookupStatus.ERROR, detail=f"HTTP {resp.status}")
        return ProviderAnswer(LookupStatus.OK, value=parser(resp.json))

    return ctx.cached_call(provider, target, call, ttl_hours=24 * 7)


def rdap_domain(domain: str, ctx: Context) -> tuple[dict[str, Any] | None, Lookup]:
    return _fetch(ctx, "rdap", f"domain:{domain}", f"domain/{domain}", parse_domain_rdap)


def rdap_ip(ip: str, ctx: Context) -> tuple[dict[str, Any] | None, Lookup]:
    return _fetch(ctx, "rdap", f"ip:{ip}", f"ip/{ip}", parse_ip_rdap)


def is_new_domain(created: str | None) -> tuple[int | None, bool | None]:
    days = age_days(created)
    if days is None:
        return None, None
    return days, days < NEW_DOMAIN_DAYS
