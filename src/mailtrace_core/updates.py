"""Update checking against GitHub Releases.

Rules:

- Never runs when update checks are disabled in settings or the network
  choke point is offline (air-gapped forensic machines).
- At most once per 24 hours unless ``force`` is set (manual check).
- Every failure mode (offline, timeout, rate limit, malformed response) is
  reported as a quiet status; nothing is raised to the caller.
- Nothing is downloaded or installed. The result carries the release page
  URL, the notes, the assets and, when the release ships a ``SHA256SUMS``
  file, the expected hashes so the operator can verify what they download.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from mailtrace_core import __version__
from mailtrace_core.case.settings import settings_dir
from mailtrace_core.util import netguard
from mailtrace_core.util.timeutil import iso_utc

REPO = "wyattrossell/Mail-Trace"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"
CHECK_INTERVAL = timedelta(hours=24)
STATE_FILE = "update_state.json"
SUMS_NAME = "SHA256SUMS"


@dataclass(slots=True)
class ReleaseAsset:
    name: str
    url: str
    size: int
    sha256: str | None = None


@dataclass(slots=True)
class UpdateCheckResult:
    status: str
    """``update_available``, ``up_to_date``, ``skipped``, ``rate_limited``, ``error``."""
    current_version: str
    latest_version: str | None = None
    tag: str | None = None
    release_name: str = ""
    release_notes: str = ""
    release_url: str = RELEASES_PAGE
    published_at: str = ""
    assets: list[ReleaseAsset] = field(default_factory=list)
    sha256sums: dict[str, str] = field(default_factory=dict)
    detail: str = ""
    checked_at: str = ""


def parse_version(tag: str | None) -> Version | None:
    if not tag:
        return None
    text = tag.strip()
    if text[:1] in {"v", "V"}:
        text = text[1:]
    try:
        return Version(text)
    except InvalidVersion:
        return None


def is_newer(tag: str | None, current: str = __version__) -> bool | None:
    """True if ``tag`` is newer than ``current``; None if either cannot be parsed."""
    latest, cur = parse_version(tag), parse_version(current)
    if latest is None or cur is None:
        return None
    return latest > cur


def state_path() -> Path:
    return settings_dir() / STATE_FILE


def _load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(path: Path, data: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse ``<hash>  <filename>`` lines (sha256sum format) into ``{filename: hash}``."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            out[parts[1].lstrip("*").strip()] = parts[0].lower()
    return out


def check_for_updates(
    *,
    enabled: bool = True,
    force: bool = False,
    current_version: str = __version__,
    http: Any = None,
    state_file: Path | None = None,
    now: datetime | None = None,
) -> UpdateCheckResult:
    """Query GitHub for the latest release. Never raises."""
    now = now or datetime.now(tz=UTC)
    res = UpdateCheckResult(status="skipped", current_version=current_version, checked_at=iso_utc(now))
    if not enabled:
        res.detail = "update checks disabled in settings"
        return res
    if netguard.is_offline():
        res.detail = "offline mode"
        return res
    spath = state_file or state_path()
    state = _load_state(spath)
    last = state.get("last_checked")
    if not force and last:
        try:
            last_dt = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            if now - last_dt < CHECK_INTERVAL:
                res.detail = f"checked {last}; next check after 24 h"
                cached = state.get("last_result")
                if isinstance(cached, dict) and cached.get("status") == "update_available":
                    return _from_cache(cached, current_version, res.checked_at)
                return res
        except ValueError:
            pass

    close = False
    if http is None:
        from mailtrace_core.enrichment.http import HttpClient

        http = HttpClient(timeout=6.0)
        close = True
    try:
        try:
            resp = http.get(
                LATEST_URL,
                netguard.NetCategory.UPDATE_CHECK,
                headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
            )
        except netguard.NetworkBlocked as exc:
            res.detail = str(exc)
            return res
        except Exception as exc:  # noqa: BLE001 - HttpError, timeouts, DNS failures
            res.status, res.detail = "error", f"{type(exc).__name__}: {exc}"
            return res
        if resp.status in {403, 429} and resp.headers.get("x-ratelimit-remaining") == "0":
            res.status, res.detail = "rate_limited", "GitHub API rate limit reached; will retry later"
            return res
        if resp.status == 404:
            res.status, res.detail = "error", "no releases published yet"
            _save_state(spath, {"last_checked": res.checked_at, "last_result": None})
            return res
        if resp.status >= 400 or not isinstance(resp.json, dict):
            res.status, res.detail = "error", f"HTTP {resp.status}"
            return res
        data = resp.json
        res.tag = str(data.get("tag_name") or "")
        v = parse_version(res.tag)
        if v is None:
            res.status, res.detail = "error", f"unparseable release tag {res.tag!r}"
            return res
        res.latest_version = str(v)
        res.release_name = str(data.get("name") or res.tag)
        res.release_notes = str(data.get("body") or "")
        res.release_url = str(data.get("html_url") or RELEASES_PAGE)
        res.published_at = str(data.get("published_at") or "")
        sums_url = None
        for a in data.get("assets", []) or []:
            if not isinstance(a, dict):
                continue
            asset = ReleaseAsset(
                name=str(a.get("name", "")),
                url=str(a.get("browser_download_url", "")),
                size=int(a.get("size") or 0),
            )
            if asset.name == SUMS_NAME:
                sums_url = asset.url
            else:
                res.assets.append(asset)
        if sums_url:
            try:
                sresp = http.get(
                    sums_url, netguard.NetCategory.UPDATE_CHECK, headers={"Accept": "text/plain"}
                )
                if sresp.status < 400:
                    res.sha256sums = parse_sha256sums(sresp.text)
                    for asset in res.assets:
                        asset.sha256 = res.sha256sums.get(asset.name)
            except Exception as exc:  # noqa: BLE001
                res.detail = f"SHA256SUMS could not be fetched: {exc}"
        newer = is_newer(res.tag, current_version)
        res.status = "update_available" if newer else "up_to_date"
        if newer is None:
            res.status, res.detail = "error", "could not compare versions"
        _save_state(spath, {"last_checked": res.checked_at, "last_result": _to_cache(res)})
        return res
    finally:
        if close:
            try:
                http.close()
            except Exception:  # noqa: BLE001
                pass


def _to_cache(res: UpdateCheckResult) -> dict[str, Any]:
    return {
        "status": res.status,
        "latest_version": res.latest_version,
        "tag": res.tag,
        "release_name": res.release_name,
        "release_notes": res.release_notes,
        "release_url": res.release_url,
        "published_at": res.published_at,
        "assets": [{"name": a.name, "url": a.url, "size": a.size, "sha256": a.sha256} for a in res.assets],
        "sha256sums": res.sha256sums,
    }


def _from_cache(c: dict[str, Any], current: str, checked_at: str) -> UpdateCheckResult:
    res = UpdateCheckResult(
        status="update_available" if is_newer(c.get("tag"), current) else "up_to_date",
        current_version=current,
        latest_version=c.get("latest_version"),
        tag=c.get("tag"),
        release_name=str(c.get("release_name") or ""),
        release_notes=str(c.get("release_notes") or ""),
        release_url=str(c.get("release_url") or RELEASES_PAGE),
        published_at=str(c.get("published_at") or ""),
        sha256sums=dict(c.get("sha256sums") or {}),
        detail="from cached check",
        checked_at=checked_at,
    )
    for a in c.get("assets", []) or []:
        res.assets.append(
            ReleaseAsset(
                name=a.get("name", ""),
                url=a.get("url", ""),
                size=int(a.get("size") or 0),
                sha256=a.get("sha256"),
            )
        )
    return res
