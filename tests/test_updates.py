from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.updates import (
    LATEST_URL,
    check_for_updates,
    is_newer,
    parse_sha256sums,
    parse_version,
)
from mailtrace_core.util import netguard

RELEASE = {
    "tag_name": "v1.2.0",
    "name": "MailTrace 1.2.0",
    "body": "## Changes\n- Faster DKIM\n- New report sections",
    "html_url": "https://github.com/wyattrossell/Mail-Trace/releases/tag/v1.2.0",
    "published_at": "2026-10-01T12:00:00Z",
    "assets": [
        {
            "name": "MailTrace-1.2.0-windows-x64.zip",
            "browser_download_url": "https://github.com/x/z.zip",
            "size": 12345,
        },
        {"name": "SHA256SUMS", "browser_download_url": "https://github.com/x/SHA256SUMS", "size": 100},
    ],
}
SUMS = "a" * 64 + "  MailTrace-1.2.0-windows-x64.zip\n" + "b" * 64 + " *other.exe\n"


def _http(handler) -> HttpClient:  # type: ignore[no-untyped-def]
    netguard.set_offline(False)
    return HttpClient(transport=httpx.MockTransport(handler))


def _ok(req: httpx.Request) -> httpx.Response:
    if str(req.url) == LATEST_URL:
        assert req.headers["Accept"] == "application/vnd.github+json"
        return httpx.Response(200, json=RELEASE)
    if str(req.url).endswith("SHA256SUMS"):
        return httpx.Response(200, text=SUMS)
    return httpx.Response(404)


def test_version_parsing() -> None:
    assert str(parse_version("v1.2.0")) == "1.2.0" and str(parse_version("2.0.0rc1")) == "2.0.0rc1"
    assert parse_version("nightly") is None
    assert is_newer("v1.2.0", "1.1.9") is True and is_newer("v1.2.0", "1.2.0") is False
    assert is_newer("v1.2.0", "1.10.0") is False and is_newer("junk", "1.0.0") is None
    assert parse_sha256sums(SUMS) == {"MailTrace-1.2.0-windows-x64.zip": "a" * 64, "other.exe": "b" * 64}


def test_update_available_with_sums(tmp_path: Path) -> None:
    res = check_for_updates(http=_http(_ok), state_file=tmp_path / "s.json", current_version="1.1.0")
    assert res.status == "update_available" and res.latest_version == "1.2.0" and res.tag == "v1.2.0"
    assert "Faster DKIM" in res.release_notes and res.release_url.endswith("/v1.2.0")
    assert [a.name for a in res.assets] == ["MailTrace-1.2.0-windows-x64.zip"]
    assert res.assets[0].sha256 == "a" * 64 and res.sha256sums["other.exe"] == "b" * 64
    state = json.loads((tmp_path / "s.json").read_text())
    assert state["last_result"]["tag"] == "v1.2.0"


def test_up_to_date_and_throttle(tmp_path: Path) -> None:
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _ok(req)

    http = _http(handler)
    res = check_for_updates(http=http, state_file=tmp_path / "s.json", current_version="1.2.0")
    assert res.status == "up_to_date" and len(calls) == 2
    res2 = check_for_updates(http=http, state_file=tmp_path / "s.json", current_version="1.2.0")
    assert res2.status == "skipped" and "next check" in res2.detail and len(calls) == 2
    res3 = check_for_updates(http=http, state_file=tmp_path / "s.json", current_version="1.2.0", force=True)
    assert res3.status == "up_to_date" and len(calls) == 4
    later = datetime.now(tz=UTC) + timedelta(hours=25)
    res4 = check_for_updates(http=http, state_file=tmp_path / "s.json", current_version="1.2.0", now=later)
    assert res4.status == "up_to_date" and len(calls) == 6


def test_cached_update_shown_within_window(tmp_path: Path) -> None:
    http = _http(_ok)
    check_for_updates(http=http, state_file=tmp_path / "s.json", current_version="1.0.0")
    res = check_for_updates(
        http=_http(lambda r: httpx.Response(500)), state_file=tmp_path / "s.json", current_version="1.0.0"
    )
    assert (
        res.status == "update_available"
        and res.detail == "from cached check"
        and res.assets[0].sha256 == "a" * 64
    )


def test_quiet_failures(tmp_path: Path) -> None:
    rl = _http(
        lambda r: httpx.Response(403, headers={"X-RateLimit-Remaining": "0"}, json={"message": "limit"})
    )
    assert check_for_updates(http=rl, state_file=tmp_path / "a.json").status == "rate_limited"

    def timeout(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    res = check_for_updates(http=_http(timeout), state_file=tmp_path / "b.json")
    assert res.status == "error" and "timed out" in res.detail
    assert (
        check_for_updates(http=_http(lambda r: httpx.Response(404)), state_file=tmp_path / "c.json").detail
        == "no releases published yet"
    )
    bad = _http(lambda r: httpx.Response(200, json={"tag_name": "nightly-build"}))
    assert check_for_updates(http=bad, state_file=tmp_path / "d.json").status == "error"


def test_disabled_and_offline(tmp_path: Path) -> None:
    calls = []
    http = _http(lambda r: (calls.append(1), _ok(r))[1])
    res = check_for_updates(enabled=False, http=http, state_file=tmp_path / "s.json")
    assert res.status == "skipped" and "disabled" in res.detail and calls == []
    netguard.set_offline(True)
    res = check_for_updates(http=http, state_file=tmp_path / "s.json")
    assert res.status == "skipped" and "offline" in res.detail and calls == []
