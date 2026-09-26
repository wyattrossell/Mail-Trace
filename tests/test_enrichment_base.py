from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mailtrace_core.enrichment.base import EnrichmentCache, RateLimiter, classify_infrastructure


def test_rate_limiter_spaces_calls() -> None:
    sleeps: list[float] = []
    rl = RateLimiter(0.5, sleep=sleeps.append)
    assert rl.wait() and rl.wait() and rl.wait()
    assert len(sleeps) == 2 and all(0 < s <= 0.5 for s in sleeps)


def test_rate_limiter_back_off_blocks() -> None:
    rl = RateLimiter(0.0, sleep=lambda _s: None)
    rl.back_off(60)
    assert rl.wait() is False


def test_cache_roundtrip_and_persistence(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    c = EnrichmentCache(path, default_ttl_hours=1)
    assert c.get("rdap", "ip:1.2.3.4") is None
    c.put("rdap", "IP:1.2.3.4", {"handle": "NET-1"})
    hit = c.get("rdap", "ip:1.2.3.4")
    assert hit is not None and hit[0] == {"handle": "NET-1"} and hit[1].endswith("Z")
    assert c.hits == 1 and c.misses == 1
    again = EnrichmentCache(path)
    assert again.get("rdap", "ip:1.2.3.4") is not None
    assert json.loads(path.read_text())["rdap|ip:1.2.3.4"]["value"]["handle"] == "NET-1"


def test_cache_expiry(tmp_path: Path) -> None:
    c = EnrichmentCache(None, default_ttl_hours=1)
    c.put("p", "t", 1)
    old = (datetime.now(tz=UTC) - timedelta(hours=2)).isoformat()
    c._data["p|t"]["fetched_at"] = old
    assert c.get("p", "t") is None
    assert c.get("p", "t", ttl_hours=3) is not None


def test_cache_survives_corrupt_file(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("{not json")
    c = EnrichmentCache(path)
    assert len(c) == 0
    c.put("a", "b", 1)
    assert json.loads(path.read_text())


def test_classify_infrastructure() -> None:
    hosting, vpn, tor, reasons = classify_infrastructure("DigitalOcean, LLC", None, "vps-9.cheaphost.test")
    assert hosting is True and vpn is None and tor is None and reasons
    hosting, vpn, tor, _ = classify_infrastructure("NordVPN S.A.")
    assert vpn is True
    _, _, tor, _ = classify_infrastructure("tor-exit-3.example")
    assert tor is True
    assert classify_infrastructure("Example County Government") == (None, None, None, [])
