"""Shared fixtures: sample paths, a deterministic resolver, and settings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailtrace_core.case.settings import Settings
from mailtrace_core.enrichment.dns_lookup import StaticResolver
from mailtrace_core.models import ParsedEmail
from mailtrace_core.parsing import parse_file
from mailtrace_core.util import netguard

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample_emails"
AGENCY_DOMAIN = "examplecounty-sheriff.gov.test"


@pytest.fixture(autouse=True)
def _no_network() -> None:
    """Every test runs with the network choke point closed."""
    netguard.set_offline(True)
    netguard.set_active_enabled(False)
    yield
    netguard.set_offline(False)


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture(scope="session")
def dns_records() -> dict[tuple[str, str], list[str]]:
    raw = json.loads((SAMPLES / "dns_fixtures.json").read_text(encoding="utf-8"))
    out: dict[tuple[str, str], list[str]] = {}
    for key, vals in raw.items():
        rtype, name = key.split(" ", 1)
        out[(name, rtype)] = vals
    return out


@pytest.fixture
def resolver(dns_records: dict[tuple[str, str], list[str]]) -> StaticResolver:
    return StaticResolver(dict(dns_records))


@pytest.fixture
def settings() -> Settings:
    return Settings(agency_domains=[AGENCY_DOMAIN])


@pytest.fixture
def parse_sample(samples_dir: Path, settings: Settings, resolver: StaticResolver):
    def _parse(name: str, *, offline: bool = False) -> ParsedEmail:
        return parse_file(samples_dir / name, settings, None if offline else resolver)

    return _parse
