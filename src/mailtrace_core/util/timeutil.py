"""UTC-first time helpers."""

from __future__ import annotations

import email.utils
from datetime import UTC, datetime


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def iso_utc(dt: datetime | None = None) -> str:
    """ISO 8601 with explicit ``Z`` suffix, millisecond precision."""
    dt = (dt or now_utc()).astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_rfc2822(value: str | None) -> datetime | None:
    """Parse an RFC 2822/5322 date. Returns a tz-aware datetime or None.

    A date with no zone is treated as UTC. Trailing comments such as
    ``(PDT)`` are tolerated by the stdlib parser.
    """
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def to_utc(dt: datetime) -> datetime:
    return dt.astimezone(UTC)
