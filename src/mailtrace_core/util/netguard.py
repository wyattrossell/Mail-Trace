"""Single choke point for outbound network activity.

Every module that talks to the network must call :func:`require` first with
the category of the call. Passive categories are allowed unless the operator
has gone offline; active ones raise unless explicitly enabled. Tests call
:func:`set_offline` to make all network use raise.
"""

from __future__ import annotations

import enum
import threading


class NetCategory(enum.StrEnum):
    DNS = "dns"
    RDAP = "rdap"
    WHOIS = "whois"
    GEOIP_API = "geoip_api"
    REPUTATION_API = "reputation_api"
    UPDATE_CHECK = "update_check"
    # Anything below is ACTIVE: it can tip off the adversary or alter evidence.
    URL_FETCH = "url_fetch"
    SENDER_CONNECT = "sender_connect"


PASSIVE = frozenset(
    {
        NetCategory.DNS,
        NetCategory.RDAP,
        NetCategory.WHOIS,
        NetCategory.GEOIP_API,
        NetCategory.REPUTATION_API,
        NetCategory.UPDATE_CHECK,
    }
)


class NetworkBlocked(RuntimeError):
    """Raised when a call would violate the passive-analysis policy."""


_lock = threading.Lock()
_offline = False
_active_enabled = False


def set_offline(flag: bool) -> None:
    global _offline
    with _lock:
        _offline = flag


def set_active_enabled(flag: bool) -> None:
    """Operator opt-in for active categories. Off by default."""
    global _active_enabled
    with _lock:
        _active_enabled = flag


def is_offline() -> bool:
    return _offline


def require(category: NetCategory) -> None:
    """Raise :class:`NetworkBlocked` if this category is not permitted right now."""
    if _offline:
        raise NetworkBlocked(f"offline mode: {category} lookups disabled")
    if category in PASSIVE:
        return
    if not _active_enabled:
        raise NetworkBlocked(
            f"'{category}' is an active technique and is disabled by default. "
            "It can alert the sender and alter evidence."
        )
