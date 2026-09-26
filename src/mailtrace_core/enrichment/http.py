"""HTTP access for enrichment providers.

Every request passes through :func:`netguard.require` with the provider's
category, carries a fixed User-Agent, times out quickly, and never follows
a redirect to a host that is not on the provider's own allowlist. Tests
inject an ``httpx.MockTransport`` so no test ever touches the network.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from mailtrace_core.util import netguard

USER_AGENT = "MailTrace/0.1 (passive forensic analysis)"
DEFAULT_TIMEOUT = 10.0


@dataclass(slots=True)
class HttpResponse:
    status: int
    json: Any
    text: str
    headers: dict[str, str]

    @property
    def retry_after(self) -> float:
        try:
            return float(self.headers.get("retry-after", "60"))
        except ValueError:
            return 60.0


class HttpError(RuntimeError):
    pass


class HttpClient:
    def __init__(
        self, transport: httpx.BaseTransport | None = None, timeout: float = DEFAULT_TIMEOUT
    ) -> None:
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        self.requests_made = 0

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        url: str,
        category: netguard.NetCategory,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        data: dict[str, Any] | None = None,
    ) -> HttpResponse:
        """Perform one request. Raises :class:`HttpError` on transport failure."""
        netguard.require(category)
        try:
            resp = self._client.request(
                method, url, params=params, headers=headers, json=json_body, data=data
            )
        except httpx.HTTPError as exc:
            raise HttpError(f"{type(exc).__name__}: {exc}") from exc
        self.requests_made += 1
        body: Any = None
        ctype = resp.headers.get("content-type", "")
        if "json" in ctype or resp.text[:1] in "{[":
            try:
                body = resp.json()
            except ValueError:
                body = None
        return HttpResponse(
            status=resp.status_code,
            json=body,
            text=resp.text,
            headers={k.lower(): v for k, v in resp.headers.items()},
        )

    def download(
        self,
        url: str,
        category: netguard.NetCategory,
        dest: Path,
        progress: Callable[[int, int], None] | None = None,
        headers: dict[str, str] | None = None,
    ) -> int:
        """Stream a file to ``dest``; returns bytes written. Raises :class:`HttpError` on failure."""
        netguard.require(category)
        done = 0
        try:
            with self._client.stream("GET", url, headers=headers) as resp:
                if resp.status_code >= 400:
                    raise HttpError(f"HTTP {resp.status_code}")
                total = int(resp.headers.get("content-length") or 0)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("wb") as fh:
                    for chunk in resp.iter_bytes(1 << 16):
                        fh.write(chunk)
                        done += len(chunk)
                        if progress:
                            progress(done, total)
        except httpx.HTTPError as exc:
            raise HttpError(f"{type(exc).__name__}: {exc}") from exc
        self.requests_made += 1
        return done

    def get(self, url: str, category: netguard.NetCategory, **kw: Any) -> HttpResponse:
        return self.request("GET", url, category, **kw)

    def post(self, url: str, category: netguard.NetCategory, **kw: Any) -> HttpResponse:
        return self.request("POST", url, category, **kw)
