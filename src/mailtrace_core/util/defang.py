"""Defanging so indicators can be shown and printed without being clickable."""

from __future__ import annotations

import re

_SCHEME_RE = re.compile(r"^(https?|ftp|ftps|sftp|smb|file|mailto|tel|javascript|data)(:)", re.IGNORECASE)


def defang_url(url: str) -> str:
    """``https://evil.example/x`` becomes ``hxxps[:]//evil[.]example/x``.

    Dots are replaced only in the host portion so paths stay readable.
    """
    m = _SCHEME_RE.match(url)
    rest = url
    prefix = ""
    if m:
        scheme = m.group(1).lower()
        if scheme.startswith("http"):
            scheme = "hxxp" + scheme[4:]
        prefix = scheme + "[:]"
        rest = url[m.end() :]
    if rest.startswith("//"):
        prefix += "//"
        rest = rest[2:]
    host_end = len(rest)
    for ch in "/?#":
        idx = rest.find(ch)
        if idx != -1:
            host_end = min(host_end, idx)
    host, tail = rest[:host_end], rest[host_end:]
    host = host.replace(".", "[.]").replace("@", "[@]")
    return prefix + host + tail


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]").replace(":", "[:]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_email(addr: str) -> str:
    return addr.replace("@", "[@]").replace(".", "[.]")
