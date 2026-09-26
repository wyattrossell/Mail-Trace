"""Streaming file and bytes hashing."""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK = 1024 * 1024


def hash_bytes(data: bytes) -> tuple[str, str]:
    """Return ``(sha256_hex, md5_hex)`` for an in-memory buffer."""
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()  # noqa: S324


def hash_file(path: Path) -> tuple[str, str]:
    """Return ``(sha256_hex, md5_hex)`` for a file, streaming in 1 MiB chunks.

    MD5 is computed alongside SHA-256 because many agencies and legacy
    evidence systems still cross-reference on MD5.
    """
    sha = hashlib.sha256()
    md5 = hashlib.md5()  # noqa: S324
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()
