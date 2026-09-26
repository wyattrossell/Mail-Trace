"""Installer script, icon asset, and verified update download."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import httpx
import pytest

from mailtrace_core.enrichment.http import HttpClient
from mailtrace_core.updates import (
    ReleaseAsset,
    UpdateCheckResult,
    UpdateDownloadError,
    download_installer,
    installer_asset,
)
from mailtrace_core.util import netguard

ROOT = Path(__file__).resolve().parents[1]


def test_inno_script_replaces_old_shortcuts_and_keeps_app_id() -> None:
    iss = (ROOT / "installer" / "mailtrace.iss").read_text(encoding="utf-8")
    assert re.search(r"AppId=\{\{[0-9A-F-]{36}\}", iss), "fixed AppId is required for in-place upgrades"
    for section in ("[InstallDelete]", "[Icons]", "[UninstallDelete]", "[Files]"):
        assert section in iss
    install_delete = iss.split("[InstallDelete]" + chr(10))[1].split("[Icons]" + chr(10))[0]
    for name in (
        "{userdesktop}\\{#AppName}.lnk",
        "{commondesktop}\\{#AppName}.lnk",
        "{userprograms}\\{#AppName}",
    ):
        assert name in install_delete, name
    assert "CloseApplications=yes" in iss and "PrivilegesRequired=lowest" in iss
    assert "SetupIconFile=..\\assets\\mailtrace.ico" in iss
    assert 'Name: "{autodesktop}\\{#AppName}"' in iss and "Tasks: desktopicon" in iss


def test_icon_asset_has_all_sizes() -> None:
    from PIL import Image

    ico = ROOT / "assets" / "mailtrace.ico"
    assert ico.is_file()
    with Image.open(ico) as im:
        sizes = sorted(im.ico.sizes())
    assert (16, 16) in sizes and (32, 32) in sizes and (256, 256) in sizes


def _result(assets: list[ReleaseAsset]) -> UpdateCheckResult:
    return UpdateCheckResult(
        status="update_available",
        current_version="0.1.0",
        latest_version="0.2.0",
        tag="v0.2.0",
        assets=assets,
        sha256sums={a.name: a.sha256 for a in assets if a.sha256},
    )


def test_installer_asset_selection() -> None:
    zip_a = ReleaseAsset("MailTrace-0.2.0-windows-x64.zip", "https://x/z.zip", 1, "a" * 64)
    setup = ReleaseAsset("MailTrace-Setup-0.2.0.exe", "https://x/setup.exe", 1, "b" * 64)
    assert installer_asset(_result([zip_a, setup])) is setup
    assert installer_asset(_result([zip_a])) is None


def test_download_verifies_hash(tmp_path: Path) -> None:
    netguard.set_offline(False)
    payload = b"MZ" + b"\x00" * 5000
    good = hashlib.sha256(payload).hexdigest()
    setup = ReleaseAsset("MailTrace-Setup-0.2.0.exe", "https://x/setup.exe", len(payload), good)
    http = HttpClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=payload, headers={"content-length": str(len(payload))})
        )
    )
    seen: list[tuple[int, int]] = []
    path = download_installer(
        _result([setup]), tmp_path, http=http, progress=lambda d, t: seen.append((d, t))
    )
    assert path.read_bytes() == payload and path.name == setup.name
    assert seen and seen[-1] == (len(payload), len(payload))


def test_download_refuses_mismatch_missing_hash_and_offline(tmp_path: Path) -> None:
    netguard.set_offline(False)
    payload = b"tampered installer"
    bad = ReleaseAsset("MailTrace-Setup-0.2.0.exe", "https://x/setup.exe", 1, "c" * 64)
    http = HttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=payload)))
    with pytest.raises(UpdateDownloadError, match="SHA-256"):
        download_installer(_result([bad]), tmp_path, http=http)
    assert not (tmp_path / bad.name).exists(), "mismatching download must be deleted"

    no_hash = ReleaseAsset("MailTrace-Setup-0.2.0.exe", "https://x/setup.exe", 1, None)
    with pytest.raises(UpdateDownloadError, match="unverified"):
        download_installer(_result([no_hash]), tmp_path, http=http)
    with pytest.raises(UpdateDownloadError, match="no Windows installer"):
        download_installer(_result([]), tmp_path, http=http)

    netguard.set_offline(True)
    with pytest.raises(UpdateDownloadError, match="offline"):
        download_installer(
            _result([ReleaseAsset("MailTrace-Setup-0.2.0.exe", "https://x/s.exe", 1, "d" * 64)]),
            tmp_path,
            http=http,
        )


def test_download_http_failure_is_clean(tmp_path: Path) -> None:
    netguard.set_offline(False)
    setup = ReleaseAsset("MailTrace-Setup-0.2.0.exe", "https://x/setup.exe", 1, "e" * 64)
    http = HttpClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    with pytest.raises(UpdateDownloadError, match="download failed"):
        download_installer(_result([setup]), tmp_path, http=http)
    assert not (tmp_path / setup.name).exists()
