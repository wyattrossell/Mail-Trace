"""Build the Windows release: PyInstaller folder -> zip -> SHA256SUMS.

Usage (from the repository root, inside the project environment)::

    python scripts/build_release.py [--skip-build]

Produces ``release/MailTrace-<version>-windows-x64.zip`` and
``release/SHA256SUMS`` (sha256sum format, verifiable with
``certutil -hashfile <file> SHA256`` or ``sha256sum -c``).
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mailtrace_core import __version__  # noqa: E402


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


ISCC_CANDIDATES = (
    Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
    Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
    Path.home() / "AppData" / "Local" / "Programs" / "Inno Setup 6" / "ISCC.exe",
)


def find_iscc() -> Path | None:
    import os

    env = os.environ.get("ISCC")
    if env and Path(env).is_file():
        return Path(env)
    return next((c for c in ISCC_CANDIDATES if c.is_file()), None)


def write_version_info(path: Path) -> None:
    """PyInstaller version resource so Explorer shows the product version on the .exe."""
    parts = [int(x) for x in __version__.split(".")[:3]] + [0]
    tup = ", ".join(str(x) for x in parts[:4])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "VSVersionInfo(\n"
        f"  ffi=FixedFileInfo(filevers=({tup}), prodvers=({tup}), mask=0x3f, flags=0x0, OS=0x40004, "
        "fileType=0x1, subtype=0x0, date=(0, 0)),\n"
        "  kids=[StringFileInfo([StringTable('040904B0', [\n"
        "    StringStruct('CompanyName', 'MailTrace'),\n"
        "    StringStruct('FileDescription', 'MailTrace passive forensic email analysis'),\n"
        f"    StringStruct('FileVersion', '{__version__}'),\n"
        "    StringStruct('ProductName', 'MailTrace'),\n"
        f"    StringStruct('ProductVersion', '{__version__}'),\n"
        "    StringStruct('LegalCopyright', 'MailTrace authors')])]),\n"
        "  VarFileInfo([VarStruct('Translation', [1033, 1200])])])\n",
        encoding="utf-8",
    )


def build_installer(out: Path) -> Path | None:
    iscc = find_iscc()
    if iscc is None:
        print("Inno Setup (ISCC.exe) not found; skipping installer build", file=sys.stderr)
        return None
    subprocess.run(
        [str(iscc), f"/DAppVersion={__version__}", f"/O{out}", str(ROOT / "installer" / "mailtrace.iss")],
        check=True,
        cwd=ROOT,
    )
    setup = out / f"MailTrace-Setup-{__version__}.exe"
    return setup if setup.exists() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true", help="reuse dist/MailTrace from a previous build")
    ap.add_argument("--out", default=str(ROOT / "release"))
    args = ap.parse_args()

    dist = ROOT / "dist" / "MailTrace"
    if not (ROOT / "assets" / "mailtrace.ico").exists():
        subprocess.run([sys.executable, str(ROOT / "assets" / "make_icon.py")], check=True, cwd=ROOT)
    write_version_info(ROOT / "build" / "version_info.txt")
    if not args.skip_build:
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", str(ROOT / "mailtrace.spec"), "--noconfirm", "--clean"],
            check=True,
            cwd=ROOT,
        )
    if not (dist / "MailTrace.exe").exists() or not (dist / "mailtrace-cli.exe").exists():
        print("build did not produce both executables in dist/MailTrace", file=sys.stderr)
        return 1

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    zip_name = f"MailTrace-{__version__}-windows-x64.zip"
    zip_path = out / zip_name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for p in sorted(dist.rglob("*")):
            if p.is_file():
                zf.write(p, Path("MailTrace") / p.relative_to(dist))
        for extra in ("README.md", "LICENSE", "docs/methodology.md"):
            src = ROOT / extra
            if src.exists():
                zf.write(src, Path("MailTrace") / Path(extra).name)

    setup = build_installer(out)
    sums = out / "SHA256SUMS"
    lines = [f"{sha256_of(zip_path)}  {zip_name}"]
    if setup is not None:
        lines.append(f"{sha256_of(setup)}  {setup.name}")
        print(f"wrote {setup} ({setup.stat().st_size / 1e6:.1f} MB)")
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {zip_path} ({zip_path.stat().st_size / 1e6:.1f} MB)")
    print(f"wrote {sums}")
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
