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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true", help="reuse dist/MailTrace from a previous build")
    ap.add_argument("--out", default=str(ROOT / "release"))
    args = ap.parse_args()

    dist = ROOT / "dist" / "MailTrace"
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

    sums = out / "SHA256SUMS"
    lines = [f"{sha256_of(zip_path)}  {zip_name}"]
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {zip_path} ({zip_path.stat().st_size / 1e6:.1f} MB)")
    print(f"wrote {sums}")
    print(lines[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
