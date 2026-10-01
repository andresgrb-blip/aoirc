#!/usr/bin/env python3
"""Build a reproducible Debian package using only the Python standard library."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "0.1.0"


def tar_gz(files: dict[str, tuple[bytes, int]], epoch: int) -> bytes:
    archive = io.BytesIO()
    directories = {"."}
    for name in files:
        directories.update(str(parent) for parent in Path(name).parents)
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(directories):
            entry = tarfile.TarInfo(name if name == "." else f"./{name}")
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            entry.mtime = epoch
            entry.uname = entry.gname = "root"
            tar.addfile(entry)
        for name, (content, mode) in sorted(files.items()):
            entry = tarfile.TarInfo(f"./{name}")
            entry.size = len(content)
            entry.mode = mode
            entry.mtime = epoch
            entry.uname = entry.gname = "root"
            tar.addfile(entry, io.BytesIO(content))
    return gzip.compress(archive.getvalue(), mtime=epoch)


def ar_archive(members: dict[str, bytes]) -> bytes:
    archive = io.BytesIO()
    archive.write(b"!<arch>\n")
    for name, content in members.items():
        # Debian requires short ar names and this exact member order.
        header = (
            f"{name:<16}{0:<12}{0:<6}{0:<6}"
            f"{'100644':<8}{len(content):<10}`\n"
        )
        archive.write(header.encode("ascii"))
        archive.write(content)
        if len(content) % 2:
            archive.write(b"\n")
    return archive.getvalue()


def build_package(output_dir: Path, version: str, epoch: int = 0) -> Path:
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*", version):
        raise ValueError("version must start with a digit and use Debian version characters")
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("SOURCE_DATE_EPOCH must be between 0 and 4294967295")
    files = {
        "usr/bin/aoirc": ((ROOT / "packaging/aoirc").read_bytes(), 0o755),
        "usr/share/aoirc/ui.py": ((ROOT / "ui.py").read_bytes(), 0o644),
        "usr/share/applications/aoirc.desktop": (
            (ROOT / "packaging/aoirc.desktop").read_bytes(), 0o644
        ),
        "usr/share/doc/aoirc/README.md": ((ROOT / "README.md").read_bytes(), 0o644),
    }
    installed_size = sum((len(content) + 1023) // 1024 for content, _ in files.values())
    control = (
        "Package: aoirc\n"
        f"Version: {version}\n"
        "Section: net\n"
        "Priority: optional\n"
        "Architecture: all\n"
        "Maintainer: AOIRC Maintainers <aoirc@localhost>\n"
        f"Installed-Size: {installed_size}\n"
        "Depends: python3 (>= 3.10), python3-tk, ca-certificates\n"
        "Description: Tkinter IRC client with AnonOps-oriented TLS defaults\n"
        " Graphical IRC client with channels, private conversations, user lists\n"
        " and NickServ authentication. Uses TLS with certificate pinning by default.\n"
    ).encode("utf-8")
    checksums = "".join(
        f"{hashlib.md5(content).hexdigest()}  {name}\n"
        for name, (content, _) in sorted(files.items())
    ).encode("ascii")
    package = ar_archive({
        "debian-binary": b"2.0\n",
        "control.tar.gz": tar_gz({
            "control": (control, 0o644), "md5sums": (checksums, 0o644)
        }, epoch),
        "data.tar.gz": tar_gz(files, epoch),
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"aoirc_{version}_all.deb"
    path.write_bytes(package)
    path.with_suffix(".deb.sha256").write_text(
        f"{hashlib.sha256(package).hexdigest()}  {path.name}\n", encoding="ascii"
    )
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
        path = build_package(args.output_dir, args.version, epoch)
    except ValueError as exc:
        parser.error(str(exc))
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
