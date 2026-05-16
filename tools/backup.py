"""
backup.py — Create a zip backup of the NetMon project.

Run this any time you want a snapshot:
  python tools/backup.py

Output (two copies written simultaneously):
  %USERPROFILE%/Documents/NETMON_BACKUP/NETMON_LATEST.zip
  %OneDrive%/NETMON_BACKUP/NETMON_LATEST.zip

Both destinations also receive a BACKUP_INFO.txt with timestamp and file count.

Excludes: .git, .env, runtime databases, captures, uploads, caches, and logs
"""

import zipfile
import datetime
import os
import io
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]

EXCLUDE_DIRS = {"__pycache__", ".git", "node_modules", "data", "security_uploads", "logs"}
EXCLUDE_EXTS = {".pyc", ".pyo"}
EXCLUDE_FILES = {".env"}

BACKUP_FILENAME = "NETMON_LATEST.zip"
BACKUP_SUBDIR   = "NETMON_BACKUP"


def _backup_destinations() -> list[Path]:
    """Return the two backup destination directories, creating them if needed."""
    user_profile = Path(os.environ.get("USERPROFILE", Path.home()))
    onedrive     = Path(os.environ.get("OneDrive",    user_profile / "OneDrive"))

    dirs = [
        user_profile / "Documents" / BACKUP_SUBDIR,
        onedrive     / BACKUP_SUBDIR,
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def make_backup():
    timestamp  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Backing up {SRC} ...")

    # Build zip in memory first so we only traverse once
    buf        = io.BytesIO()
    file_count = 0

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in SRC.rglob("*"):
            # Skip excluded directories
            if any(part in EXCLUDE_DIRS for part in file.parts):
                continue
            # Skip pcapng capture files (can be large, regenerated from capture)
            if file.suffix == ".pcapng":
                continue
            # Skip excluded extensions
            if file.suffix in EXCLUDE_EXTS:
                continue
            if file.name in EXCLUDE_FILES:
                continue
            if "dns_blocker" in file.parts and ".cache" in file.parts:
                continue
            if not file.is_file():
                continue
            # Store relative to parent so zip extracts to netmon\...
            arcname = file.relative_to(SRC.parent)
            zf.write(file, arcname)
            file_count += 1

    zip_bytes = buf.getvalue()
    size_mb   = len(zip_bytes) / 1_048_576

    info_text = (
        f"NetMon Backup\n"
        f"Timestamp : {timestamp}\n"
        f"Source    : {SRC}\n"
        f"Files     : {file_count}\n"
        f"Size      : {size_mb:.1f} MB\n"
    )

    destinations = _backup_destinations()
    for dest_dir in destinations:
        zip_path  = dest_dir / BACKUP_FILENAME
        info_path = dest_dir / "BACKUP_INFO.txt"

        zip_path.write_bytes(zip_bytes)
        info_path.write_text(info_text, encoding="utf-8")
        print(f"  Written: {zip_path}  ({size_mb:.1f} MB, {file_count} files)")

    print(f"Backup complete — {file_count} files, {size_mb:.1f} MB")
    return destinations[0] / BACKUP_FILENAME


if __name__ == "__main__":
    make_backup()
