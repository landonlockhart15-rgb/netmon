"""
network/oui.py — Offline MAC-vendor (OUI) lookup.

Bundles a local copy of the IEEE OUI registry so every MAC we see in a scan
gets a manufacturer label even when nmap couldn't resolve one. Works fully
offline after one initial download; refreshes once a month in the background.

Storage:
  data/oui.db (SQLite)  — single indexed table `oui(prefix TEXT PK, vendor TEXT)`
  ~30k rows, ~3MB on disk.

Lookup:
  First call populates an in-memory dict from SQLite.
  Subsequent calls hit the dict (sub-microsecond).
  Thread-safe (dict reads are atomic; the dict is never mutated after load).

Refresh:
  init_oui_db() is safe to call repeatedly. It downloads only if the file is
  missing or older than 30 days. Failure is silent — the rest of the app
  works without an OUI DB; vendor just shows as "unknown" for new MACs.

Source:
  https://standards-oui.ieee.org/oui/oui.csv  (public, no auth, no license fee)
"""

from __future__ import annotations

import csv
import io
import os
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUI_URL          = "https://standards-oui.ieee.org/oui/oui.csv"
_PROJECT_ROOT    = Path(__file__).resolve().parent.parent
_OUI_DB_PATH     = _PROJECT_ROOT / "data" / "oui.db"
_REFRESH_DAYS    = 30
_DOWNLOAD_TIMEOUT_S = 30

_LOAD_LOCK: threading.Lock = threading.Lock()
_CACHE: dict[str, str] | None = None


def _normalize_prefix(mac: str) -> str:
    """Return the canonical 6-hex OUI prefix from any MAC representation."""
    if not mac:
        return ""
    cleaned = "".join(c for c in mac if c.isalnum()).upper()
    return cleaned[:6]


def _is_stale(path: Path) -> bool:
    if not path.exists():
        return True
    age_days = (time.time() - path.stat().st_mtime) / 86400.0
    return age_days > _REFRESH_DAYS


def _populate_from_csv(csv_text: str, db_path: Path) -> int:
    """Parse the IEEE oui.csv body and (re)populate the SQLite table. Returns row count."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str]] = []
    reader = csv.reader(io.StringIO(csv_text))
    header = next(reader, None)
    # Expected columns: Registry, Assignment, Organization Name, Organization Address
    # We only need Assignment + Organization Name.
    org_idx = 2
    asg_idx = 1
    if header:
        try:
            org_idx = header.index("Organization Name")
            asg_idx = header.index("Assignment")
        except ValueError:
            pass
    for row in reader:
        if len(row) <= max(org_idx, asg_idx):
            continue
        prefix = (row[asg_idx] or "").strip().upper()
        vendor = (row[org_idx] or "").strip()
        if len(prefix) == 6 and vendor:
            rows.append((prefix, vendor))

    if not rows:
        return 0

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS oui (prefix TEXT PRIMARY KEY, vendor TEXT NOT NULL)")
        conn.execute("DELETE FROM oui")
        conn.executemany("INSERT OR REPLACE INTO oui(prefix, vendor) VALUES (?, ?)", rows)
        conn.commit()
    finally:
        conn.close()
    return len(rows)


def init_oui_db(force: bool = False, db_path: Path | None = None) -> bool:
    """
    Ensure the local OUI database exists and is fresh. Returns True if a
    refresh happened, False if the existing copy is fine. Safe to call on
    every startup; only downloads when stale.
    """
    path = Path(db_path) if db_path else _OUI_DB_PATH
    if not force and not _is_stale(path):
        return False
    try:
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "NetMon-OUI/1.0"})
        with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT_S) as resp:
            csv_text = resp.read().decode("utf-8", errors="replace")
        count = _populate_from_csv(csv_text, path)
        print(f"[oui] Refreshed OUI database — {count} entries at {path}")
        # Bust the in-memory cache so the next lookup re-loads.
        global _CACHE
        with _LOAD_LOCK:
            _CACHE = None
        return True
    except Exception as exc:
        print(f"[oui] Refresh failed (non-fatal): {exc}")
        return False


def _load_cache(db_path: Path) -> dict[str, str]:
    """Read the entire OUI table into a dict (cheap — <5MB, ~30k rows)."""
    if not db_path.exists():
        return {}
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.execute("SELECT prefix, vendor FROM oui")
        return {p: v for p, v in cur.fetchall()}
    finally:
        conn.close()


def lookup_vendor(mac: str) -> str | None:
    """
    Resolve a MAC address to a manufacturer name. Returns None if the OUI is
    unknown or the database hasn't been populated yet. Sub-microsecond after
    the first call.
    """
    prefix = _normalize_prefix(mac)
    if len(prefix) != 6:
        return None
    global _CACHE
    if _CACHE is None:
        with _LOAD_LOCK:
            if _CACHE is None:
                _CACHE = _load_cache(_OUI_DB_PATH)
    return _CACHE.get(prefix) or None


def enrich_vendor(mac: str, current: str | None) -> str | None:
    """
    Return the best-known vendor for a MAC:
      - If `current` looks meaningful (not empty, not "unknown") → keep it.
      - Otherwise → fall back to the OUI database.
    """
    if current and current.strip().lower() not in ("", "unknown"):
        return current
    return lookup_vendor(mac)
