"""
network/geo.py — Offline IPv4 → country lookup + per-device country history.

Bundled GeoIP via a free, no-auth CSV source (ip-location-db on GitHub). Used
to flag a device suddenly talking to a country it has never reached before —
a strong signal for compromised IoT or unusual app behavior.

Storage:
  data/geo.db (SQLite) — table `ipv4_geo(ip_start_int, ip_end_int, country_code)`
  plus a metadata table tracking last_updated.

Lookup:
  First call to country_for_ip() lazy-loads all ranges into an in-memory
  sorted list and binary-searches it. O(log n) per lookup, ~5MB RAM.

Refresh:
  init_geo_db() downloads only when the local DB is missing or >30 days old.
  Silent on any failure — NetMon works fine without geo data.

Per-device history (DeviceCountryHistory):
  is_unusual_destination()  — True if this device has never reached this country
  record_device_country()   — upsert (first_seen / last_seen / total_bytes)
"""

from __future__ import annotations

import bisect
import csv
import os
import socket
import sqlite3
import struct
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_GEO_DB_PATH  = _PROJECT_ROOT / "data" / "geo.db"
_GEO_URL      = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"
_REFRESH_DAYS = 30
_DOWNLOAD_TIMEOUT_S = 30

_TABLE = "ipv4_geo"
_META  = "metadata"

# Private / loopback / link-local / multicast — integer (start, end) ranges.
_PRIVATE: list[tuple[int, int]] = [
    (167772160,  184549375),    # 10.0.0.0/8
    (2886729728, 2887778303),   # 172.16.0.0/12
    (3232235520, 3232301055),   # 192.168.0.0/16
    (2130706432, 2147483647),   # 127.0.0.0/8 (loopback)
    (2851995648, 2852061183),   # 169.254.0.0/16 (link-local)
    (3758096384, 4026531839),   # 224.0.0.0/4 (multicast)
    (4026531840, 4294967295),   # 240.0.0.0/4 (reserved)
    (0, 16777215),              # 0.0.0.0/8
]

_LOAD_LOCK = threading.Lock()
_CACHE: list[tuple[int, int, str]] | None = None


def _ip_to_int(ip: str) -> int | None:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (OSError, struct.error):
        return None


def _is_private(ip_int: int) -> bool:
    return any(start <= ip_int <= end for start, end in _PRIVATE)


def _connect(path: Path) -> sqlite3.Connection | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(str(path))
    except sqlite3.Error:
        return None


def _last_updated(conn: sqlite3.Connection) -> datetime | None:
    try:
        conn.execute(f"CREATE TABLE IF NOT EXISTS {_META} (key TEXT PRIMARY KEY, value TEXT)")
        cur = conn.execute(f"SELECT value FROM {_META} WHERE key='last_updated'")
        row = cur.fetchone()
        if row and row[0]:
            return datetime.fromisoformat(row[0])
    except sqlite3.Error:
        pass
    return None


def _mark_updated(conn: sqlite3.Connection) -> None:
    try:
        conn.execute(f"CREATE TABLE IF NOT EXISTS {_META} (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(
            f"INSERT OR REPLACE INTO {_META}(key, value) VALUES (?, ?)",
            ("last_updated", datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    except sqlite3.Error:
        pass


def init_geo_db(force: bool = False) -> bool:
    """
    Ensure the local geo database exists and is fresh. Returns True if a
    refresh happened. Safe to call on every startup; only downloads when
    stale. Silent on failure.
    """
    with _LOAD_LOCK:
        conn = _connect(_GEO_DB_PATH)
        if not conn:
            return False
        try:
            updated = _last_updated(conn)
            if not force and updated:
                age_days = (datetime.now(timezone.utc) - updated.replace(tzinfo=timezone.utc) if updated.tzinfo is None else datetime.now(timezone.utc) - updated).days
                if age_days < _REFRESH_DAYS:
                    return False

            try:
                req = urllib.request.Request(_GEO_URL, headers={"User-Agent": "NetMon-Geo/1.0"})
                with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT_S) as resp:
                    csv_text = resp.read().decode("utf-8", errors="replace")
            except Exception as exc:
                print(f"[geo] download failed (non-fatal): {exc}")
                return False

            conn.execute(f"DROP TABLE IF EXISTS {_TABLE}")
            conn.execute(
                f"CREATE TABLE {_TABLE} ("
                "ip_start_int INTEGER PRIMARY KEY, "
                "ip_end_int   INTEGER NOT NULL, "
                "country_code TEXT NOT NULL)"
            )
            conn.commit()

            batch: list[tuple[int, int, str]] = []
            n = 0
            for row in csv.reader(csv_text.splitlines()):
                if len(row) < 3:
                    continue
                try:
                    start_int = int(row[0])
                    end_int   = int(row[1])
                    cc        = row[2].strip().upper()
                except (ValueError, IndexError):
                    continue
                if not cc:
                    continue
                batch.append((start_int, end_int, cc))
                if len(batch) >= 10000:
                    conn.executemany(f"INSERT INTO {_TABLE} VALUES (?, ?, ?)", batch)
                    n += len(batch)
                    batch = []
            if batch:
                conn.executemany(f"INSERT INTO {_TABLE} VALUES (?, ?, ?)", batch)
                n += len(batch)
            conn.commit()
            _mark_updated(conn)

            # Bust in-memory cache so the next lookup reloads.
            global _CACHE
            _CACHE = None
            print(f"[geo] Refreshed GeoIP database — {n} ranges at {_GEO_DB_PATH}")
            return True
        finally:
            conn.close()


def _load_ranges() -> list[tuple[int, int, str]]:
    """Load all ranges sorted by start IP. Empty list on failure."""
    if not _GEO_DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(str(_GEO_DB_PATH))
        try:
            cur = conn.execute(
                f"SELECT ip_start_int, ip_end_int, country_code FROM {_TABLE} ORDER BY ip_start_int"
            )
            return list(cur.fetchall())
        finally:
            conn.close()
    except sqlite3.Error:
        return []


def country_for_ip(ip: str) -> str | None:
    """Return ISO 3166-1 alpha-2 country code for an IPv4 address, or None."""
    ip_int = _ip_to_int(ip)
    if ip_int is None or _is_private(ip_int):
        return None
    global _CACHE
    if _CACHE is None:
        with _LOAD_LOCK:
            if _CACHE is None:
                _CACHE = _load_ranges()
    if not _CACHE:
        return None
    # Binary search the sorted (start, end, cc) list. bisect_right gives us
    # the insertion point for (ip_int + 1,...), so idx-1 is the candidate.
    idx = bisect.bisect_right(_CACHE, (ip_int, float("inf"), "")) - 1
    if 0 <= idx < len(_CACHE):
        start, end, cc = _CACHE[idx]
        if start <= ip_int <= end:
            return cc
    return None


def is_unusual_destination(device_id: int, country: str, db_session) -> bool:
    """True if this device has never had a recorded contact with this country."""
    from models.tables import DeviceCountryHistory
    try:
        existing = (
            db_session.query(DeviceCountryHistory)
            .filter_by(device_id=device_id, country=country)
            .first()
        )
        return existing is None
    except Exception:
        return False


def record_device_country(device_id: int, country: str, db_session, bytes_added: int = 0) -> None:
    """Upsert (device_id, country) history row. Caller commits the session."""
    from models.tables import DeviceCountryHistory
    try:
        now = datetime.now(timezone.utc)
        row = (
            db_session.query(DeviceCountryHistory)
            .filter_by(device_id=device_id, country=country)
            .first()
        )
        if row:
            row.last_seen = now
            row.total_bytes = (row.total_bytes or 0) + bytes_added
        else:
            db_session.add(DeviceCountryHistory(
                device_id=device_id,
                country=country,
                first_seen=now,
                last_seen=now,
                total_bytes=bytes_added,
            ))
    except Exception as exc:
        print(f"[geo] record_device_country error: {exc}")
