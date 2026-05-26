"""
uptime_stats.py — Durable uptime counters for long-term reliability.

HealthCheck rows are retained for charts and eventually pruned. These Setting
rows keep a compact lifetime counter so uptime percentage survives pruning.
"""

from __future__ import annotations

from datetime import datetime, timezone

from models.tables import HealthCheck, Setting

KEY_STARTED = "uptime_stats_started_at"
KEY_TOTAL = "uptime_total_checks"
KEY_ONLINE = "uptime_online_checks"
KEY_DEGRADED = "uptime_degraded_checks"
KEY_OFFLINE = "uptime_offline_checks"
KEY_LAST = "uptime_last_checked_at"


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()


def _get(db, key: str, default: str = "") -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default


def _set(db, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def _int(db, key: str) -> int:
    try:
        return int(_get(db, key, "0"))
    except (TypeError, ValueError):
        return 0


def _ensure_initialized(db) -> None:
    if _get(db, KEY_STARTED):
        return

    rows = db.query(HealthCheck).order_by(HealthCheck.id.asc()).all()
    started = rows[0].checked_at if rows else datetime.now(timezone.utc)
    total = len(rows)
    online = sum(1 for r in rows if r.status == "online")
    degraded = sum(1 for r in rows if r.status == "degraded")
    offline = sum(1 for r in rows if r.status == "offline")
    last = rows[-1].checked_at if rows else None

    _set(db, KEY_STARTED, _iso(started))
    _set(db, KEY_TOTAL, str(total))
    _set(db, KEY_ONLINE, str(online))
    _set(db, KEY_DEGRADED, str(degraded))
    _set(db, KEY_OFFLINE, str(offline))
    _set(db, KEY_LAST, _iso(last) if last else "")
    db.flush()


def record_health_check(db, status: str, checked_at: datetime | None = None) -> None:
    """Increment durable uptime counters for one completed health check."""
    _ensure_initialized(db)

    status = (status or "").lower()
    _set(db, KEY_TOTAL, str(_int(db, KEY_TOTAL) + 1))
    if status == "online":
        _set(db, KEY_ONLINE, str(_int(db, KEY_ONLINE) + 1))
    elif status == "degraded":
        _set(db, KEY_DEGRADED, str(_int(db, KEY_DEGRADED) + 1))
    elif status == "offline":
        _set(db, KEY_OFFLINE, str(_int(db, KEY_OFFLINE) + 1))
    _set(db, KEY_LAST, _iso(checked_at))


def get_uptime_stats(db) -> dict:
    """Return tracked lifetime uptime stats, initializing from retained history."""
    _ensure_initialized(db)

    total = _int(db, KEY_TOTAL)
    online = _int(db, KEY_ONLINE)
    degraded = _int(db, KEY_DEGRADED)
    offline = _int(db, KEY_OFFLINE)
    available = online + degraded
    availability_pct = round(available / total * 100, 3) if total else None
    clean_pct = round(online / total * 100, 3) if total else None
    degraded_pct = round(degraded / total * 100, 3) if total else None
    offline_pct = round(offline / total * 100, 3) if total else None

    return {
        "started_at": _get(db, KEY_STARTED) or None,
        "last_checked_at": _get(db, KEY_LAST) or None,
        "total_checks": total,
        "available_checks": available,
        "online_checks": online,
        "degraded_checks": degraded,
        "offline_checks": offline,
        "uptime_pct": availability_pct,
        "availability_pct": availability_pct,
        "clean_uptime_pct": clean_pct,
        "degraded_pct": degraded_pct,
        "offline_pct": offline_pct,
    }
