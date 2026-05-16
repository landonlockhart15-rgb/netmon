"""
activity.py — Central helper for writing to the ActivityLog table.

Use write_log() from anywhere (routes, scheduler, background threads).
It creates its own DB session so it can safely be called from threads
that have no FastAPI request context.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

LOG_MAX_ROWS  = 10_000
LOG_KEEP_ROWS =  7_500


def write_log(
    level:     str,
    category:  str,
    event:     str,
    summary:   str,
    detail:    str | dict | None = None,
    device_ip: str | None        = None,
    device_id: int | None        = None,
    actor:     str               = "system",
    revert:    dict | None       = None,
) -> int | None:
    """
    Write one ActivityLog entry. Returns the new row id (or None on failure).

    Params:
      level     — "info" | "warning" | "critical" | "action" | "threat"
      category  — "scan" | "traffic" | "ai" | "firewall" | "threat" | "system" | "alert"
      event     — machine-readable name, e.g. "scan_completed", "firewall_blocked"
      summary   — one-line human-readable string shown in the log list
      detail    — optional long text or dict (auto-JSON-encoded if dict)
      device_ip — optional IP of the relevant device
      device_id — optional FK to devices.id
      actor     — who/what triggered this: "user" | "anomaly_auto" | "ai_auto" |
                  "ntfy_command" | "system". Default "system" preserves prior behavior.
      revert    — optional {"action_type": str, "params": dict} payload that
                  POST /api/autonomous-actions/{id}/revert can replay through
                  ai_resolve() to undo this action. None means non-reversible.
    """
    from app.database import SessionLocal
    from models.tables import ActivityLog

    if isinstance(detail, dict):
        detail = json.dumps(detail, default=str)

    revert_json = json.dumps(revert, default=str) if revert else None

    db = SessionLocal()
    try:
        entry = ActivityLog(
            level       = level,
            category    = category,
            event       = event,
            summary     = summary,
            detail      = detail,
            device_ip   = device_ip,
            device_id   = device_id,
            actor       = actor,
            revert_json = revert_json,
        )
        db.add(entry)
        db.commit()
        new_id = entry.id

        # Prune once we exceed the cap (cheap: runs ~1% of the time)
        count = db.query(ActivityLog).count()
        if count > LOG_MAX_ROWS:
            cutoff_id = (
                db.query(ActivityLog.id)
                .order_by(ActivityLog.id.desc())
                .offset(LOG_KEEP_ROWS - 1)
                .limit(1)
                .scalar()
            )
            if cutoff_id:
                db.query(ActivityLog).filter(ActivityLog.id < cutoff_id).delete()
                db.commit()

        return new_id
    except Exception as exc:
        # Never let logging failures crash the caller
        print(f"[activity] write_log failed: {exc}")
        return None
    finally:
        db.close()
