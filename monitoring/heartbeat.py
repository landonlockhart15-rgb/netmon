"""
heartbeat.py — Dead-man's-switch ping to an external uptime service.

NetMon's own ntfy alerts are delivered from this PC, so they can't reach the
phone while the home internet is down. An external check (e.g. Healthchecks.io)
flips that around: NetMon pings it every minute, and when the pings stop —
internet down, router hung, PC asleep/crashed, NetMon dead — the *external*
service alerts the phone over cellular in real time.

Configure with HEARTBEAT_URL in .env (or the `heartbeat_url` setting). Unset
means the loop is a no-op. Ping failures are expected during an outage and are
only logged on state change to avoid log spam.
"""

from __future__ import annotations

import os
import urllib.request

from app.database import SessionLocal
from models.tables import Setting

_last_ok: bool | None = None


def get_url() -> str:
    url = (os.getenv("HEARTBEAT_URL") or "").strip()
    if url:
        return url
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "heartbeat_url").first()
        return (row.value or "").strip() if row else ""
    except Exception:
        return ""
    finally:
        db.close()


def ping(url: str | None = None, timeout: float = 10.0) -> bool:
    """Send one heartbeat. Returns True on a 2xx response."""
    global _last_ok
    url = url if url is not None else get_url()
    if not url:
        return False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetMon-heartbeat"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ok = 200 <= resp.status < 300
    except Exception as exc:
        ok = False
        if _last_ok is not False:
            print(f"[heartbeat] ping failed: {exc}")
    if ok and _last_ok is False:
        print("[heartbeat] ping restored")
    _last_ok = ok
    return ok
