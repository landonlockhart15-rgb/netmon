"""
traffic/incident_capture.py — Tag-and-save pcap snippets around anomalies.

When the anomaly loop fires a meaningful event (port scan, traffic spike,
sustained bandwidth, threat-intel hit, geo-anomaly), we extract the most
recent ~5-minute window from the rolling ring buffer into a permanent file
under captures/incidents/. These survive ring rotation so the user can
replay exactly what was on the wire when an incident triggered.

Pipeline:
  ring buffer (.pcapng, rotated)
        │
        ▼
  extract_incident_snippet(anomaly_log_id, device_ip, ...)
        │
        ▼
  captures/incidents/<incident_id>_<anomaly_type>.pcapng
        │ + IncidentCapture row in DB pointing at the file
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

from app.database import SessionLocal
from models.tables import IncidentCapture
from traffic.capture import CAPTURE_DIR
from traffic.analyzer import get_readable_files
from traffic.interfaces import find_tool, _no_window

INCIDENT_DIR = CAPTURE_DIR / "incidents"


def _ensure_dir() -> Path:
    INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
    return INCIDENT_DIR


def _safe_anomaly_type(s: str | None) -> str:
    s = (s or "incident").strip().lower()
    return "".join(c for c in s if c.isalnum() or c in ("_", "-")) or "incident"


def extract_incident_snippet(
    *,
    anomaly_log_id: int | None,
    anomaly_type: str,
    device_ip: str | None = None,
    minutes_back: int = 5,
) -> dict | None:
    """
    Extract the most recent N minutes from the current ring buffer into a
    permanent incident file. Returns the created IncidentCapture row's dict
    (id, file_path, packet_count, size). Returns None on failure.

    Uses editcap to slice by time so the snippet is exact even if multiple
    ring files cover the window.
    """
    editcap = find_tool("editcap")
    if not editcap:
        print("[incident] editcap not found — skipping snippet extraction")
        return None

    files = get_readable_files(CAPTURE_DIR, max_files=10)
    if not files:
        print("[incident] no ring files available — skipping")
        return None

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=minutes_back)
    _ensure_dir()

    out_path = INCIDENT_DIR / (
        f"{now.strftime('%Y%m%d_%H%M%S')}_{_safe_anomaly_type(anomaly_type)}"
        + (f"_{device_ip.replace('.', '_')}" if device_ip else "")
        + ".pcapng"
    )

    # Concatenate ring files into a temp via mergecap, then editcap-slice by time.
    mergecap = find_tool("mergecap")
    intermediate = out_path.with_suffix(".merged.pcapng")
    try:
        if mergecap and len(files) > 1:
            subprocess.run(
                [mergecap, "-w", str(intermediate), *[str(f) for f in files]],
                capture_output=True, text=True, timeout=60,
                creationflags=_no_window(),
            )
            src = intermediate
        else:
            # Single file: just operate on it directly. editcap will copy.
            src = files[-1]

        ts_start = window_start.strftime("%Y-%m-%d %H:%M:%S")
        ts_end   = now.strftime("%Y-%m-%d %H:%M:%S")
        r = subprocess.run(
            [editcap, "-A", ts_start, "-B", ts_end, str(src), str(out_path)],
            capture_output=True, text=True, timeout=60,
            creationflags=_no_window(),
        )
        # editcap returns 0 even when output is empty; check filesize.
    finally:
        if intermediate.exists():
            try:
                intermediate.unlink()
            except OSError:
                pass

    if not out_path.exists() or out_path.stat().st_size == 0:
        # Fall back: copy the most recent ring file whole if slicing produced nothing.
        try:
            shutil.copy2(files[-1], out_path)
        except Exception as exc:
            print(f"[incident] fallback copy failed: {exc}")
            return None

    size = out_path.stat().st_size

    db = SessionLocal()
    try:
        row = IncidentCapture(
            anomaly_log_id  = anomaly_log_id,
            file_path       = str(out_path),
            file_size_bytes = size,
            packet_count    = 0,  # filled lazily by analyzer if needed
            window_start    = window_start,
            window_end      = now,
            anomaly_type    = anomaly_type,
            device_ip       = device_ip,
            summary_json    = json.dumps({"minutes_back": minutes_back}),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        print(f"[incident] saved snippet {out_path.name} ({size} bytes)")
        return {
            "id":           row.id,
            "file_path":    row.file_path,
            "size_bytes":   row.file_size_bytes,
            "anomaly_type": row.anomaly_type,
            "device_ip":    row.device_ip,
        }
    finally:
        db.close()


def prune_old_incidents(retention_days: int = 30) -> int:
    """Delete incident files + DB rows older than retention_days. Returns count."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    deleted = 0
    db = SessionLocal()
    try:
        old = db.query(IncidentCapture).filter(IncidentCapture.created_at < cutoff).all()
        for row in old:
            try:
                Path(row.file_path).unlink(missing_ok=True)
            except Exception:
                pass
            db.delete(row)
            deleted += 1
        db.commit()
    finally:
        db.close()
    return deleted
