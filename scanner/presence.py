"""
presence.py — "what's currently on the network" as a merge of recent scans.

A single nmap scan is a poor definition of "current". A quick ping sweep (-sn)
and a full -sV scan find overlapping-but-different host sets, so treating only
the latest scan as the truth makes one scan appear to "forget" the devices the
other just found (and produces "device appeared / no longer responding" churn
when the two alternate). These helpers union every completed scan whose start
time falls within a merge window (the `device_merge_window_s` setting, default
15 minutes) of an anchor scan.

Used by:
  - api/routes.py            — the /api/devices and /api/devices/all lists
  - api/routes.py + scheduler — change-event diffing, so quick/full alternation
                                no longer spams spurious change events

Kept separate from scanner/diff.py on purpose: diff.py stays pure (no ORM/DB)
so it remains trivially testable. Anything that needs the database lives here.
"""

from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc

from models.tables import Scan, ScanDevice, Setting

DEFAULT_MERGE_WINDOW_S = 900.0


def _merge_window_s(db) -> float:
    """Read the configurable merge window, falling back to the 15-minute default."""
    row = db.query(Setting).filter(Setting.key == "device_merge_window_s").first()
    if row and row.value is not None:
        try:
            return float(row.value)
        except (ValueError, TypeError):
            pass
    return DEFAULT_MERGE_WINDOW_S


def window_scan_ids(db, anchor: Optional[Scan]) -> List[int]:
    """
    IDs of every completed scan whose start time is within the merge window
    ending at `anchor` (inclusive). Returns [] for a missing anchor.

    The upper bound (started_at <= anchor.started_at) matters: it lets us build
    the "previous" device set anchored at an earlier scan without the newer scan
    leaking into it.
    """
    if anchor is None:
        return []
    if anchor.started_at is None:
        return [anchor.id]
    cutoff = anchor.started_at - timedelta(seconds=_merge_window_s(db))
    rows = (
        db.query(Scan.id)
        .filter(
            Scan.status == "complete",
            Scan.started_at >= cutoff,
            Scan.started_at <= anchor.started_at,
        )
        .all()
    )
    return [r.id for r in rows]


def current_scan_ids(db) -> Tuple[Optional[Scan], List[int]]:
    """(latest completed scan, [scan ids in its window]) — or (None, []) if none."""
    latest = (
        db.query(Scan).filter(Scan.status == "complete")
        .order_by(desc(Scan.id)).first()
    )
    if not latest:
        return None, []
    return latest, window_scan_ids(db, latest)


def window_snapshot(db, scan_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """
    Build a {device_id: snapshot} dict merged across `scan_ids`, in the shape
    scanner.diff.compute_diff expects.

    The freshest ScanDevice row per device wins for ip / hostname / name. Ports
    use the same fallback the device list uses: the freshest row's ports, or —
    when that row is a ping-only (-sn) scan that recorded none — the most recent
    row anywhere that actually has ports. Without that fallback a quick scan
    would look like every port just closed.
    """
    if not scan_ids:
        return {}

    rows = (
        db.query(ScanDevice)
        .filter(ScanDevice.scan_id.in_(scan_ids))
        .order_by(ScanDevice.id.asc())  # ascending → the freshest row overwrites
        .all()
    )
    freshest: Dict[int, ScanDevice] = {}
    for sd in rows:
        freshest[sd.device_id] = sd

    snapshot: Dict[int, Dict[str, Any]] = {}
    for device_id, sd in freshest.items():
        dev = sd.device
        ports = sd.ports_list
        if not ports:
            last_with_ports = (
                db.query(ScanDevice)
                .filter(
                    ScanDevice.device_id == device_id,
                    ScanDevice.open_ports.notin_(["[]", ""]),
                    ScanDevice.open_ports.isnot(None),
                )
                .order_by(desc(ScanDevice.id))
                .first()
            )
            if last_with_ports:
                ports = last_with_ports.ports_list
        name = dev.label or sd.hostname or sd.ip or f"device-{device_id}"
        snapshot[device_id] = {
            "device_id": device_id,
            "ip":        sd.ip,
            "hostname":  sd.hostname,
            "mac":       dev.mac,
            "ports":     set(ports),
            "name":      name,
        }
    return snapshot
