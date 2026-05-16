"""
state.py — Shared mutable runtime state.

Lives in a separate module so both api/routes.py and monitoring/scheduler.py
can read/write it without creating a circular import.

All access is thread-safe (GIL + dict assignment is atomic for simple updates,
but we use a lock for multi-key updates to keep reads consistent).
"""

from __future__ import annotations

import threading

_lock = threading.Lock()

# ── Scan state ────────────────────────────────────────────────────────────────
# Updated by trigger_scan() (manual) and _run_auto_scan() (scheduler).

scan_state: dict = {
    "running":    False,
    "scan_id":    None,       # ID of the most recently *completed* scan
    "started_at": None,       # ISO string, set when scan begins
    "source":     None,       # "manual" | "auto"
    "host_count": None,       # result of last completed scan
    "new_devices": None,
    "changes":    None,
    "error":      None,
}


def scan_begin(source: str, started_at: str) -> None:
    with _lock:
        scan_state["running"]    = True
        scan_state["started_at"] = started_at
        scan_state["source"]     = source
        scan_state["error"]      = None


def scan_end(scan_id: int, host_count: int = 0,
             new_devices: int = 0, changes: int = 0,
             error: str | None = None) -> None:
    with _lock:
        scan_state["running"]     = False
        scan_state["scan_id"]     = scan_id
        scan_state["host_count"]  = host_count
        scan_state["new_devices"] = new_devices
        scan_state["changes"]     = changes
        scan_state["error"]       = error


# ── Immediate scan request flag ───────────────────────────────────────────────
# Set by anomaly detection when a critical event demands an immediate rescan.
# Consumed (cleared) by auto_scan_loop on its next iteration.

_scan_requested = False


def request_immediate_scan() -> None:
    """Signal the scan loop to run a scan immediately on its next wake."""
    global _scan_requested
    with _lock:
        _scan_requested = True


def consume_scan_request() -> bool:
    """Return True and clear the flag if an immediate scan was requested."""
    global _scan_requested
    with _lock:
        if _scan_requested:
            _scan_requested = False
            return True
        return False
