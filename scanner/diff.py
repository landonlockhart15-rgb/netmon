"""
diff.py — Compares two scan snapshots and returns detected changes.

INPUTS
  prev: dict keyed by device_id → snapshot dict  (previous scan)
  curr: dict keyed by device_id → snapshot dict  (current scan)

  Each snapshot dict has:
    device_id  (int)
    ip         (str | None)
    hostname   (str | None)   — value recorded AT scan time, not current
    mac        (str | None)
    ports      (set[int])
    name       (str)          — best available display name for this device

OUTPUT
  List of change dicts, each to become one ChangeEvent row:
    device_id   (int | None)
    change_type (str)
    message     (str)         — plain English, shown directly in the UI
    detail      (str)         — JSON string with before/after evidence

CHANGE TYPES
  new_device       — device in curr but not in prev
  device_missing   — device in prev but not in curr
  ip_changed       — same device, different IP address
  hostname_changed — same device, different hostname
  ports_changed    — same device, open port set changed

DESIGN DECISIONS
  - Conservative: we only diff devices matched by device_id (identity
    resolution already happened in routes.py when saving ScanDevice records).
    The diff engine does not try to guess identity itself.

  - Deterministic: results are always in the same order (sorted by device_id)
    so repeated runs on the same data produce identical output.

  - Honest about uncertainty: we skip hostname diffs when either side is None
    (nmap couldn't resolve it) rather than reporting a false "hostname changed".
    We also skip port diffs when both sides are empty (nothing to compare).

EDGE CASES AND LIMITATIONS
  - A device that was offline for N scans then returns will appear as
    "new_device" again because it was absent from prev. This is correct
    behaviour: it genuinely wasn't there last scan.

  - Devices without MACs are matched by IP fallback (done in routes.py).
    If a device changes IP *and* has no MAC, it may appear as one device
    going missing and a different device appearing. This is the conservative
    outcome — we'd rather miss a correlation than make a wrong one.

  - nmap sometimes fails to retrieve MAC addresses (requires root/admin on
    Windows, and only works for devices on the same subnet layer). For those
    devices, IP is the only identity anchor.

  - Port scan results can vary slightly between runs (timing, firewall
    state). A port that flickers open/closed is not filtered here — that
    would be a future "stability window" feature.
"""

import json
from typing import Dict, Any, List


def compute_diff(
    prev: Dict[int, Dict[str, Any]],
    curr: Dict[int, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Compare two scan snapshots and return a list of detected changes.

    Args:
        prev: {device_id: snapshot} from the previous completed scan
        curr: {device_id: snapshot} from the current completed scan

    Returns:
        List of change dicts ready to be inserted as ChangeEvent rows.
    """
    prev_ids = set(prev.keys())
    curr_ids = set(curr.keys())
    changes  = []

    # ── 1. New devices (appeared this scan, absent last scan) ─────────────
    for device_id in sorted(curr_ids - prev_ids):
        snap = curr[device_id]
        changes.append({
            "device_id":   device_id,
            "change_type": "new_device",
            "message":     f"{snap['name']} appeared on the network",
            "detail": json.dumps({
                "ip":       snap["ip"],
                "mac":      snap["mac"],
                "hostname": snap["hostname"],
            }),
        })

    # ── 2. Missing devices (were in prev, absent this scan) ───────────────
    for device_id in sorted(prev_ids - curr_ids):
        snap = prev[device_id]
        changes.append({
            "device_id":   device_id,
            "change_type": "device_missing",
            "message":     f"{snap['name']} is no longer responding",
            "detail": json.dumps({
                "last_ip":       snap["ip"],
                "mac":           snap["mac"],
                "last_hostname": snap["hostname"],
            }),
        })

    # ── 3. Devices present in both scans — look for attribute changes ─────
    for device_id in sorted(prev_ids & curr_ids):
        p = prev[device_id]
        c = curr[device_id]
        name = c["name"]

        # IP changed
        # Guard: only report if both sides have a real IP (not None).
        if p["ip"] and c["ip"] and p["ip"] != c["ip"]:
            changes.append({
                "device_id":   device_id,
                "change_type": "ip_changed",
                "message":     f"{name}: IP changed {p['ip']} → {c['ip']}",
                "detail":      json.dumps({"from": p["ip"], "to": c["ip"]}),
            })

        # Hostname changed
        # Guard: only report when BOTH sides have a hostname.
        # If either is None, nmap just couldn't resolve it — not a real change.
        if p["hostname"] and c["hostname"] and p["hostname"] != c["hostname"]:
            changes.append({
                "device_id":   device_id,
                "change_type": "hostname_changed",
                "message":     f"{name}: hostname changed {p['hostname']} → {c['hostname']}",
                "detail":      json.dumps({"from": p["hostname"], "to": c["hostname"]}),
            })

        # Ports changed
        # Guard: skip if both sides are empty (both had no open ports — nothing changed).
        prev_ports = p["ports"]
        curr_ports = c["ports"]
        if prev_ports != curr_ports and (prev_ports or curr_ports):
            opened = sorted(curr_ports - prev_ports)
            closed = sorted(prev_ports - curr_ports)

            parts = []
            if opened:
                parts.append(f"opened {opened}")
            if closed:
                parts.append(f"closed {closed}")

            changes.append({
                "device_id":   device_id,
                "change_type": "ports_changed",
                "message":     f"{name}: {', '.join(parts)}",
                "detail":      json.dumps({
                    "opened":     opened,
                    "closed":     closed,
                    "prev_ports": sorted(prev_ports),
                    "curr_ports": sorted(curr_ports),
                }),
            })

    return changes


def build_snapshot(scan_devices) -> Dict[int, Dict[str, Any]]:
    """
    Convert a list of ScanDevice ORM objects into the plain-dict format
    that compute_diff expects.

    Called in routes.py with both the previous and current scan's devices.

    We extract everything we need here so compute_diff never touches the ORM.
    This keeps the diff logic pure and easy to test without a database.
    """
    snapshot = {}
    for sd in scan_devices:
        dev = sd.device
        # Best display name: user label > hostname snapshot > IP > fallback
        name = dev.label or sd.hostname or sd.ip or f"device-{sd.device_id}"
        snapshot[sd.device_id] = {
            "device_id": sd.device_id,
            "ip":        sd.ip,
            "hostname":  sd.hostname,   # historical snapshot, not dev.hostname
            "mac":       dev.mac,
            "ports":     set(sd.ports_list),
            "name":      name,
        }
    return snapshot
