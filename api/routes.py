"""
routes.py — All FastAPI route handlers.

Endpoints:
  POST /api/scan                    Trigger nmap scan
  GET  /api/devices                 Devices from latest scan
  GET  /api/devices/all             All known devices (for device management)
  PATCH /api/device/{id}            Update device label / trust status
  GET  /api/scans                   Scan history
  GET  /api/diff/latest             Change events from latest scan
  GET  /api/device/{id}/history     Device scan history
  GET  /api/health/current          Latest health check result
  GET  /api/health/history          Recent health checks for the chart
  POST /api/health/check            Run an immediate health check
  POST /api/speed/test              Run an on-demand speed test (slow ~10s)
  GET  /api/speed/latest            Latest speed test result
  GET  /api/settings                All current settings as a dict
  POST /api/settings                Update one or more settings
  GET  /api/telemetry               Live CPU/memory of this process
  GET  /api/alerts                  Recent alerts with unread count
  POST /api/alerts/{id}/read        Mark one alert as read
  POST /api/alerts/read-all         Mark all alerts as read
  GET  /api/export/devices.csv      Download device list as CSV
  GET  /api/export/scans.csv        Download scan history as CSV
  POST /api/ai/analyze              Start AI analysis (background)
  GET  /api/ai/latest               Latest AI summary
  GET  /api/traffic/interfaces      List capture interfaces (dumpcap -D)
  GET  /api/traffic/status          Current capture engine status
  POST /api/traffic/start           Start ring-buffer capture
  POST /api/traffic/stop            Stop capture
  GET  /api/traffic/summary         Latest traffic analysis summary
  GET  /api/traffic/history         Recent traffic summaries (chart data)
"""

import json
import os
import threading
import uuid
import psutil
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database import get_db
from models.tables import (
    Scan, Device, ScanDevice, Alert, ChangeEvent,
    HealthCheck, SpeedTest, Setting, AISummary,
    CaptureSession, TrafficSummary, ActivityLog,
    SecurityToolRun, SecurityToolOutputChunk, SecurityAIExplanation, SecurityFile,
)
from fastapi import UploadFile, File, Form
import hashlib
from monitoring.activity import write_log
from network.protection import explain_protected_target, filter_blockable_ips, validate_block_target
from scanner.runner import run_scan
from scanner.parser import parse_nmap_xml
from scanner.diff import compute_diff, build_snapshot
from scanner.presence import current_scan_ids, window_scan_ids, window_snapshot

router = APIRouter()

# In-memory store for focused packet capture jobs {capture_id → state dict}
_deep_captures: dict = {}


def _iso(dt) -> str | None:
    """Return an ISO-8601 string with explicit UTC offset so browsers parse correctly."""
    if dt is None:
        return None
    s = dt.isoformat()
    # SQLite returns naive datetimes — append Z if no offset present
    if "+" not in s and s[-1] != "Z":
        s += "Z"
    return s


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS  (shared across routes)
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_device(db: Session, d: dict):
    """Find or create the Device row for a parsed nmap host. Returns (device, is_new)."""
    existing = None

    mac = d["mac"].lower() if d["mac"] else None
    if mac:
        existing = db.query(Device).filter(Device.mac == mac).first()

    if existing is None and d["ip"]:
        prev_sd = (
            db.query(ScanDevice)
            .join(Device)
            .filter(ScanDevice.ip == d["ip"])
            .filter(Device.mac == None)
            .order_by(desc(ScanDevice.id))
            .first()
        )
        if prev_sd:
            existing = prev_sd.device

    # Vendor enrichment via offline OUI database — fills in the gap when nmap
    # didn't return a manufacturer (very common when the device is more than
    # one hop away or has randomized MACs disabled).
    from network.oui import enrich_vendor
    enriched_vendor = enrich_vendor(mac or "", d.get("vendor"))

    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        if d["hostname"]: existing.hostname = d["hostname"]
        if enriched_vendor and not existing.vendor:
            existing.vendor = enriched_vendor
        elif d["vendor"]:
            existing.vendor = d["vendor"]
        return existing, False
    else:
        device = Device(mac=mac, vendor=enriched_vendor or d["vendor"], hostname=d["hostname"])
        db.add(device)
        db.flush()
        return device, True


def _get_setting_str(db: Session, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if (row and row.value is not None) else default


def _get_setting_float(db: Session, key: str, default: float) -> float:
    try:
        return float(_get_setting_str(db, key, str(default)))
    except (ValueError, TypeError):
        return default


def _json_list(value: str | None) -> list:
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _gateway_ip(db: Session) -> str:
    gateway = ""
    try:
        from network.autodetect import get_network_info
        gateway = get_network_info().get("gateway") or ""
    except Exception:
        pass
    return _get_setting_str(db, "autoheal_router_host", "") or gateway or "192.168.1.1"


def _router_creds(db: Session) -> dict:
    """Shared admin credentials for talking to the router's SOAP API — the
    same ones the Uptime Guardian uses to reboot it on outage."""
    return {
        "host": _gateway_ip(db),
        "user": _get_setting_str(db, "autoheal_router_user", "admin"),
        "password": os.getenv("ROUTER_PASS") or _get_setting_str(db, "autoheal_router_pass", ""),
        "use_ssl": _get_setting_str(db, "autoheal_router_ssl", "false").lower() == "true",
        "port": int(_get_setting_str(db, "autoheal_router_port", "") or 0) or None,
    }


def _latest_scan_device_with_cves(db: Session, device_id: int):
    """
    The authoritative row for "what CVEs does this device have right now."

    This is the most recent scan that actually ran service detection (a real
    -sV pass, not a quick ping-only sweep) — and its cves_json is trusted as-is,
    EMPTY INCLUDED. A previous version of this query skipped rows with an
    empty cves_json and kept walking backward for an older row that had
    findings, which meant a fixed vulnerability stayed "found" forever because
    the function refused to believe a clean scan. Quick scans (services_json
    empty) are skipped since they never ran the CVE matcher at all and would
    otherwise look like "everything's fine" between deep scans.
    """
    return (
        db.query(ScanDevice)
        .filter(
            ScanDevice.device_id == device_id,
            ScanDevice.services_json.notin_(["[]", ""]),
            ScanDevice.services_json.isnot(None),
        )
        .order_by(desc(ScanDevice.id))
        .first()
    )


def _risk_rank(risk) -> int:
    if not isinstance(risk, str):
        return 0
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(risk.lower(), 0)


_IOT_TERMS = ("iot", "camera", "cam", "bulb", "plug", "sensor", "thermostat", "tuya", "kasa", "wyze", "ring", "nest", "echo", "alexa", "printer", "roku", "tv")
_HIGH_VALUE_TERMS = ("nas", "work", "pc", "desktop", "laptop", "server", "synology", "qnap", "truenas", "freenas", "windows", "macbook", "imac")
_ADMIN_PORTS = {22, 23, 80, 443, 8080, 8443, 8000, 8888}
_TARGET_PORTS = {22, 445, 548, 3389, 5000, 5001, 5900, 8080, 8443}


def _device_text(dev: Device, sd: ScanDevice | None) -> str:
    return " ".join([
        dev.label or "", dev.hostname or "", dev.vendor or "", dev.os_guess or "",
        (sd.hostname or "") if sd else "",
    ]).lower()


def _device_name(dev: Device, sd: ScanDevice | None) -> str:
    return dev.label or (sd.hostname if sd else None) or dev.hostname or (sd.ip if sd else None) or f"Device #{dev.id}"


def _port_set(sd: ScanDevice | None) -> set[int]:
    ports = _json_list(sd.open_ports) if sd else []
    return {int(p) for p in ports if str(p).isdigit()}


def _latest_scan_device(db: Session, device_id: int):
    return (
        db.query(ScanDevice)
        .filter(ScanDevice.device_id == device_id)
        .order_by(desc(ScanDevice.id))
        .first()
    )


def _remediation_for(dev: Device, ip: str | None, gateway: str) -> dict:
    """
    How to fix this finding. Two kinds:
      - "firmware": NetMon can check/install a fix itself via the router's
        own update API (Netgear Orbi system — router + satellites are
        patched together by one "update all" action).
      - "manual": no API NetMon can drive; point at the device's own admin
        page and let the AI explain what to click once there.
    """
    text = " ".join([dev.label or "", dev.vendor or "", dev.hostname or ""]).lower()
    is_orbi_system = (ip == gateway) or ("orbi" in text) or ("netgear" in text and "router" in text)
    if is_orbi_system:
        return {"type": "firmware", "vendor": "netgear_orbi"}
    return {"type": "manual", "admin_url": f"http://{ip or gateway}/"}


def _attack_tree_device_summary(db: Session, dev: Device) -> dict:
    sd = _latest_scan_device(db, dev.id)
    cve_row = _latest_scan_device_with_cves(db, dev.id)
    cves = _json_list(cve_row.cves_json) if cve_row else []
    severe_cves = [v for v in cves if isinstance(v, dict) and _risk_rank(v.get("risk")) >= 3]
    ports = _port_set(sd)
    text = _device_text(dev, sd)
    iot_signals = [term for term in _IOT_TERMS if term in text]
    target_signals = [term for term in _HIGH_VALUE_TERMS if term in text]
    source_score = 0
    if iot_signals:
        source_score += 3
    if not dev.is_known:
        source_score += 2
    source_score += min(len(ports & _ADMIN_PORTS), 2)
    source_score += min(len(severe_cves), 3)

    target_score = 0
    if target_signals:
        target_score += 4
    target_score += min(len(ports & _TARGET_PORTS), 4)
    target_score += min(len(severe_cves), 2)

    return {
        "device": dev,
        "scan_device": sd,
        "name": _device_name(dev, sd),
        "ip": sd.ip if sd else None,
        "ports": sorted(ports),
        "cves": cves,
        "has_cve_evidence": bool(severe_cves),
        "iot_signals": iot_signals[:3],
        "target_signals": target_signals[:3],
        "source_score": source_score,
        "target_score": target_score,
    }


def _attack_risk(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _attack_step_reasons(summary: dict, source: bool) -> list[str]:
    reasons = []
    if source and summary["iot_signals"]:
        reasons.append("IoT-like identity: " + ", ".join(summary["iot_signals"]))
    if (not source) and summary["target_signals"]:
        reasons.append("High-value identity: " + ", ".join(summary["target_signals"]))
    if source and not summary["device"].is_known:
        reasons.append("Device is not trusted yet")
    interesting_ports = sorted(set(summary["ports"]) & (_ADMIN_PORTS if source else _TARGET_PORTS))
    if interesting_ports:
        reasons.append("Relevant open ports: " + ", ".join(str(p) for p in interesting_ports[:5]))
    severe = [v for v in summary["cves"] if _risk_rank(v.get("risk")) >= 3]
    if severe:
        reasons.append("High-risk CVE evidence: " + ", ".join(v.get("cve", "CVE") for v in severe[:3]))
    return reasons


# ═════════════════════════════════════════════════════════════════════════════
# SCAN  (unchanged from Phase 3)
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/status")
def get_runtime_status():
    """
    Lightweight polling endpoint — returns what's actively running right now.
    Called every 5 seconds by the frontend to drive live indicators and auto-refresh.
    """
    from monitoring.state import scan_state
    from traffic.capture import capture_engine
    from ai.provider import progress_snapshot

    prog = progress_snapshot()
    ai_running = prog.get("status") == "running"

    cap = capture_engine.get_status()

    return {
        "scan":    dict(scan_state),
        "ai":      {"running": ai_running, "kind": prog.get("kind"), "chars": prog.get("chars", 0)},
        "capture": {"running": bool(cap.get("running"))},
    }


@router.post("/api/scan")
def trigger_scan(body: dict = None, db: Session = Depends(get_db)):
    body = body or {}
    quick = bool(body.get("quick", False))
    from monitoring.state import scan_begin, scan_end

    try:
        from network.autodetect import get_scan_target
        target = get_scan_target()
    except Exception:
        target = os.getenv("SCAN_TARGET", "").strip()
        if target.lower() in ("", "auto", "autodetect", "detect"):
            target = "192.168.1.0/24"
    print(f"[scan] manual scan target: {target}")
    started_at = datetime.now(timezone.utc)

    scan_begin("manual", started_at.isoformat())

    scan = Scan(started_at=started_at, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # vulners is a deep-scan-only enrichment (CVE mapping via the nmap NSE
    # script). It needs internet and adds time per host, so it is opt-in: the
    # request can force it, otherwise we honor the persisted setting. Quick ping
    # sweeps never run it.
    vulners = False
    if not quick:
        if "vulners" in body:
            vulners = bool(body.get("vulners"))
        else:
            _vs = db.query(Setting).filter(Setting.key == "vulners_enabled").first()
            vulners = bool(_vs and _vs.value == "true")

    try:
        xml_output     = run_scan(target, quick=quick, vulners=vulners)
        parsed_devices = parse_nmap_xml(xml_output)

        new_device_count = 0
        for d in parsed_devices:
            device, is_new = _resolve_device(db, d)
            if is_new and not device.is_known:
                # Only alert for genuinely unknown new devices.
                # If is_known=True it was pre-approved (e.g. imported/pre-labeled).
                new_device_count += 1
                db.add(Alert(
                    alert_type="new_device",
                    message=f"New device: {d.get('hostname') or d['ip']} (MAC: {d['mac'] or 'unknown'})",
                    device_id=device.id,
                ))
            db.add(ScanDevice(
                scan_id=scan.id, device_id=device.id,
                ip=d["ip"], hostname=d["hostname"],
                open_ports=json.dumps(d["open_ports"]),
                services_json=json.dumps(d.get("services") or []),
                cves_json=json.dumps(d.get("vulnerabilities") or []),
            ))

        ended_at   = datetime.now(timezone.utc)
        duration   = (ended_at - started_at).total_seconds()
        scan.ended_at   = ended_at
        scan.duration_s = duration
        scan.host_count = len(parsed_devices)
        scan.status     = "complete"
        db.commit()

        prev_scan = (
            db.query(Scan)
            .filter(Scan.status == "complete", Scan.id != scan.id)
            .order_by(desc(Scan.id)).first()
        )
        change_count = 0
        if prev_scan:
            # Diff merged windows, not single scans, so quick/full alternation
            # doesn't fire spurious "appeared / no longer responding" events.
            # The current window includes this scan; the previous window is
            # anchored at prev_scan, so the new scan can't leak into it.
            changes = compute_diff(
                window_snapshot(db, window_scan_ids(db, prev_scan)),
                window_snapshot(db, window_scan_ids(db, scan)),
            )
            change_count = len(changes)
            for ch in changes:
                db.add(ChangeEvent(scan_id=scan.id, prev_scan_id=prev_scan.id, **ch))
            db.commit()

        # Auto-analyze with AI if enabled — runs in a background thread
        # so the scan result is returned immediately without waiting for the AI.
        ai_auto = _get_setting_str(db, "ai_auto_analyze", "false").lower()
        ai_on   = _get_setting_str(db, "ai_enabled",      "false").lower()
        if ai_on == "true" and ai_auto == "true":
            import threading
            from app.database import SessionLocal
            from ai.analyst import run_analysis
            def _auto_analyze():
                thread_db = SessionLocal()
                try:
                    run_analysis(thread_db, scan_id=scan.id)
                except Exception as e:
                    print(f"[ai] Auto-analyze error: {e}")
                finally:
                    thread_db.close()
            threading.Thread(target=_auto_analyze, daemon=True).start()

        scan_end(scan.id, len(parsed_devices), new_device_count, change_count)
        write_log(
            "info", "scan", "scan_completed",
            f"Manual scan — {len(parsed_devices)} device(s), {new_device_count} new, {change_count} change(s) [{round(duration,1)}s]",
            detail={"scan_id": scan.id, "hosts": len(parsed_devices),
                    "new_devices": new_device_count, "changes": change_count,
                    "duration_s": round(duration, 1), "triggered_by": "user"},
        )
        return {
            "scan_id": scan.id, "host_count": len(parsed_devices),
            "new_devices": new_device_count, "changes": change_count,
            "duration_s": round(duration, 1), "status": "complete",
        }

    except Exception as e:
        scan_end(scan.id if scan else 0, error=str(e))
        write_log("warning", "scan", "scan_failed", f"Manual scan failed: {e}")
        scan.status = "failed"
        scan.error  = str(e)
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices")
def get_devices(db: Session = Depends(get_db)):
    latest_scan, scan_ids = current_scan_ids(db)
    if not latest_scan:
        return {"scan": None, "devices": []}

    # Union ScanDevice rows across every scan in the merge window, keeping only
    # the freshest row per device (highest id wins). This is what stops a full
    # scan from "forgetting" devices a quick scan just found — and vice-versa —
    # when the two run back-to-back. See scanner.presence for the windowing.
    scan_devices = (
        db.query(ScanDevice)
        .filter(ScanDevice.scan_id.in_(scan_ids))
        .order_by(desc(ScanDevice.id))
        .all()
    )
    seen_device_ids = set()
    devices = []
    for sd in scan_devices:
        if sd.device_id in seen_device_ids:
            continue
        seen_device_ids.add(sd.device_id)
        dev = sd.device
        # Hourly auto-scan uses -sn (no ports), so sd.ports_list is empty for
        # most rows. Fall back to the most recent ScanDevice that actually has
        # port data — same approach as /api/devices/all. Without this, every
        # device shows 0 open ports between deep scans.
        ports = sd.ports_list
        if not ports:
            last_with_ports = (
                db.query(ScanDevice)
                .filter(
                    ScanDevice.device_id == dev.id,
                    ScanDevice.open_ports.notin_(["[]", ""]),
                    ScanDevice.open_ports.isnot(None),
                )
                .order_by(desc(ScanDevice.id))
                .first()
            )
            if last_with_ports:
                ports = last_with_ports.ports_list
        cve_row = _latest_scan_device_with_cves(db, dev.id)
        vulnerabilities = cve_row.cves_list if cve_row else []
        devices.append({
            "ip": sd.ip, "mac": dev.mac or "unknown",
            "vendor": dev.vendor or "unknown",
            "hostname": sd.hostname or dev.hostname or "",
            "label": dev.label or "", "open_ports": ports,
            "vulnerability_count": len(vulnerabilities),
            "max_cve_risk": max((v.get("risk") for v in vulnerabilities), key=_risk_rank, default=None),
            "os_guess": dev.os_guess or "",
            "first_seen": _iso(dev.first_seen),
            "last_seen":  _iso(dev.last_seen)  if dev.last_seen  else None,
            "is_known": dev.is_known, "device_id": dev.id,
        })
    return {
        "scan": {
            "id": latest_scan.id,
            "started_at": _iso(latest_scan.started_at),
            "duration_s": latest_scan.duration_s,
            # Merged count across the window, not just the latest scan, so the
            # number matches the device list we actually return.
            "host_count": len(devices),
        },
        "devices": sorted(devices, key=lambda d: d["ip"] or ""),
    }


@router.get("/api/scans")
def get_scan_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.id)).limit(50).all()
    return [
        {
            "id": s.id,
            "started_at": _iso(s.started_at),
            "duration_s": s.duration_s, "host_count": s.host_count,
            "status": s.status, "error": s.error,
        }
        for s in scans
    ]


@router.get("/api/diff/latest")
def get_latest_diff(db: Session = Depends(get_db)):
    latest_scan = (
        db.query(Scan).filter(Scan.status == "complete")
        .order_by(desc(Scan.id)).first()
    )
    if not latest_scan:
        return {"scan_id": None, "prev_scan_id": None, "change_count": 0, "changes": []}

    events = db.query(ChangeEvent).filter(ChangeEvent.scan_id == latest_scan.id).order_by(ChangeEvent.id).all()
    prev_scan_id = events[0].prev_scan_id if events else None
    return {
        "scan_id": latest_scan.id, "prev_scan_id": prev_scan_id,
        "change_count": len(events),
        "changes": [
            {
                "id": c.id, "change_type": c.change_type, "message": c.message,
                "detail": json.loads(c.detail or "{}"),
                "device_id": c.device_id,
                "created_at": _iso(c.created_at),
            }
            for c in events
        ],
    }


@router.get("/api/devices/all")
def get_all_devices(current_only: bool = False, db: Session = Depends(get_db)):
    """
    Return known devices. current_only=true filters to devices seen in the
    most recent completed scan only.
    Used by the Devices section for device management (labelling, trust, history).
    """
    from sqlalchemy import func

    if current_only:
        # "Current" = devices seen in any completed scan within the merge window
        # (not just the single latest scan), so a quick scan and a full scan run
        # back-to-back don't drop each other's devices. See scanner.presence.
        last_scan, scan_ids = current_scan_ids(db)
        if last_scan:
            current_device_ids = (
                db.query(ScanDevice.device_id)
                .filter(ScanDevice.scan_id.in_(scan_ids))
                .subquery()
            )
            devices = (
                db.query(Device)
                .filter(Device.id.in_(current_device_ids))
                .order_by(desc(Device.last_seen))
                .all()
            )
        else:
            devices = []
    else:
        devices = db.query(Device).order_by(desc(Device.last_seen)).all()
    result = []
    for dev in devices:
        # Most recent scan entry — used for latest IP
        latest_sd = (
            db.query(ScanDevice)
            .filter(ScanDevice.device_id == dev.id)
            .order_by(desc(ScanDevice.id))
            .first()
        )
        # Most recent scan entry that actually has port data — hourly quick scans
        # (-sn ping-only) record no ports, so we look back for the last full scan.
        latest_sd_ports = (
            db.query(ScanDevice)
            .filter(
                ScanDevice.device_id == dev.id,
                ScanDevice.open_ports.notin_(["[]", ""]),
                ScanDevice.open_ports.isnot(None),
            )
            .order_by(desc(ScanDevice.id))
            .first()
        )
        scan_count = (
            db.query(func.count(ScanDevice.id))
            .filter(ScanDevice.device_id == dev.id)
            .scalar()
        ) or 0
        cve_row = _latest_scan_device_with_cves(db, dev.id)
        vulnerabilities = cve_row.cves_list if cve_row else []
        result.append({
            "id":         dev.id,
            "mac":        dev.mac or "unknown",
            "vendor":     dev.vendor or "",
            "hostname":   dev.hostname or "",
            "label":      dev.label or "",
            "is_known":   dev.is_known,
            "first_seen": _iso(dev.first_seen),
            "last_seen":  _iso(dev.last_seen)  if dev.last_seen  else None,
            "latest_ip":  latest_sd.ip if latest_sd else None,
            "open_ports": latest_sd_ports.ports_list if latest_sd_ports else [],
            "vulnerability_count": len(vulnerabilities),
            "max_cve_risk": max((v.get("risk") for v in vulnerabilities), key=_risk_rank, default=None),
            "os_guess":   dev.os_guess or "",
            "scan_count": scan_count,
            "dhcp_option55": dev.dhcp_option55 or "",
            "dhcp_option60": dev.dhcp_option60 or "",
            "dhcp_hostname": dev.dhcp_hostname or "",
        })
    return result


@router.patch("/api/device/{device_id}")
def update_device(device_id: int, updates: dict, db: Session = Depends(get_db)):
    """Update a device's label, trust (is_known), or allow-list."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if "label" in updates:
        device.label = (updates["label"] or "").strip() or None
    if "is_known" in updates:
        device.is_known = bool(updates["is_known"])
    # Per-device allow-list (Phase 1.5): suppress anomaly alerts when the
    # device's behavior matches what the user has explicitly approved.
    # Body: {"allow": {"allowed_ports":[22,80], "allowed_countries":["US"],
    #                  "allowed_destinations":["1.2.3.4"], "allowed_high_bandwidth":true}}
    if "allow" in updates and isinstance(updates["allow"], dict):
        try:
            existing = json.loads(device.allow_json or "{}")
        except Exception:
            existing = {}
        existing.update(updates["allow"])
        device.allow_json = json.dumps(existing)
    db.commit()
    return {
        "id": device.id,
        "label": device.label,
        "is_known": device.is_known,
        "allow": json.loads(device.allow_json) if device.allow_json else {},
    }


@router.post("/api/devices/trust-all")
def trust_all_devices(db: Session = Depends(get_db)):
    """Mark every known device as trusted (is_known=True)."""
    updated = db.query(Device).filter(Device.is_known == False).update({"is_known": True})  # noqa: E712
    db.commit()
    return {"updated": updated}


@router.post("/api/device/{device_id}/allow")
def add_device_allow_entry(device_id: int, entry: dict, db: Session = Depends(get_db)):
    """
    Append a single allow-list entry. Body forms supported:
      {"port": 22}                 -> append to allowed_ports
      {"country": "US"}            -> append to allowed_countries
      {"destination": "1.2.3.4"}   -> append to allowed_destinations
      {"high_bandwidth": true}     -> set allowed_high_bandwidth flag
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        allow = json.loads(device.allow_json or "{}")
    except Exception:
        allow = {}
    for key, list_name in (("port", "allowed_ports"),
                           ("country", "allowed_countries"),
                           ("destination", "allowed_destinations")):
        if key in entry and entry[key] is not None:
            arr = allow.setdefault(list_name, [])
            if entry[key] not in arr:
                arr.append(entry[key])
    if "high_bandwidth" in entry:
        allow["allowed_high_bandwidth"] = bool(entry["high_bandwidth"])
    device.allow_json = json.dumps(allow)
    db.commit()
    return {"id": device.id, "allow": allow}


@router.get("/api/device/{device_id}/history")
def get_device_history(device_id: int, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    appearances = (
        db.query(ScanDevice).join(Scan)
        .filter(ScanDevice.device_id == device_id, Scan.status == "complete")
        .order_by(desc(ScanDevice.id)).limit(20).all()
    )
    latest_sd = (
        db.query(ScanDevice)
        .filter(ScanDevice.device_id == device_id)
        .order_by(desc(ScanDevice.id))
        .first()
    )
    return {
        "device": {
            "id": device.id, "mac": device.mac, "vendor": device.vendor,
            "hostname": device.hostname, "label": device.label,
            "is_known": device.is_known,
            "first_seen": _iso(device.first_seen),
            "last_seen":  _iso(device.last_seen)  if device.last_seen  else None,
            "latest_ip":  latest_sd.ip if latest_sd else None,
        },
        "history": [
            {
                "scan_id": sd.scan_id,
                "scan_time": _iso(sd.scan.started_at),
                "ip": sd.ip, "hostname": sd.hostname, "open_ports": sd.ports_list,
            }
            for sd in appearances
        ],
    }


@router.get("/api/security/cve-mapping")
def get_cve_mapping(current_only: bool = True, db: Session = Depends(get_db)):
    """
    Return offline CVE matches from the latest service-version scan data.

    Phase one uses conservative banner/version signatures generated during
    nmap -sV scans. It does not contact an external CVE service.
    """
    if current_only:
        latest_scan, scan_ids = current_scan_ids(db)
        if latest_scan:
            device_ids = [
                row[0] for row in (
                    db.query(ScanDevice.device_id)
                    .filter(ScanDevice.scan_id.in_(scan_ids))
                    .distinct()
                    .all()
                )
            ]
            devices = db.query(Device).filter(Device.id.in_(device_ids)).all() if device_ids else []
        else:
            devices = []
    else:
        latest_scan = db.query(Scan).filter(Scan.status == "complete").order_by(desc(Scan.id)).first()
        devices = db.query(Device).order_by(desc(Device.last_seen)).all()

    gateway = _gateway_ip(db)

    findings = []
    scanned_devices = 0
    for dev in devices:
        latest_sd = db.query(ScanDevice).filter(ScanDevice.device_id == dev.id).order_by(desc(ScanDevice.id)).first()
        # The latest real service-detection scan is the single source of truth
        # for both "did we check this device" and "what did we find" — reusing
        # one row keeps a fixed vulnerability from reappearing from stale data.
        cve_row = _latest_scan_device_with_cves(db, dev.id)
        services = cve_row.services_list if cve_row else []
        cves = cve_row.cves_list if cve_row else []
        if services:
            scanned_devices += 1
        ip = (cve_row.ip if cve_row else None) or (latest_sd.ip if latest_sd else None)
        for cve in cves:
            findings.append({
                **cve,
                "device_id": dev.id,
                "ip": ip,
                "hostname": (latest_sd.hostname if latest_sd else None) or dev.hostname or "",
                "label": dev.label or "",
                "scan_id": cve_row.scan_id if cve_row else None,
                "remediation": _remediation_for(dev, ip, gateway),
            })

    findings.sort(key=lambda f: (_risk_rank(f.get("risk")), f.get("cve") or ""), reverse=True)
    return {
        "scan": {
            "id": latest_scan.id if latest_scan else None,
            "started_at": _iso(latest_scan.started_at) if latest_scan else None,
        },
        "scanned_devices": scanned_devices,
        "finding_count": len(findings),
        "findings": findings,
    }


@router.get("/api/security/attack-tree")
def get_attack_tree(current_only: bool = True, db: Session = Depends(get_db)):
    """
    Build read-only attack-tree candidates from existing scan evidence.

    This does not run exploit tools. It highlights plausible pivot paths from a
    low-security IoT foothold to high-value local targets so the user can decide
    where segmentation, patching, or password hardening matters most.
    """
    latest_scan = db.query(Scan).filter(Scan.status == "complete").order_by(desc(Scan.id)).first()
    if current_only:
        _, scan_ids = current_scan_ids(db)
        device_ids = [
            row[0] for row in (
                db.query(ScanDevice.device_id)
                .filter(ScanDevice.scan_id.in_(scan_ids))
                .distinct()
                .all()
            )
        ] if scan_ids else []
        devices = db.query(Device).filter(Device.id.in_(device_ids)).all() if device_ids else []
    else:
        devices = db.query(Device).order_by(desc(Device.last_seen)).all()

    gateway = _gateway_ip(db)
    summaries = [_attack_tree_device_summary(db, dev) for dev in devices]
    # A path only exists if its starting point — the foothold — has an actual
    # CVE match we found on it. We never build a path from a pure device-name/
    # port guess ("looks like a camera"): that produced "attack paths" for
    # devices with nothing wrong on them, which reads as a real threat to
    # anyone who isn't a security person regardless of disclaimers or styling.
    sources = [s for s in summaries if s["has_cve_evidence"]]
    targets = [s for s in summaries if s["target_score"] >= 3]
    if not targets:
        targets = sorted(summaries, key=lambda s: s["target_score"], reverse=True)[:3]

    paths = []
    for src in sources:
        for target in targets:
            if src["device"].id == target["device"].id:
                continue
            score = src["source_score"] + target["target_score"]
            risk = _attack_risk(score)
            src_reasons = _attack_step_reasons(src, source=True)
            target_reasons = _attack_step_reasons(target, source=False)
            paths.append({
                "id": f"{src['device'].id}-{target['device'].id}",
                "risk": risk,
                "score": score,
                "source": {
                    "device_id": src["device"].id,
                    "name": src["name"],
                    "ip": src["ip"],
                    "reasons": src_reasons,
                    "remediation": _remediation_for(src["device"], src["ip"], gateway),
                },
                "target": {
                    "device_id": target["device"].id,
                    "name": target["name"],
                    "ip": target["ip"],
                    "reasons": target_reasons,
                    "remediation": _remediation_for(target["device"], target["ip"], gateway),
                },
                "steps": [
                    {
                        "title": "Initial foothold",
                        "detail": f"Attacker compromises {src['name']} using a known CVE we found on it.",
                    },
                    {
                        "title": "Local network pivot",
                        "detail": "From the same LAN, the attacker scans for file sharing, remote admin, or web consoles.",
                    },
                    {
                        "title": "High-value access",
                        "detail": f"Attacker targets {target['name']} because it exposes valuable services or looks like storage/workstation infrastructure.",
                    },
                ],
                "mitigations": [
                    "Patch or disable the vulnerable/admin service shown in the CVE evidence above.",
                    "Move IoT devices to a guest or VLAN segment that cannot initiate connections to workstations or NAS devices.",
                    "Require unique strong credentials and disable default web, SSH, SMB, or RDP access where it is not needed.",
                ],
            })

    paths.sort(key=lambda p: (p["score"], p["source"]["name"], p["target"]["name"]), reverse=True)
    paths = paths[:10]
    return {
        "scan": {
            "id": latest_scan.id if latest_scan else None,
            "started_at": _iso(latest_scan.started_at) if latest_scan else None,
        },
        "device_count": len(summaries),
        "source_count": len(sources),
        "target_count": len(targets),
        "path_count": len(paths),
        "paths": paths,
        "verified_paths": paths,
        "assumptions": [
            "Every path starts from a device with an actual CVE match we found — nothing here is a guess.",
            "This is a planning aid only; it does not prove compromise and does not execute exploit code.",
        ],
    }


@router.get("/api/security/firmware-status")
def get_firmware_status(db: Session = Depends(get_db)):
    """
    Check the router's own firmware version via its SOAP API — the same
    credentials/connection the Uptime Guardian uses to reboot it. Read-only,
    safe to call as often as the UI wants.
    """
    from network.router_firmware import check_firmware
    creds = _router_creds(db)
    if not creds["password"]:
        return {"configured": False, "error": "No router admin password set — "
                "add it under Settings → Uptime Guardian to enable firmware checks."}
    result = check_firmware(
        creds["host"], creds["user"], creds["password"],
        use_ssl=creds["use_ssl"], port=creds["port"],
    )
    return {"configured": True, **result}


@router.post("/api/security/firmware-update")
def trigger_firmware_update(body: dict = None, db: Session = Depends(get_db)):
    """
    Apply a pending firmware update on the router. Requires {"confirm": true}
    in the body — this is a real action that reboots the router for a few
    minutes, so it's never triggered without explicit confirmation from the UI.
    """
    body = body or {}
    if not body.get("confirm"):
        raise HTTPException(status_code=400, detail="Set confirm=true to apply the firmware update — "
                             "this will reboot the router for a few minutes.")
    from network.router_firmware import update_firmware
    creds = _router_creds(db)
    if not creds["password"]:
        raise HTTPException(status_code=400, detail="No router admin password configured.")
    result = update_firmware(
        creds["host"], creds["user"], creds["password"],
        use_ssl=creds["use_ssl"], port=creds["port"],
    )
    write_log(
        "action" if result.get("success") else "warning", "system", "firmware_update",
        result.get("detail") or result.get("error") or "Firmware update attempted.",
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# HEALTH CHECKS
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/health/current")
def get_health_current(db: Session = Depends(get_db)):
    """Return the most recent health check result."""
    hc = db.query(HealthCheck).order_by(desc(HealthCheck.id)).first()
    if not hc:
        return {
            "status": "unknown", "latency_ms": None, "packet_loss": None,
            "target": None, "checked_at": None, "error": "No checks run yet",
        }
    return {
        "status":            hc.status,
        "latency_ms":        hc.latency_ms,
        "local_latency_ms":  getattr(hc, "local_latency_ms", None),
        "packet_loss":       hc.packet_loss,
        "target":            hc.target,
        "local_target":      getattr(hc, "local_target", None),
        "checked_at":        _iso(hc.checked_at),
        "error":             hc.error,
    }


@router.get("/api/health/history")
def get_health_history(limit: int = 120, db: Session = Depends(get_db)):
    """
    Return the last N health checks for the latency timeline chart.
    Results are returned oldest-first so the chart renders correctly
    (time flows left → right).

    limit: max number of data points (default 120 = ~10 hours at 5-min intervals)
    """
    rows = (
        db.query(HealthCheck)
        .order_by(desc(HealthCheck.id))
        .limit(limit)
        .all()
    )
    # Reverse so oldest is first — chart reads left to right
    rows = list(reversed(rows))
    return [
        {
            "checked_at":  _iso(r.checked_at),
            "status":      r.status,
            "latency_ms":  r.latency_ms,
            "packet_loss": r.packet_loss,
        }
        for r in rows
    ]


@router.post("/api/health/check")
def run_health_check_now(db: Session = Depends(get_db)):
    """
    Run an immediate health check on demand (from the dashboard button).
    Runs synchronously in the request — takes 2–5 seconds while ping runs.
    """
    from monitoring.health import run_ping

    target       = _get_setting_str  (db, "health_target",        "8.8.8.8")
    warn_latency = _get_setting_float(db, "latency_warn_ms",      100.0)
    crit_latency = _get_setting_float(db, "latency_crit_ms",      300.0)
    warn_loss    = _get_setting_float(db, "packet_loss_warn_pct", 10.0)

    result = run_ping(
        target=target,
        warn_latency_ms=warn_latency,
        crit_latency_ms=crit_latency,
        warn_loss_pct=warn_loss,
    )

    hc = HealthCheck(
        status=result["status"],
        latency_ms=result["latency_ms"],
        packet_loss=result["packet_loss"],
        target=result["target"],
        error=result["error"],
    )
    from monitoring.uptime_stats import record_health_check
    record_health_check(db, result["status"])
    db.add(hc)
    db.commit()

    return {
        "status":      hc.status,
        "latency_ms":  hc.latency_ms,
        "packet_loss": hc.packet_loss,
        "target":      hc.target,
        "checked_at":  _iso(hc.checked_at),
        "error":       hc.error,
    }


# ═════════════════════════════════════════════════════════════════════════════
# SPEED TEST
# ═════════════════════════════════════════════════════════════════════════════

@router.post("/api/speed/test")
def run_speed_test_now(db: Session = Depends(get_db)):
    """
    Run a download speed test on demand.
    Downloads ~5MB from the configured test URL.
    Takes 5–30 seconds depending on your connection.

    Only call this from a button click — not on a timer.
    """
    from monitoring.health import run_speed_test

    gateway = ""
    try:
        from network.autodetect import get_network_info
        gateway = get_network_info().get("gateway") or ""
    except Exception:
        pass

    router_host = _get_setting_str(db, "autoheal_router_host", "") or gateway or "192.168.1.1"
    router_user = _get_setting_str(db, "autoheal_router_user", "admin")
    router_pass = os.getenv("ROUTER_PASS") or _get_setting_str(db, "autoheal_router_pass", "")

    router_cfg = {
        "host": router_host,
        "user": router_user,
        "password": router_pass,
    }

    url    = _get_setting_str(db, "speed_test_url",
                              "https://speed.cloudflare.com/__down?bytes=50000000")
    result = run_speed_test(url=url, router_cfg=router_cfg)

    st = SpeedTest(
        download_mbps=result["download_mbps"],
        upload_mbps=result.get("upload_mbps"),
        latency_ms=result["latency_ms"],
        error=result["error"],
    )
    db.add(st)
    db.commit()

    return {
        "download_mbps": st.download_mbps,
        "upload_mbps":   st.upload_mbps,
        "latency_ms":    st.latency_ms,
        "tested_at":     _iso(st.tested_at),
        "error":         st.error,
    }


@router.get("/api/speed/latest")
def get_speed_latest(db: Session = Depends(get_db)):
    """Return the most recent speed test result."""
    st = db.query(SpeedTest).order_by(desc(SpeedTest.id)).first()
    if not st:
        return {"download_mbps": None, "upload_mbps": None, "latency_ms": None, "tested_at": None, "error": None}
    return {
        "download_mbps": st.download_mbps,
        "upload_mbps":   st.upload_mbps,
        "latency_ms":    st.latency_ms,
        "tested_at":     _iso(st.tested_at),
        "error":         st.error,
    }


@router.get("/api/speed/history")
def get_speed_history(limit: int = 30, db: Session = Depends(get_db)):
    """
    Return recent speed test results oldest-first for the chart.
    limit: max results (default 30 — all manual tests)
    """
    rows = (
        db.query(SpeedTest)
        .order_by(desc(SpeedTest.id))
        .limit(limit)
        .all()
    )
    rows = list(reversed(rows))   # oldest first so chart reads left → right
    return [
        {
            "tested_at":     _iso(r.tested_at),
            "download_mbps": r.download_mbps,
            "upload_mbps":   r.upload_mbps,
            "latency_ms":    r.latency_ms,
            "error":         r.error,
        }
        for r in rows
    ]


# ═════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ═════════════════════════════════════════════════════════════════════════════

_ENV_BACKED_SECRETS = {
    "ntfy_pass": "NTFY_PASS",
    "smtp_pass": "SMTP_PASS",
}


def _env_locked_keys() -> set[str]:
    """Settings keys whose value comes from .env at runtime (UI is read-only)."""
    return {key for key, env in _ENV_BACKED_SECRETS.items() if os.getenv(env)}


@router.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    """Return all settings as a flat key→value dict.
    Env-backed secrets (ntfy_pass, smtp_pass) are blanked so the UI shows
    them as empty/locked rather than leaking the DB value."""
    rows = db.query(Setting).order_by(Setting.key).all()
    locked = _env_locked_keys()
    return {r.key: ("" if r.key in locked else r.value) for r in rows}


@router.post("/api/settings")
def update_settings(updates: dict, db: Session = Depends(get_db)):
    """
    Update one or more settings.
    Body: { "latency_warn_ms": "150", "health_check_interval_s": "120" }
    Returns: { "updated": [...], "ignored_env_backed": [...] }

    Unknown keys are silently ignored (only update keys that exist).
    Keys backed by .env (ntfy_pass, smtp_pass when set) are refused — the
    real value lives in .env, so a DB write would silently do nothing.
    """
    allowed_keys = {
        r.key for r in db.query(Setting.key).all()
    }
    locked = _env_locked_keys()
    updated: list[str] = []
    ignored: list[str] = []
    for key, value in updates.items():
        if key not in allowed_keys:
            continue
        if key in locked:
            ignored.append(key)
            continue
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = str(value)
            updated.append(key)

    db.commit()
    return {"updated": updated, "ignored_env_backed": ignored}


# ─────────────────────────────────────────────────────────────────────────────
# Notification diagnostics — used by the Settings UI to verify ntfy delivery.
# Reads the current ntfy config, masks the password, optionally sends a real
# test notification. Helps users debug why they're not getting alerts.
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/diagnostics/notifications")
def get_notification_diagnostics(db: Session = Depends(get_db)):
    """Report current ntfy/email config + reachability — never returns the password."""
    import os as _os
    def _g(k, d=""):
        row = db.query(Setting).filter(Setting.key == k).first()
        return row.value if (row and row.value is not None) else d
    cfg = {
        "ntfy_enabled":     _g("ntfy_enabled", "false"),
        "ntfy_server":      _g("ntfy_server", "https://ntfy.sh"),
        "ntfy_topic":       _g("ntfy_topic", ""),
        "ntfy_user":        _g("ntfy_user", ""),
        "ntfy_pass_set":    bool(_os.getenv("NTFY_PASS") or _g("ntfy_pass", "")),
        "ntfy_pass_source": "env" if _os.getenv("NTFY_PASS") else ("db" if _g("ntfy_pass") else "none"),
        "ntfy_min_level":   _g("ntfy_min_level", "critical"),
        "email_enabled":    _g("email_enabled", "false"),
        "email_to":         _g("email_to", ""),
    }
    # Quick missing-config checklist for the UI.
    issues: list[str] = []
    if cfg["ntfy_enabled"] != "true":
        issues.append("ntfy_enabled is false — set it to 'true' in Settings.")
    if not cfg["ntfy_topic"]:
        issues.append("ntfy_topic is empty — set a unique topic string.")
    if cfg["ntfy_server"].startswith("http://") and "localhost" not in cfg["ntfy_server"]:
        issues.append("ntfy_server is HTTP and not localhost — phone may refuse.")
    if cfg["ntfy_user"] and not cfg["ntfy_pass_set"]:
        issues.append("ntfy_user is set but no NTFY_PASS env or DB password — auth will 401.")
    if cfg["ntfy_min_level"] == "critical":
        issues.append(
            "ntfy_min_level is 'critical' — only critical+ pushes get through. "
            "Truly-new device alerts now bypass this via force_push, but other "
            "warnings (degraded health, traffic spikes) won't push until you "
            "lower the threshold."
        )
    return {**cfg, "issues": issues}


@router.post("/api/diagnostics/notifications/test")
def send_notification_test():
    """Send a real test notification through ntfy and report what happened."""
    from monitoring.notifier import alert as _notify
    try:
        _notify(
            title="NetMon test notification",
            body="If you can read this on your phone, ntfy delivery is working.",
            level="warning",
            tags=["white_check_mark"],
            force_push=True,
        )
        return {"status": "sent", "message": "Test notification fired. Check your phone."}
    except Exception as exc:
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}"}


# ═════════════════════════════════════════════════════════════════════════════
# TELEMETRY  (live, not persisted)
# ═════════════════════════════════════════════════════════════════════════════

# Cache the process object — psutil.Process(pid) is cheap but no need to recreate
_this_process = psutil.Process(os.getpid())

@router.get("/api/telemetry")
def get_telemetry():
    """
    Return live CPU and memory usage of this netmon process.
    Not stored in the database — read fresh on every call.

    cpu_pct:  % of one CPU core used by this process (0.1s sample interval)
    mem_mb:   RSS (resident set size) in megabytes — actual RAM in use
    pid:      process ID (for reference)
    """
    cpu  = _this_process.cpu_percent(interval=0.1)
    mem  = _this_process.memory_info().rss / 1_048_576   # bytes → MB
    return {
        "cpu_pct":     round(cpu, 1),
        "mem_mb":      round(mem, 1),
        "pid":         os.getpid(),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


# ═════════════════════════════════════════════════════════════════════════════
# AI ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

@router.post("/api/ai/analyze")
def ai_analyze(db: Session = Depends(get_db)):
    """
    Start an AI analysis in a background thread and return immediately.

    Why background?
      Local models (Ollama) can take 30-120 seconds to respond. Keeping
      the HTTP request open that long causes browser timeouts and blocks
      a uvicorn worker. Instead we fire-and-forget into a daemon thread
      and let the frontend poll GET /api/ai/latest for the result.

    Returns immediately with {"status": "started"}.
    The result appears in GET /api/ai/latest once the thread completes.
    """
    import threading
    from app.database import SessionLocal
    from ai.analyst import run_analysis

    # Check AI is enabled before spawning the thread
    ai_enabled = _get_setting_str(db, "ai_enabled", "false").lower()
    if ai_enabled != "true":
        return {"status": "disabled", "message": "AI is disabled in Settings"}

    def _run():
        # Each thread needs its own DB session — SQLite sessions are not thread-safe
        thread_db = SessionLocal()
        try:
            run_analysis(thread_db)
        except Exception as e:
            print(f"[ai] Background analysis error: {e}")
        finally:
            thread_db.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return {"status": "started", "message": "Analysis running — check back in 30-60 seconds"}


@router.post("/api/ai/analyze/scan")
def ai_analyze_scan(db: Session = Depends(get_db)):
    """
    Run a SCAN-only AI analysis (devices, changes, health) in a background
    thread. Smaller prompt → faster response than the legacy /api/ai/analyze.
    Poll /api/ai/progress for live token streaming.
    """
    import threading
    from app.database import SessionLocal
    from ai.analyst import run_scan_analysis

    if _get_setting_str(db, "ai_enabled", "false").lower() != "true":
        return {"status": "disabled", "message": "AI is disabled in Settings"}

    def _run():
        thread_db = SessionLocal()
        try:
            run_scan_analysis(thread_db)
        except Exception as e:
            print(f"[ai] scan analysis error: {e}")
        finally:
            thread_db.close()

    threading.Thread(target=_run, daemon=True, name="ai-scan").start()
    return {"status": "started", "kind": "scan"}


@router.post("/api/ai/analyze/traffic")
def ai_analyze_traffic(db: Session = Depends(get_db)):
    """
    Run a TRAFFIC-only AI analysis (top_domains, top_talkers, protocol_mix)
    in a background thread. Smaller, focused prompt → faster than combined.
    Poll /api/ai/progress for live token streaming.
    """
    import threading
    from app.database import SessionLocal
    from ai.analyst import run_traffic_analysis

    if _get_setting_str(db, "ai_enabled", "false").lower() != "true":
        return {"status": "disabled", "message": "AI is disabled in Settings"}

    def _run():
        thread_db = SessionLocal()
        try:
            run_traffic_analysis(thread_db)
        except Exception as e:
            print(f"[ai] traffic analysis error: {e}")
        finally:
            thread_db.close()

    threading.Thread(target=_run, daemon=True, name="ai-traffic").start()
    return {"status": "started", "kind": "traffic"}


@router.post("/api/ai/investigate")
def ai_investigate(body: dict, db: Session = Depends(get_db)):
    """
    Agentic investigation of a flagged item.

    Phase 1 — gather real data:
      - If item looks like a domain: query pcap files for which source IPs
        sent DNS queries for it (tshark). Cross-reference IPs with device labels.
      - If item looks like an IP: look up device record from DB.
      - Also pull ARP cache for MAC info.

    Phase 2 — ask AI to analyse the gathered evidence and propose a
    specific executable resolution (label a device, mark untrusted, etc.)

    Returns:
      { verdict, what, findings, sources (list of {ip,label,mac}),
        proposed_resolutions (list of {id,description,action_type,params,revert}),
        model, error }
    """
    import re as _re
    import subprocess as _sp
    from pathlib import Path as _Path
    from ai.provider import get_provider, get_investigation_provider, _extract_json, progress_begin, progress_append

    if _get_setting_str(db, "ai_enabled", "false").lower() != "true":
        return {"error": "AI is disabled"}

    item           = (body.get("item")           or "").strip()
    context        = (body.get("context")        or "analysis").strip()
    user_note      = (body.get("user_note")      or "").strip()
    deep_pcap_path = (body.get("deep_pcap_path") or "").strip()
    if not item:
        raise HTTPException(status_code=400, detail="item is required")

    provider = get_investigation_provider()
    if provider.name == "none":
        return {"error": "AI not configured"}

    # ── Quick HTTPS helper (no extra deps — uses stdlib urllib) ───────────────
    def _web_get(url: str, timeout: int = 5) -> str | None:
        """GET url, return response body text or None on any failure."""
        try:
            import urllib.request as _ur
            req = _ur.Request(url, headers={"User-Agent": "NetMon/1.0 home-network-monitor"})
            with _ur.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    # ── Phase 1: gather evidence ──────────────────────────────────────────────

    _DOMAIN_RE = _re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
    _IP_RE_    = _re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    sources: list[dict] = []   # [{ip, label, mac}]
    evidence_lines: list[str] = []

    is_domain = bool(_DOMAIN_RE.match(item))
    is_ip     = bool(_IP_RE_.match(item))

    # Detect whether the item is the NetMon server's own IP — used to prevent
    # Qwen from calling its own machine "suspicious" due to many open ports/connections.
    import socket as _own_sock
    _own_ips: set[str] = {"127.0.0.1", "localhost", "::1"}
    try:
        _own_ips.add(_own_sock.gethostbyname(_own_sock.gethostname()))
    except Exception:
        pass
    try:
        _s = _own_sock.socket(_own_sock.AF_INET, _own_sock.SOCK_DGRAM)
        _s.connect(("8.8.8.8", 80))
        _own_ips.add(_s.getsockname()[0])
        _s.close()
    except Exception:
        pass
    _is_own_machine = item in _own_ips

    # Start streaming progress so the UI can show what's happening live
    progress_begin("investigate")
    progress_append(f"Investigating {item}...\n")

    # Helper: get all known device labels {ip: label}
    def _device_labels() -> dict:
        from models.tables import ScanDevice
        labels = {}
        for sd in db.query(ScanDevice).order_by(desc(ScanDevice.id)).limit(300).all():
            if sd.ip and sd.ip not in labels:
                lbl = (sd.device.label if sd.device else "") or ""
                labels[sd.ip] = lbl
        return labels

    # Helper: get ARP cache {ip: mac}
    def _arp_cache() -> dict:
        cache = {}
        try:
            r = _sp.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and _IP_RE_.match(parts[0]):
                    cache[parts[0]] = parts[1].replace("-", ":").lower()
        except Exception:
            pass
        return cache

    if is_domain:
        # Extract base domain for matching (e.g. "skype.com" from "go.trouter.skype.com")
        parts = item.split(".")
        search_term = ".".join(parts[-2:]) if len(parts) >= 2 else item

        # Query pcap files for DNS queries containing this domain
        from traffic.interfaces import find_tool, _no_window
        from traffic.analyzer import get_readable_files, CAPTURE_DIR

        tshark = find_tool("tshark")
        pcap_sources: dict[str, int] = {}   # ip → query count

        if tshark:
            files = get_readable_files(CAPTURE_DIR, max_files=5)
            for pcap in files:
                try:
                    r = _sp.run(
                        [tshark, "-r", str(pcap), "-q",
                         "-Y", f'dns.flags.response == 0 && dns.qry.name contains "{search_term}"',
                         "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"],
                        capture_output=True, text=True, timeout=30,
                        creationflags=_no_window(),
                    )
                    for line in r.stdout.splitlines():
                        parts_ = line.strip().split("\t")
                        if parts_ and parts_[0]:
                            ip_ = parts_[0].strip()
                            if _IP_RE_.match(ip_):
                                pcap_sources[ip_] = pcap_sources.get(ip_, 0) + 1
                except Exception as ex:
                    evidence_lines.append(f"tshark error: {ex}")

        labels = _device_labels()
        arp    = _arp_cache()

        if pcap_sources:
            for ip_, count in sorted(pcap_sources.items(), key=lambda x: -x[1]):
                lbl = labels.get(ip_, "")
                mac = arp.get(ip_, "")
                sources.append({"ip": ip_, "label": lbl, "mac": mac, "queries": count})
            src_desc = ", ".join(
                f"{s['ip']} ({s['label'] or 'unlabeled'}, {s['queries']} queries)"
                for s in sources
            )
            evidence_lines.append(f"Devices querying {item}: {src_desc}")
        else:
            evidence_lines.append(f"No DNS queries for {item} found in recent captures (capture may not be running or domain uses direct IPs).")
            # Still include all devices as context
            labels = _device_labels()
            arp    = _arp_cache()

        # ── Domain internet lookups ────────────────────────────────────────────
        import socket as _dsocket

        # 1. Resolve domain → IPs
        # Query 8.8.8.8 directly (raw DNS) so our local DNS blocker doesn't
        # sabotage lookups for the very domains we're investigating.
        progress_append("Resolving domain to IPs...\n")
        _resolved_ips: list[str] = []
        try:
            def _dns_query_8888(domain: str, timeout: float = 5.0) -> list[str]:
                """Send a raw DNS A-record query to 8.8.8.8:53, bypass system resolver."""
                import struct, random as _rand
                qid  = _rand.randint(0, 65535)
                name = b"".join(len(p).to_bytes(1,"big") + p.encode() for p in domain.split(".")) + b"\x00"
                pkt  = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)
                with _dsocket.socket(_dsocket.AF_INET, _dsocket.SOCK_DGRAM) as _us:
                    _us.settimeout(timeout)
                    _us.sendto(pkt, ("8.8.8.8", 53))
                    data, _ = _us.recvfrom(512)
                ips: list[str] = []
                offset = 12
                # Skip question section
                while data[offset] != 0:
                    offset += data[offset] + 1
                offset += 5  # null label + QTYPE + QCLASS
                ans_count = struct.unpack(">H", data[6:8])[0]
                for _ in range(ans_count):
                    # Skip name (handle pointer 0xC0xx or inline label)
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                    else:
                        while data[offset] != 0:
                            offset += data[offset] + 1
                        offset += 1
                    rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
                    offset += 10
                    if rtype == 1 and rdlen == 4:  # A record
                        ips.append(".".join(str(b) for b in data[offset:offset+4]))
                    offset += rdlen
                return ips

            _resolved_ips = _dns_query_8888(item)
            if _resolved_ips:
                evidence_lines.append(f"Domain resolves to: {', '.join(_resolved_ips[:5])}")
                progress_append(f"  Resolved: {', '.join(_resolved_ips[:3])}\n")
            else:
                evidence_lines.append(f"Domain {item} did not resolve (NXDOMAIN).")
                progress_append("  Did not resolve (NXDOMAIN)\n")
        except Exception as _re_ex:
            evidence_lines.append(f"Domain resolution failed: {_re_ex}")
            progress_append(f"  Resolution error: {_re_ex}\n")

        # 2. GeoIP / ASN on each resolved IP via ipinfo.io
        for _rip in _resolved_ips[:2]:
            progress_append(f"IP info for {_rip}...\n")
            _rip_raw = _web_get(f"https://ipinfo.io/{_rip}/json", timeout=5)
            if _rip_raw:
                try:
                    _ri = json.loads(_rip_raw)
                    _rparts = [p for p in [
                        _ri.get("org"), _ri.get("company", {}).get("name") if isinstance(_ri.get("company"), dict) else None,
                        f"country: {_ri.get('country', '?')}",
                        f"city: {_ri.get('city', '?')}",
                    ] if p]
                    evidence_lines.append(f"IP info for {_rip} ({item}): {', '.join(_rparts)}")
                    progress_append(f"  {_ri.get('org', 'unknown')}\n")
                except Exception:
                    pass

        # 3. RDAP domain registration lookup (who owns this domain?)
        _tld_parts = item.rsplit(".", 2)
        _base_domain = ".".join(_tld_parts[-2:]) if len(_tld_parts) >= 2 else item
        progress_append(f"RDAP lookup for {_base_domain}...\n")
        _rdap_raw = _web_get(f"https://rdap.org/domain/{_base_domain}", timeout=6)
        if _rdap_raw:
            try:
                _rdap = json.loads(_rdap_raw)
                _registrant = ""
                for _ent in (_rdap.get("entities") or []):
                    _roles = _ent.get("roles") or []
                    if "registrant" in _roles or "registrar" in _roles:
                        _vcard = _ent.get("vcardArray") or []
                        if isinstance(_vcard, list) and len(_vcard) > 1:
                            for _vf in _vcard[1]:
                                if isinstance(_vf, list) and _vf[0] == "fn":
                                    _registrant = _vf[3] if len(_vf) > 3 else ""
                                    break
                        if not _registrant:
                            _registrant = _ent.get("handle", "")
                        if _registrant:
                            break
                _reg_date = (_rdap.get("events") or [{}])[0].get("eventDate", "")[:10]
                _rdap_parts = [p for p in [
                    f"registrant: {_registrant}" if _registrant else None,
                    f"registered: {_reg_date}" if _reg_date else None,
                    f"status: {', '.join(_rdap.get('status', []))}" if _rdap.get("status") else None,
                ] if p]
                if _rdap_parts:
                    evidence_lines.append(f"RDAP registration for {_base_domain}: {'; '.join(_rdap_parts)}")
                    progress_append(f"  Registrant: {_registrant or 'unknown'}\n")
            except Exception:
                progress_append("  RDAP parse failed\n")
        else:
            progress_append("  RDAP unavailable\n")

    elif is_ip:
        import socket as _socket
        import shutil as _shutil

        # ── DB record ─────────────────────────────────────────────────────────
        progress_append("Checking device records...\n")
        sd  = db.query(ScanDevice).filter(ScanDevice.ip == item).order_by(desc(ScanDevice.id)).first()
        dev = sd.device if sd else None
        _mac_for_lookup = ""
        if dev:
            lbl = dev.label or ""
            mac = dev.mac or ""
            _mac_for_lookup = mac
            evidence_lines.append(
                f"NetMon record — IP: {item}, label: '{lbl}', vendor: '{dev.vendor or 'unknown'}', "
                f"MAC: {mac or 'unknown'}, trusted: {dev.is_known}, hostname: '{dev.hostname or 'none'}'"
            )
            sources.append({"ip": item, "label": lbl, "mac": mac})
            progress_append(f"  Found: {lbl or 'unlabeled'}, MAC {mac or 'unknown'}\n")
        else:
            evidence_lines.append(f"IP {item} not in NetMon database — never seen in a scan.")
            progress_append("  Not in database\n")

        # ── Scan history (how long has it been here, what changed) ───────────
        history = (
            db.query(ScanDevice).filter(ScanDevice.ip == item)
            .order_by(desc(ScanDevice.id)).limit(10).all()
        )
        if history:
            first_seen = history[-1].scan.started_at if (history[-1].scan and history[-1].scan.started_at) else None
            last_seen  = history[0].scan.started_at  if (history[0].scan  and history[0].scan.started_at)  else None
            evidence_lines.append(
                f"Scan history: present in {len(history)} recent scans. "
                f"First seen: {first_seen.strftime('%Y-%m-%d') if first_seen else 'unknown'}. "
                f"Last seen: {last_seen.strftime('%Y-%m-%d') if last_seen else 'unknown'}."
            )
            all_ports: set[str] = set()
            for h in history[:5]:
                try:
                    for p in json.loads(h.open_ports or "[]"):
                        all_ports.add(str(p))
                except Exception:
                    pass
            if all_ports:
                evidence_lines.append(f"Open ports observed across recent scans: {', '.join(sorted(all_ports, key=lambda x: int(x) if x.isdigit() else 0))}")

        # ── Web lookup: MAC vendor (via macvendors.com) ───────────────────────
        # If no MAC from DB, try ARP cache
        if not _mac_for_lookup:
            _arp = _arp_cache()
            _mac_for_lookup = _arp.get(item, "")
        if _mac_for_lookup and _mac_for_lookup not in ("", "unknown"):
            progress_append("Web lookup: MAC vendor...\n")
            _mac_clean = _mac_for_lookup.replace(":", "").replace("-", "")[:12]
            _vendor_raw = _web_get(f"https://api.macvendors.com/{_mac_clean}", timeout=5)
            if _vendor_raw and "errors" not in _vendor_raw.lower() and len(_vendor_raw) < 120:
                evidence_lines.append(f"MAC vendor lookup (macvendors.com): {_mac_for_lookup} is registered to '{_vendor_raw}'")
                progress_append(f"  Vendor: {_vendor_raw}\n")
            else:
                progress_append("  Vendor lookup unavailable\n")

        # ── Web lookup: IP geolocation / ASN (via ipinfo.io) ─────────────────
        # Only look up IPs that are not obviously local (RFC 1918)
        _is_private = bool(_re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', item))
        if not _is_private:
            progress_append("Web lookup: IP info...\n")
            _ip_info_raw = _web_get(f"https://ipinfo.io/{item}/json", timeout=5)
            if _ip_info_raw:
                try:
                    _ip_info = json.loads(_ip_info_raw)
                    _ip_parts = [
                        f"org: {_ip_info.get('org', 'unknown')}",
                        f"country: {_ip_info.get('country', '?')}",
                        f"city: {_ip_info.get('city', '?')}",
                    ]
                    if _ip_info.get("hostname"):
                        _ip_parts.append(f"hostname: {_ip_info['hostname']}")
                    if _ip_info.get("bogon"):
                        _ip_parts.append("BOGON/reserved address")
                    evidence_lines.append(f"IP info (ipinfo.io): {', '.join(_ip_parts)}")
                    progress_append(f"  {_ip_info.get('org', 'unknown')}, {_ip_info.get('country', '?')}\n")
                except Exception:
                    progress_append("  IP info parse failed\n")
            else:
                progress_append("  IP info unavailable\n")
        else:
            progress_append("Private IP — skipping external lookup\n")

        # ── Reverse DNS ───────────────────────────────────────────────────────
        progress_append("Reverse DNS lookup...\n")
        try:
            rdns = _socket.gethostbyaddr(item)[0]
            if rdns and rdns != item:
                evidence_lines.append(f"Reverse DNS: {item} resolves to '{rdns}'")
                progress_append(f"  Hostname: {rdns}\n")
            else:
                evidence_lines.append(f"Reverse DNS: no hostname found for {item}")
                progress_append("  No hostname\n")
        except Exception:
            evidence_lines.append(f"Reverse DNS: no hostname found for {item}")
            progress_append("  No hostname\n")

        # ── Nmap targeted service scan ────────────────────────────────────────
        progress_append("Running nmap service scan...\n")
        _nmap = None
        for _candidate in ["nmap",
                           r"C:\Program Files (x86)\Nmap\nmap.exe",
                           r"C:\Program Files\Nmap\nmap.exe"]:
            if _shutil.which(_candidate) or (_candidate.startswith("C:\\") and os.path.isfile(_candidate)):
                _nmap = _candidate
                break
        if _nmap:
            try:
                _cflags = getattr(_sp, "CREATE_NO_WINDOW", 0)
                _nr = _sp.run(
                    [_nmap, "-sV", "--open", "-T4", "--host-timeout", "20s", item],
                    capture_output=True, text=True, timeout=30,
                    creationflags=_cflags,
                )
                _nmap_lines = [
                    l for l in _nr.stdout.splitlines()
                    if l.strip() and not l.startswith("#")
                    and "Starting Nmap" not in l and "Nmap done" not in l
                    and "Nmap scan report" not in l
                ]
                if _nmap_lines:
                    evidence_lines.append("Nmap service scan:\n  " + "\n  ".join(_nmap_lines[:25]))
                    progress_append(f"  {len(_nmap_lines)} result lines\n")
                else:
                    evidence_lines.append(f"Nmap: device at {item} appears offline or blocked all probes.")
                    progress_append("  Device offline or filtered\n")
            except Exception as ex:
                evidence_lines.append(f"Nmap scan failed: {ex}")
                progress_append(f"  Nmap error: {ex}\n")
        else:
            evidence_lines.append("Nmap not installed — install it to enable service fingerprinting.")
            progress_append("  Nmap not installed\n")

        # ── Active connections (netstat) ───────────────────────────────────────
        progress_append("Checking active connections...\n")
        try:
            _ns = _sp.run(["netstat", "-n"], capture_output=True, text=True, timeout=8)
            _conns = [l.strip() for l in _ns.stdout.splitlines()
                      if item in l and ("ESTABLISHED" in l or "TIME_WAIT" in l or "SYN" in l)]
            if _conns:
                evidence_lines.append(
                    f"Active connections to/from {item} right now:\n  " + "\n  ".join(_conns[:10])
                )
                progress_append(f"  {len(_conns)} active connection(s)\n")
            else:
                evidence_lines.append(f"No active TCP connections to/from {item} at this moment.")
                progress_append("  No active connections\n")
        except Exception as ex:
            evidence_lines.append(f"Netstat check failed: {ex}")
            progress_append(f"  Netstat error: {ex}\n")

        # ── Hardware / OS fingerprinting ──────────────────────────────────────
        # Runs multiple probes to identify what this device actually is:
        # OS detection (nmap -O), HTTP/SSH banner grabs, UPnP SSDP discovery,
        # UPnP device description XML fetch, NetBIOS name query.
        progress_append("Fingerprinting hardware/OS...\n")
        _fp_lines: list[str] = []
        _cflags = getattr(_sp, "CREATE_NO_WINDOW", 0)

        # 1. nmap OS detection — requires admin but fails gracefully if not
        if _nmap:
            try:
                _of = _sp.run(
                    [_nmap, "-O", "--osscan-guess", "-T4", "--host-timeout", "12s", item],
                    capture_output=True, text=True, timeout=20, creationflags=_cflags,
                )
                _os_hits = [
                    l.strip() for l in _of.stdout.splitlines()
                    if any(kw in l for kw in
                           ("OS details:", "Aggressive OS", "Running:", "OS CPE:", "Device type:"))
                    and l.strip()
                ]
                if _os_hits:
                    _fp_lines.append("OS detection (nmap -O): " + " | ".join(_os_hits[:4]))
                    progress_append(f"  OS: {_os_hits[0].split(':', 1)[-1].strip()[:80]}\n")
            except Exception:
                pass

        # 2. HTTP / HTTPS banner grab — reveals router/NAS/camera model from Server header
        _http_found = False
        for _hport, _use_tls in [(80, False), (443, True), (8080, False), (8443, True), (8888, False), (7080, False)]:
            if _http_found:
                break
            try:
                with _socket.create_connection((item, _hport), timeout=3) as _hs:
                    if _use_tls:
                        import ssl as _ssl
                        _sctx = _ssl.create_default_context()
                        _sctx.check_hostname = False
                        _sctx.verify_mode = _ssl.CERT_NONE
                        _raw = _sctx.wrap_socket(_hs, server_hostname=item)
                    else:
                        _raw = _hs
                    _raw.sendall(
                        f"GET / HTTP/1.0\r\nHost: {item}\r\nUser-Agent: NetMon/1.0\r\n\r\n".encode()
                    )
                    _hresp = _raw.recv(4096).decode("utf-8", errors="replace")
                    _hlines = [l.strip() for l in _hresp.splitlines()[:40] if l.strip()]
                    _interesting = [l for l in _hlines if any(kw in l.lower() for kw in [
                        "server:", "x-powered", "www-authenticate", "location:",
                        "mikrotik", "ubiquiti", "synology", "qnap", "hikvision", "dahua",
                        "tp-link", "netgear", "asus", "openwrt", "dd-wrt", "unifi",
                        "dlink", "linksys", "zyxel", "sonos", "roku", "apple-tv",
                    ])]
                    _status = _hlines[0] if _hlines and _hlines[0].startswith("HTTP/") else ""
                    if _interesting:
                        _fp_lines.append(f"HTTP port {_hport}: " + " | ".join(_interesting[:5]))
                        progress_append(f"  HTTP/{_hport}: {_interesting[0][:80]}\n")
                        _http_found = True
                    elif _status:
                        _fp_lines.append(f"HTTP port {_hport}: {_status} (web interface present, no vendor header)")
                        _http_found = True
            except Exception:
                pass

        # 3. SSH banner grab — SSH-2.0-OpenSSH_8.9 Debian / SSH-2.0-dropbear etc.
        try:
            with _socket.create_connection((item, 22), timeout=3) as _ss:
                _ssh_raw = _ss.recv(256).decode("utf-8", errors="replace").strip()
                if _ssh_raw.startswith("SSH-"):
                    _fp_lines.append(f"SSH banner (port 22): {_ssh_raw[:200]}")
                    progress_append(f"  SSH: {_ssh_raw[:80]}\n")
        except Exception:
            pass

        # 4. UPnP / SSDP — smart home devices (TVs, speakers, Alexa, printers) advertise themselves
        try:
            import socket as _usocket
            _ssdp = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {item}:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\nST: ssdp:all\r\n\r\n"
            ).encode()
            _us = _usocket.socket(_usocket.AF_INET, _usocket.SOCK_DGRAM)
            _us.settimeout(3)
            try:
                _us.sendto(_ssdp, (item, 1900))
                _ssdp_resp = _us.recv(2048).decode("utf-8", errors="replace")
                _ssdp_hits = [l.strip() for l in _ssdp_resp.splitlines() if l.strip() and
                              any(kw in l.lower() for kw in ["server:", "location:", "usn:", "st:"])]
                _ssdp_location = next(
                    (l.split(":", 1)[1].strip() for l in _ssdp_resp.splitlines()
                     if l.lower().startswith("location:")), None
                )
                if _ssdp_hits:
                    _fp_lines.append("UPnP/SSDP response: " + " | ".join(_ssdp_hits[:4]))
                    progress_append(f"  UPnP: {_ssdp_hits[0][:80]}\n")
                # Fetch the UPnP device description XML — contains make, model, serial number
                if _ssdp_location:
                    _upnp_xml = _web_get(_ssdp_location, timeout=4)
                    if _upnp_xml:
                        import re as _xre
                        def _xtag(tag: str) -> str:
                            m = _xre.search(fr'<{tag}[^>]*>([^<]+)</{tag}>', _upnp_xml, _xre.I)
                            return m.group(1).strip() if m else ""
                        _make  = _xtag("manufacturer") or _xtag("manufacturerName")
                        _model = _xtag("modelName") or _xtag("modelDescription")
                        _fname = _xtag("friendlyName")
                        _serial= _xtag("serialNumber")
                        _parts = [p for p in [_make, _model, _fname, f"S/N: {_serial}" if _serial else ""] if p]
                        if _parts:
                            _fp_lines.append(f"UPnP device description: {' | '.join(_parts)}")
                            progress_append(f"  Device: {' '.join([_make, _model])[:80]}\n")
            finally:
                _us.close()
        except Exception:
            pass

        # 5. NetBIOS / SMB name — Windows PCs, Samba NAS, printers
        if _nmap:
            try:
                _nb = _sp.run(
                    [_nmap, "--script", "nbstat.nse,smb-os-discovery.nse", "-p", "137,139,445",
                     "-T4", "--host-timeout", "10s", item],
                    capture_output=True, text=True, timeout=18, creationflags=_cflags,
                )
                _nb_hits = [
                    l.strip() for l in _nb.stdout.splitlines()
                    if l.strip().startswith("|") and len(l.strip()) > 3
                ]
                if _nb_hits:
                    _fp_lines.append("NetBIOS/SMB: " + " | ".join(_nb_hits[:5]))
                    progress_append(f"  NetBIOS: {_nb_hits[0][:80]}\n")
            except Exception:
                pass

        if _fp_lines:
            evidence_lines.append("Hardware/OS fingerprint:\n  " + "\n  ".join(_fp_lines))
            progress_append(f"  Fingerprint complete ({len(_fp_lines)} clue(s))\n")
        else:
            evidence_lines.append(
                f"Hardware/OS fingerprint: no identifying banners or UPnP responses from {item}. "
                "Device may be a simple IoT device with no open web/SSH ports, or it is filtering probes."
            )
            progress_append("  No fingerprint found\n")

        # ── Persist investigate findings to the device record ──────────────────
        # Surfaces OS + open ports in the devices tab without waiting for the
        # next deep scan. Idempotent: re-running investigate refreshes the OS
        # string and unions newly-seen ports with whatever's already stored.
        try:
            from models.tables import Device as _Device, ScanDevice as _ScanDevice
            from datetime import datetime as _dt

            # Parse open ports from nmap -sV output (lines like "80/tcp open http nginx").
            _learned_ports: set[int] = set()
            _port_line_re = _re.compile(r'^\s*(\d{1,5})/tcp\s+open\b', _re.M)
            for _ml in (_nmap_lines if _nmap else []):
                m = _port_line_re.match(_ml)
                if m:
                    try: _learned_ports.add(int(m.group(1)))
                    except ValueError: pass
            # Fold in banner-grab confirmations (these only fire if the port answered).
            for _fpl in _fp_lines:
                mm = _re.search(r'(?:HTTP|SSH)\s*(?:port|banner.*port)?\s*[: (]\s*(\d{1,5})', _fpl, _re.I)
                if mm:
                    try: _learned_ports.add(int(mm.group(1)))
                    except ValueError: pass

            # Build a short OS string from whatever fingerprint hits we got.
            _os_str = ""
            for _fpl in _fp_lines:
                if _fpl.startswith("OS detection (nmap -O):"):
                    # Pick the most useful chunk after "OS details:" or "Running:"
                    for _seg in _fpl.split("|"):
                        _seg = _seg.strip()
                        for _kw in ("OS details:", "Running:", "Aggressive OS guesses:"):
                            if _kw in _seg:
                                _os_str = _seg.split(_kw, 1)[1].strip()[:120]
                                break
                        if _os_str: break
                    if _os_str: break
            if not _os_str:
                # Fall back to SMB OS discovery line ("OS: Windows 10 ...")
                for _fpl in _fp_lines:
                    if _fpl.startswith("NetBIOS/SMB:"):
                        mm = _re.search(r'OS:\s*([^|]+)', _fpl)
                        if mm:
                            _os_str = mm.group(1).strip()[:120]
                            break
            if not _os_str:
                # UPnP device description often names the platform (e.g. "Linux/3.14 UPnP/1.0").
                for _fpl in _fp_lines:
                    if _fpl.startswith("UPnP"):
                        mm = _re.search(r'Server:\s*([^|]+)', _fpl)
                        if mm:
                            _os_str = mm.group(1).strip()[:120]
                            break

            _dev_row = (
                db.query(_ScanDevice)
                  .filter(_ScanDevice.ip == item)
                  .order_by(desc(_ScanDevice.id))
                  .first()
            )
            _dev = _dev_row.device if _dev_row else None

            _wrote = []
            if _dev:
                if _os_str:
                    _dev.os_guess = _os_str
                    _dev.os_guess_at = _dt.utcnow()
                    _wrote.append(f"OS: {_os_str}")
                if _learned_ports:
                    # Union with the most recent ScanDevice that has port data,
                    # so quick scans + investigate stack instead of overwrite.
                    _existing_ports: set[int] = set()
                    _latest_with_ports = (
                        db.query(_ScanDevice)
                          .filter(
                              _ScanDevice.device_id == _dev.id,
                              _ScanDevice.open_ports.notin_(["[]", ""]),
                              _ScanDevice.open_ports.isnot(None),
                          )
                          .order_by(desc(_ScanDevice.id))
                          .first()
                    )
                    if _latest_with_ports:
                        try: _existing_ports = set(int(p) for p in _latest_with_ports.ports_list)
                        except Exception: pass
                    _merged = sorted(_existing_ports | _learned_ports)
                    # Stamp the most-recent ScanDevice row for this IP so /api/devices
                    # picks it up immediately (it queries latest scan and falls back
                    # to the most-recent row with port data).
                    _dev_row.open_ports = json.dumps(_merged)
                    _wrote.append(f"ports: {len(_merged)} ({len(_learned_ports)} new)")
                if _wrote:
                    db.commit()
                    progress_append("  Saved to device record: " + ", ".join(_wrote) + "\n")
        except Exception as _persist_ex:
            progress_append(f"  (could not persist findings: {_persist_ex})\n")

        # ── Tshark deep traffic analysis ──────────────────────────────────────
        progress_append("Analyzing traffic captures...\n")
        try:
            from traffic.interfaces import find_tool, _no_window as _nw2
            from traffic.analyzer import get_readable_files, CAPTURE_DIR
            _tshark = find_tool("tshark")
            if _tshark:
                _files = get_readable_files(CAPTURE_DIR, max_files=3)
                _protos: dict[str, int] = {}
                _dports: dict[str, int] = {}
                _pkt_total = 0
                for _pcap in _files:
                    try:
                        _tr = _sp.run(
                            [_tshark, "-r", str(_pcap), "-q",
                             "-Y", f"ip.addr == {item}",
                             "-T", "fields",
                             "-e", "frame.protocols",
                             "-e", "tcp.dstport", "-e", "udp.dstport"],
                            capture_output=True, text=True, timeout=20,
                            creationflags=_nw2(),
                        )
                        for _tl in _tr.stdout.splitlines():
                            if not _tl.strip():
                                continue
                            _pkt_total += 1
                            _tp = _tl.split("\t")
                            _proto = (_tp[0].split(":")[-1] if _tp else "").strip()
                            if _proto:
                                _protos[_proto] = _protos.get(_proto, 0) + 1
                            _port = (_tp[1] if len(_tp) > 1 and _tp[1] else
                                     _tp[2] if len(_tp) > 2 else "").strip()
                            if _port:
                                _dports[_port] = _dports.get(_port, 0) + 1
                    except Exception:
                        pass
                if _pkt_total:
                    _top_protos = sorted(_protos.items(), key=lambda x: -x[1])[:5]
                    _top_ports  = sorted(_dports.items(),  key=lambda x: -x[1])[:8]
                    evidence_lines.append(
                        f"Packet capture analysis ({_pkt_total} packets involving {item}):\n"
                        f"  Application layers: {', '.join(f'{p}({c}pkt)' for p, c in _top_protos)}\n"
                        f"  Destination ports:  {', '.join(f'{p}({c})' for p, c in _top_ports)}"
                    )
                else:
                    evidence_lines.append(f"No packets captured for {item} in recent capture files.")
        except Exception as ex:
            evidence_lines.append(f"Traffic analysis skipped: {ex}")

    else:
        evidence_lines.append(f"Item '{item}' is a general observation (not a domain or IP).")

    # ── Focused deep capture (if a targeted pcap was provided) ────────────────
    if deep_pcap_path and os.path.isfile(deep_pcap_path):
        try:
            from traffic.interfaces import find_tool, _no_window as _nw3
            _tshark3 = find_tool("tshark")
            if _tshark3:
                import subprocess as _sp3
                _dr = _sp3.run(
                    [_tshark3, "-r", deep_pcap_path, "-q",
                     "-T", "fields",
                     "-e", "frame.protocols", "-e", "ip.dst",
                     "-e", "tcp.dstport", "-e", "udp.dstport",
                     "-e", "dns.qry.name", "-e", "http.host",
                     "-e", "tls.handshake.extensions_server_name"],
                    capture_output=True, text=True, timeout=30,
                    creationflags=_nw3(),
                )
                _d_protos: dict = {}
                _d_dests:  dict = {}
                _d_hosts:  set  = set()
                _d_pkts = 0
                for _dl in _dr.stdout.splitlines():
                    _dp = _dl.split("\t")
                    if not _dp or not _dp[0]:
                        continue
                    _d_pkts += 1
                    _proto = (_dp[0].split(":")[-1] or "").strip()
                    if _proto:
                        _d_protos[_proto] = _d_protos.get(_proto, 0) + 1
                    _dst = _dp[1].strip() if len(_dp) > 1 else ""
                    if _dst and _dst != item:
                        _d_dests[_dst] = _d_dests.get(_dst, 0) + 1
                    for _hf in (_dp[4] if len(_dp) > 4 else "",
                                _dp[5] if len(_dp) > 5 else "",
                                _dp[6] if len(_dp) > 6 else ""):
                        if _hf and _hf.strip():
                            _d_hosts.add(_hf.strip())
                if _d_pkts:
                    _top_dp = sorted(_d_protos.items(), key=lambda x: -x[1])[:6]
                    _top_dd = sorted(_d_dests.items(),  key=lambda x: -x[1])[:8]
                    _dc_lines = [
                        f"FOCUSED CAPTURE — {_d_pkts} packets captured exclusively from {item}:",
                        f"  Protocols: {', '.join(f'{p}({c})' for p,c in _top_dp)}",
                        f"  Talking to: {', '.join(f'{d}({c}pkt)' for d,c in _top_dd)}",
                    ]
                    if _d_hosts:
                        _dc_lines.append(f"  Hostnames contacted: {', '.join(sorted(_d_hosts)[:12])}")
                    evidence_lines.insert(0, "\n".join(_dc_lines))
                else:
                    evidence_lines.insert(0, f"Focused capture file present but contained no packets for {item}.")
        except Exception as _dex:
            evidence_lines.insert(0, f"Focused capture analysis error: {_dex}")

    # ── Threat intelligence lookup ─────────────────────────────────────────────
    _ti_hits: list = []
    if is_ip or is_domain:
        progress_append("Checking threat intelligence feeds...\n")
        try:
            from ai.threat_intel import check as _ti_check, summary as _ti_summary, is_confirmed_malicious as _ti_critical
            _ti_hits = _ti_check(item)
            if _ti_hits:
                _ti_text = _ti_summary(_ti_hits)
                evidence_lines.append(_ti_text)
                progress_append(f"  THREAT INTEL HIT: {', '.join(h.label for h in _ti_hits)}\n")
            else:
                evidence_lines.append(f"Threat intelligence: no known listings for {item}")
                progress_append("  Clean — no threat intel matches\n")
        except Exception as _ti_ex:
            progress_append(f"  Threat intel check failed: {_ti_ex}\n")

    # ── User context note (provided via the follow-up box) ────────────────────
    if user_note:
        evidence_lines.insert(0, f"OWNER HINT (unverified — use as context, not fact): {user_note}")

    # ── Security Lab tool phase (IP investigations only) ──────────────────────
    if is_ip:
        from ai.investigation_tools import (
            check_existing_seclab_results,
            detect_http_ports,
            run_nikto_investigation,
            run_shodan_investigation,
        )

        # 1. Pull any existing Security Lab results for this IP (< 24h)
        progress_append("Checking Security Lab history for this IP...\n")
        _seclab = check_existing_seclab_results(db, item)
        if _seclab:
            for _sr in _seclab:
                evidence_lines.append(_sr)
            progress_append(f"  Found {len(_seclab)} recent Security Lab scan(s) — included in evidence\n")
        else:
            progress_append("  No recent Security Lab scans for this IP\n")

        # 2. Auto-run Nikto if HTTP ports are open
        progress_append("Checking for open HTTP ports...\n")
        _http_ports = detect_http_ports(item)
        if _http_ports:
            progress_append(f"  HTTP port(s) detected: {_http_ports} — running Nikto (up to 3 min)...\n")
            _nikto = run_nikto_investigation(item, _http_ports, timeout=180)
            evidence_lines.append(_nikto)
            progress_append(f"  Nikto complete\n")
        else:
            progress_append("  No HTTP ports open — skipping Nikto\n")

        # 3. Shodan exposure check
        progress_append("Shodan exposure check...\n")
        _shodan = run_shodan_investigation(item)
        evidence_lines.append(_shodan)
        progress_append(f"  {_shodan[:100]}\n")

    progress_append("Evidence gathered — asking AI to analyze...\n")
    evidence_block = "\n".join(evidence_lines) if evidence_lines else "No additional data gathered."

    # ── Phase 2: AI analysis with evidence ────────────────────────────────────

    resolution_options = (
        "AVAILABLE action_types (use ONLY these exact strings):\n"
        '- "label_device":          give ONE device a descriptive name. params: {ip, label}.\n'
        '  CRITICAL: label_device targets exactly ONE device. If you want to label N devices, produce N separate label_device actions, each with its own ip and label. NEVER combine two device names into one action.\n'
        '  params.ip MUST be a real IPv4 address (e.g. "192.168.1.39") — not a hostname, not two IPs, not "unknown".\n'
        '  params.label MUST be a specific human-readable name (e.g. "Wyze Smart Bulb", "Alex\'s Pixel 10") — not a combined name for two devices.\n'
        '- "mark_trusted":          mark as known/safe after confirming identity. params: {ip}\n'
        '- "mark_untrusted":        flag as untrusted — alerts on future scans. params: {ip}\n'
        '- "block_domain_outbound": block outbound traffic to a specific domain/service only — does NOT cut off the whole device. Use this when one app or service is the concern. params: {domain, reason}\n'
        '- "block_device":          mark untrusted + create persistent alert. params: {ip} — USE SPARINGLY, only when device itself is the threat.\n'
        '- "block_ip_firewall":     add Windows Firewall rules to block ALL traffic to/from device. params: {ip} — LAST RESORT ONLY, completely cuts device off network.\n'
        '- "create_alert":          log a persistent alert note. params: {message}\n'
        '- "no_action":             take no action now.\n'
        "\n"
        "PREFERRED ESCALATION ORDER: label_device → mark_untrusted → block_domain_outbound → block_device → block_ip_firewall\n"
        "If the concern is a SPECIFIC APP or SERVICE (Evernote, Teams, TikTok, etc.), use block_domain_outbound — not block_ip_firewall.\n"
        "block_ip_firewall cuts off phones/tablets entirely — only propose it for confirmed hostile devices with no legitimate owner.\n"
    )

    _own_machine_note = (
        f"\n⚠️  NETMON SERVER ALERT: {item} IS THIS MACHINE — the computer running NetMon itself.\n"
        "It will always have many open ports, connections, and high network activity because it is "
        "actively monitoring the network. This is 100% expected and normal. "
        "NEVER suggest blocking, marking untrusted, or flagging as suspicious. "
        "The only sensible actions are: label it and mark trusted.\n"
    ) if _is_own_machine else ""

    prompt = (
        "You are a friendly home network assistant helping a non-technical user understand "
        "their home devices. This is a PRIVATE RESIDENTIAL NETWORK — all devices are almost "
        "certainly owned by the household (family phones, laptops, smart TVs, routers, etc.).\n\n"

        "YOUR PRIMARY JOB IS TO IDENTIFY DEVICES, not to find threats. "
        "Default assumption: every device is NORMAL and owned by the family.\n\n"

        "VERDICT GUIDE — be very conservative:\n"
        '- "normal":     device is identified and behaves as expected. Use this for nearly everything.\n'
        '- "noise":      routine background traffic (mDNS, NTP, SSDP, DHCP, UPnP). Not a concern.\n'
        '- "suspicious": something genuinely unusual with NO innocent explanation AND no threat intel hit.\n'
        '                DO NOT use this just because a device has open ports, makes many connections,\n'
        '                or is unlabeled. Those are all completely normal for home devices.\n'
        '- "malicious":  ONLY when there is a confirmed THREAT INTELLIGENCE HIT in the evidence.\n'
        '                If threat intel is clean, the verdict CANNOT be malicious.\n\n'

        "BLOCKING RULES — extremely conservative:\n"
        "- NEVER suggest block_ip_firewall or block_device unless verdict is 'malicious' AND threat intel hit confirmed.\n"
        "- For 'suspicious': at most suggest mark_untrusted or create_alert. NEVER block.\n"
        "- Open ports on a device are NOT a reason to block — they are normal for smart home devices.\n"
        "- Many network connections are NOT a reason to block — phones and smart TVs connect constantly.\n\n"

        "DEVICE LABELS ARE NOT RELIABLE — DHCP assigns IPs dynamically:\n"
        "- A stored label like 'Alex's PC' was correct when that IP was last scanned with that MAC.\n"
        "- The IP may since have been reassigned to a completely different physical device.\n"
        "- ALWAYS cross-reference the MAC address (from ARP or DB) against the MAC vendor lookup.\n"
        "- If the MAC vendor doesn't match the label (e.g. label says 'Windows laptop' but MAC is a camera vendor),\n"
        "  the label is stale. Identify the device by its MAC vendor and open ports, NOT the old label.\n\n"

        + _own_machine_note

        + f"FLAGGED ITEM: {item}\n"
        f"CONTEXT: {context}\n"
        + (f"OWNER HINT: {user_note}\n" if user_note else "")
        + "\n"
        "=== EVIDENCE COLLECTED ===\n"
        f"{evidence_block}\n"
        "=== END EVIDENCE ===\n\n"
        f"{resolution_options}\n"
        "Return ONLY valid JSON matching this exact schema:\n"
        "{\n"
        '  "verdict": "normal" | "suspicious" | "noise" | "malicious",\n'
        '  "what": "one sentence — what is this device or domain?",\n'
        '  "findings": "2-4 sentences in plain English. Focus on IDENTIFYING the device. Only mention security concerns if the evidence specifically supports them.",\n'
        '  "auto_execute": "action_type to run immediately — for normal home devices use label_device or no_action",\n'
        '  "proposed_resolutions": [\n'
        '    {\n'
        '      "id": "r1",\n'
        '      "description": "Short button label (e.g. Label as Roku TV, Mark as Trusted)",\n'
        '      "why_it_helps": "One sentence",\n'
        '      "action_type": "...",\n'
        '      "params": {},\n'
        '      "impact": "low" | "medium" | "high"\n'
        '    }\n'
        '  ]\n'
        "}\n\n"
        "Rules:\n"
        "- auto_execute: for normal/noise verdicts use label_device (if you can identify it) or no_action.\n"
        "  Blocking actions ONLY if verdict=malicious AND threat intel confirmed. Never auto-block suspicious.\n"
        "- proposed_resolutions: 2-3 options. For normal devices: label + mark_trusted. "
        "  Avoid suggesting blocking unless malicious verdict.\n"
        "- Always include no_action as the last resolution.\n"
        "- Use the real IP from the evidence in every params object that requires one.\n"
        f"- The flagged item is {'an IP address — use it directly in params.' if is_ip else 'a domain. label_device/mark_trusted need a real IPv4 from the evidence — only include them if the evidence contains a specific source IP.'}\n"
        "- Label suggestions must be specific: use UPnP description, HTTP banner, MAC vendor, OS detection, "
        "  SSH banner, NetBIOS name. Examples: 'Alex's iPhone 15', 'Roku Streaming Stick 4K', "
        "  'Synology NAS', 'Orbi Router', 'HP OfficeJet Printer'.\n"
        "- findings: plain English only. No jargon. Focus on what the device IS, not what could go wrong.\n"
        + ("- OWNER HINT is the home owner's unverified opinion.\n" if user_note else "")
    )

    result = provider.analyze({}, prompt=prompt, kind="investigate")
    raw    = result.get("raw_response") or ""
    parsed = _extract_json(raw) if raw else {}

    # ── Auto-execute the AI's top recommendation ──────────────────────────────
    auto_action_type = parsed.get("auto_execute", "no_action") or "no_action"
    auto_executed    = None

    resolutions = parsed.get("proposed_resolutions") or []
    if not isinstance(resolutions, list):
        resolutions = []
    auto_res = next(
        (r for r in resolutions if isinstance(r, dict) and r.get("action_type") == auto_action_type),
        None,
    )

    # Guardrail — blocking actions need explicit user approval UNLESS
    # the evidence contains a confirmed threat intel hit (C2, malware, phishing).
    _BLOCKING_ACTIONS  = {"block_ip_firewall", "block_device", "block_domain_outbound"}
    _ALWAYS_BLOCKED    = {"unblock_ip_firewall"}   # never auto-fire regardless
    _verdict           = parsed.get("verdict", "")
    _has_threat_intel  = any("THREAT INTELLIGENCE HIT" in e for e in evidence_lines)

    if auto_action_type in _ALWAYS_BLOCKED:
        auto_executed = {
            "action_type": auto_action_type,
            "error": f"auto_execute blocked: '{auto_action_type}' always requires explicit user approval.",
        }
        auto_action_type = "no_action"
    elif auto_action_type in _BLOCKING_ACTIONS and not (_verdict == "malicious" and _has_threat_intel):
        auto_executed = {
            "action_type": auto_action_type,
            "error": f"auto_execute blocked: '{auto_action_type}' requires explicit user approval — not auto-fired.",
        }
        auto_action_type = "no_action"
    elif auto_action_type in {"block_ip_firewall", "block_device"} and auto_res:
        _target_ip = (auto_res.get("params") or {}).get("ip", "")
        _protected_reason = explain_protected_target(_target_ip)
        if _protected_reason:
            auto_executed = {
                "action_type": auto_action_type,
                "error": f"auto_execute blocked: {_protected_reason}",
            }
            auto_action_type = "no_action"

    if auto_action_type and auto_action_type != "no_action" and auto_res:
        try:
            exec_body   = {"action_type": auto_action_type, "params": auto_res.get("params", {})}
            exec_result = ai_resolve(exec_body, db)
            _exec_ok = isinstance(exec_result, dict) and bool(exec_result.get("success"))
            try:
                from ai.knowledge_bridge import record_remediation_outcome
                _lesson_service_map = {
                    "block_ip_firewall": "security",
                    "block_device": "security",
                    "block_domain_outbound": "dns",
                    "whitelist_domain": "dns",
                    "remove_from_whitelist": "dns",
                    "unblock_ip_firewall": "security",
                    "unblock_domain_outbound": "dns",
                    "unblock_by_rule_names": "security",
                    "mark_untrusted": "device",
                    "mark_trusted": "device",
                    "label_device": "device",
                    "create_alert": "device",
                }
                record_remediation_outcome(
                    service=_lesson_service_map.get(auto_action_type, "netmon"),
                    evidence={
                        "item": item,
                        "context": (context or "")[:500],
                        "verdict": parsed.get("verdict"),
                        "what": (parsed.get("what") or "")[:200],
                    },
                    action=auto_action_type,
                    params=auto_res.get("params", {}),
                    success=_exec_ok,
                    summary=f"AI auto-executed {auto_action_type} on {item}: "
                            f"{(parsed.get('what') or '')[:160]}",
                    severity=("high" if parsed.get("verdict") == "malicious" else "medium"),
                )
            except Exception:
                pass  # never let learning break the action path
            if _exec_ok:
                auto_executed = {
                    "action_type":  auto_action_type,
                    "description":  auto_res.get("description", ""),
                    "why_it_helps": auto_res.get("why_it_helps", ""),
                    "result":       exec_result.get("description", ""),
                    "revert":       exec_result.get("revert"),
                }
                resolutions = [r for r in resolutions if r.get("action_type") != auto_action_type]
                # Audit row tagged as autonomous + reversible. ai_resolve's own
                # write_log captures the underlying change; this row provides
                # the revert payload the dashboard's Undo button will use.
                if exec_result.get("revert"):
                    write_log(
                        "action", "ai", "ai_auto_action",
                        f"AI auto-executed: {auto_action_type} on {item} — {exec_result.get('description', '')}",
                        detail={
                            "item":         item,
                            "action_type":  auto_action_type,
                            "params":       auto_res.get("params", {}),
                            "result":       exec_result.get("description", ""),
                            "why_it_helps": auto_res.get("why_it_helps", ""),
                        },
                        device_ip=item if is_ip else None,
                        actor="ai_auto",
                        revert=exec_result.get("revert"),
                    )
        except Exception as ex:
            auto_executed = {"action_type": auto_action_type, "error": str(ex)}

    _final_verdict = parsed.get("verdict", "unknown")
    _level_map     = {"malicious": "threat", "suspicious": "warning", "critical": "critical"}
    _log_level     = _level_map.get(_final_verdict, "info")
    write_log(
        _log_level, "ai", "ai_verdict",
        f"AI verdict for {item}: {_final_verdict} — {parsed.get('what', '')}",
        detail={
            "item":          item,
            "verdict":       _final_verdict,
            "what":          parsed.get("what"),
            "findings":      parsed.get("findings"),
            "auto_executed": auto_executed,
            "threat_intel":  _has_threat_intel,
        },
        device_ip=item if is_ip else None,
    )

    # For domain investigations always offer whitelist/unblock — this is the
    # primary user action after investigating a DNS blocked domain.
    if is_domain:
        _wl_option = {
            "action_type":  "whitelist_domain",
            "description":  f"Add to whitelist — never block {item} again",
            "params":       {"domain": item},
            "why_it_helps": "Stops the DNS blocker from intercepting this domain so affected devices work normally.",
        }
        # Put it first if domain appears benign, last if suspicious/malicious
        if _final_verdict in ("benign", "unknown"):
            resolutions = [_wl_option] + resolutions
        else:
            resolutions = resolutions + [_wl_option]

    return {
        "verdict":              _final_verdict,
        "what":                 parsed.get("what", ""),
        "findings":             parsed.get("findings", ""),
        "sources":              sources,
        "evidence_items":       evidence_lines,
        "auto_executed":        auto_executed,
        "proposed_resolutions": resolutions,
        "model":                result.get("model", ""),
        "error":                result.get("error") if not parsed else None,
        "raw":                  raw if not parsed else None,
        # Echo back so the frontend can pass these on follow-up calls
        "item":                 item,
        "context":              context,
    }


@router.post("/api/ai/resolve")
def ai_resolve(body: dict, db: Session = Depends(get_db)):
    """
    Execute a resolution proposed by /api/ai/investigate.

    Body: { "action_type": "label_device", "params": {"ip": "...", "label": "..."} }
    Returns: { "success": bool, "description": str, "revert": {action_type, params} }
    """
    action_type = (body.get("action_type") or "").strip()
    params      = body.get("params") or {}

    def _dismiss_device_alerts(dev, alert_types=("new_device",)):
        """
        Mark matching unread alerts for this device as read.
        Only targets the alert types passed in — defaults to 'new_device' so that
        port-change alerts, suspicious-activity flags, and manual AI notes are
        left visible (they are different events, not the same one being re-shown).
        """
        if dev is None:
            return
        unread = (
            db.query(Alert)
            .filter(
                Alert.device_id == dev.id,
                Alert.read == False,
                Alert.alert_type.in_(alert_types),
            )
            .all()
        )
        for a in unread:
            a.read = True
        if unread:
            db.commit()

    if action_type == "no_action":
        return {"success": True, "description": "No action taken.", "revert": None}

    if action_type == "label_device":
        ip    = (params.get("ip") or "").strip()
        label = (params.get("label") or "").strip()
        import re as _re
        if not ip:
            raise HTTPException(status_code=400, detail="label_device requires params.ip (a single IPv4 address)")
        if not label:
            raise HTTPException(status_code=400, detail="label_device requires params.label (a device name)")
        if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            raise HTTPException(status_code=400, detail=f"params.ip must be a single IPv4 address, got: {ip!r}")
        sd = db.query(ScanDevice).filter(ScanDevice.ip == ip).order_by(desc(ScanDevice.id)).first()
        dev = sd.device if sd else None
        if not dev:
            raise HTTPException(status_code=404, detail=f"No device found for {ip}")
        old_label = dev.label or ""
        dev.label = label
        db.commit()
        _dismiss_device_alerts(dev)
        write_log("action", "ai", "device_labeled",
                  f"Device labeled: {ip} → '{label}'" + (f" (was: '{old_label}')" if old_label else ""),
                  detail={"ip": ip, "label": label, "old_label": old_label},
                  device_ip=ip, device_id=dev.id)
        return {
            "success": True,
            "description": f"Labeled {ip} as '{label}'. Related alerts dismissed.",
            "revert": {"action_type": "label_device", "params": {"ip": ip, "label": old_label or "(clear label)"}},
        }

    if action_type in ("mark_untrusted", "mark_trusted"):
        ip      = params.get("ip", "")
        trusted = (action_type == "mark_trusted")
        if not ip:
            raise HTTPException(status_code=400, detail="ip required")
        sd = db.query(ScanDevice).filter(ScanDevice.ip == ip).order_by(desc(ScanDevice.id)).first()
        dev = sd.device if sd else None
        if not dev:
            raise HTTPException(status_code=404, detail=f"No device found for {ip}")
        old_known = dev.is_known
        dev.is_known = trusted
        db.commit()
        if trusted:
            _dismiss_device_alerts(dev)
        verb   = "trusted" if trusted else "untrusted"
        revert = "mark_trusted" if not trusted else "mark_untrusted"
        dismissed_note = " Alerts for this device dismissed." if trusted else ""
        return {
            "success": True,
            "description": f"Marked {ip} as {verb}.{dismissed_note}",
            "revert": {"action_type": revert, "params": {"ip": ip}},
        }

    if action_type == "create_alert":
        ip      = params.get("ip", "")
        message = params.get("message", "")
        if not message:
            raise HTTPException(status_code=400, detail="message required")
        alert = Alert(
            alert_type = "manual",
            message    = f"[AI Investigation] {message}",
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return {
            "success": True,
            "description": f"Alert created: {message}",
            "revert": {"action_type": "delete_alert", "params": {"alert_id": alert.id}},
        }

    if action_type == "delete_alert":
        alert_id = params.get("alert_id")
        if not alert_id:
            raise HTTPException(status_code=400, detail="alert_id required")
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            db.delete(alert)
            db.commit()
        return {"success": True, "description": f"Alert {alert_id} deleted.", "revert": None}

    if action_type == "block_ip_firewall":
        import subprocess as _fwsp
        ip = params.get("ip", "")
        if not ip:
            raise HTTPException(status_code=400, detail="ip required")
        try:
            ip = validate_block_target(ip)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=f"refusing firewall block: {exc}")
        rule_in  = f"NetMon-Block-{ip}-IN"
        rule_out = f"NetMon-Block-{ip}-OUT"
        errors = []
        _cflags = getattr(_fwsp, "CREATE_NO_WINDOW", 0)
        for rule_name, direction in [(rule_in, "in"), (rule_out, "out")]:
            r = _fwsp.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", f"dir={direction}", "action=block",
                 f"remoteip={ip}", "enable=yes", "profile=any"],
                capture_output=True, text=True, timeout=10,
                creationflags=_cflags,
            )
            if r.returncode != 0:
                errors.append(r.stderr.strip() or r.stdout.strip())
        if errors:
            raise HTTPException(status_code=500, detail=f"Firewall rule failed: {'; '.join(errors)}")
        # Also mark untrusted in DB and close any open alerts (replaced by the block action)
        sd  = db.query(ScanDevice).filter(ScanDevice.ip == ip).order_by(desc(ScanDevice.id)).first()
        dev = sd.device if sd else None
        if dev:
            dev.is_known = False
            db.commit()
            _dismiss_device_alerts(dev)
        write_log("action", "firewall", "firewall_blocked",
                  f"Firewall: ALL traffic blocked for {ip}",
                  detail={"ip": ip, "rules": [f"NetMon-Block-{ip}-IN", f"NetMon-Block-{ip}-OUT"]},
                  device_ip=ip)
        return {
            "success": True,
            "description": (
                f"Windows Firewall rules added: all traffic to and from {ip} is now blocked. "
                f"Device marked as untrusted and alerts dismissed."
            ),
            "revert": {"action_type": "unblock_ip_firewall", "params": {"ip": ip}},
        }

    if action_type == "unblock_ip_firewall":
        import subprocess as _fwsp
        ip = params.get("ip", "")
        if not ip:
            raise HTTPException(status_code=400, detail="ip required")
        _cflags = getattr(_fwsp, "CREATE_NO_WINDOW", 0)
        for rule_name in [f"NetMon-Block-{ip}-IN", f"NetMon-Block-{ip}-OUT"]:
            _fwsp.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True, text=True, timeout=10,
                creationflags=_cflags,
            )
        write_log("action", "firewall", "firewall_unblocked",
                  f"Firewall: rules removed, {ip} is now unblocked",
                  device_ip=ip)
        return {
            "success": True,
            "description": f"Firewall rules removed: {ip} is now unblocked.",
            "revert": {"action_type": "block_ip_firewall", "params": {"ip": ip}},
        }

    if action_type == "block_device":
        # Mark untrusted AND create an alert — the closest we can do without firewall access
        ip      = params.get("ip", "")
        message = params.get("message", f"Device {ip} flagged as potentially hostile by AI investigation.")
        if not ip:
            raise HTTPException(status_code=400, detail="ip required")
        try:
            ip = validate_block_target(ip)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=f"refusing device block: {exc}")
        sd  = db.query(ScanDevice).filter(ScanDevice.ip == ip).order_by(desc(ScanDevice.id)).first()
        dev = sd.device if sd else None
        if not dev:
            raise HTTPException(status_code=404, detail=f"No device found for {ip}")
        dev.is_known = False
        # Dismiss existing alerts and replace with one definitive BLOCKED alert
        _dismiss_device_alerts(dev)
        alert = Alert(
            alert_type = "manual",
            message    = f"[BLOCKED] {message}",
            device_id  = dev.id,
        )
        db.add(alert)
        db.commit()
        write_log("action", "firewall", "device_blocked",
                  f"Device blocked: {ip} marked untrusted and persistent block alert created",
                  detail={"ip": ip, "message": message}, device_ip=ip, device_id=dev.id)
        return {
            "success": True,
            "description": f"Blocked {ip}: marked untrusted, prior alerts dismissed, block alert created.",
            "revert": {"action_type": "mark_trusted", "params": {"ip": ip}},
        }

    if action_type == "block_domain_outbound":
        import subprocess as _fwsp
        import socket as _sock
        domain = (params.get("domain") or "").strip().lstrip("*. ")
        reason = params.get("reason", f"Blocked by NetMon AI investigation")
        if not domain:
            raise HTTPException(status_code=400, detail="domain required")

        # Resolve domain to IPs via 8.8.8.8 directly (bypass local DNS blocker)
        resolved_ips: list[str] = []
        try:
            import struct as _fwst, random as _fwrand
            _qid  = _fwrand.randint(0, 65535)
            _name = b"".join(len(p).to_bytes(1,"big") + p.encode() for p in domain.split(".")) + b"\x00"
            _pkt  = _fwst.pack(">HHHHHH", _qid, 0x0100, 1, 0, 0, 0) + _name + _fwst.pack(">HH", 1, 1)
            with _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM) as _fwu:
                _fwu.settimeout(5)
                _fwu.sendto(_pkt, ("8.8.8.8", 53))
                _fwd, _ = _fwu.recvfrom(512)
            _off = 12
            while _fwd[_off] != 0: _off += _fwd[_off] + 1
            _off += 5
            for _ in range(_fwst.unpack(">H", _fwd[6:8])[0]):
                if _fwd[_off] & 0xC0 == 0xC0: _off += 2
                else:
                    while _fwd[_off] != 0: _off += _fwd[_off] + 1
                    _off += 1
                _rt, _, _, _rl = _fwst.unpack(">HHIH", _fwd[_off:_off+10]); _off += 10
                if _rt == 1 and _rl == 4:
                    resolved_ips.append(".".join(str(b) for b in _fwd[_off:_off+4]))
                _off += _rl
        except Exception:
            pass
        resolved_ips, skipped_ips = filter_blockable_ips(resolved_ips)

        rule_names: list[str] = []
        errors:     list[str] = skipped_ips[:]

        for ip4 in resolved_ips:
            rule = f"NetMon-DomainBlock-{domain}-{ip4}"
            rule_names.append(rule)
            for direction in ("out",):
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule}",
                    "dir=out",
                    "action=block",
                    "protocol=TCP",
                    f"remoteip={ip4}",
                    "remoteport=80,443",
                    "enable=yes",
                    f"description=NetMon: {reason}",
                ]
                try:
                    _fwsp.run(cmd, check=True, capture_output=True,
                              creationflags=getattr(_fwsp, "CREATE_NO_WINDOW", 0x08000000))
                except Exception as ex:
                    errors.append(f"{ip4}: {ex}")

        # Log persistent alert
        alert = Alert(
            alert_type = "manual",
            message    = (
                f"[DOMAIN BLOCKED] {domain} — {reason}. "
                + (f"Firewall rules added for {len(resolved_ips)} IP(s): {', '.join(resolved_ips)}."
                   if resolved_ips else "No IPs resolved; no firewall rules created.")
                + " NOTE: This blocks traffic from the NetMon host only. "
                  "For network-wide blocking, also add a DNS entry or router ACL."
            ),
        )
        db.add(alert)
        db.commit()

        if errors:
            return {
                "success": False,
                "description": f"Partial block for {domain}: {'; '.join(errors)}",
                "revert": {"action_type": "unblock_domain_outbound", "params": {"domain": domain, "rule_names": rule_names}},
            }

        ip_list = ", ".join(resolved_ips) if resolved_ips else "none resolved"
        write_log("action", "firewall", "domain_blocked",
                  f"Domain blocked: {domain} ({ip_list}) — {reason}",
                  detail={"domain": domain, "resolved_ips": resolved_ips, "reason": reason})
        return {
            "success": True,
            "description": (
                f"Outbound traffic to {domain} blocked ({ip_list}). "
                "Firewall rules added for ports 80 and 443 on this host. "
                "To block network-wide, add a DNS block or router ACL."
            ),
            "revert": {"action_type": "unblock_domain_outbound", "params": {"domain": domain, "rule_names": rule_names}},
        }

    if action_type == "unblock_domain_outbound":
        import subprocess as _fwsp
        domain     = (params.get("domain") or "").strip()
        rule_names = params.get("rule_names") or []
        if not domain and not rule_names:
            raise HTTPException(status_code=400, detail="domain or rule_names required")

        removed, errors = [], []
        for rule in rule_names:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
            try:
                _fwsp.run(cmd, check=True, capture_output=True,
                          creationflags=getattr(_fwsp, "CREATE_NO_WINDOW", 0x08000000))
                removed.append(rule)
            except Exception as ex:
                errors.append(f"{rule}: {ex}")

        if errors:
            return {
                "success": False,
                "description": f"Partial unblock for {domain}: {'; '.join(errors)}",
                "revert": None,
            }
        return {
            "success": True,
            "description": f"Domain block for {domain} removed ({len(removed)} rule(s) deleted).",
            "revert": None,
        }

    if action_type == "whitelist_domain":
        import json as _json
        domain = (params.get("domain") or "").strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="domain required")
        # Add to in-memory whitelist immediately (takes effect on next DNS query)
        from dns_blocker import blocklist as _bl
        _bl.WHITELIST.add(domain)
        # Persist to DB under dns_user_whitelist (JSON array)
        _wl_key = "dns_user_whitelist"
        _wl_row = db.query(Setting).filter(Setting.key == _wl_key).first()
        _wl_list = _json.loads(_wl_row.value) if (_wl_row and _wl_row.value) else []
        if domain not in _wl_list:
            _wl_list.append(domain)
            if _wl_row:
                _wl_row.value = _json.dumps(_wl_list)
            else:
                db.add(Setting(key=_wl_key, value=_json.dumps(_wl_list)))
            db.commit()
        write_log("action", "dns", "dns_whitelisted",
                  f"Domain added to whitelist: {domain} — will no longer be blocked",
                  detail={"domain": domain})
        return {
            "success": True,
            "description": f"'{domain}' added to DNS whitelist. It will never be blocked again.",
            "revert": {"action_type": "remove_from_whitelist", "params": {"domain": domain}},
        }

    if action_type == "remove_from_whitelist":
        import json as _json
        domain = (params.get("domain") or "").strip().lower().rstrip(".")
        if not domain:
            raise HTTPException(status_code=400, detail="domain required")
        from dns_blocker import blocklist as _bl
        _bl.WHITELIST.discard(domain)
        _wl_key = "dns_user_whitelist"
        _wl_row = db.query(Setting).filter(Setting.key == _wl_key).first()
        if _wl_row and _wl_row.value:
            _wl_list = _json.loads(_wl_row.value)
            _wl_list = [d for d in _wl_list if d != domain]
            _wl_row.value = _json.dumps(_wl_list)
            db.commit()
        return {"success": True, "description": f"'{domain}' removed from whitelist and will be blocked again.", "revert": None}

    if action_type == "unblock_by_rule_names":
        # Generic firewall-rule revert. Each autonomous block records the exact
        # rule names it created in revert_json so this works regardless of
        # whether the block came from anomaly detection, ntfy command, or AI.
        import subprocess as _ubrn_sp
        rule_names = params.get("rule_names") or []
        ip         = params.get("ip") or ""
        if not isinstance(rule_names, list) or not rule_names:
            raise HTTPException(status_code=400, detail="rule_names (non-empty list) required")
        _cflags = getattr(_ubrn_sp, "CREATE_NO_WINDOW", 0x08000000)
        removed = []
        for rule in rule_names:
            try:
                r = _ubrn_sp.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_cflags,
                )
                if r.returncode == 0:
                    removed.append(rule)
            except Exception:
                pass
        write_log(
            "action", "firewall", "rules_removed",
            f"Reverted firewall block: removed {len(removed)} rule(s)" + (f" for {ip}" if ip else ""),
            detail={"rule_names": rule_names, "removed": removed, "ip": ip},
            device_ip=ip or None,
            actor="user",
        )
        return {
            "success": True,
            "description": f"Removed {len(removed)} firewall rule(s)" + (f" for {ip}." if ip else "."),
            "revert": None,
        }

    raise HTTPException(status_code=400, detail=f"Unknown action_type: {action_type}")


# ── Deep / Focused Packet Capture ────────────────────────────────────────────
#
# Starts a targeted tshark capture filtered to one IP for N seconds.
# Returns a capture_id immediately; the frontend polls until status == "done",
# then re-calls ai_investigate with deep_pcap_path set to the saved file.
#
# NOTE: On a typical switched home network this machine can only see its own
# traffic and broadcast frames. Traffic between two OTHER devices is not visible.
# The focused capture is most useful for watching what the device sends TO/FROM
# this server (NetMon host), and any broadcast/mDNS/ARP traffic it emits.

@router.post("/api/ai/deep_capture/start")
def start_deep_capture(body: dict):
    import subprocess as _dcsp
    from traffic.interfaces import find_tool, list_interfaces, _no_window as _dcnw

    ip       = (body.get("ip") or "").strip()
    duration = min(max(int(body.get("duration", 30)), 10), 120)
    if not ip:
        raise HTTPException(status_code=400, detail="ip required")

    capture_id = uuid.uuid4().hex[:10]
    pcap_path  = os.path.abspath(f"data/captures/deep_{capture_id}.pcapng")

    _deep_captures[capture_id] = {
        "status":     "starting",
        "ip":         ip,
        "duration":   duration,
        "pcap_path":  pcap_path,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "error":      None,
    }

    def _run():
        tshark = find_tool("tshark")
        if not tshark:
            _deep_captures[capture_id]["status"] = "error"
            _deep_captures[capture_id]["error"]  = "tshark not found — install Wireshark to enable focused capture"
            return

        iface_info = list_interfaces()
        if not iface_info["available"] or not iface_info["interfaces"]:
            _deep_captures[capture_id]["status"] = "error"
            _deep_captures[capture_id]["error"]  = "No capture interface found (install Wireshark / Npcap)"
            return

        # Use the first interface — same one the ring-buffer capture uses
        iface = iface_info["interfaces"][0]["name"]
        _deep_captures[capture_id]["status"]    = "capturing"
        _deep_captures[capture_id]["interface"] = iface_info["interfaces"][0].get("display", iface)

        os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
        try:
            r = _dcsp.run(
                [tshark, "-i", iface,
                 "-f", f"host {ip}",      # BPF filter — only this IP
                 "-w", pcap_path,
                 "-a", f"duration:{duration}",
                 "-q"],
                capture_output=True, text=True,
                timeout=duration + 20,
                creationflags=_dcnw(),
            )
            if r.returncode == 0 and os.path.isfile(pcap_path):
                _deep_captures[capture_id]["status"] = "done"
            else:
                _deep_captures[capture_id]["status"] = "error"
                _deep_captures[capture_id]["error"]  = (r.stderr or r.stdout or "capture process exited non-zero").strip()
        except Exception as ex:
            _deep_captures[capture_id]["status"] = "error"
            _deep_captures[capture_id]["error"]  = str(ex)

    threading.Thread(target=_run, daemon=True).start()
    return {"capture_id": capture_id, "ip": ip, "duration": duration}


@router.get("/api/ai/deep_capture/{capture_id}")
def poll_deep_capture(capture_id: str):
    state = _deep_captures.get(capture_id)
    if not state:
        raise HTTPException(status_code=404, detail="Unknown capture_id")
    return state


@router.get("/api/ai/progress")
def ai_progress():
    """
    Live progress of the currently-running AI analysis (or last finished one).
    The frontend polls this every ~500ms while waiting for a result, so the
    user can see the AI's response forming in real time.

    Returns no-store headers so browsers don't cache the polling response.

    Shape:
      { id, kind, status: idle|running|done|error,
        partial: str, chars: int,
        started_at: float, updated_at: float,
        elapsed_s: float,
        error: str|None }
    """
    import time
    from fastapi.responses import JSONResponse
    from ai.provider import progress_snapshot
    snap = progress_snapshot()
    started = snap.get("started_at") or 0
    snap["elapsed_s"] = round(time.time() - started, 1) if started else 0
    return JSONResponse(
        content=snap,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma":        "no-cache",
        },
    )


@router.get("/api/ai/latest")
def ai_latest(db: Session = Depends(get_db)):
    """
    Return the most recent AI summary, or a status object if none exists.

    Shape:
      { id, created_at, scan_id, provider, model,
        summary, severity, benign[], concerning[], next_steps[],
        input_tokens, output_tokens, error }

    The 'error' field being set does NOT mean HTTP error — it means the
    AI analysis itself failed or is disabled. The dashboard handles this.
    """
    from ai.analyst import get_latest

    # Check if AI is even enabled so the UI can show the right empty state
    ai_enabled = _get_setting_str(db, "ai_enabled", "false").lower() == "true"

    result = get_latest(db)
    if result is None:
        return {
            "id":           None,
            "ai_enabled":   ai_enabled,
            "summary":      None,
            "error":        "No analysis run yet" if ai_enabled else "AI is disabled",
        }

    result["ai_enabled"] = ai_enabled
    return result


# ═════════════════════════════════════════════════════════════════════════════
# ALERTS
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/alerts")
def get_alerts(limit: int = 100, db: Session = Depends(get_db)):
    """Return recent alerts newest-first, with unread count."""
    alerts      = db.query(Alert).order_by(desc(Alert.id)).limit(limit).all()
    unread_count = db.query(Alert).filter(Alert.read == False).count()
    return {
        "unread_count": unread_count,
        "alerts": [
            {
                "id":         a.id,
                "created_at": _iso(a.created_at),
                "alert_type": a.alert_type,
                "message":    a.message,
                "read":       a.read,
                "device_id":  a.device_id,
            }
            for a in alerts
        ],
    }


@router.post("/api/alerts/{alert_id}/read")
def mark_alert_read(alert_id: int, db: Session = Depends(get_db)):
    """Mark a single alert as read."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.read = True
    db.commit()
    return {"id": alert.id, "read": True}


@router.post("/api/alerts/read-all")
def mark_all_alerts_read(db: Session = Depends(get_db)):
    """Mark all unread alerts as read."""
    db.query(Alert).filter(Alert.read == False).update({"read": True})
    db.commit()
    return {"status": "ok"}


@router.delete("/api/alerts/clear-read")
def clear_read_alerts(db: Session = Depends(get_db)):
    """Delete every alert that has already been marked read — clears the backlog."""
    deleted = db.query(Alert).filter(Alert.read == True).delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted}


@router.delete("/api/alerts/{alert_id}")
def delete_alert_route(alert_id: int, db: Session = Depends(get_db)):
    """Permanently delete a single alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"id": alert_id, "deleted": True}


@router.post("/api/alerts/{alert_id}/explain")
def explain_alert(alert_id: int, db: Session = Depends(get_db)):
    """Generate an AI-powered explanation for a specific alert."""
    from models.tables import Alert, Device
    from ai.provider import get_investigation_provider

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    provider = get_investigation_provider()
    if provider.name == "none":
        raise HTTPException(status_code=400, detail="AI is not configured.")

    device_info = ""
    if alert.device_id:
        device = db.query(Device).filter(Device.id == alert.device_id).first()
        if device:
            device_info = (
                f"Device details:\n"
                f"- IP: {device.ip}\n"
                f"- Hostname: {device.hostname or 'unknown'}\n"
                f"- Vendor: {device.vendor or 'unknown'}\n"
                f"- Label: {device.label or 'None'}\n"
                f"- Trusted: {device.trusted}\n"
            )

    prompt = (
        f"You are NetMon AI. Explain the following network alert in clear, friendly, and non-technical terms "
        f"for a home network owner. Explain why it might have happened, whether they should be worried, "
        f"and what simple steps they should take to resolve or verify it.\n\n"
        f"Alert Type: {alert.alert_type}\n"
        f"Alert Message: {alert.message}\n"
        f"Alert Date: {alert.created_at.isoformat()}\n"
        f"{device_info}\n"
        f"Please provide a concise explanation (1-2 paragraphs) in Markdown format."
    )

    result = provider.analyze({}, prompt=prompt, kind="alert_explain")
    if result.get("error"):
        raise HTTPException(status_code=500, detail=f"AI error: {result['error']}")

    explanation = result.get("raw_response") or result.get("summary") or ""
    if not explanation.strip():
        raise HTTPException(status_code=500, detail="AI returned an empty explanation.")

    return {"explanation": explanation.strip()}


@router.post("/api/ai/contextual-insight")
def get_contextual_insight(body: dict, db: Session = Depends(get_db)):
    """
    Generate a 2-sentence summary: 'What happened' and 'Why it matters' for any finding or alert.
    """
    from ai.provider import get_investigation_provider

    ai_enabled = _get_setting_str(db, "ai_enabled", "false").lower() == "true"
    if not ai_enabled:
        raise HTTPException(status_code=400, detail="AI is disabled in Settings")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    text = body.get("text")
    if text is None:
        raise HTTPException(status_code=400, detail="text is required")
    if not isinstance(text, str):
        raise HTTPException(status_code=400, detail="text must be a string")
    text = text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="text cannot be empty")
    if len(text) > 5000:
        raise HTTPException(status_code=400, detail="text parameter exceeds maximum length of 5000 characters")

    context = body.get("context", "")
    if context is None:
        context = ""
    if not isinstance(context, str):
        raise HTTPException(status_code=400, detail="context must be a string")
    context = context.strip()
    if len(context) > 5000:
        raise HTTPException(status_code=400, detail="context parameter exceeds maximum length of 5000 characters")

    provider = get_investigation_provider()
    if provider.name == "none":
        raise HTTPException(status_code=400, detail="AI is not configured.")

    prompt = (
        "You are NetMon Security Assistant. You must analyze the following security finding or health alert "
        "and generate a response containing exactly two sentences.\n"
        "Sentence 1 must start with 'What happened: ' and explain what the event/finding means.\n"
        "Sentence 2 must start with 'Why it matters: ' and explain why this is important, why they should care, or what the impact is.\n\n"
        "Keep it concise, friendly, and non-technical. Do not use technical jargon.\n\n"
        f"Item details: {text}\n"
        f"Additional context: {context}\n"
    )

    try:
        result = provider.analyze({}, prompt=prompt, kind="contextual_insight")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed to execute: {str(e)}")

    if not isinstance(result, dict):
        raise HTTPException(status_code=500, detail="AI provider returned an invalid response format.")

    if result.get("error"):
        raise HTTPException(status_code=500, detail=f"AI error: {result['error']}")

    explanation = result.get("raw_response") or result.get("summary") or ""
    if not isinstance(explanation, str):
        raise HTTPException(status_code=500, detail="AI provider returned a non-string explanation.")

    explanation = explanation.strip()
    if not explanation:
        raise HTTPException(status_code=500, detail="AI returned an empty explanation.")

    return {"explanation": explanation}





# ═════════════════════════════════════════════════════════════════════════════
# ACTIVITY LOG
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/logs")
def get_activity_logs(
    category: str = "",
    level:    str = "",
    event:    str = "",
    actor:    str = "",
    device_ip: str = "",
    search:   str = "",
    limit:    int = 50,
    offset:   int = 0,
    db: Session = Depends(get_db),
):
    """
    Fetch paginated activity log entries.

    Query params:
      category — filter by category (scan|traffic|ai|firewall|threat|system|alert)
      level    — filter by level (info|warning|critical|action|threat)
      event    — filter by machine event name
      actor    — filter by initiator (system|user|ai_auto|anomaly_auto|ntfy_command)
      device_ip — filter by device IP
      search   — substring match against summary, detail, event, actor, or device_ip
      limit    — rows to return (max 200)
      offset   — pagination offset
    """
    from sqlalchemy import or_

    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    q = db.query(ActivityLog).order_by(ActivityLog.id.desc())
    if category:
        q = q.filter(ActivityLog.category == category)
    if level:
        q = q.filter(ActivityLog.level == level)
    if event:
        q = q.filter(ActivityLog.event == event)
    if actor:
        q = q.filter(ActivityLog.actor == actor)
    if device_ip:
        q = q.filter(ActivityLog.device_ip == device_ip)
    if search:
        like = f"%{search}%"
        q = q.filter(or_(
            ActivityLog.summary.ilike(like),
            ActivityLog.detail.ilike(like),
            ActivityLog.event.ilike(like),
            ActivityLog.actor.ilike(like),
            ActivityLog.device_ip.ilike(like),
        ))

    total = q.count()
    rows  = q.offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": [
            {
                "id":         r.id,
                "created_at": _iso(r.created_at),
                "level":      r.level,
                "category":   r.category,
                "event":      r.event,
                "summary":    r.summary,
                "detail":     r.detail,
                "device_ip":  r.device_ip,
                "device_id":  r.device_id,
                "actor":      r.actor,
                "reversible": bool(r.revert_json) and r.reverted_at is None,
                "reverted_at": _iso(r.reverted_at),
                "reverted_by": r.reverted_by,
            }
            for r in rows
        ],
    }


@router.get("/api/logs/facets")
def get_activity_log_facets(db: Session = Depends(get_db)):
    """Return lightweight log filter metadata for custom queries."""
    from sqlalchemy import func

    def _counts(column, limit=50):
        rows = (
            db.query(column, func.count(ActivityLog.id))
            .group_by(column)
            .order_by(func.count(ActivityLog.id).desc())
            .limit(limit)
            .all()
        )
        return [{"value": value, "count": count} for value, count in rows if value]

    return {
        "levels": _counts(ActivityLog.level),
        "categories": _counts(ActivityLog.category),
        "events": _counts(ActivityLog.event),
        "actors": _counts(ActivityLog.actor),
    }


@router.get("/api/logs/insights")
def get_activity_log_insights(
    days: int = 7,
    db: Session = Depends(get_db),
):
    """Return deterministic, non-AI history insights for the requested window."""
    from ai.history import build_history_context

    return build_history_context(db, days=days)


@router.post("/api/ai/history-synthesis")
def run_history_synthesis(body: dict | None = None, db: Session = Depends(get_db)):
    """
    Ask AI to synthesize recent logs, alerts, health, reports, and traffic history.
    This does not execute network/security actions. It writes one queryable
    ActivityLog row with event=history_synthesis.
    """
    body = body or {}
    if _get_setting_str(db, "ai_enabled", "false").lower() != "true":
        return {"status": "disabled", "message": "AI is disabled in Settings"}

    days = int(body.get("days", 7) or 7)
    question = str(body.get("question", "") or "")

    from ai.history import synthesize_history

    return synthesize_history(db, days=days, question=question)


@router.post("/api/autonomy/learn-noise")
def learn_noise_patterns(body: dict | None = None, db: Session = Depends(get_db)):
    """
    Safely learn noisy patterns from recent logs.

    This endpoint does not delete logs, block devices, or change firewall rules.
    It records a queryable ActivityLog decision. If apply=true and the category
    is dns, it only dismisses old DNS feed entries so the Shield feed is quieter;
    DNS blocking behavior remains unchanged.
    """
    from collections import Counter

    body = body or {}
    category = str(body.get("category", "dns") or "dns").strip()
    days = max(1, min(int(body.get("days", 7) or 7), 30))
    apply = bool(body.get("apply", False))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    q = db.query(ActivityLog).filter(ActivityLog.created_at >= since)
    if category:
        q = q.filter(ActivityLog.category == category)
    rows = q.order_by(desc(ActivityLog.id)).limit(1000).all()

    patterns = Counter((r.event, r.summary) for r in rows)
    repeated = [
        {"event": event, "summary": summary, "count": count}
        for (event, summary), count in patterns.most_common(20)
        if count >= 3
    ]

    changed = 0
    if apply and category == "dns":
        changed = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.category == "dns",
                ActivityLog.created_at >= since,
                ActivityLog.dismissed == False,  # noqa: E712
            )
            .update({"dismissed": True}, synchronize_session=False)
        )
        db.commit()

    detail = {
        "category": category,
        "days": days,
        "apply": apply,
        "dismissed_rows": changed,
        "repeated_patterns": repeated,
        "safety": "Only feed dismissal is applied; no network, DNS, firewall, or device behavior changed.",
    }
    write_log(
        "info",
        "ai",
        "noise_learning",
        (
            f"Learned {len(repeated)} repeated {category or 'all'} log patterns"
            + (f"; dismissed {changed} DNS feed rows" if changed else "")
        ),
        detail=detail,
        actor="ai_auto",
    )
    return {"status": "ok", **detail}


@router.delete("/api/logs")
def clear_activity_logs(db: Session = Depends(get_db)):
    """Delete all activity log entries."""
    db.query(ActivityLog).delete()
    db.commit()
    return {"status": "ok", "message": "Activity log cleared."}


# ═════════════════════════════════════════════════════════════════════════════
# AUTONOMOUS ACTIONS  (audit trail for things NetMon did without you)
# ═════════════════════════════════════════════════════════════════════════════

_AUTONOMOUS_ACTORS = ("anomaly_auto", "ai_auto", "ntfy_command")


@router.get("/api/autonomous-actions")
def list_autonomous_actions(
    status: str = "active",
    limit:  int = 50,
    db: Session = Depends(get_db),
):
    """
    Return recent autonomous actions (those NetMon took without explicit user
    click). Each row carries a revert payload — the dashboard "Undo" button
    POSTs to /api/autonomous-actions/{id}/revert to replay it.

    Query params:
      status — "active" (not yet reverted, default), "reverted", or "all"
      limit  — rows to return (max 200)
    """
    limit = max(1, min(limit, 200))
    q = (db.query(ActivityLog)
           .filter(ActivityLog.actor.in_(_AUTONOMOUS_ACTORS))
           .filter(ActivityLog.revert_json.isnot(None)))
    if status == "active":
        q = q.filter(ActivityLog.reverted_at.is_(None))
    elif status == "reverted":
        q = q.filter(ActivityLog.reverted_at.isnot(None))
    rows = q.order_by(ActivityLog.id.desc()).limit(limit).all()

    out = []
    for r in rows:
        try:
            revert = json.loads(r.revert_json) if r.revert_json else None
        except Exception:
            revert = None
        out.append({
            "id":          r.id,
            "created_at":  _iso(r.created_at),
            "actor":       r.actor,
            "category":    r.category,
            "event":       r.event,
            "summary":     r.summary,
            "device_ip":   r.device_ip,
            "revert":      revert,
            "reverted_at": _iso(r.reverted_at) if r.reverted_at else None,
            "reverted_by": r.reverted_by,
        })
    return {"entries": out, "count": len(out), "status": status}


@router.post("/api/autonomous-actions/{action_id}/revert")
def revert_autonomous_action(action_id: int, db: Session = Depends(get_db)):
    """
    One-click undo for an autonomous action. Replays the stored revert payload
    through ai_resolve(), then marks the row as reverted so it disappears from
    the "active" list and the button can't be double-clicked.
    """
    row = db.query(ActivityLog).filter(ActivityLog.id == action_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
    if row.reverted_at is not None:
        raise HTTPException(status_code=409, detail="Action already reverted")
    if not row.revert_json:
        raise HTTPException(status_code=400, detail="Action is not reversible (no revert payload stored)")

    try:
        payload = json.loads(row.revert_json)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stored revert payload is invalid: {e}")

    action_type = payload.get("action_type", "")
    params      = payload.get("params", {}) or {}
    if not action_type:
        raise HTTPException(status_code=400, detail="Stored revert payload missing action_type")

    try:
        result = ai_resolve({"action_type": action_type, "params": params}, db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Revert execution failed: {e}")

    row.reverted_at = datetime.now(timezone.utc)
    row.reverted_by = "user"
    db.commit()

    return {
        "success":     bool(result.get("success", False)) if isinstance(result, dict) else True,
        "description": (result or {}).get("description", "Reverted."),
        "action_id":   action_id,
    }


# ═════════════════════════════════════════════════════════════════════════════
# EXPORT
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/export/devices.csv")
def export_devices_csv(db: Session = Depends(get_db)):
    """Download current device list as a CSV file."""
    import csv
    import io
    from fastapi.responses import StreamingResponse

    latest_scan = (
        db.query(Scan).filter(Scan.status == "complete")
        .order_by(desc(Scan.id)).first()
    )
    rows = []
    if latest_scan:
        for sd in db.query(ScanDevice).filter(ScanDevice.scan_id == latest_scan.id).all():
            dev = sd.device
            rows.append({
                "ip":         sd.ip or "",
                "mac":        dev.mac or "",
                "hostname":   sd.hostname or dev.hostname or "",
                "vendor":     dev.vendor or "",
                "label":      dev.label or "",
                "trusted":    "yes" if dev.is_known else "no",
                "open_ports": ",".join(str(p) for p in sd.ports_list),
                "first_seen": _iso(dev.first_seen) if dev.first_seen else "",
                "last_seen":  _iso(dev.last_seen)  if dev.last_seen  else "",
            })

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ip", "mac", "hostname", "vendor", "label", "trusted",
        "open_ports", "first_seen", "last_seen",
    ])
    writer.writeheader()
    writer.writerows(rows)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netmon_devices.csv"},
    )


@router.get("/api/export/scans.csv")
def export_scans_csv(db: Session = Depends(get_db)):
    """Download scan history as a CSV file."""
    import csv
    import io
    from fastapi.responses import StreamingResponse

    scans = (
        db.query(Scan).filter(Scan.status == "complete")
        .order_by(desc(Scan.id)).limit(500).all()
    )

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "started_at", "duration_s", "host_count", "status",
    ])
    writer.writeheader()
    for s in scans:
        writer.writerow({
            "id":         s.id,
            "started_at": _iso(s.started_at) if s.started_at else "",
            "duration_s": s.duration_s or "",
            "host_count": s.host_count or 0,
            "status":     s.status,
        })

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netmon_scans.csv"},
    )


# ═════════════════════════════════════════════════════════════════════════════
# TRAFFIC CAPTURE
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/traffic/interfaces")
def traffic_interfaces():
    """
    List network interfaces available for capture (via dumpcap -D or tshark -D).
    Returns available: true/false, a list of interfaces, and an install hint
    if the tool is not found.
    """
    from traffic.interfaces import list_interfaces
    return list_interfaces()


@router.get("/api/traffic/status")
def traffic_status():
    """
    Return the current state of the capture engine:
      running, session_id, interface, started_at, error, capture_dir
    """
    from traffic.capture import capture_engine
    return capture_engine.get_status()


@router.post("/api/traffic/start")
def traffic_start(body: dict, db: Session = Depends(get_db)):
    """
    Start ring-buffer capture.
    Body: { "interface": "\\Device\\NPF_...", "file_size_mb": 10, "file_count": 5 }

    Also persists the settings so capture auto-resumes on restart.
    """
    from traffic.capture import capture_engine
    from app.database import SessionLocal

    interface    = (body.get("interface") or "").strip()
    file_size_mb = int(body.get("file_size_mb", 10))
    file_count   = int(body.get("file_count",   5))

    # Auto-detect interface if not provided
    if not interface:
        try:
            from traffic.interfaces import list_interfaces
            iface_info = list_interfaces()
            ifaces = iface_info.get("interfaces", [])
            _skip = {"loopback", "wsl", "hyper-v", "bluetooth", "tailscale", "virtual", "vethernet"}
            for ifc in ifaces:
                desc = (ifc.get("description") or ifc.get("display") or "").lower()
                if "wi-fi" in desc or "wifi" in desc or "wireless" in desc:
                    interface = ifc.get("name", ""); break
            if not interface:
                for ifc in ifaces:
                    desc = (ifc.get("description") or ifc.get("display") or "").lower()
                    if "ethernet" in desc and not any(s in desc for s in _skip):
                        interface = ifc.get("name", ""); break
            if not interface and ifaces:
                interface = ifaces[0].get("name", "")
        except Exception:
            pass
    if not interface:
        raise HTTPException(status_code=400, detail="No capture interface found. Install Wireshark/Npcap.")

    # Persist settings so capture can auto-resume after server restart
    for key, val in [
        ("capture_enabled",      "true"),
        ("capture_interface",    interface),
        ("capture_file_size_mb", str(file_size_mb)),
        ("capture_file_count",   str(file_count)),
    ]:
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = val
    db.commit()

    result = capture_engine.start(
        interface=interface,
        file_size_mb=file_size_mb,
        file_count=file_count,
        session_factory=SessionLocal,
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message", "capture error"))

    return result


@router.post("/api/traffic/stop")
def traffic_stop(db: Session = Depends(get_db)):
    """
    Stop the running capture process, persist capture_enabled=false,
    and auto-trigger an AI analysis in the background.
    """
    from traffic.capture import capture_engine
    from app.database import SessionLocal

    # Mark capture disabled so it does not auto-resume on restart
    row = db.query(Setting).filter(Setting.key == "capture_enabled").first()
    if row:
        row.value = "false"
    db.commit()

    result = capture_engine.stop(session_factory=SessionLocal)

    # Auto-trigger traffic-specific AI analysis after capture stops
    ai_enabled = _get_setting_str(db, "ai_enabled", "false").lower()
    if ai_enabled == "true":
        import threading
        from ai.analyst import run_traffic_analysis

        def _run():
            thread_db = SessionLocal()
            try:
                run_traffic_analysis(thread_db)
            except Exception as e:
                print(f"[ai] Post-capture traffic analysis error: {e}")
            finally:
                thread_db.close()

        threading.Thread(target=_run, daemon=True, name="ai-post-capture-traffic").start()
        result["ai_analysis"] = "started"
    else:
        result["ai_analysis"] = "disabled"

    return result


@router.get("/api/traffic/summary")
def traffic_summary(db: Session = Depends(get_db)):
    """
    Return the most recent traffic analysis summary.
    Returns an empty skeleton if no summaries exist yet.
    """
    row = db.query(TrafficSummary).order_by(desc(TrafficSummary.id)).first()
    if not row:
        return {
            "id":               None,
            "created_at":       None,
            "session_id":       None,
            "total_packets":    0,
            "total_bytes":      0,
            "files_analyzed":   0,
            "top_talkers":      [],
            "top_destinations": [],
            "protocol_mix":     {},
            "dns_count":        0,
            "error":            None,
        }
    return {
        "id":               row.id,
        "created_at":       _iso(row.created_at),
        "session_id":       row.session_id,
        "total_packets":    row.total_packets or 0,
        "total_bytes":      row.total_bytes   or 0,
        "files_analyzed":   row.files_analyzed or 0,
        "top_talkers":      json.loads(row.top_talkers      or "[]"),
        "top_destinations": json.loads(row.top_destinations or "[]"),
        "protocol_mix":     json.loads(row.protocol_mix     or "{}"),
        "dns_count":        row.dns_count or 0,
        "top_domains":      json.loads(row.top_domains      or "[]"),
        "error":            row.error,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Traffic dashboard endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/traffic/dashboard")
def traffic_dashboard(db: Session = Depends(get_db)):
    """
    Bundles everything the redesigned Traffic tab needs:
      • capture state + packet rate + active devices count
      • last summary's conversations + top talkers + protocols
      • recent incident captures
    Cheap — all from existing tables.
    """
    from traffic.capture import capture_engine
    status = capture_engine.get_status()
    summary_row = db.query(TrafficSummary).order_by(desc(TrafficSummary.id)).first()

    pps = 0.0
    bps = 0.0
    devices_active = 0
    top_protocol = "—"
    if summary_row:
        prev = (
            db.query(TrafficSummary)
            .filter(TrafficSummary.id < summary_row.id)
            .order_by(desc(TrafficSummary.id)).first()
        )
        if prev and summary_row.created_at and prev.created_at:
            try:
                dur = (summary_row.created_at - prev.created_at).total_seconds() or 1
                pps = round(max(0, (summary_row.total_packets or 0) - (prev.total_packets or 0)) / dur, 1)
                bps = round(max(0, (summary_row.total_bytes or 0) - (prev.total_bytes or 0)) / dur, 0)
            except Exception:
                pass
        try:
            devices_active = len(json.loads(summary_row.top_talkers or "[]"))
        except Exception:
            pass
        try:
            mix = json.loads(summary_row.protocol_mix or "{}")
            if mix:
                top_protocol = max(mix.items(), key=lambda kv: kv[1])[0]
        except Exception:
            pass

    # Conversations — analyzer now emits these alongside the summary. They're
    # not persisted as a separate column, so we reconstruct from top_talkers
    # + top_destinations when raw conversations aren't available.
    conversations: list[dict] = []
    if summary_row:
        try:
            talkers = json.loads(summary_row.top_talkers or "[]")
            dests = json.loads(summary_row.top_destinations or "[]")
            # Naive pairing: present each (talker, destination) row scaled by bytes share.
            for t in talkers[:6]:
                for d in dests[:6]:
                    conversations.append({
                        "src":      t.get("ip"),
                        "dst":      d.get("ip"),
                        "src_ip":   t.get("ip"),
                        "dst_ip":   d.get("ip"),
                        "bytes":    min(t.get("bytes", 0), d.get("bytes", 0)),
                        "packets":  min(t.get("packets", 0), d.get("packets", 0)),
                        "country":  None,
                    })
        except Exception:
            pass

    # Enrich destinations with country from geo
    try:
        from network.geo import country_for_ip
        for c in conversations:
            if c.get("dst_ip"):
                c["country"] = country_for_ip(c["dst_ip"])
    except Exception:
        pass

    # Recent incident captures
    try:
        from models.tables import IncidentCapture
        incident_rows = (
            db.query(IncidentCapture)
            .order_by(desc(IncidentCapture.id)).limit(20).all()
        )
        incidents = [{
            "id":            r.id,
            "created_at":    _iso(r.created_at),
            "anomaly_type":  r.anomaly_type,
            "device_ip":     r.device_ip,
            "file_path":     r.file_path,
            "size_bytes":    r.file_size_bytes,
        } for r in incident_rows]
    except Exception:
        incidents = []

    return {
        "capture": {
            "running":   bool(status.get("running")),
            "capturing": bool(status.get("running")),
            "interface": status.get("interface"),
            "started_at": _iso(status.get("started_at")) if status.get("started_at") else None,
        },
        "stats": {
            "pps":          pps,
            "bps":          bps,
            "devices":      devices_active,
            "top_protocol": top_protocol,
        },
        "conversations": conversations[:30],
        "incidents":     incidents,
    }


@router.get("/api/traffic/device/{device_id}")
def traffic_for_device(device_id: int, db: Session = Depends(get_db)):
    """Top destinations + DNS hints + country mix for one device."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    summary_row = db.query(TrafficSummary).order_by(desc(TrafficSummary.id)).first()
    talkers = []
    dests   = []
    domains = []
    if summary_row:
        try:
            for t in json.loads(summary_row.top_talkers or "[]"):
                talkers.append(t)
            for d in json.loads(summary_row.top_destinations or "[]"):
                dests.append(d)
            for d in json.loads(summary_row.top_domains or "[]"):
                domains.append(d)
        except Exception:
            pass

    try:
        from models.tables import DeviceCountryHistory
        country_rows = (
            db.query(DeviceCountryHistory)
            .filter(DeviceCountryHistory.device_id == device_id)
            .order_by(desc(DeviceCountryHistory.last_seen)).all()
        )
        countries = [{
            "country":     c.country,
            "first_seen":  _iso(c.first_seen),
            "last_seen":   _iso(c.last_seen),
            "total_bytes": c.total_bytes or 0,
        } for c in country_rows]
    except Exception:
        countries = []

    return {
        "device_id":         device.id,
        "label":             device.label,
        "hostname":          device.hostname,
        "vendor":            device.vendor,
        "top_destinations":  dests,
        "top_talkers":       talkers,
        "top_domains":       domains,
        "countries":         countries,
    }


@router.get("/api/traffic/device/{device_ip}/activity")
def device_activity(device_ip: str, db: Session = Depends(get_db)):
    """
    Deep activity extraction for a specific device IP.
    Extracts HTTP URLs, TLS SNI (HTTPS domains), and DNS queries
    from recent pcap files using tshark. Returns clickable URLs.
    Also saves learned fingerprint data (device type, vendor) back to the device record.
    """
    from traffic.analyzer import get_device_activity, CAPTURE_DIR
    result = get_device_activity(device_ip, CAPTURE_DIR, max_files=10)

    # Save what we learn back to the device record
    _learn_from_activity(device_ip, result, db)

    # Retrieve the updated device to include the inferred role and vendor in the response
    device = (db.query(Device)
              .join(ScanDevice, ScanDevice.device_id == Device.id)
              .filter(ScanDevice.ip == device_ip)
              .order_by(desc(ScanDevice.id)).first())
    if device:
        result["inferred_role"] = device.label or ""
        result["inferred_vendor"] = device.vendor or ""
    else:
        result["inferred_role"] = ""
        result["inferred_vendor"] = ""

    return result


def _learn_from_activity(device_ip: str, activity: dict, db) -> None:
    """Fingerprint device from captured traffic and update its record."""
    try:
        device = (db.query(Device)
                  .join(ScanDevice, ScanDevice.device_id == Device.id)
                  .filter(ScanDevice.ip == device_ip)
                  .order_by(desc(ScanDevice.id)).first())
        if not device:
            return

        ua_strings = [r.get("ua", "") for r in activity.get("http_requests", []) if r.get("ua")]
        domains    = [d["domain"] for d in activity.get("summary", {}).get("top_domains", [])]
        changed    = False

        # Infer device type from User-Agent
        inferred_vendor = _infer_vendor_from_ua(ua_strings)
        if inferred_vendor and not device.vendor:
            device.vendor = inferred_vendor
            changed = True

        # Infer device role using the passive traffic analyzer (headers, flow patterns, DNS/UA)
        from traffic.role_inference import extract_flow_stats, infer_device_role, CAPTURE_DIR
        try:
            flow_stats = extract_flow_stats(device_ip, CAPTURE_DIR, max_files=10)
        except Exception:
            flow_stats = {}
        inferred_role = infer_device_role(device_ip, activity, flow_stats)
        if inferred_role and not device.label:
            device.label = inferred_role
            changed = True
        elif not device.label:
            # Fallback to DNS patterns
            inferred_type = _infer_type_from_domains(domains)
            if inferred_type:
                device.label = inferred_type
                changed = True

        # Store top domains in allow_json as 'learned_domains' for future use
        if domains:
            try:
                existing = json.loads(device.allow_json or "{}")
            except Exception:
                existing = {}
            existing["learned_domains"] = domains[:20]
            existing["last_activity_ip"] = device_ip
            device.allow_json = json.dumps(existing)
            changed = True

        if changed:
            db.commit()
            write_log("info", "system", "device_learned",
                      f"Learned from traffic: {device_ip} → vendor={device.vendor} label={device.label}",
                      device_ip=device_ip)
            try:
                from ai.knowledge_bridge import (
                    record_device_profile_lesson,
                    record_timeline_event,
                )
                profile = {
                    "device_id": device.id,
                    "ip": device_ip,
                    "label": device.label,
                    "vendor": device.vendor,
                    "os_guess": getattr(device, "os_guess", None),
                }
                evidence = {
                    "top_domains": domains[:20],
                    "user_agents": ua_strings[:5],
                    "source": "traffic_activity",
                }
                record_device_profile_lesson(
                    device_key=f"netmon.device.{device.id}",
                    profile=profile,
                    evidence=evidence,
                    summary=f"Traffic activity identified {device_ip} as {device.label or device.vendor or 'unknown'}",
                )
                record_timeline_event(
                    correlation_id=f"netmon.device.{device.id}",
                    service="device",
                    event_type="device_profile_learned",
                    severity="info",
                    summary=f"NetMon learned profile details for {device_ip}",
                    detail={"profile": profile, "evidence": evidence},
                )
            except Exception:
                pass
    except Exception as _e:
        db.rollback()


def _infer_vendor_from_ua(ua_strings: list[str]) -> str:
    """Extract vendor/manufacturer from HTTP User-Agent strings."""
    for ua in ua_strings:
        ua_l = ua.lower()
        if "iphone" in ua_l or "ipad" in ua_l:   return "Apple (iPhone/iPad)"
        if "android" in ua_l and "samsung" in ua_l: return "Samsung Android"
        if "android" in ua_l:                       return "Android Device"
        if "roku" in ua_l:                          return "Roku"
        if "kindle" in ua_l or "silk" in ua_l:      return "Amazon Kindle"
        if "windows nt" in ua_l:                    return "Windows PC"
        if "macintosh" in ua_l or "mac os" in ua_l: return "Apple Mac"
        if "linux" in ua_l and "x86" in ua_l:       return "Linux PC"
        if "playstation" in ua_l:                   return "PlayStation"
        if "xbox" in ua_l:                          return "Xbox"
    return ""


def _infer_type_from_domains(domains: list[str]) -> str:
    """Infer device type from DNS query patterns."""
    dom = " ".join(domains).lower()
    if any(x in dom for x in ["apple.com","icloud.com","apple-dns","courier.push.apple"]):
        return "Apple Device"
    if any(x in dom for x in ["android","googleapis","gstatic","play.google"]):
        return "Android Device"
    if any(x in dom for x in ["roku","rbxd.com"]):
        return "Roku Streaming"
    if any(x in dom for x in ["amazon","kindle","alexa","echo"]):
        return "Amazon Device"
    if any(x in dom for x in ["xbox","microsoft.com","xboxlive"]):
        return "Xbox"
    if any(x in dom for x in ["playstation","sony"]):
        return "PlayStation"
    if any(x in dom for x in ["ring.com","ring-door","blink"]):
        return "Ring/Security Camera"
    if any(x in dom for x in ["tuya","smartlife","tp-link","tplink-smarthome","kasa"]):
        return "Smart Home Device"
    if any(x in dom for x in ["netgear","routerlogin","192.168.1.1"]):
        return "Router/Gateway"
    if any(x in dom for x in ["philips","hue","meethue"]):
        return "Philips Hue"
    if any(x in dom for x in ["nest","google-nest"]):
        return "Google Nest"
    return ""


@router.get("/api/incidents")
def list_incidents(limit: int = 50, db: Session = Depends(get_db)):
    from models.tables import IncidentCapture
    rows = (
        db.query(IncidentCapture)
        .order_by(desc(IncidentCapture.id)).limit(limit).all()
    )
    return [{
        "id":              r.id,
        "created_at":      _iso(r.created_at),
        "anomaly_log_id":  r.anomaly_log_id,
        "anomaly_type":    r.anomaly_type,
        "device_ip":       r.device_ip,
        "file_path":       r.file_path,
        "size_bytes":      r.file_size_bytes,
        "window_start":    _iso(r.window_start) if r.window_start else None,
        "window_end":      _iso(r.window_end)   if r.window_end   else None,
    } for r in rows]


@router.get("/api/learning/overview")
def learning_overview(limit: int = 20):
    """Read-only view of shared NetMon/Sentinel learning state."""
    try:
        from ai.knowledge_bridge import learning_overview as _learning_overview
        return _learning_overview(limit=limit)
    except Exception as exc:
        return {
            "available": False,
            "lessons": [],
            "timeline": [],
            "feedback": [],
            "error": str(exc)[:300],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 — Hunt rule management
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/hunt/rules")
def list_hunt_rules(db: Session = Depends(get_db)):
    from models.tables import HuntRule
    rows = db.query(HuntRule).order_by(HuntRule.id).all()
    return [{
        "id":            r.id,
        "name":          r.name,
        "description":   r.description,
        "yaml_body":     r.yaml_body,
        "enabled":       r.enabled,
        "severity":      r.severity,
        "last_fired_at": _iso(r.last_fired_at) if r.last_fired_at else None,
        "fire_count":    r.fire_count or 0,
    } for r in rows]


@router.post("/api/hunt/rules")
def create_or_update_hunt_rule(body: dict, db: Session = Depends(get_db)):
    from models.tables import HuntRule
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    yaml_body = body.get("yaml_body") or body.get("body") or ""
    if not yaml_body.strip():
        raise HTTPException(status_code=400, detail="yaml_body is required")
    row = db.query(HuntRule).filter(HuntRule.name == name).first()
    if not row:
        row = HuntRule(name=name)
        db.add(row)
    row.description = body.get("description")
    row.yaml_body   = yaml_body
    row.enabled     = bool(body.get("enabled", True))
    row.severity    = body.get("severity") or "warning"
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "enabled": row.enabled}


@router.delete("/api/hunt/rules/{rule_id}")
def delete_hunt_rule(rule_id: int, db: Session = Depends(get_db)):
    from models.tables import HuntRule
    row = db.query(HuntRule).filter(HuntRule.id == rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.get("/api/traffic/mitm/status")
def traffic_mitm_status():
    """Return current ARP MitM engine state."""
    from traffic.mitm import mitm_engine
    return mitm_engine.get_status()


@router.post("/api/traffic/mitm/start")
def traffic_mitm_start(body: dict, db: Session = Depends(get_db)):
    """
    Start ARP MitM so all device traffic flows through this machine.
    Body: { "interface": "\\Device\\NPF_...", "gateway_ip": "192.168.1.1" (optional) }
    Targets are pulled automatically from the most recent completed scan.
    """
    from traffic.mitm import mitm_engine

    interface  = (body.get("interface") or "").strip()
    gateway_ip = (body.get("gateway_ip") or "").strip() or None
    target_ips = body.get("target_ips")  # optional: list of specific IPs

    # Auto-detect interface if not provided — prefer Wi-Fi/Ethernet over virtual adapters
    if not interface:
        try:
            from traffic.interfaces import list_interfaces
            iface_info = list_interfaces()
            ifaces = iface_info.get("interfaces", [])
            # Priority: Wi-Fi first, then Ethernet, then any non-virtual
            _skip = {"loopback", "wsl", "hyper-v", "bluetooth", "tailscale",
                     "local area connection", "virtual", "vethernet"}
            preferred = None
            for ifc in ifaces:
                desc = (ifc.get("description") or ifc.get("display") or "").lower()
                name = ifc.get("name", "")
                if "wi-fi" in desc or "wifi" in desc or "wireless" in desc:
                    preferred = name
                    break
            if not preferred:
                for ifc in ifaces:
                    desc = (ifc.get("description") or ifc.get("display") or "").lower()
                    if "ethernet" in desc and not any(s in desc for s in _skip):
                        preferred = ifc.get("name", "")
                        break
            if not preferred:
                for ifc in ifaces:
                    desc = (ifc.get("description") or ifc.get("display") or "").lower()
                    if not any(s in desc for s in _skip):
                        preferred = ifc.get("name", "")
                        break
            interface = preferred or (ifaces[0].get("name", "") if ifaces else "")
        except Exception:
            pass
    if not interface:
        raise HTTPException(status_code=400, detail="Could not auto-detect network interface. Please specify one in the Traffic tab.")

    if target_ips and isinstance(target_ips, list):
        # Caller specified exact targets
        targets = [ip.strip() for ip in target_ips if ip and ip.strip()]
    else:
        # Default: all devices from latest scan
        latest_scan = (
            db.query(Scan).filter(Scan.status == "complete")
            .order_by(desc(Scan.id)).first()
        )
        if not latest_scan:
            raise HTTPException(status_code=400,
                                detail="Run a network scan first so targets are known")
        targets = [
            sd.ip for sd in
            db.query(ScanDevice).filter(ScanDevice.scan_id == latest_scan.id).all()
            if sd.ip
        ]

    result = mitm_engine.start(
        interface=interface,
        targets=targets,
        gateway_ip=gateway_ip,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
    return result


@router.post("/api/traffic/mitm/stop")
def traffic_mitm_stop(db: Session = Depends(get_db)):
    """Stop ARP MitM and restore all device ARP tables.
    Also triggers activity learning for all targeted devices."""
    from traffic.mitm import mitm_engine
    state = mitm_engine.get_status()
    targets = state.get("targets", [])
    result = mitm_engine.stop()

    # Background: learn from what we captured for each targeted device
    if targets:
        import threading
        def _learn_all():
            from traffic.analyzer import get_device_activity, CAPTURE_DIR
            from app.database import SessionLocal
            db2 = SessionLocal()
            try:
                for ip in targets:
                    try:
                        activity = get_device_activity(ip, CAPTURE_DIR, max_files=10)
                        _learn_from_activity(ip, activity, db2)
                    except Exception:
                        pass
            finally:
                db2.close()
        threading.Thread(target=_learn_all, daemon=True, name="mitm-learn").start()

    return result


@router.get("/api/traffic/mitm/diagnose")
def traffic_mitm_diagnose(db: Session = Depends(get_db)):
    """
    Diagnostic: show ARP cache entries vs. known scan targets.
    Helps identify why MACs are or aren't resolving.
    """
    from traffic.mitm import _get_arp_cache, _detect_gateway

    cache = _get_arp_cache()
    gateway_ip = _detect_gateway()

    # Pull target IPs from latest scan
    latest_scan = (
        db.query(Scan).filter(Scan.status == "complete")
        .order_by(desc(Scan.id)).first()
    )
    targets = []
    if latest_scan:
        targets = [
            sd.ip for sd in
            db.query(ScanDevice).filter(ScanDevice.scan_id == latest_scan.id).all()
            if sd.ip
        ]

    resolved   = {ip: cache[ip] for ip in targets if ip in cache}
    unresolved = [ip for ip in targets if ip not in cache]

    return {
        "gateway_ip":        gateway_ip,
        "gateway_mac":       cache.get(gateway_ip),
        "arp_cache_total":   len(cache),
        "targets_total":     len(targets),
        "targets_resolved":  len(resolved),
        "targets_unresolved": len(unresolved),
        "resolved":          resolved,
        "unresolved":        unresolved,
        "arp_cache":         cache,
    }


@router.get("/api/traffic/dns-live")
def traffic_dns_live():
    """
    Return recent DNS/TLS queries grouped by source device IP.
    Reads from the last 2 ring-buffer capture files.
    Requires capture to be running and tshark installed.
    """
    try:
        from traffic.capture import CAPTURE_DIR
        from traffic.analyzer import get_dns_per_device
        return get_dns_per_device(CAPTURE_DIR, max_files=2)
    except Exception as exc:
        return {"error": str(exc)}


@router.post("/api/command")
async def handle_remote_command(request: Request):
    """
    Execute a remote command (from ntfy action buttons, API, or the dashboard).
    Supported: block <ip>, unblock <ip>, investigate <ip>, scan, dismiss
    """
    body = await request.json()
    raw = body.get("command", "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="No command provided")

    from monitoring.scheduler import _execute_command
    import threading
    threading.Thread(
        target=_execute_command, args=(raw.lower(), raw), daemon=True
    ).start()
    write_log("action", "system", "api_command", f"Command dispatched: {raw}")
    return {"status": "dispatched", "command": raw}


@router.post("/api/notifications/test")
async def test_notification(request: Request):
    """
    Send a test push notification.
    Pass {"level": "critical"} to fire a full mock threat alert with action buttons —
    same path as a real anomaly detection event.
    """
    from monitoring.notifier import send_ntfy, alert as _alert, block_action, investigate_action, dismiss_action, _cfg
    body  = {}
    try:
        body = await request.json()
    except Exception:
        pass
    level = body.get("level", "info")

    cfg = _cfg()
    results = {
        "ntfy_enabled": cfg["ntfy_enabled"],
        "ntfy_server":  cfg["ntfy_server"],
        "ntfy_topic":   cfg["ntfy_topic"],
        "ntfy_user":    cfg["ntfy_user"],
        "level_sent":   level,
        "ntfy_sent":    False,
        "ntfy_error":   None,
    }

    if cfg["ntfy_enabled"] != "true" or not cfg["ntfy_topic"]:
        results["ntfy_error"] = "ntfy not enabled or topic is empty"
        return results

    import urllib.request, urllib.error, base64

    cfg = _cfg()
    server = cfg["ntfy_server"].rstrip("/")
    topic  = cfg["ntfy_topic"]
    url    = f"{server}/{topic}"

    headers = {
        "Title":    "TEST - Critical Alert" if level == "critical" else "NetMon test",
        "Priority": "urgent" if level == "critical" else "default",
        "Tags":     "rotating_light" if level == "critical" else "bell",
    }
    auth_value = ""
    if cfg["ntfy_user"] and cfg["ntfy_pass"]:
        creds = base64.b64encode(f"{cfg['ntfy_user']}:{cfg['ntfy_pass']}".encode()).decode()
        auth_value = f"Basic {creds}"
        headers["Authorization"] = auth_value

    if level == "critical":
        cmd_url = f"{server}/{topic}-cmd"
        # Pass the same Basic auth in each action so the phone's POST to the
        # self-hosted ntfy server is authenticated — otherwise the server
        # returns 401 and the ntfy app shows "cannot connect".
        a = f", headers.Authorization={auth_value}" if auth_value else ""
        headers["Actions"] = (
            f"http, Investigate, {cmd_url}, method=POST, body=investigate 192.168.1.99, clear=true{a}; "
            f"http, Block IP, {cmd_url}, method=POST, body=block 192.168.1.99, clear=true{a}; "
            f"http, Dismiss, {cmd_url}, method=POST, body=dismiss, clear=true{a}"
        )

    body_text = (
        "This is a test critical alert.\nIn a real event this describes the threat."
        if level == "critical" else "Notifications are working."
    )

    results["url"] = url
    results["auth_header_set"] = "Authorization" in headers

    try:
        req = urllib.request.Request(url, data=body_text.encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            results["ntfy_sent"]      = True
            results["http_status"]    = resp.status
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        results["ntfy_error"]    = f"HTTP {exc.code} {exc.reason}"
        results["ntfy_response"] = body_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        results["ntfy_error"] = f"{type(exc).__name__}: {exc}"

    return results


@router.get("/api/traffic/history")
def traffic_history(limit: int = 60, db: Session = Depends(get_db)):
    """
    Return recent traffic summaries (packet/byte totals over time).
    Oldest-first so the chart reads left → right.
    """
    rows = (
        db.query(TrafficSummary)
        .order_by(desc(TrafficSummary.id))
        .limit(limit)
        .all()
    )
    rows = list(reversed(rows))
    return [
        {
            "created_at":   _iso(r.created_at),
            "total_packets": r.total_packets or 0,
            "total_bytes":   r.total_bytes   or 0,
            "dns_count":     r.dns_count     or 0,
        }
        for r in rows
    ]


# ── Shield / Security Dashboard ───────────────────────────────────────────────

def _get_netmon_firewall_rules() -> list[dict]:
    """Return all NetMon-managed Windows Firewall rules."""
    import subprocess
    try:
        from traffic.interfaces import _no_window
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=NetMon*"],
            capture_output=True, text=True, timeout=10,
            creationflags=_no_window(),
        )
        rules, current = [], {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Rule Name:"):
                if current.get("rule_name"):
                    rules.append(current)
                name = line.split(":", 1)[1].strip()
                parts = name.replace("NetMon-", "").split("-")
                ip     = parts[-1] if parts else ""
                reason = " ".join(parts[:-1]).title() if len(parts) > 1 else "Manual block"
                current = {"rule_name": name, "ip": ip, "reason": reason, "direction": ""}
            elif line.startswith("Direction:") and current:
                current["direction"] = line.split(":", 1)[1].strip()
            elif line.startswith("Action:") and current:
                current["action"] = line.split(":", 1)[1].strip()
        if current.get("rule_name"):
            rules.append(current)
        # Deduplicate by IP, keep outbound
        seen, unique = set(), []
        for rule in rules:
            if rule["ip"] and rule["ip"] not in seen:
                seen.add(rule["ip"])
                unique.append(rule)
        return unique
    except Exception:
        return []


@router.post("/api/reports/chat")
async def reports_chat(request: Request, db: Session = Depends(get_db)):
    """Ask Qwen a question about your network, using recent reports and status as context."""
    body = await request.json()
    question = (body.get("question") or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")

    ai_row = db.query(Setting).filter(Setting.key == "ai_enabled").first()
    if not (ai_row and (ai_row.value or "").lower() == "true"):
        raise HTTPException(status_code=400, detail="AI is not enabled — turn it on in Settings")

    from models.tables import SecurityReport, TrafficSummary, HealthCheck, Scan

    now = datetime.now(timezone.utc)

    # ── Last scan ────────────────────────────────────────────────────────
    last_scan = db.query(Scan).filter(Scan.status == "complete").order_by(desc(Scan.ended_at)).first()
    scan_info = "never"
    if last_scan and last_scan.ended_at:
        ended = last_scan.ended_at.replace(tzinfo=timezone.utc) if last_scan.ended_at.tzinfo is None else last_scan.ended_at
        age_m = int((now - ended).total_seconds() / 60)
        scan_info = f"{age_m} minutes ago ({last_scan.host_count} devices)"

    # ── Last health check ────────────────────────────────────────────────
    last_hc = db.query(HealthCheck).order_by(desc(HealthCheck.id)).first()
    health_info = "no data"
    if last_hc:
        age_m = int((now - last_hc.checked_at.replace(tzinfo=timezone.utc)).total_seconds() / 60) if last_hc.checked_at else "?"
        health_info = f"{last_hc.status} (latency {last_hc.latency_ms}ms, loss {last_hc.packet_loss}%) — checked {age_m}m ago"

    # ── Last traffic summary ─────────────────────────────────────────────
    last_ts = db.query(TrafficSummary).order_by(desc(TrafficSummary.id)).first()
    traffic_info = "no capture data"
    if last_ts and last_ts.created_at:
        age_m = int((now - last_ts.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 60)
        traffic_info = f"last summary {age_m}m ago ({last_ts.total_packets} packets, {last_ts.dns_count} DNS)"

    # ── Recent anomalies ─────────────────────────────────────────────────
    recent_anomalies = (
        db.query(ActivityLog)
        .filter(
            ActivityLog.created_at >= now - timedelta(hours=24),
            ActivityLog.level.in_(["warning", "critical", "threat"]),
        )
        .order_by(desc(ActivityLog.id))
        .limit(10)
        .all()
    )
    anomaly_lines = [f"- [{e.level.upper()}] {e.summary}" for e in recent_anomalies] or ["- None in the last 24h"]

    # ── Recent reports ───────────────────────────────────────────────────
    recent_reports = (
        db.query(SecurityReport)
        .order_by(desc(SecurityReport.id))
        .limit(5)
        .all()
    )
    report_lines = []
    for r in recent_reports:
        if r.error:
            report_lines.append(f"- [ERROR] {r.error[:100]}")
        else:
            ts = r.created_at.strftime("%H:%M") if r.created_at else "?"
            report_lines.append(f"- [{ts}] Severity: {r.severity} — {r.headline}")
            if r.body:
                report_lines.append(f"  {r.body[:300]}")

    # ── Background task status ───────────────────────────────────────────
    from monitoring.state import scan_state
    from traffic.capture import capture_engine
    capture_status = capture_engine.get_status()

    def _s(key, d=""):
        row = db.query(Setting).filter(Setting.key == key).first()
        return row.value if (row and row.value is not None) else d

    bg_status = [
        f"Auto-scan: {'running' if scan_state['running'] else 'idle'} — last completed {scan_info}",
        f"Health monitor: active — {health_info}",
        f"Traffic capture: {'running' if capture_status['running'] else 'stopped'} — {traffic_info}",
        f"Anomaly detection: {'enabled' if _s('anomaly_detection_enabled','true')=='true' else 'disabled'} — runs every 60s",
        f"Autonomous reports: {'enabled' if _s('auto_report_enabled','true')=='true' else 'disabled'} — runs every hour",
        f"Push notifications: {'enabled (min level: '+_s('ntfy_min_level','critical')+')' if _s('ntfy_enabled')=='true' else 'disabled'}",
    ]

    context = "\n".join([
        "BACKGROUND TASK STATUS:",
        *bg_status,
        "",
        "RECENT ANOMALIES (last 24h):",
        *anomaly_lines,
        "",
        "RECENT HOURLY REPORTS:",
        *(report_lines if report_lines else ["- No reports generated yet"]),
    ])

    prompt = (
        "You are NetMon, a friendly home network security assistant. "
        "Answer the user's question based on the live data below. "
        "Be conversational and concise (2-5 sentences). If they ask if everything is running, "
        "confirm each background task. If they ask about threats, be specific about what was found. "
        "Don't repeat the raw data back — synthesize it into a plain-English answer.\n\n"
        f"Network Data:\n{context}\n\n"
        f"User question: {question}\n\n"
        "Answer:"
    )

    from ai.provider import get_provider
    provider = get_provider()
    result = provider.analyze({}, prompt=prompt, kind="chat")

    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    raw = result.get("raw_response") or ""
    # Strip any JSON wrapper if the model returned one
    import re
    if raw.strip().startswith("{"):
        try:
            data = json.loads(raw)
            raw = data.get("summary") or data.get("answer") or data.get("body") or raw
        except Exception:
            pass

    return {"answer": raw.strip()}


@router.post("/api/reports/run-now")
def run_report_now():
    """Trigger an immediate autonomous security report in the background."""
    import threading
    from monitoring.scheduler import _run_autonomous_report
    t = threading.Thread(target=_run_autonomous_report, daemon=True, name="report-manual")
    t.start()
    return {"ok": True, "message": "Report generation started — check back in ~30 seconds."}


@router.get("/api/reports")
def get_reports(limit: int = 48, db: Session = Depends(get_db)):
    """Return recent autonomous security reports (up to `limit`, newest first)."""
    from models.tables import SecurityReport
    rows = (
        db.query(SecurityReport)
        .order_by(desc(SecurityReport.id))
        .limit(min(limit, 168))
        .all()
    )
    return [
        {
            "id":              r.id,
            "created_at":      _iso(r.created_at),
            "report_type":     r.report_type,
            "period_start":    _iso(r.period_start),
            "period_end":      _iso(r.period_end),
            "severity":        r.severity or "low",
            "headline":        r.headline,
            "body":            r.body,
            "anomalies":       json.loads(r.anomalies or "[]"),
            "recommendations": json.loads(r.recommendations or "[]"),
            "model":           r.model,
            "error":           r.error,
        }
        for r in rows
    ]


@router.get("/api/shield")
def shield_status(db: Session = Depends(get_db)):
    """Security dashboard data — threat level, protection layers, events, blocks."""

    def _setting(key, default="false"):
        row = db.query(Setting).filter(Setting.key == key).first()
        return row.value if (row and row.value is not None) else default

    def _last_event_iso(category):
        ev = (db.query(ActivityLog)
              .filter(ActivityLog.category == category)
              .order_by(desc(ActivityLog.id)).first())
        return _iso(ev.created_at) if ev else None

    # Threat level from recent *undismissed* events + health
    # DNS blocks are excluded — blocking an ad domain is normal operation, not an anomaly
    cutoff_2h  = datetime.now(timezone.utc) - timedelta(hours=2)
    critical_n = db.query(ActivityLog).filter(
        ActivityLog.created_at >= cutoff_2h,
        ActivityLog.level.in_(["critical", "threat"]),
        ActivityLog.category != "dns",
        ActivityLog.dismissed == False,  # noqa: E712
    ).count()
    warning_n  = db.query(ActivityLog).filter(
        ActivityLog.created_at >= cutoff_2h,
        ActivityLog.level == "warning",
        ActivityLog.category != "dns",
        ActivityLog.dismissed == False,  # noqa: E712
    ).count()
    latest_hc  = db.query(HealthCheck).order_by(desc(HealthCheck.id)).first()
    health_st  = latest_hc.status if latest_hc else "unknown"

    if critical_n > 0 or health_st == "offline":
        threat_level = "critical"
    elif warning_n > 0 or health_st == "degraded":
        threat_level = "warning"
    else:
        threat_level = "secure"

    # Stats
    scan_count   = db.query(Scan).filter(Scan.status == "complete").count()
    _last_scan   = db.query(Scan).filter(Scan.status == "complete").order_by(desc(Scan.id)).first()
    device_count = _last_scan.host_count if (_last_scan and _last_scan.host_count) else db.query(Device).count()
    hc_rows      = db.query(HealthCheck).order_by(desc(HealthCheck.id)).limit(200).all()
    uptime_pct   = round(sum(1 for r in hc_rows if r.status == "online") / max(len(hc_rows), 1) * 100, 1)
    threats_24h  = db.query(ActivityLog).filter(
        ActivityLog.created_at >= datetime.now(timezone.utc) - timedelta(hours=24),
        ActivityLog.level.in_(["critical", "threat"]),
        ActivityLog.dismissed == False,  # noqa: E712
    ).count()
    blocks       = _get_netmon_firewall_rules()

    # ── Real-time health data for protection layers ───────────────────────────
    scan_interval = _setting("auto_scan_interval_h", "4")
    hc_interval   = _setting("health_check_interval_s", "300")

    def _ago(dt):
        """Return human-readable relative time, e.g. '4m ago', '2h ago'."""
        if dt is None:
            return None
        if hasattr(dt, "tzinfo") and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        diff = (datetime.now(timezone.utc) - dt).total_seconds()
        if diff < 90:
            return "just now"
        if diff < 3600:
            return f"{int(diff / 60)}m ago"
        if diff < 86400:
            return f"{int(diff / 3600)}h ago"
        return f"{int(diff / 86400)}d ago"

    # Auto-scan: last scan actual result
    from monitoring.state import scan_state
    last_scan          = db.query(Scan).order_by(desc(Scan.id)).first()
    last_complete_scan = db.query(Scan).filter(Scan.status == "complete").order_by(desc(Scan.id)).first()
    if scan_state.get("running"):
        scan_stat       = f"Running now · {scan_count} complete"
        scan_last_event = _last_event_iso("scan")
    elif last_scan is None:
        scan_stat       = f"Every {scan_interval}h · never run"
        scan_last_event = None
    elif last_scan.status == "failed":
        ago = _ago(last_scan.started_at) or "recently"
        scan_stat       = f"Every {scan_interval}h · last attempt FAILED {ago}"
        scan_last_event = _iso(last_complete_scan.ended_at) if last_complete_scan else None
    elif last_scan.status == "complete":
        scan_stat       = f"Every {scan_interval}h · last ran {_ago(last_scan.ended_at)} · {scan_count} total"
        scan_last_event = _iso(last_scan.ended_at)
    else:
        scan_stat       = f"Every {scan_interval}h · {scan_count} scans run"
        scan_last_event = _last_event_iso("scan")

    # Health monitoring: actual check interval + current status
    hc_min = int(hc_interval) // 60
    hc_stat = (
        f"Every {hc_min}m · {health_st} · "
        f"last {_ago(latest_hc.checked_at) if latest_hc else 'never'}"
    )

    # Traffic capture: actual process state
    try:
        from traffic.capture import capture_engine as _ce
        cap_status     = _ce.get_status()
        cap_running    = cap_status.get("running", False)
    except Exception:
        cap_running    = False
    traffic_enabled = _setting("capture_enabled", "false") == "true"
    if traffic_enabled and cap_running:
        traffic_stat = "Running · DNS + TLS + HTTP visible"
    elif traffic_enabled and not cap_running:
        traffic_stat = "STOPPED — watchdog restarting..."
    else:
        traffic_stat = "Off · enable to start deep inspection"

    # Threat intelligence: real IOC count
    try:
        from ai import threat_intel as _ti
        ti_count = sum(len(v) for v in _ti._STORE.values())
        ti_stat  = f"{ti_count:,} IOCs loaded · refreshes every 4h"
    except Exception:
        ti_stat = "45,000+ IOCs · refreshes every 4h"

    # Autonomous reports: last report time
    try:
        from models.tables import SecurityReport as _SR
        last_rep = (
            db.query(_SR)
            .filter(_SR.error.is_(None))
            .order_by(desc(_SR.id))
            .first()
        )
        report_last_event = _iso(last_rep.period_end) if last_rep else None
        report_stat = (
            f"Every hour · last {_ago(last_rep.period_end)}" if last_rep
            else "Every hour · no reports yet"
        )
    except Exception:
        report_last_event = None
        report_stat       = "Every hour · saved in Reports section"

    # Push notifications: verify ntfy server is actually reachable
    ntfy_server_val  = _setting("ntfy_server", "")
    ntfy_enabled_val = _setting("ntfy_enabled", "false") == "true"
    ntfy_reachable   = False
    if ntfy_enabled_val and ntfy_server_val:
        try:
            import urllib.request as _ur
            _ur.urlopen(ntfy_server_val, timeout=2).close()
            ntfy_reachable = True
        except Exception:
            ntfy_reachable = False
    if ntfy_enabled_val and not ntfy_reachable:
        ntfy_stat = f"{ntfy_server_val} — server unreachable"
    elif ntfy_enabled_val:
        ntfy_stat = f"{ntfy_server_val} — connected"
    else:
        ntfy_stat = ntfy_server_val or "not configured"

    # AI last investigation
    ai_last_event = _last_event_iso("ai")

    # Anomaly last check — use last ActivityLog entry written by anomaly (any level)
    anomaly_last_log = (
        db.query(ActivityLog)
        .filter(ActivityLog.category.in_(["alert", "anomaly"]))
        .order_by(desc(ActivityLog.id))
        .first()
    )
    anomaly_last_event = _iso(anomaly_last_log.created_at) if anomaly_last_log else _last_event_iso("scan")

    # Protection layers
    layers = [
        {
            "id": "auto_scan", "name": "Network Scanning",
            "description": f"Scans every {scan_interval}h for new or changed devices. Alerts on unknown devices immediately.",
            "enabled": _setting("auto_scan_enabled", "true") == "true",
            "setting_key": "auto_scan_enabled",
            "last_event": scan_last_event,
            "stat": scan_stat,
        },
        {
            "id": "health", "name": "Health Monitoring",
            "description": f"Checks latency and packet loss every {hc_min}m. Detects outages and DDoS saturation.",
            "enabled": True, "setting_key": None,
            "last_event": _iso(latest_hc.checked_at) if latest_hc else None,
            "stat": hc_stat,
        },
        {
            "id": "anomaly", "name": "Anomaly Detection",
            "description": "Runs every 60s. Detects traffic spikes, port scans, and sustained outages. Auto-blocks confirmed threats.",
            "enabled": _setting("anomaly_detection_enabled", "true") == "true",
            "setting_key": "anomaly_detection_enabled",
            "last_event": anomaly_last_event,
            "stat": "Every 60s · auto-blocks port scanners",
        },
        {
            "id": "threat_intel", "name": "Threat Intelligence",
            "description": "Checks IPs and domains against Feodo C2, Emerging Threats, URLhaus, and OpenPhish blocklists.",
            "enabled": True, "setting_key": None,
            "last_event": _last_event_iso("threat"),
            "stat": ti_stat,
        },
        {
            "id": "nighttime", "name": "Nighttime Guard",
            "description": "Unknown devices appearing 22:00–06:00 CT trigger critical priority alerts to your phone immediately.",
            "enabled": _setting("anomaly_detection_enabled", "true") == "true",
            "setting_key": "anomaly_detection_enabled",
            "last_event": None,
            "stat": "22:00 – 06:00 Central Time",
        },
        {
            "id": "traffic", "name": "Traffic Analysis",
            "description": "Deep packet inspection — DNS queries, HTTPS destinations (TLS SNI), protocol mix, top talkers.",
            "enabled": traffic_enabled,
            "setting_key": "capture_enabled",
            "last_event": _last_event_iso("traffic"),
            "stat": traffic_stat,
        },
        {
            "id": "ai", "name": "AI Investigation",
            "description": "Qwen2.5 analyzes suspicious devices locally and recommends or auto-executes defensive actions.",
            "enabled": _setting("ai_enabled", "false") == "true",
            "setting_key": "ai_enabled",
            "last_event": ai_last_event,
            "stat": "Local only · no cloud · no data leaves network",
        },
        {
            "id": "auto_report", "name": "Autonomous Reports",
            "description": "Qwen generates hourly plain-English security reports analyzing traffic, health, and anomalies automatically.",
            "enabled": _setting("ai_enabled", "false") == "true" and _setting("auto_report_enabled", "true") == "true",
            "setting_key": "auto_report_enabled",
            "last_event": report_last_event,
            "stat": report_stat,
        },
        {
            "id": "notifications", "name": "Push Notifications",
            "description": "Instant alerts to your phone via ntfy. Two-way: tap Block or Investigate directly from the notification.",
            "enabled": ntfy_enabled_val,
            "setting_key": "ntfy_enabled",
            "last_event": None,
            "stat": ntfy_stat,
        },
    ]

    # Recent security events — split into main feed and DNS feed
    # DNS events are excluded from main feed (too numerous) — shown in their own tab
    events = (
        db.query(ActivityLog)
        .filter(
            ActivityLog.level.in_(["warning", "critical", "threat", "action"]),
            ActivityLog.category != "dns",
            ActivityLog.dismissed == False,  # noqa: E712
        )
        .order_by(desc(ActivityLog.id))
        .limit(100)
        .all()
    )

    # DNS blocked events — separate feed, most recent 200
    dns_events = (
        db.query(ActivityLog)
        .filter(
            ActivityLog.category == "dns",
            ActivityLog.dismissed == False,  # noqa: E712
        )
        .order_by(desc(ActivityLog.id))
        .limit(200)
        .all()
    )

    # DNS blocked count (for tab badge)
    dns_blocked_count = db.query(ActivityLog).filter(
        ActivityLog.category == "dns",
        ActivityLog.dismissed == False,  # noqa: E712
    ).count()

    # Attach most recent Qwen verdict for each device_ip that has one
    ai_verdicts: dict[str, dict] = {}
    if _setting("ai_enabled") == "true":
        ip_set = {e.device_ip for e in events if e.device_ip}
        for ip in ip_set:
            verdict = (
                db.query(AISummary)
                .filter(AISummary.scan_id == None)  # noqa: E711  — investigation summaries
                .order_by(desc(AISummary.id))
                .limit(20)
                .all()
            )
            for v in verdict:
                raw = v.raw_response or ""
                if ip in raw and not v.error:
                    ai_verdicts[ip] = {
                        "severity":  v.severity,
                        "summary":   v.summary,
                        "created_at": _iso(v.created_at),
                    }
                    break

    def _parse_detail(raw):
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {"note": str(raw)[:300]}

    def _fmt_event(e, ai_verdicts=None):
        return {
            "id":         e.id,
            "created_at": _iso(e.created_at),
            "level":      e.level,
            "category":   e.category,
            "event":      e.event,
            "summary":    e.summary,
            "detail":     _parse_detail(e.detail),
            "device_ip":  e.device_ip,
            "ai_verdict": (ai_verdicts or {}).get(e.device_ip) if e.device_ip else None,
        }

    return {
        "threat_level": threat_level,
        "stats": {
            "devices":        device_count,
            "uptime_pct":     uptime_pct,
            "blocks":         len(blocks),
            "threats_24h":    threats_24h,
            "scans":          scan_count,
            "dns_blocked_total": dns_blocked_count,
        },
        "layers": layers,
        "events":     [_fmt_event(e, ai_verdicts) for e in events],
        "dns_events": [_fmt_event(e) for e in dns_events],
        "blocks": blocks,
    }


@router.post("/api/shield/events/{event_id}/dismiss")
def dismiss_shield_event(event_id: int, db: Session = Depends(get_db)):
    """Mark a single Shield feed event as dismissed so it leaves the feed."""
    entry = db.query(ActivityLog).filter(ActivityLog.id == event_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Event not found")
    entry.dismissed = True
    db.commit()
    return {"ok": True}


@router.post("/api/shield/dismiss-all")
def dismiss_all_shield_events(db: Session = Depends(get_db)):
    """Dismiss all non-DNS warning/critical/threat/action events from the feed."""
    db.query(ActivityLog).filter(
        ActivityLog.level.in_(["warning", "critical", "threat", "action"]),
        ActivityLog.category != "dns",
        ActivityLog.dismissed == False,  # noqa: E712
    ).update({"dismissed": True}, synchronize_session=False)
    db.commit()
    return {"ok": True}


@router.post("/api/shield/clear-dns-logs")
def clear_dns_logs(db: Session = Depends(get_db)):
    """Delete all DNS blocked log entries."""
    deleted = db.query(ActivityLog).filter(
        ActivityLog.category == "dns",
    ).delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": deleted}


@router.post("/api/shield/clear-all-logs")
def clear_all_logs(db: Session = Depends(get_db)):
    """Delete ALL activity log entries (full reset)."""
    deleted = db.query(ActivityLog).delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": deleted}


# ═════════════════════════════════════════════════════════════════════════════
# DNS AD BLOCKER
# ═════════════════════════════════════════════════════════════════════════════

@router.get("/api/dns/status")
def dns_status(db: Session = Depends(get_db)):
    """Return DNS blocker running state + stats."""
    from dns_blocker import blocklist, server as dns_srv

    row = db.query(Setting).filter(Setting.key == "dns_blocker_enabled").first()
    enabled = (row.value if row else "false") == "true"

    row2 = db.query(Setting).filter(Setting.key == "dns_upstream").first()
    upstream = row2.value if row2 else "8.8.8.8"

    # Get local IP for router instructions
    import socket
    local_ip = "Unknown"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    return {
        "enabled":   enabled,
        "running":   dns_srv.is_running(),
        "upstream":  upstream,
        "local_ip":  local_ip,
        "stats":     blocklist.get_stats(),
    }


@router.post("/api/dns/enable")
def dns_enable(db: Session = Depends(get_db)):
    """Enable the DNS blocker: update setting, download blocklists, start server."""
    row = db.query(Setting).filter(Setting.key == "dns_blocker_enabled").first()
    if row:
        row.value = "true"
    else:
        db.add(Setting(key="dns_blocker_enabled", value="true"))
    db.commit()

    row2 = db.query(Setting).filter(Setting.key == "dns_upstream").first()
    upstream = row2.value if row2 else "8.8.8.8"

    def _start():
        from dns_blocker import blocklist, server as dns_srv
        if not dns_srv.is_running():
            blocklist.refresh()
            blocklist.start_auto_refresh()
            ok = dns_srv.start(upstream=upstream)
            if not ok:
                print("[api/dns] Failed to start DNS server — port 53 may need admin rights")

    threading.Thread(target=_start, daemon=True, name="dns-enable").start()
    return {"ok": True, "message": "DNS blocker enabling — blocklists downloading..."}


@router.post("/api/dns/disable")
def dns_disable(db: Session = Depends(get_db)):
    """Disable the DNS blocker and stop the server."""
    row = db.query(Setting).filter(Setting.key == "dns_blocker_enabled").first()
    if row:
        row.value = "false"
    else:
        db.add(Setting(key="dns_blocker_enabled", value="false"))
    db.commit()

    from dns_blocker import server as dns_srv
    dns_srv.stop()
    return {"ok": True, "message": "DNS blocker disabled."}


@router.post("/api/dns/blocklist/refresh")
def dns_refresh_blocklist():
    """Force re-download of all blocklists (bypasses 24h cache)."""
    def _refresh():
        from dns_blocker import blocklist
        blocklist.refresh(force=True)

    threading.Thread(target=_refresh, daemon=True, name="dns-refresh").start()
    return {"ok": True, "message": "Blocklist refresh started in background..."}


@router.post("/api/dns/stats/reset")
def dns_reset_stats():
    """Reset today's query/blocked counters."""
    from dns_blocker import blocklist
    blocklist.reset_daily_stats()
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# NETWORK INFO  (local adapter, router, DNS, public IP)
# ═════════════════════════════════════════════════════════════════════════════

import re as _re
import subprocess as _sp
import urllib.request as _ureq

# ipconfig /all key → our field name mapping
_IPCFG_KEYS = {
    "Description":        "description",
    "Physical Address":   "mac",
    "DHCP Enabled":       "dhcp_enabled",
    "IPv4 Address":       "ipv4",
    "IPv6 Address":       "ipv6",
    "Subnet Mask":        "subnet",
    "Default Gateway":    "gateway",
    "DHCP Server":        "dhcp_server",
    "DNS Servers":        "dns_primary",
    "Lease Obtained":     "lease_obtained",
    "Lease Expires":      "lease_expires",
}

# Pattern: <label dots/spaces> : <value>
# ipconfig uses " . . . " padding between key and colon
_LINE_RE = _re.compile(r"^[ \t]+(.+?)[\s\.]+:\s+(.+)$")
_IP_RE   = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse_ipconfig_all() -> list[dict]:
    """
    Run `ipconfig /all` and parse each adapter block into a dict.
    Returns adapters that have at least one IPv4 address assigned.
    """
    try:
        out = _sp.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True,
            creationflags=0x08000000,
        ).stdout
    except Exception:
        return []

    adapters: list[dict] = []
    current:  dict | None = None
    last_field: str | None = None   # tracks multi-line fields (e.g. extra DNS)

    for line in out.splitlines():
        # Adapter header: no leading whitespace, ends with ":"
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            if current:
                adapters.append(current)
            current    = {"name": line.strip().rstrip(":")}
            last_field = None
            continue

        if current is None:
            continue

        m = _LINE_RE.match(line)
        if m:
            raw_key = m.group(1).strip()
            value   = m.group(2).strip().split("(")[0].strip()  # strip "(Preferred)"

            # Match raw_key against known keys (starts-with, case-insensitive)
            matched = None
            for k, f in _IPCFG_KEYS.items():
                if raw_key.lower().startswith(k.lower()):
                    matched = (k, f)
                    break

            if matched:
                _, field = matched
                if field == "dns_primary":
                    # Store as a list; first entry on this line
                    current.setdefault("dns_servers", [])
                    if value:
                        current["dns_servers"].append(value)
                    last_field = "dns_servers"
                else:
                    current.setdefault(field, value)
                    last_field = field
        else:
            # Continuation line: extra DNS servers are bare IPs on indented lines
            stripped = line.strip()
            if stripped and last_field == "dns_servers" and _IP_RE.match(stripped):
                current.setdefault("dns_servers", []).append(stripped)

    if current:
        adapters.append(current)

    # Only return adapters that have a real IP (not link-local 169.x)
    return [
        a for a in adapters
        if a.get("ipv4") and not a["ipv4"].startswith("169.")
    ]


_net_info_cache: dict = {}


def _get_public_ip() -> str:
    for url in ["https://api.ipify.org", "https://checkip.amazonaws.com"]:
        try:
            req = _ureq.Request(url, headers={"User-Agent": "NetMon/1.0"})
            with _ureq.urlopen(req, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            pass
    return "Unavailable"


def _get_public_ip_hardened() -> str:
    """
    Fetch public IP using a direct IP connection so it works even when
    DNS is pointing to 127.0.0.1 and the blocker isn't running yet.
    Uses Cloudflare's IP-addressed endpoint to avoid DNS dependency.
    """
    import socket
    for ip, host, path in [
        ("1.1.1.1",        "one.one.one.one",   "/cdn-cgi/trace"),
        ("208.67.222.222", "resolver1.opendns.com", None),
    ]:
        try:
            # Direct IP connection — no DNS needed
            req = _ureq.Request(
                f"https://{ip}/cdn-cgi/trace",
                headers={"Host": host, "User-Agent": "NetMon/1.0"},
            )
            with _ureq.urlopen(req, timeout=4) as r:
                for line in r.read().decode().splitlines():
                    if line.startswith("ip="):
                        return line.split("=", 1)[1].strip()
        except Exception:
            pass
    # Last resort: ipify via hardcoded IP
    try:
        req = _ureq.Request(
            "https://216.239.32.21/",   # Google IP
            headers={"Host": "api.ipify.org", "User-Agent": "NetMon/1.0"},
        )
        with _ureq.urlopen(req, timeout=4) as r:
            return r.read().decode().strip()
    except Exception:
        return "Unavailable"


def _refresh_public_ip_bg():
    """Refresh public IP in background thread; store in cache."""
    import time as _time
    try:
        ip = _get_public_ip_hardened()
        _net_info_cache["public_ip"]    = ip
        _net_info_cache["public_ip_ts"] = _time.time()
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
# UPTIME GUARDIAN  (auto-heal — detect outage, reboot router)
# ═════════════════════════════════════════════════════════════════════════════

_AUTOHEAL_KEYS = {
    "autoheal_enabled", "autoheal_dry_run", "autoheal_interval_s", "autoheal_confirm_checks",
    "autoheal_reboot_method", "autoheal_router_host", "autoheal_router_user", "autoheal_router_pass",
    "autoheal_router_ssl", "autoheal_router_port",
    "autoheal_internet_targets", "autoheal_max_reboots_per_outage", "autoheal_cooldown_min",
    "autoheal_max_reboots_per_day", "autoheal_recovery_window_s",
    "autoheal_smartplug_method", "autoheal_smartplug_host", "autoheal_smartplug_user", "autoheal_smartplug_pass",
}


@router.get("/api/autoheal")
def autoheal_status(db: Session = Depends(get_db)):
    """Uptime Guardian status — config (password redacted), live outage state,
    recent events, and reboot stats."""
    from monitoring.autoheal import get_config, _STATE, attempt_stats, build_storyline, group_events_into_incidents, get_playbook
    from monitoring.uptime_stats import get_uptime_stats

    cfg = get_config(db)
    safe_cfg = {k: v for k, v in cfg.items() if k not in ("router_pass", "smartplug_pass")}

    rows = (db.query(ActivityLog)
            .filter(ActivityLog.category == "autoheal")
            .order_by(desc(ActivityLog.id)).limit(40).all())

    def _detail(r):
        if not r.detail:
            return None
        try:
            return json.loads(r.detail)
        except Exception:
            return r.detail

    events = build_storyline([
        {"id": r.id, "event": r.event, "level": r.level, "summary": r.summary,
         "detail": _detail(r), "created_at": _iso(r.created_at)}
        for r in rows
    ])

    incidents = group_events_into_incidents(events, db)

    stats = attempt_stats(db)
    uptime = get_uptime_stats(db)
    playbook = get_playbook(db)

    return {
        "config": safe_cfg,
        "state": {
            "offline": _STATE["offline_since"] is not None,
            "offline_since": _iso(_STATE["offline_since"]) if _STATE["offline_since"] else None,
            "consecutive_offline": _STATE["consecutive_offline"],
            "rebooted_this_outage": _STATE["rebooted_this_outage"],
        },
        "stats": {"reboots_today": stats["reboots_today"],
                  "last_reboot": _iso(stats["last_reboot_at"]) if stats["last_reboot_at"] else None,
                  "counter_reset_at": _iso(stats["counter_reset_at"]) if stats["counter_reset_at"] else None,
                  "uptime": uptime},
        "events": events,
        "incidents": incidents,
        "playbook": playbook,
    }


@router.post("/api/autoheal/config")
def autoheal_save_config(body: dict = None, db: Session = Depends(get_db)):
    """Save Uptime Guardian settings (whitelisted keys only)."""
    body = body or {}
    saved = []
    for k, v in body.items():
        if k not in _AUTOHEAL_KEYS:
            continue
        val = "true" if v is True else "false" if v is False else str(v)
        row = db.query(Setting).filter(Setting.key == k).first()
        if row:
            row.value = val
        else:
            db.add(Setting(key=k, value=val))
        saved.append(k)
    db.commit()
    # Never log the password value itself.
    write_log("action", "autoheal", "config_updated",
              f"Uptime Guardian settings updated ({len(saved)} field(s))", actor="user")
    return {"saved": [k for k in saved if k != "autoheal_router_pass"],
            "password_set": "autoheal_router_pass" in saved}


@router.post("/api/autoheal/reboot-now")
def autoheal_reboot_now(body: dict = None, db: Session = Depends(get_db)):
    """Trigger a reboot on demand. Honors dry-run unless {"force": true}."""
    from monitoring.autoheal import manual_reboot
    force = bool((body or {}).get("force", False))
    return manual_reboot(db, force=force)


@router.post("/api/autoheal/reset-counter")
def autoheal_reset_counter(db: Session = Depends(get_db)):
    """Reset counted reboot attempts while preserving the ActivityLog audit trail."""
    from monitoring.autoheal import reset_reboot_counter
    return reset_reboot_counter(db)


@router.post("/api/autoheal/simulate")
def autoheal_simulate(body: dict = None, db: Session = Depends(get_db)):
    """Run the decision logic against synthetic scenarios — zero side effects.
    Lets the UI verify the brain without waiting for a real outage."""
    from monitoring.autoheal import decide, get_config
    cfg = get_config(db)
    now = datetime.now(timezone.utc)
    recovered_at = now - timedelta(seconds=cfg["recovery_window_s"] + 10)
    scenarios = [
        ("Brief blip (not yet confirmed)", False, True, 1, 0, None, False, 0),
        ("Confirmed outage, gateway reachable", False, True, cfg["confirm_checks"], 0, None, False, 0),
        ("Confirmed outage, gateway also down", False, False, cfg["confirm_checks"], 0, None, False, 0),
        ("Rebooted once, still down past recovery window", False, True, cfg["confirm_checks"] + 5, 1, recovered_at, False, 0),
        ("DNS blackout, raw IP still works", True, True, 0, 0, None, True, cfg["confirm_checks"]),
        ("Back online", True, True, 0, 0, None, False, 0),
    ]
    out = []
    for label, inet, gw, consec, reboots, last_at, dns_blackout, dns_checks in scenarios:
        d = decide(internet_up=inet, gateway_up=gw, dns_blackout=dns_blackout, dns_blackout_checks=dns_checks,
                   consecutive_offline=consec, cfg=cfg,
                   reboots_in_outage=reboots, reboots_today=reboots, last_attempt_at=last_at, now=now)
        out.append({"scenario": label, "decision": d})
    return {"dry_run": cfg["dry_run"], "enabled": cfg["enabled"], "scenarios": out}


@router.get("/api/network/info")
def get_network_info():
    """
    Detailed network info: all adapters, primary adapter details, router IP,
    current DNS servers, DHCP info, and public WAN IP.
    Never blocks on external network calls — public IP is fetched in background.
    """
    import time as _time
    adapters = _parse_ipconfig_all()

    # Primary = first adapter with a private-range gateway
    primary = None
    for a in adapters:
        gw = a.get("gateway", "")
        if gw and _re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", gw):
            primary = a
            break
    if not primary and adapters:
        primary = adapters[0]

    # Public IP — served from cache, refreshed in background every 5 min
    now = _time.time()
    if now - _net_info_cache.get("public_ip_ts", 0) > 300:
        # Don't block the request — kick off background refresh
        _net_info_cache["public_ip_ts"] = now  # prevent multiple simultaneous fetches
        threading.Thread(target=_refresh_public_ip_bg, daemon=True, name="public-ip").start()

    return {
        "adapters":  adapters,
        "primary":   primary,
        "public_ip": _net_info_cache.get("public_ip", "Fetching…"),
    }


@router.post("/api/network/detect")
def detect_network(request: Request):
    """Force re-detection of current network and return results."""
    from network.autodetect import get_network_info, invalidate_cache
    invalidate_cache()
    info = get_network_info()
    # Update app.state so scheduler picks it up immediately
    try:
        request.app.state.network_info = info
    except Exception:
        pass
    return info


# ═════════════════════════════════════════════════════════════════════════════
# SECURITY LAB — Phase 1: Generic routes + file upload
# ═════════════════════════════════════════════════════════════════════════════

from sqlalchemy import func as _sqlfunc

_running_procs: dict = {}
_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "security_uploads")


@router.post("/api/security/runs")
def list_security_runs(body: dict, db: Session = Depends(get_db)):
    tool   = body.get("tool")
    limit  = int(body.get("limit", 50))
    offset = int(body.get("offset", 0))
    q = db.query(SecurityToolRun)
    if tool:
        q = q.filter(SecurityToolRun.tool == tool)
    rows = q.order_by(desc(SecurityToolRun.created_at)).offset(offset).limit(limit).all()
    return {"runs": [
        {
            "id":               r.id,
            "tool":             r.tool,
            "tab":              r.tab,
            "target":           r.target,
            "status":           r.status,
            "risk_level":       r.risk_level,
            "created_at":       _iso(r.created_at),
            "completed_at":     _iso(r.completed_at),
            "duration_seconds": r.duration_seconds,
        }
        for r in rows
    ]}


@router.post("/api/security/run")
def get_security_run(body: dict, db: Session = Depends(get_db)):
    run_id = body.get("run_id")
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    run_data = {c.name: getattr(run, c.name) for c in run.__table__.columns}
    for k, v in run_data.items():
        if isinstance(v, datetime):
            run_data[k] = v.isoformat()

    chunks = (
        db.query(SecurityToolOutputChunk)
        .filter(SecurityToolOutputChunk.run_id == run_id)
        .order_by(SecurityToolOutputChunk.sequence)
        .all()
    )
    ai = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id).first()

    return {
        "run":    run_data,
        "chunks": [{"sequence": c.sequence, "stream": c.stream, "content": c.content, "created_at": _iso(c.created_at)} for c in chunks],
        "ai":     {
            "summary_text":          ai.summary_text,
            "findings_json":         json.loads(ai.findings_json or "[]"),
            "recommendations_json":  json.loads(ai.recommendations_json or "[]"),
        } if ai else None,
    }


@router.post("/api/security/run/stream")
def stream_security_run(body: dict, db: Session = Depends(get_db)):
    run_id         = body.get("run_id")
    after_sequence = int(body.get("after_sequence", 0))
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    chunks = (
        db.query(SecurityToolOutputChunk)
        .filter(SecurityToolOutputChunk.run_id == run_id, SecurityToolOutputChunk.sequence > after_sequence)
        .order_by(SecurityToolOutputChunk.sequence)
        .all()
    )
    return {
        "chunks": [{"sequence": c.sequence, "stream": c.stream, "content": c.content} for c in chunks],
        "status": run.status,
    }


@router.post("/api/security/fix/run")
def run_security_fix(body: dict, db: Session = Depends(get_db)):
    from security.fixes import run_fix, NIKTO_FIX_MAP
    action_key  = body.get("action_key", "")
    finding_text = body.get("finding_text", "")
    run_id      = body.get("run_id")
    if not action_key:
        raise HTTPException(status_code=400, detail="action_key required")
    result = run_fix(action_key)
    # Log as a lightweight security run entry
    try:
        from security.common import create_security_run, mark_run_started, mark_run_completed
        fix_run_id = create_security_run(db, tool="fix", tab="fix",
                                         target=f"{action_key}:{finding_text[:80]}",
                                         is_attack_tool=False, authorization_confirmed=True)
        mark_run_started(db, fix_run_id, command=[action_key])
        mark_run_completed(db, fix_run_id, status="succeeded" if result.get("ok") else "failed")
    except Exception:
        pass
    return result


@router.post("/api/security/fix/suggestions")
def fix_suggestions(body: dict, db: Session = Depends(get_db)):
    """Return matched fix actions for a given run's raw output."""
    from security.fixes import match_findings
    run_id = body.get("run_id")
    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    raw = run.raw_output_text or ""
    return {"suggestions": match_findings(raw)}


@router.post("/api/security/chat")
def security_chat(body: dict, db: Session = Depends(get_db)):
    run_id  = body.get("run_id")
    message = (body.get("message") or "").strip()
    history = body.get("history") or []
    if not run_id or not message:
        return {"reply": "Missing run_id or message.", "ok": False}

    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    ai  = db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id).first()

    tool   = run.tool   if run else "security"
    target = run.target if run else "your device"
    summary = ai.summary_text if ai else "No prior scan summary available."

    system_msg = (
        f"You are NetMon Security AI — a friendly home network security assistant. "
        f"A {tool} scan just ran on {target}. Key findings: {summary[:800]}. "
        f"Help the user fix issues step by step in plain English. Be concise, practical, "
        f"and assume they are not technical. Never suggest anything illegal."
    )

    messages = [{"role": "system", "content": system_msg}]
    for h in history[-10:]:  # cap context to last 10 turns
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": message})

    try:
        from ai.provider import chain_chat
        reply = chain_chat(messages)
        return {"reply": reply or "No response from AI.", "ok": True}
    except Exception as exc:
        print(f"[security.chat] {exc}")
        return {"reply": f"AI unavailable: {exc}", "ok": False}


@router.post("/api/security/run/cancel")
def cancel_security_run(body: dict, db: Session = Depends(get_db)):
    run_id = body.get("run_id")
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    proc = _running_procs.pop(run_id, None)
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    if run:
        run.status       = "cancelled"
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
    return {"ok": True}


@router.post("/api/security/upload")
async def upload_security_file(
    file: UploadFile = File(...),
    file_type: str   = Form(...),
    db: Session      = Depends(get_db),
):
    os.makedirs(_UPLOAD_DIR, exist_ok=True)
    contents = await file.read()
    sha256   = hashlib.sha256(contents).hexdigest()
    ext      = os.path.splitext(file.filename or "")[1]
    path     = os.path.join(_UPLOAD_DIR, f"{sha256}{ext}")
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(contents)
    existing = db.query(SecurityFile).filter(SecurityFile.sha256 == sha256).first()
    if existing:
        return {"file_id": existing.id, "sha256": sha256, "size_bytes": len(contents), "original_name": file.filename}
    sf = SecurityFile(
        file_type=file_type,
        original_name=file.filename,
        storage_path=path,
        sha256=sha256,
        size_bytes=len(contents),
    )
    db.add(sf)
    db.commit()
    db.refresh(sf)
    return {"file_id": sf.id, "sha256": sha256, "size_bytes": len(contents), "original_name": file.filename}


# ── Security Lab Phase 2: WSL ──────────────────────────────────────────────────

from security.wsl import check_wsl, check_all_tools, get_install_command, _wsl_exe
from security.common import create_security_run, mark_run_started, append_output_chunk, mark_run_completed


@router.post("/api/security/wsl/check")
def check_wsl_route(body: dict = None, db: Session = Depends(get_db)):
    body   = body or {}
    distro = body.get("distro") or "kali-linux"

    wsl    = check_wsl()
    tools  = check_all_tools(distro) if wsl["wsl_installed"] else {}
    cmd    = get_install_command(distro)
    missing = [t for t, info in tools.items() if not info.get("installed")]

    from models.tables import SecurityWSLCheck
    try:
        db.add(SecurityWSLCheck(
            wsl_installed        = wsl["wsl_installed"],
            default_distro       = wsl.get("default_distro"),
            distro_list_text     = wsl.get("distro_list_text", ""),
            tools_json           = json.dumps(tools),
            install_command_text = cmd,
        ))
        db.commit()
    except Exception:
        db.rollback()

    return {
        "wsl_installed":  wsl["wsl_installed"],
        "kali_present":   wsl.get("kali_present", False),
        "default_distro": wsl.get("default_distro"),
        "distro_list":    wsl.get("distro_list_text", ""),
        "distro":         distro,
        "tools":          tools,
        "install_command": cmd,
        "missing_tools":  missing,
    }


@router.post("/api/security/wsl/install/start")
def start_wsl_install(body: dict = None, db: Session = Depends(get_db)):
    body   = body or {}
    distro = body.get("distro") or "kali-linux"
    if not body.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="authorization_confirmed required")

    run_id = create_security_run(db, tool="wsl_install", tab="setup",
                                 is_attack_tool=False, authorization_confirmed=True)

    def _install(run_id, distro):
        from app.database import SessionLocal as _SL
        db2 = _SL()
        try:
            mark_run_started(db2, run_id)
            cmd = get_install_command(distro)
            proc = subprocess.Popen(
                [_wsl_exe(), "-d", distro, "--", "bash", "-lc", cmd],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            _running_procs[run_id] = proc

            def _pipe(stream_name, pipe):
                db3 = _SL()
                try:
                    for line in iter(pipe.readline, ""):
                        if line:
                            append_output_chunk(db3, run_id, stream=stream_name, content=line)
                finally:
                    db3.close(); pipe.close()

            t_out = threading.Thread(target=_pipe, args=("stdout", proc.stdout), daemon=True)
            t_err = threading.Thread(target=_pipe, args=("stderr", proc.stderr), daemon=True)
            t_out.start(); t_err.start()
            rc = proc.wait()
            t_out.join(); t_err.join()
            mark_run_completed(db2, run_id, status="succeeded" if rc == 0 else "failed", exit_code=rc)
        except Exception as e:
            append_output_chunk(db2, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db2, run_id, status="failed", error_message=str(e))
        finally:
            _running_procs.pop(run_id, None)
            db2.close()

    threading.Thread(target=_install, args=(run_id, distro), daemon=True).start()
    return {"run_id": run_id}


# ── Security Lab Phase 4: Nikto ────────────────────────────────────────────────

from security.validators import require_local_target
from security.nikto import run_nikto as _run_nikto


@router.post("/api/security/nikto/start")
def start_nikto_scan(body: dict, db: Session = Depends(get_db)):
    target = body.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="target is required")

    auth = bool(body.get("authorization_confirmed", False))
    require_local_target(target, authorization_confirmed=auth)

    run_id = create_security_run(
        db, tool="nikto", tab="vulnerability_scan",
        target=target, target_type="device_ip",
        is_attack_tool=False, authorization_confirmed=auth,
        device_id=body.get("device_id"),
    )

    # Accept either:
    #   { port: 80 }                — legacy single-port
    #   { ports: [80,443,8080] }    — explicit list
    #   { ports: "80,443,8080" }    — comma-string from the UI
    #   { auto: true }              — nmap-probe and scan whatever HTTP ports are open
    raw_ports = body.get("ports")
    parsed_ports: list[int] | None = None
    if isinstance(raw_ports, list):
        parsed_ports = [int(p) for p in raw_ports if str(p).strip().isdigit()]
    elif isinstance(raw_ports, str) and raw_ports.strip():
        parsed_ports = [int(p) for p in raw_ports.split(",") if p.strip().isdigit()]

    threading.Thread(
        target=_run_nikto,
        kwargs={
            "run_id":   run_id,
            "target":   target,
            "port":     body.get("port"),
            "ports":    parsed_ports,
            "auto":     bool(body.get("auto", False)),
            "use_ssl":  bool(body.get("use_ssl", False)),
            "distro":   body.get("distro", "kali-linux"),
        },
        daemon=True,
    ).start()

    return {"run_id": run_id}


# ── Security Lab Phase 5: Shodan ───────────────────────────────────────────────

import security.shodan_check as _shodan_mod


@router.post("/api/security/shodan/settings")
def save_shodan_settings(body: dict, db: Session = Depends(get_db)):
    api_key = body.get("api_key", "")
    row = db.query(Setting).filter(Setting.key == "shodan_api_key").first()
    if row:
        row.value = api_key
    else:
        db.add(Setting(key="shodan_api_key", value=api_key))
    db.commit()
    return {"ok": True}


@router.post("/api/security/shodan/check")
def start_shodan_check(body: dict, db: Session = Depends(get_db)):
    target_ip = body.get("target_ip")
    query_ip  = body.get("query_ip")
    device_id = body.get("device_id")

    row = db.query(Setting).filter(Setting.key == "shodan_api_key").first()
    api_key = (row.value or "").strip() if row else ""
    if not api_key:
        # Fall back to env var
        import os
        api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Shodan API key not configured. Go to Security Lab > Internet Exposure to add it.",
        )

    run_id = create_security_run(
        db, tool="shodan", tab="internet_exposure",
        target=target_ip, target_type="device_ip",
        is_attack_tool=False, authorization_confirmed=True,
        device_id=device_id,
    )

    threading.Thread(
        target=_shodan_mod.run_shodan_check,
        kwargs={"run_id": run_id, "target_ip": target_ip,
                "query_ip": query_ip, "api_key": api_key},
        daemon=True,
    ).start()

    return {"run_id": run_id}


# ── Security Lab Phases 6-10: tshark, john, hydra, aircrack, metasploit ───────

import security.tshark_ext as _tshark_mod
import security.john       as _john_mod
import security.hydra      as _hydra_mod
import security.aircrack   as _aircrack_mod
import security.metasploit as _msf_mod


# ── tshark ────────────────────────────────────────────────────────────────────

@router.post("/api/security/tshark/capture/start")
def start_tshark_capture(body: dict, db: Session = Depends(get_db)):
    auth = bool(body.get("authorization_confirmed", False))
    run_id = create_security_run(db, tool="tshark", tab="packet_capture",
        target=body.get("interface"), is_attack_tool=False, authorization_confirmed=auth)
    threading.Thread(target=_tshark_mod.run_tshark_capture, kwargs={
        "run_id": run_id, "interface": body.get("interface", "eth0"),
        "duration_seconds": int(body.get("duration_seconds", 60)),
        "capture_filter": body.get("capture_filter"),
        "distro": body.get("distro", "kali-linux"),
    }, daemon=True).start()
    return {"run_id": run_id}


@router.post("/api/security/tshark/analyze/start")
def start_tshark_analyze(body: dict, db: Session = Depends(get_db)):
    file_id = body.get("pcap_file_id")
    if not file_id:
        raise HTTPException(status_code=400, detail="pcap_file_id required")
    sf = db.query(SecurityFile).filter(SecurityFile.id == file_id).first()
    if not sf:
        raise HTTPException(status_code=404, detail="File not found")
    run_id = create_security_run(db, tool="tshark", tab="packet_capture",
        target=sf.original_name, is_attack_tool=False, authorization_confirmed=True)
    threading.Thread(target=_tshark_mod.run_tshark_analyze, kwargs={
        "run_id": run_id, "pcap_file_path": sf.storage_path,
        "distro": body.get("distro", "kali-linux"),
    }, daemon=True).start()
    return {"run_id": run_id}


# ── John the Ripper ───────────────────────────────────────────────────────────

@router.post("/api/security/john/start")
def start_john(body: dict, db: Session = Depends(get_db)):
    if not body.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="authorization_confirmed required")
    hash_file_id = body.get("hash_file_id")
    if not hash_file_id:
        raise HTTPException(status_code=400, detail="hash_file_id required")
    hf = db.query(SecurityFile).filter(SecurityFile.id == hash_file_id).first()
    if not hf:
        raise HTTPException(status_code=404, detail="Hash file not found")
    wl_path = None
    if body.get("wordlist_file_id"):
        wf = db.query(SecurityFile).filter(SecurityFile.id == body["wordlist_file_id"]).first()
        if wf:
            wl_path = wf.storage_path
    run_id = create_security_run(db, tool="john", tab="password_test",
        target=hf.original_name, is_attack_tool=True, authorization_confirmed=True)
    threading.Thread(target=_john_mod.run_john, kwargs={
        "run_id": run_id, "hash_file_path": hf.storage_path,
        "wordlist_file_path": wl_path,
        "format_name": body.get("format_name", "auto"),
        "distro": body.get("distro", "kali-linux"),
        "max_runtime_seconds": int(body.get("max_runtime_seconds", 900)),
    }, daemon=True).start()
    return {"run_id": run_id}


# ── Hydra ─────────────────────────────────────────────────────────────────────

@router.post("/api/security/hydra/start")
def start_hydra(body: dict, db: Session = Depends(get_db)):
    target = body.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="target required")
    if not body.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="authorization_confirmed required")
    require_local_target(target, authorization_confirmed=True)
    pw_path = None
    if body.get("password_file_id"):
        pf = db.query(SecurityFile).filter(SecurityFile.id == body["password_file_id"]).first()
        if pf:
            pw_path = pf.storage_path
    un_path = None
    if body.get("username_file_id"):
        uf = db.query(SecurityFile).filter(SecurityFile.id == body["username_file_id"]).first()
        if uf:
            un_path = uf.storage_path
    run_id = create_security_run(db, tool="hydra", tab="password_test",
        target=target, is_attack_tool=True, authorization_confirmed=True,
        device_id=body.get("device_id"))

    # Auto mode: nmap-detect open login services, then test each one. The user
    # only supplies the target — no need to know which service to pick.
    if body.get("auto") or body.get("service") == "auto":
        threading.Thread(target=_hydra_mod.run_hydra_auto, kwargs={
            "run_id": run_id, "target": target,
            "username": body.get("username"),
            "username_file_path": un_path,
            "password_file_path": pw_path,
            "single_password": body.get("single_password"),
            "max_parallel_tasks": int(body.get("max_parallel_tasks", 4)),
            "distro": body.get("distro", "kali-linux"),
        }, daemon=True).start()
        return {"run_id": run_id}

    threading.Thread(target=_hydra_mod.run_hydra, kwargs={
        "run_id": run_id, "target": target,
        "service": body.get("service", "ssh"),
        "username": body.get("username"),
        "username_file_path": un_path,
        "password_file_path": pw_path,
        "single_password": body.get("single_password"),
        "port": body.get("port"),
        "login_path": body.get("login_path"),
        "form_spec": body.get("form_spec"),
        "max_parallel_tasks": int(body.get("max_parallel_tasks", 4)),
        "distro": body.get("distro", "kali-linux"),
    }, daemon=True).start()
    return {"run_id": run_id}


# ── Aircrack-ng ───────────────────────────────────────────────────────────────

@router.post("/api/security/wifi/capture/start")
def start_wifi_capture(body: dict, db: Session = Depends(get_db)):
    if not body.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="authorization_confirmed required")
    run_id = create_security_run(db, tool="aircrack", tab="wifi_test",
        target=body.get("bssid") or body.get("interface"), is_attack_tool=True, authorization_confirmed=True)
    threading.Thread(target=_aircrack_mod.run_wifi_capture, kwargs={
        "run_id": run_id,
        "interface": body.get("interface", "wlan0"),
        "bssid": body.get("bssid"),
        "channel": body.get("channel"),
        "duration_seconds": int(body.get("duration_seconds", 60)),
        "distro": body.get("distro", "kali-linux"),
    }, daemon=True).start()
    return {"run_id": run_id}


@router.post("/api/security/wifi/aircrack/start")
def start_aircrack(body: dict, db: Session = Depends(get_db)):
    if not body.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="authorization_confirmed required")
    cap_id = body.get("capture_file_id")
    wl_id  = body.get("wordlist_file_id")
    if not cap_id or not wl_id:
        raise HTTPException(status_code=400, detail="capture_file_id and wordlist_file_id required")
    cf = db.query(SecurityFile).filter(SecurityFile.id == cap_id).first()
    wf = db.query(SecurityFile).filter(SecurityFile.id == wl_id).first()
    if not cf or not wf:
        raise HTTPException(status_code=404, detail="File not found")
    run_id = create_security_run(db, tool="aircrack-ng", tab="wifi_test",
        target=body.get("bssid") or cf.original_name, is_attack_tool=True, authorization_confirmed=True)
    threading.Thread(target=_aircrack_mod.run_aircrack, kwargs={
        "run_id": run_id,
        "capture_file_path": cf.storage_path,
        "wordlist_file_path": wf.storage_path,
        "bssid": body.get("bssid"),
        "distro": body.get("distro", "kali-linux"),
    }, daemon=True).start()
    return {"run_id": run_id}


# ── Metasploit ────────────────────────────────────────────────────────────────

@router.post("/api/security/metasploit/start")
def start_metasploit(body: dict, db: Session = Depends(get_db)):
    target      = body.get("target")
    # Default to a safe TCP port scan when no module is supplied so the run
    # never fails just because the caller omitted module_name.
    module_name = (body.get("module_name") or "").strip() or "auxiliary/scanner/portscan/tcp"
    if not target:
        raise HTTPException(status_code=400, detail="target required")
    if not body.get("authorization_confirmed"):
        raise HTTPException(status_code=400, detail="authorization_confirmed required")
    require_local_target(target, authorization_confirmed=True)
    run_id = create_security_run(db, tool="metasploit", tab="exploit_test",
        target=target, is_attack_tool=True, authorization_confirmed=True,
        device_id=body.get("device_id"))
    threading.Thread(target=_msf_mod.run_metasploit, kwargs={
        "run_id": run_id, "target": target,
        "module_name": module_name,
        "options": body.get("options", {}),
        "distro": body.get("distro", "kali-linux"),
        "timeout_seconds": int(body.get("timeout_seconds", 3600)),
    }, daemon=True).start()
    return {"run_id": run_id}


# ═════════════════════════════════════════════════════════════════════════════
# DEVICE INVESTIGATION CHAT
# Interactive AI chat per-device: ask questions, request tools, propose identity.
# ═════════════════════════════════════════════════════════════════════════════

def _device_or_404(db: Session, device_id: int) -> Device:
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail=f"device {device_id} not found")
    return dev


def _device_chat_history(db: Session, device_id: int, limit: int = 60) -> list[dict]:
    from models.tables import DeviceChat
    rows = (db.query(DeviceChat)
              .filter(DeviceChat.device_id == device_id)
              .order_by(DeviceChat.id.asc()).all())
    rows = rows[-limit:]
    out = []
    for r in rows:
        meta = None
        if r.meta_json:
            try: meta = json.loads(r.meta_json)
            except Exception: pass
        out.append({
            "id": r.id, "role": r.role, "content": r.content,
            "meta": meta, "created_at": _iso(r.created_at),
        })
    return out


def _device_notes(db: Session, device_id: int) -> list[str]:
    from models.tables import DeviceNote
    rows = (db.query(DeviceNote)
              .filter(DeviceNote.device_id == device_id)
              .order_by(desc(DeviceNote.id)).limit(40).all())
    return [r.body for r in rows]


def _save_chat_turn(db: Session, device_id: int, role: str, content: str,
                    meta: dict | None = None):
    from models.tables import DeviceChat
    row = DeviceChat(
        device_id=device_id, role=role, content=content,
        meta_json=json.dumps(meta) if meta else None,
    )
    db.add(row)
    db.flush()
    return row


def _save_note(db: Session, device_id: int, body: str, kind: str = "fact",
               confidence: float | None = None, source: str | None = None):
    from models.tables import DeviceNote
    existing = (db.query(DeviceNote)
                  .filter(DeviceNote.device_id == device_id)
                  .order_by(desc(DeviceNote.id)).limit(40).all())
    body_norm = body.strip().lower()
    for e in existing:
        if e.body.strip().lower() == body_norm:
            return e
    row = DeviceNote(device_id=device_id, body=body.strip(),
                     kind=kind, confidence=confidence, source=source)
    db.add(row)
    db.flush()
    return row


@router.get("/api/device/{device_id}/chat")
def device_chat_history(device_id: int, db: Session = Depends(get_db)):
    """Return chat transcript + durable notes for a device."""
    _device_or_404(db, device_id)
    from models.tables import DeviceNote
    notes = (db.query(DeviceNote)
                .filter(DeviceNote.device_id == device_id)
                .order_by(desc(DeviceNote.id)).limit(40).all())
    return {
        "history": _device_chat_history(db, device_id, limit=200),
        "notes": [{
            "id": n.id, "kind": n.kind, "body": n.body,
            "confidence": n.confidence, "source": n.source,
            "created_at": _iso(n.created_at),
        } for n in notes],
    }


_DEAD_END_PATTERNS = (
    "let's try", "let me try", "let's check", "let me check",
    "let's see", "let me see", "let's look", "let me look",
    "let's find", "more clues", "more analysis", "more digging",
    "i'll run", "i'll check", "i will check", "i will run",
    "we should look", "we need to look",
)

# Default fallback chain when the AI dead-ends — tried in order, first one
# whose name hasn't already appeared in chat history is the auto-pick.
_FALLBACK_TOOL_ORDER = [
    "mac_randomization_check",
    "mdns_ssdp_hostnames",
    "tls_sni_history",
    "talked_to_hosts",
    "http_user_agents",
    "dhcp_fingerprint_history",
    "port_history",
    "recent_traffic_summary",
    "oui_lookup",
]


def _is_dead_end_reply(parsed: dict) -> bool:
    """No action AND no proposal AND not a concrete question to the user."""
    if parsed.get("tool_request") or parsed.get("proposal"):
        return False
    reply = (parsed.get("reply") or "").strip()
    if not reply:
        return True
    lower = reply.lower()
    if any(p in lower for p in _DEAD_END_PATTERNS):
        return True
    # No promise phrase, but also no proposal/tool: only acceptable if the AI
    # is asking the user a concrete question.
    if "?" in reply:
        return False
    return True


def _pick_fallback_tool(db: Session, device_id: int) -> str | None:
    """Pick the next never-tried passive tool from the fallback order."""
    from models.tables import DeviceChat
    used: set[str] = set()
    for row in (db.query(DeviceChat)
                  .filter(DeviceChat.device_id == device_id,
                          DeviceChat.role == "tool")
                  .all()):
        if row.meta_json:
            try:
                m = json.loads(row.meta_json)
                if m.get("tool"):
                    used.add(m["tool"])
            except Exception:
                pass
    for name in _FALLBACK_TOOL_ORDER:
        if name not in used:
            return name
    return None


def _ai_chat_step(db: Session, device, user_message: str | None,
                  tool_result: dict | None,
                  allow_retry: bool = True) -> dict:
    """One LLM round. Returns parsed {reply, tool_request, proposal, notes}.

    If the model returns a dead-end reply (promise of future action with no
    tool_request and no proposal), retry once with a stricter instruction.
    If that still dead-ends, the caller will auto-pick a fallback tool.
    """
    from ai.provider import get_investigation_provider
    from ai.investigation_chat import (
        build_chat_prompt, build_evidence_bundle, parse_chat_response,
    )
    provider = get_investigation_provider()
    if provider.name == "none":
        return {"reply": "AI is not configured.", "tool_request": None,
                "proposal": None, "notes": []}
    history = _device_chat_history(db, device.id, limit=20)
    notes = _device_notes(db, device.id)
    evidence = build_evidence_bundle(db, device)
    prompt = build_chat_prompt(
        device=device, evidence_bundle=evidence, notes=notes,
        history=history, user_message=user_message or "", tool_result=tool_result,
    )
    result = provider.analyze({}, prompt=prompt, kind="device_chat")
    raw = result.get("raw_response") or result.get("summary") or ""
    if result.get("error"):
        return {"reply": f"AI error: {result['error']}", "tool_request": None,
                "proposal": None, "notes": []}
    parsed = parse_chat_response(raw)

    if allow_retry and _is_dead_end_reply(parsed):
        # Retry once with an explicit corrective addendum.
        stricter = prompt + (
            "\n\nYour previous answer was a dead-end (promised an action but "
            "set tool_request=null AND proposal=null). REWRITE: either set "
            "`tool_request` to a specific tool name from the catalog, OR set "
            "`proposal` with your best guess at confidence 0.4–0.7, OR ask the "
            "user a single concrete question. No 'let's try' phrasing."
        )
        result2 = provider.analyze({}, prompt=stricter, kind="device_chat")
        raw2 = result2.get("raw_response") or ""
        if raw2 and not result2.get("error"):
            parsed2 = parse_chat_response(raw2)
            if not _is_dead_end_reply(parsed2):
                return parsed2

        # Still stuck — auto-pick a fallback passive tool.
        fb = _pick_fallback_tool(db, device.id)
        if fb:
            parsed["tool_request"] = {
                "name": fb, "args": {},
                "rationale": "auto-selected because the AI dead-ended",
            }
            if not parsed.get("reply"):
                parsed["reply"] = f"Trying {fb} to gather more evidence."

    return parsed


def _apply_proposal(db: Session, device, proposal: dict,
                    prev_label: str | None = None,
                    prev_os: str | None = None) -> dict:
    """Apply a proposed identity update. ≥0.80 confidence required."""
    changes = []
    name = (proposal.get("name") or "").strip()
    category = (proposal.get("category") or "").strip()
    os_str = (proposal.get("os") or "").strip()
    confidence = float(proposal.get("confidence") or 0)

    if confidence < 0.80:
        return {"applied": False, "reason": "below 0.80 confidence",
                "confidence": confidence}

    if prev_label is None: prev_label = device.label
    if prev_os is None: prev_os = device.os_guess

    if name and name != device.label:
        changes.append(f"label: {device.label or '(none)'} → {name}")
        device.label = name
        device.is_known = True
    if os_str and os_str != (device.os_guess or ""):
        changes.append(f"os: {device.os_guess or '(none)'} → {os_str}")
        device.os_guess = os_str
        device.os_guess_at = datetime.utcnow()
    if category:
        _save_note(db, device.id, f"category: {category}", kind="identity",
                   confidence=confidence, source="proposal")
        changes.append(f"category: {category}")
    reasoning = (proposal.get("reasoning") or "").strip()
    if reasoning:
        _save_note(db, device.id, f"identity reasoning: {reasoning[:300]}",
                   kind="identity", confidence=confidence, source="proposal")

    if changes:
        # Inline ActivityLog write — write_log() opens its own session and
        # would deadlock against the device row we just modified.
        db.add(ActivityLog(
            level="action", category="ai",
            event="identity_auto_apply",
            summary=f"AI auto-identified device #{device.id}: {name or '(no change to name)'}",
            detail=json.dumps({"changes": changes, "confidence": confidence,
                               "proposal": proposal}, default=str),
            device_id=device.id, actor="ai_auto",
            revert_json=json.dumps({
                "action_type": "device_label_revert",
                "params": {"device_id": device.id,
                           "prev_label": prev_label, "prev_os": prev_os},
            }, default=str),
        ))
        try:
            from ai.knowledge_bridge import (
                record_device_profile_lesson,
                record_timeline_event,
            )
            profile = {
                "device_id": device.id,
                "label": device.label,
                "os_guess": device.os_guess,
                "is_known": device.is_known,
                "category": category,
            }
            evidence = {
                "proposal": proposal,
                "changes": changes,
                "reasoning": reasoning,
                "source": "identity_proposal",
            }
            record_device_profile_lesson(
                device_key=f"netmon.device.{device.id}",
                profile=profile,
                evidence=evidence,
                confidence=confidence,
                summary=f"AI identity proposal applied to device #{device.id}: {name or device.label or 'unnamed'}",
            )
            record_timeline_event(
                correlation_id=f"netmon.device.{device.id}",
                service="device",
                event_type="identity_auto_apply",
                severity="info",
                summary=f"AI auto-applied identity for device #{device.id}",
                detail={"profile": profile, "evidence": evidence},
            )
        except Exception:
            pass
    return {"applied": True, "changes": changes, "confidence": confidence}


def _persist_ai_turn(db: Session, device, parsed: dict,
                     tool_name: str | None = None):
    meta: dict = {}
    if parsed.get("tool_request"): meta["tool_request"] = parsed["tool_request"]
    if parsed.get("proposal"):     meta["proposal"]     = parsed["proposal"]
    if tool_name:                  meta["after_tool"]   = tool_name
    _save_chat_turn(db, device.id, "assistant", parsed.get("reply", ""),
                    meta=meta or None)
    for n in (parsed.get("notes") or []):
        if isinstance(n, str) and n.strip():
            _save_note(db, device.id, n.strip(), kind="fact", source="chat")
    proposal = parsed.get("proposal")
    auto_result: dict | None = None
    if proposal:
        prev_label = device.label
        prev_os = device.os_guess
        auto_result = _apply_proposal(db, device, proposal,
                                      prev_label=prev_label, prev_os=prev_os)
    return auto_result


@router.post("/api/device/{device_id}/chat")
def device_chat_post(device_id: int, body: dict, db: Session = Depends(get_db)):
    """
    Send user message OR approve/reject a previously-requested tool.

    Body shapes:
      {"message": "is this my phone?"}
      {"approve_tool": {"name":"nmap_quick", "args":{}}}
      {"reject_tool": {"name":"nmap_deep"}}
    """
    from ai.investigation_chat import ACTIVE_TOOLS, PASSIVE_TOOLS, execute_tool
    from models.tables import DeviceChat as _DC, DeviceNote
    device = _device_or_404(db, device_id)
    message = (body.get("message") or "").strip()
    approve_tool = body.get("approve_tool")
    reject_tool = body.get("reject_tool")

    max_id_row = (db.query(_DC.id)
                    .filter(_DC.device_id == device_id)
                    .order_by(desc(_DC.id)).first())
    last_id_before = (max_id_row[0] if max_id_row else 0)

    pending_approval = False
    applied_info: dict | None = None

    def _chain_passive_tool(parsed, depth=0):
        """If parsed.tool_request is passive, auto-run it and loop. Max 6 chains."""
        nonlocal applied_info, pending_approval
        if depth >= 6:
            return parsed
        req = parsed.get("tool_request")
        if not req:
            return parsed
        name = req.get("name")
        if name in ACTIVE_TOOLS:
            pending_approval = True
            return parsed
        if name not in PASSIVE_TOOLS:
            return parsed
        args = req.get("args") or {}
        out = execute_tool(db, device, name, args)
        _save_chat_turn(db, device_id, "tool", out,
                        meta={"tool": name, "args": args})
        db.commit()
        next_parsed = _ai_chat_step(db, device, user_message=None,
                                    tool_result={"name": name, "args": args,
                                                 "output": out})
        applied = _persist_ai_turn(db, device, next_parsed, tool_name=name)
        applied_info = applied or applied_info
        db.commit()
        return _chain_passive_tool(next_parsed, depth=depth + 1)

    if approve_tool:
        name = (approve_tool.get("name") or "").strip()
        args = approve_tool.get("args") or {}
        if not name:
            raise HTTPException(status_code=400, detail="approve_tool.name required")
        _save_chat_turn(db, device_id, "user", f"(approved {name})",
                        meta={"approval": name})
        output = execute_tool(db, device, name, args)
        _save_chat_turn(db, device_id, "tool", output,
                        meta={"tool": name, "args": args})
        db.commit()
        parsed = _ai_chat_step(db, device, user_message=None,
                               tool_result={"name": name, "args": args,
                                            "output": output})
        applied_info = _persist_ai_turn(db, device, parsed, tool_name=name)
        db.commit()
        parsed = _chain_passive_tool(parsed)
        if parsed.get("tool_request", {}) and parsed["tool_request"].get("name") in ACTIVE_TOOLS:
            pending_approval = True
    elif reject_tool:
        name = (reject_tool.get("name") or "").strip()
        _save_chat_turn(db, device_id, "user", f"(declined to run {name})",
                        meta={"rejected": name})
        db.commit()
        parsed = _ai_chat_step(db, device,
                               user_message=f"The user declined to run {name}. Proceed with what you have.",
                               tool_result=None)
        applied_info = _persist_ai_turn(db, device, parsed, tool_name=None)
        db.commit()
        parsed = _chain_passive_tool(parsed)
        if parsed.get("tool_request", {}) and parsed["tool_request"].get("name") in ACTIVE_TOOLS:
            pending_approval = True
    else:
        if not message:
            raise HTTPException(status_code=400,
                                detail="message, approve_tool, or reject_tool required")
        _save_chat_turn(db, device_id, "user", message)
        db.commit()
        parsed = _ai_chat_step(db, device, user_message=message, tool_result=None)
        applied_info = _persist_ai_turn(db, device, parsed, tool_name=None)
        db.commit()
        parsed = _chain_passive_tool(parsed)
        if parsed.get("tool_request", {}) and parsed["tool_request"].get("name") in ACTIVE_TOOLS:
            pending_approval = True

    # Collect rows appended this round
    new_rows = (db.query(_DC)
                  .filter(_DC.device_id == device_id, _DC.id > last_id_before)
                  .order_by(_DC.id.asc()).all())
    appended = []
    for r in new_rows:
        meta = None
        if r.meta_json:
            try: meta = json.loads(r.meta_json)
            except Exception: pass
        appended.append({
            "id": r.id, "role": r.role, "content": r.content,
            "meta": meta, "created_at": _iso(r.created_at),
        })
    notes = (db.query(DeviceNote)
                .filter(DeviceNote.device_id == device_id)
                .order_by(desc(DeviceNote.id)).limit(40).all())

    latest_proposal = None
    latest_tool_request = None
    for r in reversed(new_rows):
        if r.role != "assistant" or not r.meta_json:
            continue
        try:
            meta = json.loads(r.meta_json)
        except Exception:
            continue
        if latest_proposal is None and meta.get("proposal"):
            latest_proposal = meta["proposal"]
        if latest_tool_request is None and meta.get("tool_request"):
            latest_tool_request = meta["tool_request"]
        if latest_proposal and latest_tool_request: break

    return {
        "appended": appended,
        "notes": [{
            "id": n.id, "kind": n.kind, "body": n.body,
            "confidence": n.confidence, "source": n.source,
            "created_at": _iso(n.created_at),
        } for n in notes],
        "proposal": latest_proposal,
        "proposal_applied": bool(applied_info and applied_info.get("applied")),
        "applied_changes": (applied_info or {}).get("changes") or [],
        "tool_request": latest_tool_request,
        "pending_approval": pending_approval,
        "device": {"id": device.id, "label": device.label,
                   "os_guess": device.os_guess, "is_known": device.is_known},
    }


@router.get("/api/device/{device_id}/chat/tools")
def device_chat_tools(device_id: int, db: Session = Depends(get_db)):
    """Catalog of tools the chat can use."""
    _device_or_404(db, device_id)
    from ai.investigation_chat import tool_catalog
    return {"tools": tool_catalog()}


@router.post("/api/device/{device_id}/chat/proposal")
def device_chat_proposal_action(device_id: int, body: dict,
                                db: Session = Depends(get_db)):
    """Manually accept/edit/reject a proposal that didn't auto-apply."""
    device = _device_or_404(db, device_id)
    action = (body.get("action") or "").strip()
    proposal = body.get("proposal") or {}
    if action == "accept":
        p = dict(proposal)
        p["confidence"] = max(float(p.get("confidence") or 0), 0.99)
        if body.get("name"): p["name"] = body["name"]
        if body.get("os"):   p["os"]   = body["os"]
        result = _apply_proposal(db, device, p)
        _save_chat_turn(db, device_id, "system",
                        f"User accepted identity: {p.get('name','?')} ({p.get('category','?')})",
                        meta={"manual_accept": p})
        db.commit()
        try:
            from ai.knowledge_bridge import record_user_feedback
            record_user_feedback(
                target_type="device_identity",
                target=f"netmon.device.{device.id}",
                verdict="accepted",
                note=json.dumps(p, default=str)[:1000],
            )
        except Exception:
            pass
        return {"applied": True, "changes": result.get("changes", []),
                "device": {"id": device.id, "label": device.label,
                           "os_guess": device.os_guess}}
    elif action == "reject":
        _save_chat_turn(db, device_id, "system",
                        f"User rejected proposal: {proposal.get('name','?')}",
                        meta={"manual_reject": proposal})
        db.commit()
        try:
            from ai.knowledge_bridge import record_user_feedback
            record_user_feedback(
                target_type="device_identity",
                target=f"netmon.device.{device.id}",
                verdict="rejected",
                note=json.dumps(proposal, default=str)[:1000],
            )
        except Exception:
            pass
        return {"applied": False}
    else:
        raise HTTPException(status_code=400, detail="action must be accept or reject")


@router.post("/api/device/{device_id}/chat/undo")
def device_chat_undo(device_id: int, db: Session = Depends(get_db)):
    """Undo the most recent identity_auto_apply for this device (within 5 min)."""
    device = _device_or_404(db, device_id)
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    log = (db.query(ActivityLog)
             .filter(ActivityLog.device_id == device_id,
                     ActivityLog.event == "identity_auto_apply",
                     ActivityLog.reverted_at == None,
                     ActivityLog.created_at >= cutoff)
             .order_by(desc(ActivityLog.id)).first())
    if not log or not log.revert_json:
        return {"undone": False, "reason": "nothing to undo"}
    try:
        rj = json.loads(log.revert_json)
        params = rj.get("params") or {}
        device.label = params.get("prev_label")
        device.os_guess = params.get("prev_os")
        log.reverted_at = datetime.utcnow()
        log.reverted_by = "user"
        _save_chat_turn(db, device_id, "system",
                        "User undid the last AI identity application.",
                        meta={"undo": True})
        db.commit()
        return {"undone": True, "device": {
            "id": device.id, "label": device.label, "os_guess": device.os_guess,
        }}
    except Exception as ex:
        db.rollback()
        return {"undone": False, "reason": str(ex)}


@router.delete("/api/device/{device_id}/chat")
def device_chat_clear(device_id: int, db: Session = Depends(get_db)):
    """Clear chat transcript (durable notes are kept)."""
    from models.tables import DeviceChat
    _device_or_404(db, device_id)
    db.query(DeviceChat).filter(DeviceChat.device_id == device_id).delete()
    db.commit()
    return {"cleared": True}


@router.post("/api/device/{device_id}/chat/{turn_id}/explain")
def device_chat_explain(device_id: int, turn_id: int, db: Session = Depends(get_db)):
    """Generate an AI-powered explanation for a specific chat turn."""
    from models.tables import DeviceChat
    from ai.provider import get_investigation_provider
    from ai.investigation_chat import build_explanation_prompt

    device = _device_or_404(db, device_id)
    turn = (db.query(DeviceChat)
              .filter(DeviceChat.device_id == device_id, DeviceChat.id == turn_id)
              .first())
    if not turn:
        raise HTTPException(status_code=404, detail=f"chat turn {turn_id} not found")

    provider = get_investigation_provider()
    if provider.name == "none":
        raise HTTPException(status_code=400, detail="AI is not configured.")

    meta = {}
    if turn.meta_json:
        try:
            meta = json.loads(turn.meta_json)
        except Exception:
            pass

    prompt = build_explanation_prompt(device, turn.role, turn.content, meta)
    result = provider.analyze({}, prompt=prompt, kind="device_chat_explain")
    if result.get("error"):
        raise HTTPException(status_code=500, detail=f"AI error: {result['error']}")

    explanation = result.get("raw_response") or result.get("summary") or ""
    if not explanation.strip():
        raise HTTPException(status_code=500, detail="AI returned an empty explanation.")

    meta["explanation"] = explanation.strip()
    turn.meta_json = json.dumps(meta)
    db.commit()

    return {"explanation": meta["explanation"]}
