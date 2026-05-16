"""
ai/analyst.py — Orchestrates the AI analysis pipeline.

Flow:
  1. Check ai_enabled setting — bail out early if disabled
  2. Pull structured data from the DB (latest scan, diff, devices, health, alerts)
  3. Build context dict via ai/prompt.py
  4. Call provider.analyze(context)
  5. Save result to ai_summaries table
  6. Return the saved row's data

This module never raises — all errors are caught and stored in the
AISummary.error column so the dashboard can show them gracefully.

Separation of concerns:
  analyst.py  — knows about the DB and what data to pull
  prompt.py   — knows how to format data into a prompt
  provider.py — knows how to call the AI API
"""

import json
from datetime import datetime, timezone
from sqlalchemy import desc
from sqlalchemy.orm import Session

from models.tables import (
    Scan, Device, ScanDevice, ChangeEvent,
    HealthCheck, Alert, Setting, AISummary, TrafficSummary,
)
from ai.prompt import (
    build_context, build_prompt,
    build_scan_context, build_scan_prompt,
    build_traffic_context, build_traffic_prompt,
)
from ai.provider import get_provider


def _get_setting(db: Session, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if (row and row.value is not None) else default


def run_analysis(db: Session, scan_id: int | None = None) -> dict:
    """
    Run an AI analysis and persist the result.

    scan_id:
      If provided, analyse that specific scan.
      If None, use the latest completed scan.

    Returns a dict suitable for JSON serialization.
    Always returns something — on any failure the dict has 'error' set.
    """
    # ── 1. Check AI is enabled ─────────────────────────────────────────────────
    ai_enabled = _get_setting(db, "ai_enabled", "false").lower()
    if ai_enabled != "true":
        return _error_result(None, "AI is disabled. Enable it in Settings.")

    # ── 2. Resolve the scan to analyse ────────────────────────────────────────
    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
    else:
        scan = (
            db.query(Scan)
            .filter(Scan.status == "complete")
            .order_by(desc(Scan.id))
            .first()
        )

    if not scan:
        return _error_result(None, "No completed scan found to analyse.")

    # ── 3. Pull supporting data ────────────────────────────────────────────────

    # Changes from this scan
    changes = (
        db.query(ChangeEvent)
        .filter(ChangeEvent.scan_id == scan.id)
        .order_by(ChangeEvent.id)
        .all()
    )

    # Is this the first scan? (no prev_scan_id on any change event)
    is_first = not any(c.prev_scan_id for c in changes)

    # Current devices (from this scan)
    scan_devices = (
        db.query(ScanDevice)
        .filter(ScanDevice.scan_id == scan.id)
        .all()
    )
    devices = [
        {
            "ip":        sd.ip,
            "hostname":  sd.hostname or sd.device.hostname or "",
            "vendor":    sd.device.vendor or "",
            "label":     sd.device.label or "",
            "is_known":  sd.device.is_known,
            "open_ports": sd.ports_list,
        }
        for sd in scan_devices
    ]

    # Run a fresh health check FIRST so the AI sees current latency, not a stale value.
    # This must happen BEFORE we query health_current / health_events below.
    try:
        from monitoring.health import run_ping
        from models.tables import HealthCheck as _HC
        fresh = run_ping(target=_get_setting(db, "health_target", "8.8.8.8"))
        if fresh.get("latency_ms") is not None:
            hc_row = _HC(
                status     = fresh["status"],
                latency_ms = fresh["latency_ms"],
                packet_loss= fresh.get("packet_loss", 0),
                target     = fresh.get("target"),
            )
            db.add(hc_row)
            db.commit()
            print(f"[ai] Fresh ping: {fresh['status']} {fresh['latency_ms']}ms")
    except Exception as e:
        print(f"[ai] Pre-analysis health check failed: {e}")

    # Health current — read AFTER the fresh ping so we get the latest row
    latest_hc = db.query(HealthCheck).order_by(desc(HealthCheck.id)).first()
    health_current = {
        "status":     latest_hc.status     if latest_hc else "unknown",
        "latency_ms": latest_hc.latency_ms if latest_hc else None,
    }

    # Recent non-online health events (anomalies only — no need to send 120 "online" rows)
    health_events = [
        {
            "status":      hc.status,
            "latency_ms":  hc.latency_ms,
            "packet_loss": hc.packet_loss,
            "when":        hc.checked_at.isoformat() if hc.checked_at else None,
        }
        for hc in (
            db.query(HealthCheck)
            .filter(HealthCheck.status != "online")
            .order_by(desc(HealthCheck.id))
            .limit(10)
            .all()
        )
    ]

    # Recent unread alerts
    recent_alerts = [
        {
            "type":    a.alert_type,
            "message": a.message,
            "when":    a.created_at.isoformat() if a.created_at else None,
        }
        for a in (
            db.query(Alert)
            .order_by(desc(Alert.id))
            .limit(10)
            .all()
        )
    ]

    # Latest traffic summary (if any)
    latest_traffic = db.query(TrafficSummary).order_by(desc(TrafficSummary.id)).first()
    traffic_data = None
    if latest_traffic:
        traffic_data = {
            "total_packets":    latest_traffic.total_packets,
            "total_bytes":      latest_traffic.total_bytes,
            "total_mb":         round((latest_traffic.total_bytes or 0) / 1_048_576, 1),
            "dns_count":        latest_traffic.dns_count,
            "files_analyzed":   latest_traffic.files_analyzed,
            "top_talkers":      json.loads(latest_traffic.top_talkers      or "[]"),
            "top_destinations": json.loads(latest_traffic.top_destinations or "[]"),
            "protocol_mix":     json.loads(latest_traffic.protocol_mix     or "{}"),
            "top_domains":      json.loads(latest_traffic.top_domains      or "[]"),
            "error":            latest_traffic.error,
        }

    # ── 4. Build context dict ─────────────────────────────────────────────────
    scan_dict = {
        "id":           scan.id,
        "started_at":   scan.started_at.isoformat() if scan.started_at else None,
        "host_count":   scan.host_count,
        "duration_s":   scan.duration_s,
        "is_first_scan": is_first,
    }
    changes_list = [
        {
            "change_type": c.change_type,
            "message":     c.message,
        }
        for c in changes
    ]

    context = build_context(
        scan           = scan_dict,
        changes        = changes_list,
        devices        = devices,
        health_current = health_current,
        health_events  = health_events,
        recent_alerts  = recent_alerts,
        traffic_data   = traffic_data,
    )

    # ── 5. Call provider ──────────────────────────────────────────────────────
    provider = get_provider()

    # NullProvider means AI is not configured — return informative error
    if provider.name == "none":
        return _error_result(scan.id, provider.analyze(context)["error"])

    # Use the legacy combined prompt for back-compat
    prompt = build_prompt(context)
    result = provider.analyze(context, prompt=prompt, kind="combined") \
        if "prompt" in provider.analyze.__code__.co_varnames \
        else provider.analyze(context)

    # ── 6. Persist to DB ─────────────────────────────────────────────────────
    summary_row = AISummary(
        scan_id      = scan.id,
        provider     = provider.name,
        model        = result.get("model"),
        summary      = result.get("summary"),
        severity     = result.get("severity"),
        benign       = json.dumps(result.get("benign",     [])),
        concerning   = json.dumps(result.get("concerning", [])),
        next_steps   = json.dumps(result.get("next_steps", [])),
        raw_response = result.get("raw_response"),
        input_tokens = result.get("input_tokens"),
        output_tokens= result.get("output_tokens"),
        error        = result.get("error"),
    )
    db.add(summary_row)
    db.commit()
    db.refresh(summary_row)

    return _serialize(summary_row)


def get_latest(db: Session) -> dict | None:
    """Return the most recent AISummary row, or None if none exist."""
    row = db.query(AISummary).order_by(desc(AISummary.id)).first()
    if not row:
        return None
    return _serialize(row)


# ── Focused entry points (split scan vs traffic) ──────────────────────────────
#
# These two functions exist so the Overview page and the Traffic page each
# get their OWN purpose-built prompt — half the size of the legacy combined
# prompt → roughly 2x faster on local Gemma.

def run_scan_analysis(db: Session, scan_id: int | None = None) -> dict:
    """
    Analyse the latest (or specified) nmap scan. NO traffic data — that's
    a separate analysis run via run_traffic_analysis(). Streams via Ollama.
    """
    if _get_setting(db, "ai_enabled", "false").lower() != "true":
        return _error_result(None, "AI is disabled. Enable it in Settings.")

    if scan_id:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
    else:
        scan = (db.query(Scan).filter(Scan.status == "complete")
                .order_by(desc(Scan.id)).first())
    if not scan:
        return _error_result(None, "No completed scan found to analyse.")

    # Fresh ping FIRST so health_current is current
    _refresh_health(db)

    # Pull supporting data
    changes = (db.query(ChangeEvent).filter(ChangeEvent.scan_id == scan.id)
               .order_by(ChangeEvent.id).all())
    is_first = not any(c.prev_scan_id for c in changes)

    scan_devices = db.query(ScanDevice).filter(ScanDevice.scan_id == scan.id).all()
    devices = [
        {
            "ip":         sd.ip,
            "hostname":   sd.hostname or sd.device.hostname or "",
            "vendor":     sd.device.vendor or "",
            "label":      sd.device.label or "",
            "is_known":   sd.device.is_known,
            "open_ports": sd.ports_list,
        }
        for sd in scan_devices
    ]

    latest_hc = db.query(HealthCheck).order_by(desc(HealthCheck.id)).first()
    health_current = {
        "status":     latest_hc.status     if latest_hc else "unknown",
        "latency_ms": latest_hc.latency_ms if latest_hc else None,
    }
    health_events = [
        {"status": hc.status, "latency_ms": hc.latency_ms, "packet_loss": hc.packet_loss}
        for hc in (db.query(HealthCheck).filter(HealthCheck.status != "online")
                   .order_by(desc(HealthCheck.id)).limit(5).all())
    ]

    scan_dict = {
        "id":            scan.id,
        "host_count":    scan.host_count,
        "is_first_scan": is_first,
    }
    changes_list = [{"change_type": c.change_type, "message": c.message} for c in changes]

    ctx = build_scan_context(
        scan           = scan_dict,
        changes        = changes_list,
        devices        = devices,
        health_current = health_current,
        health_events  = health_events,
    )
    prompt = build_scan_prompt(ctx)

    provider = get_provider()
    if provider.name == "none":
        return _error_result(scan.id, provider.analyze(ctx)["error"])

    result = provider.analyze(ctx, prompt=prompt, kind="scan")
    return _persist(db, result, scan_id=scan.id)


def run_traffic_analysis(db: Session) -> dict:
    """
    Analyse the latest TrafficSummary. NO scan/device data — pure packet
    capture analysis. Streams via Ollama.
    """
    if _get_setting(db, "ai_enabled", "false").lower() != "true":
        return _error_result(None, "AI is disabled. Enable it in Settings.")

    latest_traffic = db.query(TrafficSummary).order_by(desc(TrafficSummary.id)).first()
    if not latest_traffic:
        return _error_result(None, "No traffic summary yet — run a packet capture first.")

    traffic_data = {
        "total_packets":    latest_traffic.total_packets,
        "total_bytes":      latest_traffic.total_bytes,
        "total_mb":         round((latest_traffic.total_bytes or 0) / 1_048_576, 1),
        "dns_count":        latest_traffic.dns_count,
        "top_talkers":      json.loads(latest_traffic.top_talkers      or "[]"),
        "top_destinations": json.loads(latest_traffic.top_destinations or "[]"),
        "protocol_mix":     json.loads(latest_traffic.protocol_mix     or "{}"),
        "top_domains":      json.loads(latest_traffic.top_domains      or "[]"),
    }

    # Build IP→label map so the model can name talkers by their friendly label
    device_labels: dict[str, str] = {}
    for sd in db.query(ScanDevice).order_by(desc(ScanDevice.id)).limit(200).all():
        if sd.ip not in device_labels and sd.device and sd.device.label:
            device_labels[sd.ip] = sd.device.label

    ctx = build_traffic_context(traffic_data, device_labels=device_labels)
    prompt = build_traffic_prompt(ctx)

    provider = get_provider()
    if provider.name == "none":
        return _error_result(None, provider.analyze(ctx)["error"])

    # Latest scan_id just for foreign-key bookkeeping (a TrafficSummary isn't
    # tied to a scan but the AISummary table requires one).
    last_scan = db.query(Scan).order_by(desc(Scan.id)).first()
    scan_id = last_scan.id if last_scan else None

    result = provider.analyze(ctx, prompt=prompt, kind="traffic")
    return _persist(db, result, scan_id=scan_id)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _refresh_health(db: Session) -> None:
    """Run a fresh ping and store it so the AI sees current latency."""
    try:
        from monitoring.health import run_ping
        from models.tables import HealthCheck as _HC
        fresh = run_ping(target=_get_setting(db, "health_target", "8.8.8.8"))
        if fresh.get("latency_ms") is not None:
            db.add(_HC(
                status     = fresh["status"],
                latency_ms = fresh["latency_ms"],
                packet_loss= fresh.get("packet_loss", 0),
                target     = fresh.get("target"),
            ))
            db.commit()
            print(f"[ai] Fresh ping: {fresh['status']} {fresh['latency_ms']}ms")
    except Exception as e:
        print(f"[ai] Pre-analysis health check failed: {e}")


def _persist(db: Session, result: dict, scan_id: int | None) -> dict:
    """Save an AI result row and return its serialized form.

    If the result has no summary and no error (i.e. JSON parsing failed due to
    truncation), we skip saving to avoid polluting /api/ai/latest with empty rows
    that the frontend can't distinguish from successful ones.
    """
    if not result.get("summary") and not result.get("error"):
        print("[ai] Skipping persist — result has no summary (likely truncated JSON). Raw snippet:",
              (result.get("raw_response") or "")[:120])
        return _error_result(scan_id, "AI response was truncated — try again")

    provider = get_provider()
    summary_row = AISummary(
        scan_id      = scan_id,
        provider     = provider.name,
        model        = result.get("model"),
        summary      = result.get("summary"),
        severity     = result.get("severity"),
        benign       = json.dumps(result.get("benign",     [])),
        concerning   = json.dumps(result.get("concerning", [])),
        next_steps   = json.dumps(result.get("next_steps", [])),
        raw_response = result.get("raw_response"),
        input_tokens = result.get("input_tokens"),
        output_tokens= result.get("output_tokens"),
        error        = result.get("error"),
    )
    db.add(summary_row)
    db.commit()
    db.refresh(summary_row)
    return _serialize(summary_row)


# ── Serialization helpers ─────────────────────────────────────────────────────

def _serialize(row: AISummary) -> dict:
    return {
        "id":           row.id,
        "created_at":   (row.created_at.isoformat() + "Z") if row.created_at else None,
        "scan_id":      row.scan_id,
        "provider":     row.provider,
        "model":        row.model,
        "summary":      row.summary,
        "severity":     row.severity,
        "benign":       json.loads(row.benign      or "[]"),
        "concerning":   json.loads(row.concerning  or "[]"),
        "next_steps":   json.loads(row.next_steps  or "[]"),
        "input_tokens": row.input_tokens,
        "output_tokens":row.output_tokens,
        "error":        row.error,
    }


def _error_result(scan_id: int | None, message: str) -> dict:
    return {
        "id":           None,
        "created_at":   datetime.now(timezone.utc).isoformat(),
        "scan_id":      scan_id,
        "provider":     None,
        "model":        None,
        "summary":      None,
        "severity":     None,
        "benign":       [],
        "concerning":   [],
        "next_steps":   [],
        "input_tokens": None,
        "output_tokens":None,
        "error":        message,
    }
