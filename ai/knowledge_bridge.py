"""
knowledge_bridge.py — NetMon's connection to the shared AI-Hub knowledge.db.

Lets anomaly.py record significant events and lets history.py inject prior
lessons into the AI synthesis prompt. Path-injects the AI-Hub project dir
so we can `import knowledge` from there without packaging.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

_AI_HUB = os.environ.get(
    "AI_HUB_DIR",
    r"C:\Users\lock_\OneDrive\Projects\AI-Hub",
)
if _AI_HUB not in sys.path:
    sys.path.insert(0, _AI_HUB)

try:
    import knowledge  # type: ignore
    _AVAILABLE = True
    knowledge.init_db()
except Exception as e:  # bridge must never break NetMon
    knowledge = None  # type: ignore
    _AVAILABLE = False
    sys.stderr.write(f"[knowledge_bridge] disabled: {e}\n")


_NETMON_SERVICE_HINTS = {
    "traffic_spike": "traffic",
    "port_scan": "security",
    "health_outage": "router",
    "nighttime_device": "device",
}


def available() -> bool:
    """True if the shared knowledge store is reachable."""
    return _AVAILABLE


def record_netmon_incident(ev: dict) -> Optional[int]:
    """Record a NetMon anomaly event as an incident in the shared store.

    `ev` is a dict from anomaly.run_anomaly_checks() with keys:
      type, ip, level, title, body.
    Skips events below 'warning' severity. Returns incident_id or None.
    """
    if not _AVAILABLE:
        return None
    level = (ev.get("level") or "info").lower()
    if level not in ("warning", "critical", "action"):
        return None
    service = _NETMON_SERVICE_HINTS.get(ev.get("type") or "", "netmon")
    severity = "high" if level in ("critical", "action") else "medium"
    evidence = {
        "ip": ev.get("ip"),
        "type": ev.get("type"),
        "level": level,
        "title": ev.get("title", ""),
        "body": (ev.get("body") or "")[:2000],
    }
    try:
        return knowledge.open_incident(
            "netmon",
            service,
            evidence,
            signature=f"{ev.get('type','')}:{ev.get('ip') or ''}"[:120],
            severity=severity,
        )
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] open_incident failed: {e}\n")
        return None


def known_fixes_for(services: list[str] | None = None, limit: int = 5) -> list[dict]:
    """Top relevant lessons across given services (default: netmon-related).
    Used by history.py to inject `KNOWN_FIXES:` into the synthesis prompt.
    """
    if not _AVAILABLE:
        return []
    services = set(services or ["router", "dns", "traffic", "wifi", "device", "security", "netmon"])
    try:
        lessons = knowledge.top_lessons(50)
    except Exception:
        return []
    out = []
    for l in lessons:
        if l.get("service") in services:
            out.append({
                "service": l.get("service"),
                "pattern": l.get("pattern_summary"),
                "fix": l.get("recommended_action"),
                "args": l.get("recommended_args"),
                "success": l.get("success_count"),
                "fail": l.get("fail_count"),
                "last_outcome": l.get("last_outcome"),
            })
            if len(out) >= limit:
                break
    return out


def record_suggested_remediations(incident_id: int, suggestions: list[str]) -> None:
    """Persist AI-suggested next_steps as remediations with status='suggested'."""
    if not _AVAILABLE or not incident_id or not suggestions:
        return
    for s in suggestions[:10]:
        try:
            knowledge.record_remediation(
                incident_id,
                action="suggested",
                args={"text": str(s)[:500]},
                status="suggested",
                proposed_by="netmon.history",
                output=str(s)[:500],
            )
        except Exception:
            pass


def log_event(kind: str, message: str) -> None:
    """Append a NetMon line to the shared build_log.md."""
    if not _AVAILABLE:
        return
    try:
        knowledge.log_event(f"netmon.{kind}", message)
    except Exception:
        pass


def record_remediation_outcome(
    service: str,
    evidence: dict,
    action: str,
    params: Optional[dict],
    success: bool,
    summary: str = "",
    severity: str = "medium",
) -> Optional[int]:
    """Record a complete detect→act→outcome cycle as both an incident and a lesson.

    `service` is the NetMon domain (router/dns/traffic/wifi/device/security/netmon).
    `evidence` is the pattern context — same shape used by open_incident — what
    NetMon saw that triggered the action.
    `action` is the action_type that was executed (e.g. block_ip_firewall).
    `params` is what was passed to it.
    Returns the incident_id, or None if knowledge store is unavailable.
    """
    if not _AVAILABLE:
        return None
    outcome = "success" if success else "fail"
    incident_id = None
    try:
        incident_id = knowledge.open_incident(
            "netmon", service, evidence or {},
            signature=(summary or action)[:120],
            severity=severity,
        )
        knowledge.resolve_incident(incident_id, postmortem=summary[:2000])
        fp = knowledge.fingerprint(service, evidence or {})
        knowledge.upsert_lesson(
            fp, service, action, params or {},
            (summary or f"{action} on {service}")[:500],
            outcome,
        )
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] record_remediation_outcome failed: {e}\n")
    return incident_id
