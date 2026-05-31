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
    r"C:\Projects\AI-Hub",
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

_SERVICE_LABELS = {
    "device": "Device identity",
    "dns": "DNS",
    "netmon": "NetMon",
    "ntfy": "Notifications",
    "router": "Router / internet",
    "security": "Security",
    "sentinel": "Sentinel",
    "traffic": "Network traffic",
    "wifi": "Wi-Fi",
}

_ACTION_LABELS = {
    "device_profile": "remember this device profile",
    "device_profile_update": "update the saved device profile",
    "health_outage": "watch for router or internet downtime",
    "label_device": "save a clearer device label",
    "restart": "restart the affected service",
    "suggested": "review the suggested next step",
}


def _display_service(service: str | None) -> str:
    key = (service or "netmon").strip().lower()
    return _SERVICE_LABELS.get(key, key.replace("_", " ").title())


def _plain_pattern(service: str | None, pattern: object, action: object = None) -> str:
    service_label = _display_service(service)
    pattern_text = str(pattern or "").strip()
    action_text = str(action or "").strip()
    action_label = _ACTION_LABELS.get(action_text.lower(), action_text.replace("_", " "))

    lower_pattern = pattern_text.lower()
    if service == "device":
        if "vendor=" in lower_pattern or "label=" in lower_pattern or "profile" in lower_pattern:
            return "NetMon matched traffic details to a known device identity so the device can be labeled more accurately next time."
        return "NetMon learned something about a device on the network so future scans can identify it more confidently."
    if service == "traffic":
        return "NetMon noticed a recurring traffic pattern and will use it as context when reviewing future network activity."
    if service == "security":
        return "NetMon saw a security-related pattern and saved it so similar activity is easier to recognize later."
    if service in {"router", "dns", "wifi"}:
        return f"NetMon connected this {service_label.lower()} pattern with a likely network condition so future outages are easier to explain."
    if action_label:
        return f"{service_label} learned that a repeated pattern is usually handled by: {action_label}."
    if pattern_text:
        return f"{service_label} learned a recurring pattern: {pattern_text[:180]}."
    return f"{service_label} learned a new pattern it can reuse during future checks."


def _plain_action(action: object, args: object = None) -> str:
    action_text = str(action or "").strip()
    if not action_text:
        return "No automatic fix has been chosen yet."
    label = _ACTION_LABELS.get(action_text.lower(), action_text.replace("_", " "))
    if action_text.lower() in {"device_profile", "device_profile_update", "label_device"}:
        return "Use this saved identity evidence when naming or confirming the device later."
    if action_text.lower() == "restart":
        return "Restart the affected service if policy allows it."
    if action_text.lower() == "suggested" and isinstance(args, dict) and args.get("text"):
        return str(args["text"])[:220]
    return label[:1].upper() + label[1:]


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


def learning_overview(limit: int = 20) -> dict:
    """Return shared lessons/timeline/feedback for NetMon UI surfaces."""
    if not _AVAILABLE:
        return {"available": False, "lessons": [], "timeline": [], "feedback": []}
    services = {"router", "dns", "traffic", "wifi", "device", "security", "netmon"}
    try:
        raw_lessons = knowledge.top_lessons(max(limit, 50))
    except Exception:
        raw_lessons = []
    lessons = []
    for l in raw_lessons:
        service = l.get("service")
        if service not in services:
            continue
        pattern = l.get("pattern_summary")
        action = l.get("recommended_action")
        args = l.get("recommended_args")
        lessons.append({
            "id": l.get("id"),
            "source": l.get("source") or "shared",
            "service": service,
            "service_label": _display_service(service),
            "pattern": pattern,
            "plain_english": _plain_pattern(service, pattern, action),
            "action": action,
            "action_plain_english": _plain_action(action, args),
            "args": args,
            "success": l.get("success_count") or 0,
            "fail": l.get("fail_count") or 0,
            "confidence": l.get("confidence"),
            "suppressed": bool(l.get("suppressed")),
            "last_outcome": l.get("last_outcome"),
            "last_used_at": l.get("last_used_at"),
            "learned_from": "NetMon" if service in services else _display_service(service),
        })
        if len(lessons) >= limit:
            break

    timeline_fn = _knowledge_func("recent_timeline_events")
    feedback_fn = _knowledge_func("recent_feedback")
    try:
        timeline = timeline_fn(limit=limit) if timeline_fn else []
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] recent_timeline_events failed: {e}\n")
        timeline = []
    try:
        feedback = feedback_fn(limit=limit) if feedback_fn else []
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] recent_feedback failed: {e}\n")
        feedback = []
    return {
        "available": True,
        "lessons": lessons,
        "timeline": timeline,
        "feedback": feedback,
    }


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


def _knowledge_func(name: str):
    if not _AVAILABLE or knowledge is None:
        return None
    fn = getattr(knowledge, name, None)
    return fn if callable(fn) else None


def set_incident_root_cause(incident_id: int, root_cause_service: str) -> None:
    """Attach root-cause context when the shared store supports it."""
    fn = _knowledge_func("set_incident_root_cause")
    if not fn or not incident_id:
        return
    try:
        fn(incident_id, root_cause_service)
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] set_incident_root_cause failed: {e}\n")


def record_timeline_event(
    correlation_id: str,
    service: str,
    event_type: str,
    severity: str,
    summary: str,
    detail: Optional[dict] = None,
) -> Optional[int]:
    """Append a shared timeline event if AI-Hub exposes timeline support."""
    fn = _knowledge_func("record_timeline_event")
    if not fn:
        return None
    try:
        return fn(
            correlation_id=correlation_id or "uncorrelated",
            source="netmon",
            service=service,
            event_type=event_type,
            severity=severity,
            summary=summary,
            detail=detail or {},
        )
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] record_timeline_event failed: {e}\n")
        return None


def record_user_feedback(
    target_type: str,
    target: str,
    verdict: str,
    note: str = "",
    source: str = "netmon",
) -> Optional[int]:
    """Store operator feedback when the shared store supports feedback rows."""
    fn = _knowledge_func("record_feedback")
    if not fn:
        return None
    try:
        return fn(source, target_type, target, verdict, note)
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] record_user_feedback failed: {e}\n")
        return None


def record_device_profile_lesson(
    device_key: str,
    profile: dict,
    evidence: Optional[dict] = None,
    confidence: Optional[float] = None,
    outcome: str = "success",
    summary: str = "",
) -> Optional[int]:
    """Persist a durable lesson about a device identity/profile.

    Newer AI-Hub builds may expose a first-class record_device_profile_lesson().
    Older builds fall back to the generic lessons table.
    """
    if not _AVAILABLE:
        return None

    fn = _knowledge_func("record_device_profile_lesson")
    if fn:
        try:
            return fn(
                source="netmon",
                device_key=device_key,
                profile=profile or {},
                evidence=evidence or {},
                confidence=confidence,
                outcome=outcome,
                summary=summary,
            )
        except TypeError:
            try:
                return fn(device_key, profile or {}, evidence or {}, confidence, outcome, summary)
            except Exception as e:
                sys.stderr.write(f"[knowledge_bridge] record_device_profile_lesson failed: {e}\n")
                return None
        except Exception as e:
            sys.stderr.write(f"[knowledge_bridge] record_device_profile_lesson failed: {e}\n")
            return None

    try:
        fp = knowledge.fingerprint("device", {
            "device_key": device_key,
            "profile": profile or {},
            "evidence": evidence or {},
        })
        lesson = knowledge.upsert_lesson(
            fp,
            "device",
            "device_profile_learned",
            {
                "device_key": device_key,
                "profile": profile or {},
                "confidence": confidence,
            },
            (summary or f"Device profile learned for {device_key}")[:500],
            outcome if outcome in ("success", "fail") else "success",
        )
        return int(lesson.get("id")) if isinstance(lesson, dict) and lesson.get("id") else None
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] record_device_profile_lesson fallback failed: {e}\n")
        return None


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
        set_incident_root_cause(incident_id, service)
        record_timeline_event(
            correlation_id=f"netmon.incident.{incident_id}",
            service=service,
            event_type="remediation_outcome",
            severity=severity,
            summary=(summary or f"{action} on {service}")[:1000],
            detail={
                "action": action,
                "params": params or {},
                "outcome": outcome,
                "evidence": evidence or {},
            },
        )
        fp = knowledge.fingerprint(service, evidence or {})
        knowledge.upsert_lesson(
            fp, service, action, params or {},
            (summary or f"{action} on {service}")[:500],
            outcome,
        )
    except Exception as e:
        sys.stderr.write(f"[knowledge_bridge] record_remediation_outcome failed: {e}\n")
    return incident_id
