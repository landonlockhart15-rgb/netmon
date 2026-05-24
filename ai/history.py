"""
ai/history.py - History synthesis helpers for safe NetMon autonomy.

This module is intentionally read-only against the network. It summarizes
existing DB history and asks the configured AI provider for suggestions only.
Any resulting decision is written to ActivityLog so it can be queried later.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone, timedelta

from sqlalchemy import desc

from models.tables import (
    ActivityLog, Alert, AISummary, HealthCheck, SecurityReport, TrafficSummary
)


def _json_loads(value, fallback):
    try:
        return json.loads(value or "")
    except Exception:
        return fallback


def _iso(dt):
    if dt is None:
        return None
    s = dt.isoformat()
    if "+" not in s and not s.endswith("Z"):
        s += "Z"
    return s


def build_history_context(db, days: int = 7, max_rows: int = 300) -> dict:
    """Build a compact, bounded context from recent NetMon history."""
    days = max(1, min(int(days or 7), 30))
    max_rows = max(50, min(int(max_rows or 300), 1000))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    logs = (
        db.query(ActivityLog)
        .filter(ActivityLog.created_at >= since)
        .order_by(desc(ActivityLog.id))
        .limit(max_rows)
        .all()
    )
    alerts = (
        db.query(Alert)
        .filter(Alert.created_at >= since)
        .order_by(desc(Alert.id))
        .limit(100)
        .all()
    )
    health = (
        db.query(HealthCheck)
        .filter(HealthCheck.checked_at >= since)
        .order_by(desc(HealthCheck.id))
        .limit(500)
        .all()
    )
    traffic = (
        db.query(TrafficSummary)
        .filter(TrafficSummary.created_at >= since)
        .order_by(desc(TrafficSummary.id))
        .limit(100)
        .all()
    )
    reports = (
        db.query(SecurityReport)
        .filter(SecurityReport.created_at >= since)
        .order_by(desc(SecurityReport.id))
        .limit(20)
        .all()
    )
    ai_runs = (
        db.query(AISummary)
        .filter(AISummary.created_at >= since)
        .order_by(desc(AISummary.id))
        .limit(20)
        .all()
    )

    by_level = Counter(r.level for r in logs)
    by_category = Counter(r.category for r in logs)
    by_event = Counter(r.event for r in logs)
    noisy = Counter((r.category, r.event, r.summary) for r in logs)

    blocked_domains = Counter()
    dns_clients = Counter()
    for row in logs:
        if row.category != "dns":
            continue
        detail = _json_loads(row.detail, {})
        domain = detail.get("domain")
        client = detail.get("client_ip") or row.device_ip
        if domain:
            blocked_domains[domain] += 1
        if client:
            dns_clients[client] += 1

    bad_health = [h for h in health if h.status in ("degraded", "offline")]
    latest_traffic = traffic[0] if traffic else None

    return {
        "window_days": days,
        "counts": {
            "logs": len(logs),
            "alerts": len(alerts),
            "health_checks": len(health),
            "bad_health_checks": len(bad_health),
            "traffic_summaries": len(traffic),
            "security_reports": len(reports),
            "ai_runs": len(ai_runs),
        },
        "log_breakdown": {
            "by_level": dict(by_level.most_common()),
            "by_category": dict(by_category.most_common()),
            "top_events": [{"event": k, "count": v} for k, v in by_event.most_common(12)],
            "repeated_patterns": [
                {"category": c, "event": e, "summary": s, "count": n}
                for (c, e, s), n in noisy.most_common(12)
                if n >= 2
            ],
        },
        "dns_noise": {
            "blocked_entries": sum(blocked_domains.values()),
            "top_blocked_domains": [
                {"domain": d, "count": n} for d, n in blocked_domains.most_common(15)
            ],
            "top_clients": [
                {"ip": ip, "count": n} for ip, n in dns_clients.most_common(10)
            ],
        },
        "recent_alerts": [
            {
                "id": a.id,
                "created_at": _iso(a.created_at),
                "type": a.alert_type,
                "message": a.message,
                "read": bool(a.read),
                "device_id": a.device_id,
            }
            for a in alerts[:25]
        ],
        "health": {
            "latest_status": health[0].status if health else "unknown",
            "latest_latency_ms": health[0].latency_ms if health else None,
            "latest_packet_loss": health[0].packet_loss if health else None,
            "bad_recent": [
                {
                    "checked_at": _iso(h.checked_at),
                    "status": h.status,
                    "latency_ms": h.latency_ms,
                    "packet_loss": h.packet_loss,
                    "error": h.error,
                }
                for h in bad_health[:20]
            ],
        },
        "traffic_latest": {
            "created_at": _iso(latest_traffic.created_at) if latest_traffic else None,
            "total_packets": latest_traffic.total_packets if latest_traffic else 0,
            "dns_count": latest_traffic.dns_count if latest_traffic else 0,
            "top_domains": _json_loads(latest_traffic.top_domains, [])[:15] if latest_traffic else [],
            "top_talkers": _json_loads(latest_traffic.top_talkers, [])[:10] if latest_traffic else [],
        },
        "recent_reports": [
            {
                "created_at": _iso(r.created_at),
                "severity": r.severity,
                "headline": r.headline,
                "recommendations": _json_loads(r.recommendations, [])[:5],
                "error": r.error,
            }
            for r in reports
        ],
        "recent_ai": [
            {
                "created_at": _iso(r.created_at),
                "severity": r.severity,
                "summary": r.summary,
                "next_steps": _json_loads(r.next_steps, [])[:5],
                "error": r.error,
            }
            for r in ai_runs
        ],
    }


def build_history_prompt(ctx: dict, question: str = "") -> str:
    data = json.dumps(ctx, default=str, separators=(",", ":"))
    question = (question or "").strip()[:1000]
    known = ""
    try:
        from ai import knowledge_bridge as _kb
        fixes = _kb.known_fixes_for(limit=5)
        if fixes:
            known = "KNOWN_FIXES (from prior successful remediations across NetMon+sentinel):\n" + \
                    json.dumps(fixes, separators=(",", ":"), default=str) + "\n"
    except Exception:
        known = ""
    return (
        "You are NetMon's cautious home-network autonomy advisor. "
        "Analyze existing history only and return ONE JSON object exactly shaped as:\n"
        '{"summary":"1-3 sentences","severity":"low|medium|high",'
        '"benign":["..."],"concerning":["..."],"next_steps":["..."]}\n'
        "Rules:\n"
        "- This is a normal home network; avoid alarmist conclusions.\n"
        "- Do not recommend destructive actions unless evidence is repeated and specific.\n"
        "- Prefer safe autonomous suggestions: mark known-benign noise, lower notification priority, "
        "schedule a scan, label a device, watch for recurrence, or ask user confirmation.\n"
        "- DNS blocking is usually expected ad/tracker blocking; treat repeated DNS blocked logs as noise "
        "unless domains look malware-like.\n"
        "- Name repeated patterns and common issues from DATA. Never invent devices, IPs, domains, or attacks.\n"
        "- next_steps must be safe, limited, and reversible where possible.\n"
        "- Prefer fixes from KNOWN_FIXES when their pattern matches the current data.\n"
        "- Keep every list item under 220 chars. Return only JSON.\n"
        f"{known}"
        f"USER_QUESTION:{question}\n"
        f"DATA:{data}"
    )


def synthesize_history(db, days: int = 7, question: str = "") -> dict:
    """Run AI synthesis over bounded history and persist a queryable decision."""
    from ai.provider import get_provider
    from monitoring.activity import write_log

    ctx = build_history_context(db, days=days)
    provider = get_provider()
    prompt = build_history_prompt(ctx, question=question)
    result = provider.analyze(ctx, prompt=prompt, kind="history")

    decision_detail = {
        "days": ctx["window_days"],
        "question": question,
        "provider": getattr(provider, "name", None),
        "model": result.get("model"),
        "severity": result.get("severity"),
        "benign": result.get("benign", []),
        "concerning": result.get("concerning", []),
        "next_steps": result.get("next_steps", []),
        "error": result.get("error"),
        "context_counts": ctx.get("counts", {}),
        "dns_noise": ctx.get("dns_noise", {}),
    }
    write_log(
        "info" if not result.get("error") else "warning",
        "ai",
        "history_synthesis",
        result.get("summary") or "AI history synthesis failed",
        detail=decision_detail,
        actor="ai_auto",
    )
    try:
        from ai import knowledge_bridge as _kb
        if _kb.available():
            iid = _kb.knowledge.open_incident(
                "netmon", "history",
                {"summary": result.get("summary"), "severity": result.get("severity")},
                signature=f"history:{result.get('severity','')}"[:80],
                severity=(result.get("severity") or "low"),
            )
            _kb.record_suggested_remediations(iid, result.get("next_steps", []))
    except Exception:
        pass

    return {
        "status": "error" if result.get("error") else "ok",
        "summary": result.get("summary"),
        "severity": result.get("severity"),
        "benign": result.get("benign", []),
        "concerning": result.get("concerning", []),
        "next_steps": result.get("next_steps", []),
        "model": result.get("model"),
        "error": result.get("error"),
        "context": ctx,
    }
