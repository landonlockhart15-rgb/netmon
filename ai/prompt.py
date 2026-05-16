"""
ai/prompt.py — Builds the prompt sent to the AI provider.

Two purpose-built prompts (each kept compact for speed on local models):

  build_scan_prompt(scan_ctx)        — for nmap scan + health analysis
  build_traffic_prompt(traffic_ctx)  — for packet capture analysis

And one legacy combined prompt for backwards compatibility:

  build_prompt(combined_ctx)         — used by callers that haven't migrated

Plus the matching context builders:

  build_scan_context(...)
  build_traffic_context(...)
  build_context(...)                 — legacy combined builder

Design rules
------------
* Use compact JSON (no indent) — every byte costs prompt-eval time on CPU.
* Keep the worked example to ONE line per field (Gemma follows compact schemas).
* Skip "FIELD EXPLAINED" sections — keys are self-evident.
* Include only fields the model needs for THIS specific analysis.
"""

import json


# ── Scan context + prompt ─────────────────────────────────────────────────────

def build_scan_context(
    scan: dict,
    changes: list[dict],
    devices: list[dict],
    health_current: dict,
    health_events: list[dict],
) -> dict:
    """
    Compact context for SCAN analysis. No traffic data — that lives in its
    own pipeline. Only the fields needed to reason about devices + connectivity.
    """
    flagged = [
        {
            "ip":         d["ip"],
            "hostname":   d["hostname"] or None,
            "vendor":     d["vendor"]   or None,
            "label":      d["label"]    or None,
            "trusted":    d["is_known"],
            "open_ports": d["open_ports"],
        }
        for d in devices
        if not d["is_known"] or d["open_ports"]
    ][:15]

    return {
        "scan": {
            "id":            scan["id"],
            "host_count":    scan["host_count"],
            "is_first_scan": scan.get("is_first_scan", False),
        },
        "changes":         [{"type": c["change_type"], "msg": c["message"]} for c in changes],
        "flagged_devices": flagged,
        "health_status":   health_current.get("status", "unknown"),
        "health_latency_ms": health_current.get("latency_ms"),
        "recent_health_issues": [
            {"status": h.get("status"), "ms": h.get("latency_ms"), "loss": h.get("packet_loss")}
            for h in health_events[:3]
        ],
    }


def build_scan_prompt(ctx: dict) -> str:
    data = json.dumps(ctx, default=str, separators=(",", ":"))
    return (
        'You are a home-network security analyst. Analyse this nmap scan data and reply with ONE JSON object EXACTLY in this shape:\n'
        '{"summary":"1-3 sentences","severity":"low|medium|high","benign":["..."],"concerning":["..."],"next_steps":["..."]}\n'
        'Rules:\n'
        '- Only reference devices/IPs present in DATA. Never invent.\n'
        '- trusted=true means the user knows it; treat as expected unless ports changed.\n'
        '- If a device has a "label", use the label name.\n'
        '- Use health_status for the CURRENT state. Only call it "degraded" if health_status is literally "degraded".\n'
        '- If changes is empty: severity MUST be "low".\n'
        '- Severity: low=normal, medium=unknown device or new open ports, high=clearly malicious or unexpected open ports on unknown host.\n'
        '- Each list item under 200 chars. Empty lists allowed. Return ONLY the JSON, no prose.\n'
        f'DATA:{data}'
    )


# ── Traffic context + prompt ──────────────────────────────────────────────────

def build_traffic_context(traffic_data: dict, device_labels: dict[str, str] | None = None) -> dict:
    """
    Compact context for PACKET CAPTURE analysis. No scan/device list — just
    what we extracted from the pcaps.

    device_labels: optional {ip: label} map so the model can name talker IPs
    by their friendly label rather than just the raw IP.
    """
    talkers = (traffic_data.get("top_talkers") or [])[:6]
    # Annotate talkers with labels if we have them
    if device_labels:
        for t in talkers:
            lbl = device_labels.get(t.get("ip"))
            if lbl:
                t["label"] = lbl

    return {
        "total_packets":    traffic_data.get("total_packets", 0),
        "total_mb":         traffic_data.get("total_mb", 0),
        "dns_queries":      traffic_data.get("dns_count", 0),
        "top_talkers":      talkers,
        "top_destinations": (traffic_data.get("top_destinations") or [])[:6],
        "protocol_mix":     traffic_data.get("protocol_mix", {}),
        "top_domains":      (traffic_data.get("top_domains") or [])[:15],
    }


def build_traffic_prompt(ctx: dict) -> str:
    data = json.dumps(ctx, default=str, separators=(",", ":"))
    return (
        'You are a home-network packet-capture analyst. Analyse this traffic summary and reply with ONE JSON object EXACTLY in this shape:\n'
        '{"summary":"1-3 sentences","severity":"low|medium|high","benign":["..."],"concerning":["..."],"next_steps":["..."]}\n'
        'Rules:\n'
        '- Only reference IPs/domains present in DATA. Never invent.\n'
        '- You MUST name 2-3 specific domains from top_domains in benign or concerning. Identify what each is (IoT phone-home, video streaming, ad/telemetry SDK, social media, etc.).\n'
        '- IoT vendor domains (wyzecam, ecobee, roborock, life360, etc.) are normal device phone-home → benign.\n'
        '- Ad/tracking SDKs (appsflyersdk, doubleclick, branch.io, adjust.io, etc.) → concerning telemetry.\n'
        '- Name at least one specific talker IP from top_talkers and what it appears to be doing based on its destinations. Use its "label" if present.\n'
        '- Severity: low=expected traffic only, medium=heavy ad-tracking or unusual external destinations, high=clearly malicious patterns (C2, exfil, malware domains).\n'
        '- Each list item under 200 chars. Empty lists allowed. Return ONLY the JSON, no prose.\n'
        f'DATA:{data}'
    )


# ── Legacy combined builder (kept for backwards compatibility) ────────────────

def build_context(
    scan,
    changes: list[dict],
    devices: list[dict],
    health_current: dict,
    health_events: list[dict],
    recent_alerts: list[dict],
    traffic_data: dict | None = None,
) -> dict:
    """Legacy combined context — used by callers that still pass everything at once."""
    ctx = build_scan_context(scan, changes, devices, health_current, health_events)
    if traffic_data:
        ctx["traffic"] = build_traffic_context(traffic_data)
    return ctx


def build_prompt(context: dict) -> str:
    """Legacy combined prompt — used when caller hasn't migrated to scan/traffic split."""
    data = json.dumps(context, default=str, separators=(",", ":"))
    return (
        'You are a home-network security analyst. Analyse this network monitoring data and reply with ONE JSON object EXACTLY in this shape:\n'
        '{"summary":"1-3 sentences","severity":"low|medium|high","benign":["..."],"concerning":["..."],"next_steps":["..."]}\n'
        'Rules:\n'
        '- Only reference devices/IPs/domains present in DATA. Never invent.\n'
        '- trusted=true means the user knows it; treat as expected unless ports changed. Use any "label" name when referring to a device.\n'
        '- Use health_status for the CURRENT state. Only call it "degraded" if health_status is literally "degraded".\n'
        '- If a "traffic" key is present: name 2-3 specific domains from traffic.top_domains and identify them (IoT phone-home, ad/tracking SDK, streaming, etc.).\n'
        '- Severity: low=normal, medium=unknown device / heavy ad-tracking / new open ports, high=clearly malicious.\n'
        '- Each list item under 200 chars. Empty lists allowed. Return ONLY the JSON, no prose.\n'
        f'DATA:{data}'
    )
