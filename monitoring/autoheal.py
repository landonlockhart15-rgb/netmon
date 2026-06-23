"""
autoheal.py — "Uptime Guardian": detect internet outages and auto-reboot the
router to restore connectivity.

Flow (run every autoheal_interval_s by autoheal_loop in scheduler.py):
  1. probe()   — fresh pings to internet targets + the gateway.
  2. decide()  — PURE rule function: given connectivity + outage age + reboot
                 history, return one action. No I/O, fully unit-testable.
  3. run_cycle — orchestrates: applies the decision, logs to ActivityLog,
                 pushes ntfy, and (unless dry-run) calls the router driver.

Design rules:
  - The DECISION is deterministic (decide()). The local AI only writes a
    human-readable DIAGNOSIS string — it never decides to cut power.
  - Off by default; dry-run by default. Dry-run logs "would reboot" and still
    consumes the per-outage / per-day budget, so you can watch it behave safely.
  - Hard caps + cooldowns prevent boot-loops. A reboot that doesn't restore
    connectivity escalates to "give up + notify", not endless reboots.
  - Reboot attempts are persisted in ActivityLog (category="autoheal"), so caps
    survive a process restart. Short-term outage tracking lives in _STATE.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.database import SessionLocal
from models.tables import Setting, ActivityLog

# Events we write to ActivityLog (category="autoheal")
EV_REBOOT      = "router_reboot"          # real reboot attempt (success/fail in detail)
EV_DRYRUN      = "router_reboot_dryrun"   # dry-run "would have rebooted"
EV_RECOVERED   = "recovered"
EV_GIVEUP      = "giveup"
EV_OUTAGE      = "outage_detected"
EV_RESET       = "reboot_counter_reset"
# Attempts that count against caps/cooldown (real + dry-run, so dry-run behaves identically)
_ATTEMPT_EVENTS = (EV_REBOOT, EV_DRYRUN)
_STORY_EVENTS = {EV_OUTAGE, EV_DRYRUN, EV_REBOOT, EV_RECOVERED, EV_GIVEUP, EV_RESET}

# Short-term, in-process outage tracking. Persisted reboot history (ActivityLog)
# is the source of truth for caps; this just tracks the *current* outage so we
# require sustained offline before acting and notify recovery once.
_STATE: dict = {
    "offline_since": None,        # datetime when the current outage began
    "consecutive_offline": 0,     # consecutive offline probes
    "rebooted_this_outage": False,
    "gave_up": False,
    "outage_announced": False,
}


def _reset_state() -> None:
    _STATE.update(offline_since=None, consecutive_offline=0,
                  rebooted_this_outage=False, gave_up=False, outage_announced=False)


# ── Config ────────────────────────────────────────────────────────────────────

def _get(db, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if (row and row.value is not None) else default


def get_config(db) -> dict:
    """Read auto-heal settings. Router password prefers the ROUTER_PASS env var
    over the DB (same pattern as ntfy/smtp secrets)."""
    def _int(k, d):
        try: return int(_get(db, k, str(d)))
        except (ValueError, TypeError): return d

    gateway = ""
    try:
        from network.autodetect import get_network_info
        gateway = get_network_info().get("gateway") or ""
    except Exception:
        pass

    host = _get(db, "autoheal_router_host", "") or gateway or "192.168.1.1"
    password = os.getenv("ROUTER_PASS") or _get(db, "autoheal_router_pass", "")
    router_ssl = _get(db, "autoheal_router_ssl", "false") == "true"
    router_port_str = _get(db, "autoheal_router_port", "")
    router_port = None
    if router_port_str.strip():
        try:
            router_port = int(router_port_str)
        except ValueError:
            pass
    elif router_ssl:
        router_port = 443

    smartplug_pass = os.getenv("SMARTPLUG_PASS") or _get(db, "autoheal_smartplug_pass", "")

    return {
        "enabled":        _get(db, "autoheal_enabled", "false") == "true",
        "dry_run":        _get(db, "autoheal_dry_run", "true") == "true",
        "interval_s":     _int("autoheal_interval_s", 30),
        "confirm_checks": _int("autoheal_confirm_checks", 3),
        "method":         _get(db, "autoheal_reboot_method", "netgear_soap"),
        "router_host":    host,
        "router_user":    _get(db, "autoheal_router_user", "admin"),
        "router_pass":    password,
        "router_ssl":     router_ssl,
        "router_port":    router_port,
        "has_password":   bool(password),
        "max_per_outage": _int("autoheal_max_reboots_per_outage", 1),
        "cooldown_s":     _int("autoheal_cooldown_min", 10) * 60,
        "max_per_day":    _int("autoheal_max_reboots_per_day", 4),
        "recovery_window_s": _int("autoheal_recovery_window_s", 240),
        "internet_targets": [t.strip() for t in _get(db, "autoheal_internet_targets", "8.8.8.8,1.1.1.1").split(",") if t.strip()],
        "smartplug_method": _get(db, "autoheal_smartplug_method", "none"),
        "smartplug_host":   _get(db, "autoheal_smartplug_host", ""),
        "smartplug_user":   _get(db, "autoheal_smartplug_user", ""),
        "smartplug_pass":   smartplug_pass,
        "smartplug_has_password": bool(smartplug_pass),
    }


# ── Probe ───────────────────────────────────────────────────────────────────

def probe(cfg: dict) -> dict:
    """Fresh connectivity probe. internet_up = ANY internet target reachable;
    gateway_up = the router itself answers. Fast (2 packets each)."""
    from monitoring.health import run_ping

    internet_up = False
    internet_latency = None
    for tgt in cfg.get("internet_targets") or ["8.8.8.8"]:
        r = run_ping(target=tgt, count=2, warn_loss_pct=50.0)
        if r["status"] != "offline":
            internet_up = True
            internet_latency = r["latency_ms"]
            break

    gw = run_ping(target=cfg["router_host"], count=2, warn_loss_pct=50.0)
    gateway_up = gw["status"] != "offline"

    return {
        "internet_up": internet_up,
        "gateway_up": gateway_up,
        "internet_latency_ms": internet_latency,
        "gateway_latency_ms": gw["latency_ms"],
    }


# ── Decision (PURE — unit-testable, no I/O) ───────────────────────────────────

def decide(
    *,
    internet_up: bool,
    gateway_up: bool,
    consecutive_offline: int,
    cfg: dict,
    reboots_in_outage: int,
    reboots_today: int,
    last_attempt_at: Optional[datetime],
    now: datetime,
) -> dict:
    """
    Return the single action to take this cycle. Pure function.

    action ∈ {
      "online"           internet is up — nothing to do
      "confirming"       offline but not yet sustained long enough to act
      "awaiting_recovery" we recently rebooted; give the router time to boot
      "cooldown"         within the min gap between reboot attempts
      "reboot"           confirmed outage, budget available → reboot now
      "giveup"           reboot(s) didn't help or caps hit → stop, notify
    }
    """
    if internet_up:
        return {"action": "online"}

    if consecutive_offline < cfg["confirm_checks"]:
        return {"action": "confirming", "have": consecutive_offline, "need": cfg["confirm_checks"]}

    # We've recently attempted a reboot — wait out the boot/recovery window
    # before judging it failed (Orbi + cable-modem resync is slow).
    if last_attempt_at is not None:
        since = (now - last_attempt_at).total_seconds()
        if since < cfg["recovery_window_s"]:
            return {"action": "awaiting_recovery", "since_s": round(since)}

    if reboots_in_outage >= cfg["max_per_outage"]:
        return {"action": "giveup",
                "reason": "Reboot did not restore connectivity within the recovery window — "
                          "likely an ISP outage or hardware fault. Manual intervention may be needed."}

    if reboots_today >= cfg["max_per_day"]:
        return {"action": "giveup",
                "reason": f"Daily reboot cap ({cfg['max_per_day']}) reached — not rebooting again today."}

    if last_attempt_at is not None and (now - last_attempt_at).total_seconds() < cfg["cooldown_s"]:
        return {"action": "cooldown"}

    return {"action": "reboot",
            "reason": f"Internet unreachable for {consecutive_offline} consecutive checks; "
                      f"gateway {'reachable' if gateway_up else 'unreachable'}. Rebooting router."}


# ── Diagnosis (AI advisory only — deterministic fallback always present) ──────

def diagnose(db, probe_result: dict, offline_for_s: Optional[float], cfg: dict) -> str:
    """Plain-English diagnosis. Deterministic base; optionally enriched by the
    local model when AI is enabled. Never blocks the heal flow."""
    mins = f"{offline_for_s/60:.1f} min" if offline_for_s else "unknown"
    if probe_result["gateway_up"]:
        base = (f"Internet unreachable for ~{mins}, but the router/gateway is responding on the LAN. "
                "This is the classic 'router needs a kick' case a reboot usually fixes (and resyncs the cable modem).")
    else:
        base = (f"Internet unreachable for ~{mins} and the router/gateway is not answering on the LAN either. "
                "The whole box may be hung; a reboot is worth attempting if it's still reachable on the admin interface.")

    if _get(db, "ai_enabled", "false") != "true":
        return base
    try:
        ai = _ai_diagnose(probe_result, mins)
        return f"{base}\n\nAI: {ai}" if ai else base
    except Exception:
        return base


def _ai_diagnose(probe_result: dict, mins: str) -> Optional[str]:
    """Best-effort one-paragraph diagnosis from the local Ollama model. Short
    timeout; returns None on any failure (AI is purely advisory here)."""
    import json, urllib.request
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    model = os.getenv("AI_FAST_MODEL", os.getenv("AI_MODEL", "qwen2.5:3b"))
    prompt = (
        "You are a home-network assistant. The internet is down. "
        f"Gateway reachable on LAN: {probe_result['gateway_up']}. Offline for ~{mins}. "
        "In 2 sentences, state the most likely cause and whether rebooting the router will likely help. Be concise."
    )
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False,
                          "options": {"num_predict": 120}}).encode()
    req = urllib.request.Request(f"{host}/api/generate", data=payload,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode())
    return (data.get("response") or "").strip() or None


# ── Persisted reboot history (caps survive restarts) ──────────────────────────

def _attempts_since(db, since: datetime) -> list:
    reset_at = _last_reset_at(db)
    if reset_at and reset_at > since:
        since = reset_at
    rows = (db.query(ActivityLog)
            .filter(ActivityLog.category == "autoheal",
                    ActivityLog.event.in_(_ATTEMPT_EVENTS),
                    ActivityLog.created_at >= since)
            .order_by(ActivityLog.created_at).all())
    return rows


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _last_reset_at(db) -> Optional[datetime]:
    row = (db.query(ActivityLog)
           .filter(ActivityLog.category == "autoheal",
                   ActivityLog.event == EV_RESET)
           .order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc())
           .first())
    return _aware(row.created_at) if row else None


def attempt_stats(db, now: Optional[datetime] = None) -> dict:
    """Return reboot attempt stats after the most recent counter reset."""
    now = now or datetime.now(timezone.utc)
    reset_at = _last_reset_at(db)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_start = max(midnight, reset_at) if reset_at else midnight

    reboots_today = (db.query(ActivityLog)
                     .filter(ActivityLog.category == "autoheal",
                             ActivityLog.event.in_(_ATTEMPT_EVENTS),
                             ActivityLog.created_at >= today_start)
                     .count())

    last_q = (db.query(ActivityLog)
              .filter(ActivityLog.category == "autoheal",
                      ActivityLog.event.in_(_ATTEMPT_EVENTS)))
    if reset_at:
        last_q = last_q.filter(ActivityLog.created_at >= reset_at)
    last_reboot = last_q.order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc()).first()

    return {
        "reboots_today": reboots_today,
        "last_reboot_at": _aware(last_reboot.created_at) if last_reboot else None,
        "counter_reset_at": reset_at,
    }


def _duration_label(seconds: Optional[float]) -> Optional[str]:
    if seconds is None:
        return None
    try:
        seconds = max(0, int(round(float(seconds))))
    except (TypeError, ValueError):
        return None
    if seconds < 90:
        return f"{seconds}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    return f"{minutes / 60:.1f}h"


def _storyline_for_event(event: str, summary: str, detail: dict | str | None, prior_steps: list[str] | None = None) -> str:
    """Convert autoheal audit rows into a compact human-readable storyline."""
    steps = list(prior_steps or [])
    detail_dict = detail if isinstance(detail, dict) else {}
    gateway_up = detail_dict.get("gateway_up")
    router_state = "responsive" if gateway_up is True else "unresponsive" if gateway_up is False else None

    if event == EV_OUTAGE:
        steps = ["Detected internet drop"]
        if router_state:
            steps.append(f"Identified router as {router_state}")
    elif event == EV_DRYRUN:
        if not steps:
            steps = ["Detected sustained internet drop"]
            if router_state:
                steps.append(f"Identified router as {router_state}")
        steps.append("Prepared safe reboot in dry-run")
    elif event == EV_REBOOT:
        if not steps:
            steps = ["Detected sustained internet drop"]
            if router_state:
                steps.append(f"Identified router as {router_state}")
        result = detail_dict.get("result")
        success = result.get("success") if isinstance(result, dict) else None
        steps.append("Initiated safe reboot" if success is not False else "Router reboot attempt failed")
    elif event == EV_RECOVERED:
        if not steps:
            steps = ["Connection recovered"]
        label = _duration_label(detail_dict.get("downtime_s"))
        steps.append(f"Connection restored in {label}" if label else "Connection restored")
    elif event == EV_GIVEUP:
        if not steps:
            steps = ["Detected sustained internet drop"]
        steps.append("Stopped automatic rebooting after safety limits")
    elif event == EV_RESET:
        steps = ["Reboot safety counter reset"]
    else:
        return summary

    return " -> ".join(steps)


def build_storyline(events: list[dict]) -> list[dict]:
    """
    Add narrative text to autoheal event dicts without discarding raw fields.
    Input is expected newest-first, matching /api/autoheal.
    """
    chronological = list(reversed(events))
    story_steps: list[str] = []
    story_by_id: dict[int, str] = {}

    for event in chronological:
        name = event.get("event")
        if name not in _STORY_EVENTS:
            story_by_id[event["id"]] = event.get("summary", "")
            continue
        if name == EV_OUTAGE:
            story_steps = []
        story = _storyline_for_event(name, event.get("summary", ""), event.get("detail"), story_steps)
        story_by_id[event["id"]] = story
        story_steps = story.split(" -> ") if name != EV_RESET else []
        if name in (EV_RECOVERED, EV_GIVEUP):
            story_steps = []

    return [{**event, "storyline": story_by_id.get(event["id"], event.get("summary", ""))}
            for event in events]


_AI_NARRATIVE_CACHE: dict[str, str] = {}
_AI_NARRATIVE_GENERATING: set[str] = set()

def group_events_into_incidents(events: list[dict], db) -> list[dict]:
    """
    Groups chronological autoheal events into logical incidents.
    Input events list is newest-first (as returned by build_storyline).
    """
    chronological = list(reversed(events))
    groups = []
    current_group = []
    
    for ev in chronological:
        name = ev.get("event")
        if name == EV_RESET:
            if current_group:
                groups.append(current_group)
                current_group = []
            groups.append([ev])
        elif name == EV_OUTAGE:
            if current_group:
                groups.append(current_group)
            current_group = [ev]
        else:
            if not current_group:
                if name in _STORY_EVENTS:
                    current_group = [ev]
            else:
                if name in _STORY_EVENTS:
                    current_group.append(ev)
            if name in (EV_RECOVERED, EV_GIVEUP):
                if current_group:
                    groups.append(current_group)
                    current_group = []
                
    if current_group:
        groups.append(current_group)
        
    incidents = []
    for grp in groups:
        if not grp:
            continue
        inc_id = grp[-1]["id"]
        
        types = [e.get("event") for e in grp]
        is_reset = any(t == EV_RESET for t in types)
        
        start_time = grp[0].get("created_at")
        end_time = grp[-1].get("created_at") if len(grp) > 1 else start_time
        
        downtime_s = None
        recovered_ev = next((e for e in grp if e.get("event") == EV_RECOVERED), None)
        if recovered_ev and recovered_ev.get("detail"):
            detail = recovered_ev["detail"]
            if isinstance(detail, dict):
                downtime_s = detail.get("downtime_s")
                
        status = "unknown"
        if is_reset:
            status = "reset"
        elif EV_RECOVERED in types:
            status = "resolved"
        elif EV_GIVEUP in types:
            status = "failed"
        elif any(t in _ATTEMPT_EVENTS for t in types):
            status = "rebooting"
        else:
            status = "outage"
            
        storyline = grp[-1].get("storyline", grp[-1].get("summary", ""))
        
        # Determine gateway status and reboot method
        gateways = [e["detail"].get("gateway_up") for e in grp if e.get("detail") and isinstance(e["detail"], dict) and "gateway_up" in e["detail"]]
        gateway_status = gateways[-1] if gateways else None
        
        reboot_methods = [e["detail"].get("method") for e in grp if e.get("detail") and isinstance(e["detail"], dict) and "method" in e["detail"]]
        reboot_method = reboot_methods[-1] if reboot_methods else None
        
        ai_narrative = get_ai_narrative_for_incident(grp, db)
        
        incidents.append({
            "id": inc_id,
            "type": "reset" if is_reset else "outage",
            "status": status,
            "start_time": start_time,
            "end_time": None if status in ("outage", "rebooting") else end_time,
            "downtime_s": downtime_s,
            "gateway_up": gateway_status,
            "reboot_method": reboot_method,
            "storyline": storyline,
            "ai_narrative": ai_narrative,
            "events": grp
        })
        
    return list(reversed(incidents))


def get_ai_narrative_for_incident(grp: list[dict], db) -> str:
    if len(grp) == 1 and grp[0].get("event") == EV_RESET:
        return ""
        
    grp_key = ",".join(str(e["id"]) for e in grp)
    
    if grp_key in _AI_NARRATIVE_CACHE:
        return _AI_NARRATIVE_CACHE[grp_key]
        
    ai_enabled = _get(db, "ai_enabled", "false") == "true"
    if not ai_enabled:
        return ""
        
    if grp_key in _AI_NARRATIVE_GENERATING:
        return "Generating AI narrative..."
        
    _AI_NARRATIVE_GENERATING.add(grp_key)
    
    import threading
    
    def worker():
        try:
            narrative = generate_ai_narrative_sync(grp)
            _AI_NARRATIVE_CACHE[grp_key] = narrative
        except Exception as e:
            print(f"[autoheal] AI narrative generation failed: {e}")
            _AI_NARRATIVE_CACHE[grp_key] = ""
        finally:
            _AI_NARRATIVE_GENERATING.discard(grp_key)
            
    threading.Thread(target=worker, daemon=True).start()
    
    return "Generating AI narrative..."


def generate_ai_narrative_sync(grp: list[dict]) -> str:
    try:
        from ai.provider import chain_chat
    except ImportError:
        return ""
        
    event_lines = []
    for e in grp:
        evt = e.get("event")
        time_str = e.get("created_at")
        summary = e.get("summary", "")
        detail = e.get("detail") or {}
        
        detail_str = ""
        if isinstance(detail, dict):
            if "gateway_up" in detail:
                detail_str += f" (Gateway reachable: {detail['gateway_up']})"
            if "downtime_s" in detail:
                detail_str += f" (Downtime: {detail['downtime_s']}s)"
            if "method" in detail:
                detail_str += f" (Method: {detail['method']})"
            if "result" in detail:
                res = detail["result"]
                succ = res.get("success") if isinstance(res, dict) else None
                detail_str += f" (Reboot success: {succ})"
                
        event_lines.append(f"- {time_str}: Event: {evt}. Summary: '{summary}'. Details: {detail_str}")
        
    events_block = "\n".join(event_lines)
    
    prompt = f"""You are Antigravity NetMon's network self-healing assistant.
We have collected a sequence of automated logs representing a network outage and recovery incident.
Please analyze the sequence of events and write a clean, user-friendly narrative log explaining exactly what happened, why it was fixed (or what happened with the fix attempt), and what the 'healing' action did.

Constraint:
- The response MUST be a concise 2-sentence paragraph.
- Use friendly, clear language, suitable for a home dashboard.
- Avoid raw JSON, database keys, or internal event codes. Use words like "Internet Outage", "Router reboot", "Recovery".
- Do not repeat information redundantly.

Here are the incident events:
{events_block}

AI Narrative:"""

    messages = [
        {"role": "system", "content": "You are a professional network administrator explaining automated healing actions in a concise, user-friendly way."},
        {"role": "user", "content": prompt}
    ]
    
    response = chain_chat(messages, max_tokens=150)
    
    if "AI unavailable" in response or not response.strip():
        return ""
        
    narrative = response.strip().strip('"').strip("'").strip()
    return narrative



# ── Orchestration ─────────────────────────────────────────────────────────────

def run_cycle(db=None, probe_fn=None) -> dict:
    """
    One auto-heal cycle. `probe_fn` lets tests inject synthetic connectivity.
    Returns the decision dict (with extra context) for logging/inspection.
    """
    own = db is None
    if own:
        db = SessionLocal()
    try:
        cfg = get_config(db)
        if not cfg["enabled"]:
            return {"action": "disabled"}

        pr = (probe_fn or probe)(cfg)
        now = datetime.now(timezone.utc)

        # ── Recovered / healthy ──────────────────────────────────────────────
        if pr["internet_up"]:
            was_offline = _STATE["offline_since"] is not None
            rebooted = _STATE["rebooted_this_outage"]
            outage_started = _STATE["offline_since"]
            _reset_state()
            if was_offline and rebooted:
                downtime = (now - outage_started).total_seconds() if outage_started else None
                msg = ("Internet is back online after an auto-reboot"
                       + (f" — total downtime ~{downtime/60:.1f} min." if downtime else "."))
                _emit(EV_RECOVERED, "info", msg, {"downtime_s": round(downtime) if downtime else None}, notify=True)
            return {"action": "online", "recovered": was_offline}

        # ── Internet down: update outage tracking ────────────────────────────
        if _STATE["offline_since"] is None:
            _STATE["offline_since"] = now
            _STATE["consecutive_offline"] = 1
        else:
            _STATE["consecutive_offline"] += 1
        offline_since = _STATE["offline_since"]
        offline_for_s = (now - offline_since).total_seconds()

        attempts = _attempts_since(db, offline_since)
        reboots_in_outage = len(attempts)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        reboots_today = len(_attempts_since(db, midnight))
        last_attempt_at = _aware(attempts[-1].created_at) if attempts else None

        decision = decide(
            internet_up=False, gateway_up=pr["gateway_up"],
            consecutive_offline=_STATE["consecutive_offline"], cfg=cfg,
            reboots_in_outage=reboots_in_outage, reboots_today=reboots_today,
            last_attempt_at=last_attempt_at, now=now,
        )
        action = decision["action"]

        # Announce the outage once (info-level) when first confirmed.
        if action in ("reboot", "giveup", "cooldown", "awaiting_recovery") and not _STATE["outage_announced"]:
            _STATE["outage_announced"] = True
            _emit(EV_OUTAGE, "warning",
                  f"Internet outage detected — offline for ~{offline_for_s/60:.1f} min.",
                  {"gateway_up": pr["gateway_up"]}, notify=False)

        if action == "reboot":
            diag = diagnose(db, pr, offline_for_s, cfg)
            _STATE["rebooted_this_outage"] = True
            if cfg["dry_run"]:
                _emit(EV_DRYRUN, "action",
                      "DRY-RUN: would reboot the router now to restore connectivity.",
                      {"reason": decision["reason"], "diagnosis": diag, "gateway_up": pr["gateway_up"]},
                      notify=True)
                decision["executed"] = "dry_run"
            else:
                from network.router_reboot import reboot_router
                res = reboot_router(
                    cfg["router_host"],
                    cfg["router_user"],
                    cfg["router_pass"],
                    method=cfg["method"],
                    use_ssl=cfg["router_ssl"],
                    port=cfg["router_port"],
                )
                
                # Check for smart plug fallback if main reboot fails and fallback is configured
                if not res["success"] and cfg.get("smartplug_method") and cfg["smartplug_method"] != "none":
                    primary_error = res["error"]
                    _emit(EV_REBOOT, "warning",
                          f"Primary reboot ({cfg['method']}) failed: {primary_error}. Attempting smart plug fallback ({cfg['smartplug_method']})...",
                          {"primary_result": res, "gateway_up": pr["gateway_up"]}, notify=True)
                    
                    fallback_res = reboot_router(
                        cfg["smartplug_host"],
                        cfg["smartplug_user"],
                        cfg["smartplug_pass"],
                        method=cfg["smartplug_method"],
                        use_ssl=False,
                        port=None,
                    )
                    res = fallback_res
                    if not res["success"]:
                        res["error"] = f"Primary failed ({primary_error}) and fallback failed: {res['error']}"

                level = "action" if res["success"] else "warning"
                summary = ("Rebooted the router to restore connectivity."
                           if res["success"] else f"Router reboot FAILED: {res['error']}")
                _emit(EV_REBOOT, level, summary,
                      {"reason": decision["reason"], "diagnosis": diag, "result": res,
                       "gateway_up": pr["gateway_up"]}, notify=True)
                decision["executed"] = res
        elif action == "giveup":
            if not _STATE["gave_up"]:
                _STATE["gave_up"] = True
                _emit(EV_GIVEUP, "warning", decision["reason"],
                      {"offline_for_s": round(offline_for_s)}, notify=True)

        decision.update(offline_for_s=round(offline_for_s),
                        reboots_in_outage=reboots_in_outage, reboots_today=reboots_today,
                        gateway_up=pr["gateway_up"])
        return decision
    finally:
        if own:
            db.close()


def _emit(event: str, level: str, summary: str, detail: dict, notify: bool) -> None:
    """Write to ActivityLog and optionally push an ntfy/email alert."""
    from monitoring.activity import write_log
    write_log(level, "autoheal", event, summary, detail=detail, actor="autoheal")
    if notify:
        try:
            from monitoring.notifier import alert
            # force_push so uptime events reach the phone regardless of min-level.
            # (Outage pushes may only land after connectivity returns — expected.)
            alert(f"NetMon Uptime Guardian", summary, level=level, force_push=True)
        except Exception as exc:
            print(f"[autoheal] notify failed: {exc}")


def manual_reboot(db=None, force: bool = False) -> dict:
    """
    Trigger a reboot on demand (the UI 'Reboot Router Now' button / test path).
    Honors dry-run unless force=True. Returns the driver result (or dry-run note).
    """
    own = db is None
    if own:
        db = SessionLocal()
    try:
        cfg = get_config(db)
        if cfg["dry_run"] and not force:
            _emit(EV_DRYRUN, "action", "DRY-RUN: manual reboot requested (no real reboot sent).",
                  {"trigger": "manual"}, notify=False)
            return {"success": True, "dry_run": True,
                    "detail": "Dry-run mode — no real reboot sent. Use force to actually reboot."}
        from network.router_reboot import reboot_router
        res = reboot_router(
            cfg["router_host"],
            cfg["router_user"],
            cfg["router_pass"],
            method=cfg["method"],
            use_ssl=cfg["router_ssl"],
            port=cfg["router_port"],
        )
        if not res["success"] and cfg.get("smartplug_method") and cfg["smartplug_method"] != "none":
            primary_error = res["error"]
            _emit(EV_REBOOT, "warning",
                  f"Manual primary reboot ({cfg['method']}) failed: {primary_error}. Attempting smart plug fallback ({cfg['smartplug_method']})...",
                  {"trigger": "manual", "primary_result": res}, notify=True)
            fallback_res = reboot_router(
                cfg["smartplug_host"],
                cfg["smartplug_user"],
                cfg["smartplug_pass"],
                method=cfg["smartplug_method"],
                use_ssl=False,
                port=None,
            )
            res = fallback_res
            if not res["success"]:
                res["error"] = f"Primary failed ({primary_error}) and fallback failed: {res['error']}"

        level = "action" if res["success"] else "warning"
        summary = ("Manual router reboot sent." if res["success"]
                   else f"Manual router reboot FAILED: {res['error']}")
        _emit(EV_REBOOT, level, summary, {"trigger": "manual", "result": res}, notify=True)
        res["dry_run"] = False
        return res
    finally:
        if own:
            db.close()


def reset_reboot_counter(db=None) -> dict:
    """
    Reset the counted reboot/dry-run budget without deleting audit history.
    Prior attempt rows remain visible; future caps count from this reset marker.
    """
    own = db is None
    if own:
        db = SessionLocal()
    try:
        before = attempt_stats(db)
        _STATE["rebooted_this_outage"] = False
        _STATE["gave_up"] = False
        reset_entry = ActivityLog(
            level="action",
            category="autoheal",
            event=EV_RESET,
            summary="Uptime Guardian reboot counter reset by user.",
            detail=json.dumps({"cleared_reboots_today": before["reboots_today"]}),
            actor="autoheal",
        )
        db.add(reset_entry)
        db.commit()
        reset_at = _aware(reset_entry.created_at) or datetime.now(timezone.utc)
        return {
            "status": "ok",
            "cleared_reboots_today": before["reboots_today"],
            "counter_reset_at": reset_at.isoformat(),
        }
    finally:
        if own:
            db.close()
