"""
anomaly.py — Behavioral anomaly detection engine.

Runs every 60 seconds inside anomaly_loop() (scheduler.py).

Checks:
  1. Traffic spike      — device suddenly sending/receiving far above its baseline
  2. Port scan          — device probing many ports/hosts (attacker inside network)
  3. Nighttime device   — unknown device appears between 22:00–06:00 local time
  4. Health outage      — sustained packet loss / latency spike (potential DDoS)

Each check produces zero or more AnomalyEvent dicts:
  {type, ip, level, title, body, actions}

De-duplication: in-memory dict _COOLDOWNS maps a string key to the last time
that exact event was notified. Re-alerts only after the cooldown expires.
This prevents alert storms during sustained incidents.

All anomalies are written to the ActivityLog and sent via notifier.alert().
"""

import json
import subprocess
from datetime import datetime, timezone, timedelta

from app.database import SessionLocal
from models.tables import TrafficSummary, HealthCheck, Device, ActivityLog
from monitoring.activity import write_log
import monitoring.notifier as notifier

# ── Cooldown registry (in-memory, resets on server restart) ──────────────────
_COOLDOWNS: dict[str, datetime] = {}

_COOLDOWN_MINUTES = {
    "traffic_spike":   30,
    "port_scan":       15,
    "health_outage":   10,
    "nighttime_device": 60 * 24,   # once per device per day
}

# Night hours (local — Central Time). 22:00 – 05:59
_NIGHT_START = 22
_NIGHT_END   = 6


def _is_cooled_down(key: str, event_type: str) -> bool:
    """Return True if the cooldown has expired (safe to re-alert)."""
    last = _COOLDOWNS.get(key)
    if last is None:
        return True
    cooldown = timedelta(minutes=_COOLDOWN_MINUTES.get(event_type, 15))
    return datetime.now(timezone.utc) - last >= cooldown


def _stamp(key: str) -> None:
    _COOLDOWNS[key] = datetime.now(timezone.utc)


# ── Night-time check ──────────────────────────────────────────────────────────

def _is_night() -> bool:
    """Return True if current Central Time hour is between 22:00 and 05:59."""
    from zoneinfo import ZoneInfo
    ct = datetime.now(ZoneInfo("America/Chicago"))
    return ct.hour >= _NIGHT_START or ct.hour < _NIGHT_END


# ── 1. Traffic spike detection ────────────────────────────────────────────────

def check_traffic_spikes(db) -> list[dict]:
    """
    Compare the most recent TrafficSummary's per-IP bytes against a rolling
    baseline (last 12 summaries, ~5–10 min at 30 s interval).

    Fires when: current_bytes > threshold_multiplier × baseline AND > 5 MB absolute.
    """
    events = []

    # Need at least 5 data points for a meaningful baseline
    rows = (
        db.query(TrafficSummary)
        .order_by(TrafficSummary.id.desc())
        .limit(15)
        .all()
    )
    if len(rows) < 5:
        return events

    latest = rows[0]
    history = rows[1:]  # baseline period

    try:
        latest_talkers = {t["ip"]: t["bytes"] for t in json.loads(latest.top_talkers or "[]")}
    except Exception:
        return events

    # Build per-IP baseline from history
    baseline: dict[str, list[int]] = {}
    for row in history:
        try:
            for t in json.loads(row.top_talkers or "[]"):
                baseline.setdefault(t["ip"], []).append(t["bytes"])
        except Exception:
            pass

    try:
        from models.tables import Setting
        row = db.query(Setting).filter(Setting.key == "anomaly_spike_multiplier").first()
        threshold = float(row.value) if row and row.value else 4.0
    except Exception:
        threshold = 4.0

    MIN_BYTES = 5 * 1_048_576   # 5 MB absolute floor

    for ip, current_bytes in latest_talkers.items():
        if current_bytes < MIN_BYTES:
            continue
        if ip not in baseline:
            continue
        avg = sum(baseline[ip]) / len(baseline[ip])
        if avg < 100_000:   # baseline is near-zero — not meaningful
            continue
        if current_bytes >= threshold * avg:
            key = f"traffic_spike:{ip}"
            if not _is_cooled_down(key, "traffic_spike"):
                continue
            _stamp(key)
            mb = round(current_bytes / 1_048_576, 1)
            avg_mb = round(avg / 1_048_576, 1)
            events.append({
                "type":    "traffic_spike",
                "ip":      ip,
                "level":   "warning",
                "title":   f"Traffic spike — {ip}",
                "body":    f"{ip} is using {mb} MB (baseline ~{avg_mb} MB, {round(current_bytes/avg, 1)}× above normal)",
                "actions": [notifier.investigate_action(ip), notifier.dismiss_action()],
            })

    return events


# ── 2. Port scan detection ────────────────────────────────────────────────────

def check_port_scans() -> list[dict]:
    """
    Analyze current capture files for port-scan signatures:
      • Vertical scan:   single src→dst pair with >20 distinct dest ports
      • Horizontal scan: single src connecting to >15 distinct dest hosts

    Uses tshark to extract TCP SYN packets (connection attempts only).
    """
    events = []

    try:
        from traffic.capture import CAPTURE_DIR
        from traffic.analyzer import get_readable_files
        from traffic.interfaces import find_tool, _no_window
        import subprocess, re

        tshark = find_tool("tshark")
        if not tshark:
            return events

        files = get_readable_files(CAPTURE_DIR, max_files=2)
        if not files:
            return events

        # {src_ip: {dst_ip: set(ports)}}
        syn_map: dict[str, dict[str, set]] = {}

        for pcap in files:
            try:
                r = subprocess.run(
                    [tshark, "-r", str(pcap),
                     "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                     "-T", "fields",
                     "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport"],
                    capture_output=True, text=True, timeout=60,
                    creationflags=_no_window(),
                )
                for line in r.stdout.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) < 3:
                        continue
                    src, dst, port = parts[0], parts[1], parts[2]
                    try:
                        int(port)
                    except ValueError:
                        continue
                    syn_map.setdefault(src, {}).setdefault(dst, set()).add(port)
            except Exception:
                pass

        VERT_THRESHOLD  = 20   # ports on single target
        HORIZ_THRESHOLD = 15   # distinct hosts scanned

        for src, targets in syn_map.items():
            # Vertical scan
            for dst, ports in targets.items():
                if len(ports) >= VERT_THRESHOLD:
                    key = f"port_scan:vert:{src}:{dst}"
                    if not _is_cooled_down(key, "port_scan"):
                        continue
                    _stamp(key)
                    events.append({
                        "type":    "port_scan",
                        "ip":      src,
                        "level":   "critical",
                        "title":   f"Port scan detected — {src}",
                        "body":    f"{src} probed {len(ports)} ports on {dst}. Possible vulnerability scan.",
                        "actions": [
                            notifier.block_action(src),
                            notifier.investigate_action(src),
                            notifier.dismiss_action(),
                        ],
                    })

            # Horizontal scan
            if len(targets) >= HORIZ_THRESHOLD:
                key = f"port_scan:horiz:{src}"
                if not _is_cooled_down(key, "port_scan"):
                    continue
                _stamp(key)
                events.append({
                    "type":    "port_scan",
                    "ip":      src,
                    "level":   "critical",
                    "title":   f"Network sweep detected — {src}",
                    "body":    f"{src} probed {len(targets)} distinct hosts. Possible network reconnaissance.",
                    "actions": [
                        notifier.block_action(src),
                        notifier.investigate_action(src),
                        notifier.dismiss_action(),
                    ],
                })

    except Exception as exc:
        print(f"[anomaly] port scan check error: {exc}")

    return events


# ── 3. Health outage / DDoS saturation ───────────────────────────────────────

def check_health_outage(db) -> list[dict]:
    """
    Fire when the last 3 consecutive health checks are all offline or degraded
    AND average packet loss exceeds 40% (sustained outage, not a blip).

    This can signal DDoS saturation, ISP outage, or router issues.
    """
    events = []

    rows = (
        db.query(HealthCheck)
        .order_by(HealthCheck.id.desc())
        .limit(3)
        .all()
    )
    if len(rows) < 3:
        return events

    all_bad = all(r.status in ("offline", "degraded") for r in rows)
    avg_loss = sum(r.packet_loss or 0 for r in rows) / len(rows)

    if all_bad and avg_loss >= 40:
        key = "health_outage"
        if not _is_cooled_down(key, "health_outage"):
            return events
        _stamp(key)

        avg_lat = sum(r.latency_ms or 0 for r in rows if r.latency_ms) / max(1, sum(1 for r in rows if r.latency_ms))
        worst   = rows[0]
        events.append({
            "type":    "health_outage",
            "ip":      None,
            "level":   "critical",
            "title":   "Network outage detected",
            "body":    (
                f"Last 3 checks all {worst.status}. "
                f"Avg packet loss {round(avg_loss)}%, avg latency {round(avg_lat)} ms. "
                "Possible DDoS saturation or ISP outage."
            ),
            "actions": [notifier.dismiss_action()],
        })

    return events


# ── 4. Nighttime device (injected from scheduler, not polled) ─────────────────

def nighttime_device_alert(ip: str, mac: str, hostname: str, device_id: int) -> None:
    """
    Called by _run_auto_scan() when a new unknown device appears during night hours.
    Separate from the other checks because the trigger is scan-time, not poll-time.
    """
    if not _is_night():
        return

    key = f"nighttime_device:{mac or ip}"
    if not _is_cooled_down(key, "nighttime_device"):
        return
    _stamp(key)

    label = hostname or ip
    notifier.alert(
        title   = f"Unknown device on network — {label}",
        body    = (
            f"A new unrecognized device appeared while you were sleeping.\n"
            f"IP: {ip}  MAC: {mac or 'unknown'}  Host: {hostname or '—'}\n"
            "Tap Investigate to run an AI analysis, or Block to isolate it."
        ),
        level   = "critical",
        actions = [
            notifier.investigate_action(ip),
            notifier.block_action(ip),
            notifier.dismiss_action(),
        ],
    )
    write_log(
        "critical", "alert", "nighttime_device",
        f"Unknown device appeared at night: {ip} (MAC: {mac or 'unknown'})",
        detail     = {"ip": ip, "mac": mac, "hostname": hostname, "device_id": device_id},
        device_ip  = ip,
        device_id  = device_id,
    )


# ── Auto-block logic ──────────────────────────────────────────────────────────

def _is_this_machine(ip: str) -> bool:
    """Return True if ip belongs to this PC — never auto-block ourselves."""
    import socket
    try:
        # Get all IPs assigned to this machine
        hostname = socket.gethostname()
        local_ips = {addr[4][0] for addr in socket.getaddrinfo(hostname, None)}
        local_ips.update({"127.0.0.1", "::1", "0.0.0.0"})
        # Also add the primary outbound IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.add(s.getsockname()[0])
        s.close()
        return ip in local_ips
    except Exception:
        return False


def _auto_block(ip: str, reason: str) -> None:
    """Block an IP via Windows Firewall and log the action with a revert payload."""
    import subprocess

    # Never block this machine's own IP
    if _is_this_machine(ip):
        print(f"[anomaly] Skipping auto-block of local machine IP {ip}")
        return

    rule_name = f"NetMon-AutoBlock-{ip}"
    try:
        from traffic.interfaces import _no_window
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", "action=block",
             f"remoteip={ip}", "enable=yes", "profile=any"],
            check=True, capture_output=True, text=True,
            creationflags=_no_window(),
        )
        write_log(
            "action", "firewall", "auto_block",
            f"Auto-blocked {ip}: {reason}",
            detail={"ip": ip, "rule": rule_name, "reason": reason},
            device_ip=ip,
            actor="anomaly_auto",
            revert={"action_type": "unblock_by_rule_names",
                    "params": {"rule_names": [rule_name], "ip": ip}},
        )
        notifier.alert(
            title   = f"Auto-blocked {ip}",
            body    = f"NetMon automatically blocked {ip}.\nReason: {reason}",
            level   = "action",
        )
    except Exception as exc:
        print(f"[anomaly] auto-block {ip} failed: {exc}")


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run_anomaly_checks() -> None:
    """
    Run all anomaly checks. Called every 60 s by anomaly_loop() in scheduler.py.
    Logs every anomaly to ActivityLog and sends push/email notifications.
    For critical threats with confirmed evidence, auto-blocks the source IP.
    """
    db = SessionLocal()
    try:
        all_events: list[dict] = []
        all_events.extend(check_traffic_spikes(db))
        all_events.extend(check_health_outage(db))
    except Exception as exc:
        print(f"[anomaly] DB check error: {exc}")
    finally:
        db.close()

    # Port scan check is capture-file based, no DB session needed
    try:
        all_events.extend(check_port_scans())
    except Exception as exc:
        print(f"[anomaly] port scan check error: {exc}")

    for ev in all_events:
        write_log(
            ev["level"], "alert", ev["type"],
            ev["body"],
            device_ip = ev.get("ip"),
        )
        notifier.alert(
            title   = ev["title"],
            body    = ev["body"],
            level   = ev["level"],
            actions = ev.get("actions"),
        )
        # Auto-block confirmed critical threats (port scans inside the network)
        # Never block our own IP — nmap scans from this machine look like port scans
        if ev["level"] == "critical" and ev["type"] == "port_scan" and ev.get("ip"):
            if not _is_this_machine(ev["ip"]):
                _auto_block(ev["ip"], ev["title"])

        # Request immediate rescan on any critical anomaly
        if ev["level"] == "critical":
            from monitoring.state import request_immediate_scan
            request_immediate_scan()

        # Auto-investigate traffic spikes (fire-and-forget HTTP to running server)
        if ev["type"] == "traffic_spike" and ev.get("ip"):
            try:
                import urllib.request as _ureq, json as _json
                _payload = _json.dumps({"target": ev["ip"], "source": "anomaly_auto"}).encode()
                _req = _ureq.Request(
                    "http://127.0.0.1:8000/api/ai/investigate",
                    data=_payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                _ureq.urlopen(_req, timeout=3)
            except Exception:
                pass  # AI may be disabled; notification already sent above

    if all_events:
        print(f"[anomaly] {len(all_events)} anomaly event(s) detected and notified")
