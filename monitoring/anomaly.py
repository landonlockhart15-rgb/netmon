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
from models.tables import TrafficSummary, HealthCheck, Device, Scan, ScanDevice, ActivityLog
from monitoring.activity import write_log
import monitoring.notifier as notifier
from network.protection import explain_protected_target, validate_block_target
try:
    from ai import knowledge_bridge as _kb
except Exception:
    _kb = None

# ── Cooldown registry (in-memory, resets on server restart) ──────────────────
_COOLDOWNS: dict[str, datetime] = {}

_COOLDOWN_MINUTES = {
    "traffic_spike":         30,
    "port_scan":             15,
    "health_outage":         10,
    "nighttime_device":      60 * 24,   # once per device per day
    "sustained_bandwidth":   45,        # don't nag about the same hog repeatedly
    "degraded_health":       20,
    "shadow_device":         60 * 24,   # scan-history behavior changes slowly
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
            # Never alert on port scans originating from this machine — Security
            # Lab tools (Nikto, nmap, Hydra) running here look identical to an
            # attacker scan and would spam the user.
            if _is_this_machine(src):
                continue

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


# ── 5. Sustained-bandwidth check ──────────────────────────────────────────────

def check_sustained_bandwidth(db) -> list[dict]:
    """Flag a device that has stayed in the top-talkers list above an absolute
    floor across the last N consecutive traffic summaries.

    Different from check_traffic_spikes: that fires once on a sharp surge, then
    cools down. This one fires on a persistent hog (stuck stream, runaway
    backup, possible exfil) that the spike check has moved past.
    """
    events = []
    N = 6  # ~3–6 minutes at 30–60 s intervals
    rows = (
        db.query(TrafficSummary)
        .order_by(TrafficSummary.id.desc())
        .limit(N)
        .all()
    )
    if len(rows) < N:
        return events

    MIN_BYTES_PER_WINDOW = 8 * 1_048_576  # 8 MB per window

    per_ip_windows: dict[str, list[int]] = {}
    for r in rows:
        try:
            for t in json.loads(r.top_talkers or "[]"):
                per_ip_windows.setdefault(t["ip"], []).append(int(t.get("bytes") or 0))
        except Exception:
            pass

    for ip, vals in per_ip_windows.items():
        if len(vals) < N:
            continue  # device didn't show in every window — not sustained
        if all(v >= MIN_BYTES_PER_WINDOW for v in vals):
            key = f"sustained_bandwidth:{ip}"
            if not _is_cooled_down(key, "sustained_bandwidth"):
                continue
            _stamp(key)
            total_mb = round(sum(vals) / 1_048_576, 1)
            avg_mb = round((sum(vals) / len(vals)) / 1_048_576, 1)
            events.append({
                "type":    "sustained_bandwidth",
                "ip":      ip,
                "level":   "warning",
                "title":   f"Sustained bandwidth use — {ip}",
                "body":    (
                    f"{ip} has been a top talker for the last {N} windows "
                    f"(≈{avg_mb} MB/window, {total_mb} MB total). "
                    "Could be a stuck stream, runaway backup, or exfiltration."
                ),
                "actions": [notifier.investigate_action(ip), notifier.dismiss_action()],
            })
    return events


# ── 6. Degraded-health (sub-outage) check ─────────────────────────────────────

def check_degraded_health(db) -> list[dict]:
    """Fire when recent health checks show meaningfully worse loss/latency than
    a longer baseline, but not bad enough for check_health_outage to trigger.

    Catches gradual ISP degradation, congestion, or a flaky router that doesn't
    fall fully offline.
    """
    events = []
    rows = (
        db.query(HealthCheck)
        .order_by(HealthCheck.id.desc())
        .limit(30)
        .all()
    )
    if len(rows) < 15:
        return events

    recent = rows[:5]
    baseline = rows[5:]

    def _avg(items, attr):
        vals = [getattr(r, attr) for r in items if getattr(r, attr) is not None]
        return (sum(vals) / len(vals)) if vals else 0.0

    rec_loss = _avg(recent, "packet_loss")
    base_loss = _avg(baseline, "packet_loss")
    rec_lat = _avg(recent, "latency_ms")
    base_lat = _avg(baseline, "latency_ms")

    loss_jumped = rec_loss >= 8 and (base_loss < 2 or rec_loss >= 3 * max(base_loss, 1))
    lat_jumped  = rec_lat  >= 80 and (base_lat < 30 or rec_lat  >= 2 * max(base_lat, 1))

    # Skip if a full outage is already in progress — check_health_outage owns it
    if all(r.status == "offline" for r in recent):
        return events

    if loss_jumped or lat_jumped:
        key = "degraded_health"
        if not _is_cooled_down(key, "degraded_health"):
            return events
        _stamp(key)
        events.append({
            "type":    "degraded_health",
            "ip":      None,
            "level":   "warning",
            "title":   "Network performance degraded",
            "body":    (
                f"Recent loss {rec_loss:.1f}% (baseline {base_loss:.1f}%), "
                f"latency {rec_lat:.0f} ms (baseline {base_lat:.0f} ms). "
                "Not a full outage — likely ISP congestion or a flaky uplink."
            ),
            "actions": [notifier.dismiss_action()],
        })
    return events


# ── 7. Shadow-device behavior check ──────────────────────────────────────────

def _utc_naive(dt: datetime) -> datetime:
    """Normalize mixed SQLite datetimes for comparisons in tests and prod."""
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _is_locally_administered_mac(mac: str | None) -> bool:
    """True for randomized/private MACs where the locally administered bit is set."""
    if not mac:
        return False
    first_octet = mac.replace("-", ":").split(":")[0]
    try:
        return bool(int(first_octet, 16) & 0x02)
    except ValueError:
        return False


def check_shadow_devices(db) -> list[dict]:
    """
    Detect devices that behave unlike stable inventory:
      - brief untrusted appearances that are already absent from the current scan
      - one IP seen with several different MAC addresses in the recent window

    This deliberately uses only persisted scan history, so it is a safe first
    phase before adding passive mDNS/DHCP event streams.
    """
    events: list[dict] = []
    latest = (
        db.query(Scan)
        .filter(Scan.status == "complete")
        .order_by(Scan.id.desc())
        .first()
    )
    if not latest or not latest.started_at:
        return events

    latest_started = _utc_naive(latest.started_at)
    lookback = latest_started - timedelta(hours=24)

    current_device_ids = {
        row.device_id
        for row in db.query(ScanDevice.device_id)
        .filter(ScanDevice.scan_id == latest.id)
        .all()
    }

    recent_rows = (
        db.query(ScanDevice)
        .join(Scan)
        .filter(Scan.status == "complete", Scan.started_at >= lookback)
        .order_by(ScanDevice.id.asc())
        .all()
    )
    if not recent_rows:
        return events

    rows_by_device: dict[int, list[ScanDevice]] = {}
    rows_by_ip: dict[str, list[ScanDevice]] = {}
    for sd in recent_rows:
        rows_by_device.setdefault(sd.device_id, []).append(sd)
        if sd.ip:
            rows_by_ip.setdefault(sd.ip, []).append(sd)

    for device_id, rows in rows_by_device.items():
        dev = rows[-1].device
        if dev.is_known or device_id in current_device_ids:
            continue
        first_seen = min(_utc_naive(r.scan.started_at) for r in rows if r.scan.started_at)
        last_seen = max(_utc_naive(r.scan.started_at) for r in rows if r.scan.started_at)
        age_s = (last_seen - first_seen).total_seconds()
        absent_s = (latest_started - last_seen).total_seconds()
        if len(rows) <= 2 and age_s <= 30 * 60 and absent_s >= 5 * 60:
            mac = dev.mac or "unknown"
            ip = rows[-1].ip
            key = f"shadow_device:brief:{device_id}:{mac}"
            if not _is_cooled_down(key, "shadow_device"):
                continue
            _stamp(key)
            label = dev.hostname or rows[-1].hostname or ip or f"device #{device_id}"
            events.append({
                "type": "shadow_device",
                "ip": ip,
                "device_id": device_id,
                "level": "warning",
                "title": f"Shadow device disappeared — {label}",
                "body": (
                    f"Untrusted device {label} appeared briefly and is absent from the latest scan. "
                    f"MAC: {mac}. This can indicate a rogue or transient device."
                ),
                "actions": [notifier.investigate_action(ip), notifier.dismiss_action()] if ip else [notifier.dismiss_action()],
            })

    for ip, rows in rows_by_ip.items():
        macs: dict[str, Device] = {}
        for sd in rows:
            mac = (sd.device.mac or "").lower()
            if mac:
                macs[mac] = sd.device
        if len(macs) < 3:
            continue
        local_count = sum(1 for mac in macs if _is_locally_administered_mac(mac))
        unknown_count = sum(1 for dev in macs.values() if not dev.is_known)
        if local_count < 2 and unknown_count < 3:
            continue
        key = f"shadow_device:mac_rotation:{ip}"
        if not _is_cooled_down(key, "shadow_device"):
            continue
        _stamp(key)
        latest_row = rows[-1]
        events.append({
            "type": "shadow_device",
            "ip": ip,
            "device_id": latest_row.device_id,
            "level": "warning",
            "title": f"MAC rotation detected — {ip}",
            "body": (
                f"{ip} used {len(macs)} different MAC addresses in the last 24 hours "
                f"({local_count} look randomized/private). Frequent rotation can hide rogue hardware."
            ),
            "actions": [notifier.investigate_action(ip), notifier.dismiss_action()],
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
    if _kb is not None:
        try:
            _kb.record_netmon_incident({
                "type": "nighttime_device", "ip": ip, "level": "critical",
                "title": f"Unknown device {label}",
                "body": f"MAC={mac} host={hostname} device_id={device_id}",
            })
        except Exception:
            pass


# ── Auto-block logic ──────────────────────────────────────────────────────────

def _is_this_machine(ip: str) -> bool:
    """Return True if ip belongs to this PC — never auto-block ourselves."""
    return explain_protected_target(ip) is not None


def _auto_block(ip: str, reason: str) -> None:
    """Block an IP via Windows Firewall and log the action with a revert payload."""
    import subprocess

    try:
        ip = validate_block_target(ip)
    except ValueError as exc:
        print(f"[anomaly] Skipping auto-block of protected target {ip}: {exc}")
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
        try:
            from ai.knowledge_bridge import record_remediation_outcome
            record_remediation_outcome(
                service="security",
                evidence={"ip": ip, "reason": reason, "trigger": "anomaly_auto_block"},
                action="block_ip_firewall",
                params={"ip": ip, "rule": rule_name},
                success=True,
                summary=f"Auto-blocked {ip}: {reason}",
                severity="high",
            )
        except Exception:
            pass
    except Exception as exc:
        print(f"[anomaly] auto-block {ip} failed: {exc}")
        try:
            from ai.knowledge_bridge import record_remediation_outcome
            record_remediation_outcome(
                service="security",
                evidence={"ip": ip, "reason": reason, "trigger": "anomaly_auto_block"},
                action="block_ip_firewall",
                params={"ip": ip},
                success=False,
                summary=f"Auto-block of {ip} failed: {exc}"[:200],
                severity="high",
            )
        except Exception:
            pass


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
        all_events.extend(check_sustained_bandwidth(db))
        all_events.extend(check_degraded_health(db))
        all_events.extend(check_shadow_devices(db))
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
        log_id = write_log(
            ev["level"], "alert", ev["type"],
            ev["body"],
            device_ip = ev.get("ip"),
            device_id = ev.get("device_id"),
        )
        if _kb is not None:
            try:
                _kb.record_netmon_incident(ev)
            except Exception:
                pass
        notifier.alert(
            title   = ev["title"],
            body    = ev["body"],
            level   = ev["level"],
            actions = ev.get("actions"),
        )

        # Phase 4: snapshot ~5 minutes of traffic around this anomaly so the
        # user can replay it later. Best-effort; never blocks the notifier.
        try:
            from app.database import SessionLocal as _SL
            from models.tables import Setting
            _db = _SL()
            try:
                _row = _db.query(Setting).filter(Setting.key == "incident_capture_enabled").first()
                _enabled = (_row.value if _row else "true").lower() == "true"
            finally:
                _db.close()
            if _enabled:
                import threading as _thr
                from traffic.incident_capture import extract_incident_snippet
                _thr.Thread(
                    target=extract_incident_snippet,
                    kwargs={
                        "anomaly_log_id": log_id,
                        "anomaly_type":   ev["type"],
                        "device_ip":      ev.get("ip"),
                        "minutes_back":   5,
                    },
                    daemon=True,
                    name=f"incident-snap-{ev['type']}",
                ).start()
        except Exception as _ic_exc:
            print(f"[anomaly] incident snippet trigger failed: {_ic_exc}")
        # Auto-block confirmed critical threats (port scans inside the network)
        # Never block our own IP — nmap scans from this machine look like port scans
        if ev["level"] == "critical" and ev["type"] == "port_scan" and ev.get("ip"):
            if not _is_this_machine(ev["ip"]):
                _auto_block(ev["ip"], ev["title"])

        # Request immediate rescan on any critical anomaly
        if ev["level"] == "critical":
            from monitoring.state import request_immediate_scan
            request_immediate_scan()

        # Auto-investigate bandwidth anomalies (fire-and-forget HTTP to running server)
        if ev["type"] in ("traffic_spike", "sustained_bandwidth") and ev.get("ip"):
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
