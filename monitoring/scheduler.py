"""
scheduler.py — Background health check loop.

Runs as a long-lived asyncio task inside the FastAPI/uvicorn process.
Periodically calls run_ping() and saves the result to the database.

WHY run_in_executor?
  subprocess.run() (called inside run_ping) is a blocking operation — it
  halts the thread it runs on until ping finishes (~2–5 seconds).
  If we called it directly inside an async function, it would freeze the
  entire asyncio event loop during that time, meaning FastAPI could not
  serve any HTTP requests.

  run_in_executor() runs the blocking function in a separate thread from
  a thread pool. The event loop schedules other work while it waits,
  then resumes when the thread finishes.

WHY re-read settings each interval?
  The user can change the check interval, target, or thresholds via the
  Settings page without restarting the app. Reading from the DB each cycle
  means changes take effect after the current sleep finishes — no restart needed.

RETENTION
  We keep a maximum of 2000 health check rows. Once that's exceeded, we
  delete the oldest half (down to 1000 rows). This keeps the DB small
  while preserving enough history for a useful chart (~3 days at 5-min intervals).
"""

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from app.database import SessionLocal
from models.tables import HealthCheck, Setting, TrafficSummary

# Six worker threads: health checks, traffic analysis, auto-scan, anomaly, commands, reports
_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="netmon")

MAX_ROWS    = 2000   # prune when we exceed this
KEEP_ROWS   = 1000   # keep this many after pruning
STARTUP_DELAY_S = 8  # wait for server to fully start before first check


def _get_str(db, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if (row and row.value is not None) else default


def _get_float(db, key: str, default: float) -> float:
    try:
        return float(_get_str(db, key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_int(db, key: str, default: int) -> int:
    try:
        return int(_get_str(db, key, str(default)))
    except (ValueError, TypeError):
        return default


def _run_and_save() -> None:
    """
    Synchronous: run one health check and persist the result.
    Designed to run inside a ThreadPoolExecutor worker thread.
    """
    # Import here to avoid circular import at module load time
    from monitoring.health import run_ping

    db = SessionLocal()
    try:
        # Read thresholds from settings
        target         = _get_str  (db, "health_target",        "8.8.8.8")
        _auto_gw       = None
        try:
            from network.autodetect import get_network_info
            _auto_gw = get_network_info().get("gateway")
        except Exception:
            pass
        local_target   = _auto_gw or _get_str(db, "health_local_target", "192.168.1.1")
        warn_latency   = _get_float(db, "latency_warn_ms",      100.0)
        crit_latency   = _get_float(db, "latency_crit_ms",      300.0)
        warn_loss      = _get_float(db, "packet_loss_warn_pct", 10.0)

        result = run_ping(
            target=target,
            warn_latency_ms=warn_latency,
            crit_latency_ms=crit_latency,
            warn_loss_pct=warn_loss,
        )

        # Local ping (router) — 2 packets, fast
        local_result = run_ping(target=local_target, count=2,
                                warn_latency_ms=50.0, crit_latency_ms=100.0,
                                warn_loss_pct=50.0)

        hc = HealthCheck(
            status=result["status"],
            latency_ms=result["latency_ms"],
            local_latency_ms=local_result["latency_ms"],
            packet_loss=result["packet_loss"],
            target=result["target"],
            local_target=local_target,
            error=result["error"],
        )
        db.add(hc)
        db.commit()

        # ── Prune old rows ───────────────────────────────────────────────
        count = db.query(HealthCheck).count()
        if count > MAX_ROWS:
            # Find the ID at the KEEP_ROWS-th most-recent row
            cutoff_id = (
                db.query(HealthCheck.id)
                .order_by(HealthCheck.id.desc())
                .offset(KEEP_ROWS - 1)
                .limit(1)
                .scalar()
            )
            if cutoff_id:
                db.query(HealthCheck).filter(HealthCheck.id < cutoff_id).delete()
                db.commit()

        print(
            f"[health] {result['status'].upper():8s} | "
            f"latency={result['latency_ms']}ms | "
            f"loss={result['packet_loss']}%"
        )

    except Exception as e:
        print(f"[health] _run_and_save error: {e}")
    finally:
        db.close()


def _run_traffic_analysis() -> None:
    """
    Synchronous: check capture status, run tshark analysis, save summary.
    Runs in a ThreadPoolExecutor worker — safe to block.
    """
    from traffic.capture import capture_engine, CAPTURE_DIR
    from traffic.analyzer import run_analysis, cleanup_old_captures

    db = SessionLocal()
    try:
        # Check if capture process is still alive (updates DB if it died)
        capture_engine.check_alive(session_factory=SessionLocal)

        # Only analyze when capture is running
        status = capture_engine.get_status()
        if not status["running"]:
            return

        retention = _get_int(db, "capture_retention_days", 3)
        cleanup_old_captures(CAPTURE_DIR, retention)

        result = run_analysis(CAPTURE_DIR)

        import json
        summary = TrafficSummary(
            session_id       = status.get("session_id"),
            total_packets    = result.get("total_packets", 0),
            total_bytes      = result.get("total_bytes", 0),
            files_analyzed   = result.get("files_analyzed", 0),
            top_talkers      = json.dumps(result.get("top_talkers", [])),
            top_destinations = json.dumps(result.get("top_destinations", [])),
            protocol_mix     = json.dumps(result.get("protocol_mix", {})),
            dns_count        = result.get("dns_count", 0),
            top_domains      = json.dumps(result.get("top_domains", [])),
            error            = result.get("error"),
        )
        db.add(summary)
        db.commit()

        pkts = result.get("total_packets", 0)
        dns  = result.get("dns_count", 0)
        err  = result.get("error") or ""
        print(f"[traffic] summary saved — {pkts} pkts, {dns} DNS queries {err}")

        # ── Threat intel sweep on top destinations ────────────────────────
        try:
            from ai.threat_intel import check_ip, is_confirmed_malicious, summary as _ti_summary
            from monitoring.activity import write_log as _wlog
            from monitoring.notifier import alert as _notify
            from monitoring.anomaly import _auto_block

            _PRIVATE = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.", "127.", "169.254.", "0.")
            checked: set = set()
            for dest in result.get("top_destinations", [])[:10]:
                ip = dest.get("ip", "")
                if not ip or ip in checked:
                    continue
                if any(ip.startswith(p) for p in _PRIVATE):
                    continue
                checked.add(ip)
                hits = check_ip(ip)
                if hits and is_confirmed_malicious(hits):
                    desc = _ti_summary(hits)
                    _wlog("threat", "threat", "threat_intel_hit",
                          f"Threat intel hit in traffic: {ip} — {desc}",
                          detail={"ip": ip, "hits": [{"feed": h.feed_name, "severity": h.severity} for h in hits]},
                          device_ip=ip)
                    _notify(
                        title=f"Threat detected: {ip}",
                        body=f"{desc}\nIP {ip} is active on your network.",
                        level="critical",
                    )
                    _auto_block(ip, desc)
        except Exception as _ti_exc:
            print(f"[traffic] Threat intel sweep error: {_ti_exc}")

        # Prune old summaries (keep last 500)
        count = db.query(TrafficSummary).count()
        if count > 500:
            cutoff_id = (
                db.query(TrafficSummary.id)
                .order_by(TrafficSummary.id.desc())
                .offset(499)
                .limit(1)
                .scalar()
            )
            if cutoff_id:
                db.query(TrafficSummary).filter(TrafficSummary.id < cutoff_id).delete()
                db.commit()

    except Exception as e:
        print(f"[traffic] _run_traffic_analysis error: {e}")
    finally:
        db.close()


def _watchdog_capture() -> None:
    """
    If capture_enabled=true but dumpcap is not running (unexpected exit),
    restart it automatically using the saved interface/settings.
    Called every tick of traffic_analysis_loop.
    """
    from traffic.capture import capture_engine
    from app.database import SessionLocal as _SL
    from models.tables import Setting

    db = _SL()
    try:
        def _g(k, d=""):
            row = db.query(Setting).filter(Setting.key == k).first()
            return row.value if (row and row.value) else d

        if _g("capture_enabled") != "true":
            return
        if capture_engine.get_status()["running"]:
            return

        # Capture should be running but isn't — restart it
        interface    = _g("capture_interface", "")
        file_size_mb = int(_g("capture_file_size_mb", "10"))
        file_count   = int(_g("capture_file_count",   "5"))

        if not interface:
            return

        print("[capture] Watchdog: capture died unexpectedly — restarting...")
        result = capture_engine.start(
            interface=interface,
            file_size_mb=file_size_mb,
            file_count=file_count,
            session_factory=_SL,
        )
        print(f"[capture] Watchdog restart result: {result.get('status')}")
    except Exception as e:
        print(f"[capture] Watchdog error: {e}")
    finally:
        db.close()


async def traffic_analysis_loop() -> None:
    """
    Background coroutine: periodically analyzes capture files.
    Also runs a watchdog that auto-restarts capture if it dies unexpectedly.
    """
    loop = asyncio.get_running_loop()
    await asyncio.sleep(5)   # short startup delay

    while True:
        db = SessionLocal()
        try:
            interval_s = _get_int(db, "traffic_summary_interval_s", 20)
        finally:
            db.close()

        # Clamp to sensible range: 10s min, 300s max
        interval_s = max(10, min(interval_s, 300))

        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            print("[traffic] Scheduler cancelled — shutting down.")
            break

        try:
            await loop.run_in_executor(_executor, _watchdog_capture)
            await loop.run_in_executor(_executor, _run_traffic_analysis)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[traffic] Loop error: {e}")


def _run_auto_scan() -> dict:
    """
    Synchronous: run one scheduled nmap scan, persist results, log everything.
    Runs in a ThreadPoolExecutor worker — safe to block.
    Returns a summary dict.

    Strategy:
      1. Fast ping scan (-sn) across the whole subnet — finds all live hosts quickly.
      2. For any newly discovered device, immediately run a targeted full scan
         (-sV) on just that IP to capture open ports and service versions.
    """
    from scanner.runner import run_scan
    from scanner.parser import parse_nmap_xml
    from scanner.diff import compute_diff, build_snapshot
    from models.tables import Scan, Device, ScanDevice, Alert, ChangeEvent
    from monitoring.activity import write_log
    from sqlalchemy import desc

    from monitoring.state import scan_begin, scan_end

    db = SessionLocal()
    try:
        from network.autodetect import get_scan_target
        target = get_scan_target()
    except Exception:
        target = os.getenv("SCAN_TARGET", "").strip()
        if target.lower() in ("", "auto", "autodetect", "detect"):
            target = "192.168.1.0/24"
    started_at = datetime.now(timezone.utc)
    scan = None

    try:
        scan_begin("auto", started_at.isoformat())
        write_log("info", "scan", "scan_started",
                  f"Scheduled network scan started — target: {target}")

        scan = Scan(started_at=started_at, status="running")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Fast host-discovery pass — no port scanning
        xml_output     = run_scan(target, quick=True)
        parsed_devices = parse_nmap_xml(xml_output)

        new_devices   = []
        new_dev_count = 0
        new_ips       = []   # collect IPs that need a deep scan
        for d in parsed_devices:
            from api.routes import _resolve_device
            device, is_new = _resolve_device(db, d)
            if is_new and not device.is_known:
                new_dev_count += 1
                new_ips.append(d["ip"])
                new_devices.append({"ip": d["ip"], "mac": d.get("mac") or "unknown",
                                    "hostname": d.get("hostname") or "", "device_id": device.id})
                db.add(Alert(
                    alert_type="new_device",
                    message=f"New device: {d.get('hostname') or d['ip']} (MAC: {d.get('mac') or 'unknown'})",
                    device_id=device.id,
                ))
                # Notify immediately — nighttime gets critical push
                from monitoring.anomaly import nighttime_device_alert
                from monitoring.notifier import alert as _notify
                nighttime_device_alert(
                    ip=d["ip"], mac=d.get("mac") or "unknown",
                    hostname=d.get("hostname") or "", device_id=device.id,
                )
                # Daytime: still notify but at warning level (not critical)
                from monitoring.anomaly import _is_night
                if not _is_night():
                    _notify(
                        title=f"New device: {d.get('hostname') or d['ip']}",
                        body=(
                            f"An unrecognized device joined your network.\n"
                            f"IP: {d['ip']}  MAC: {d.get('mac') or 'unknown'}"
                        ),
                        level="warning",
                    )
            db.add(ScanDevice(
                scan_id=scan.id, device_id=device.id,
                ip=d["ip"], hostname=d.get("hostname"),
                open_ports=json.dumps(d.get("open_ports", [])),
            ))

        # Deep scan new devices — get their open ports and services.
        # We do this AFTER the quick scan so discovery is never blocked by
        # a slow per-host port scan.
        if new_ips:
            print(f"[auto-scan] {len(new_ips)} new device(s) — running deep scan: {', '.join(new_ips)}")
            try:
                deep_xml     = run_scan(" ".join(new_ips), quick=False)
                deep_devices = parse_nmap_xml(deep_xml)
                deep_map     = {d["ip"]: d for d in deep_devices}
                # Update the ScanDevice rows we just created with real port data
                for sd in db.query(ScanDevice).filter(ScanDevice.scan_id == scan.id).all():
                    if sd.ip in deep_map:
                        sd.open_ports = json.dumps(deep_map[sd.ip].get("open_ports", []))
                        sd.hostname   = deep_map[sd.ip].get("hostname") or sd.hostname
                db.commit()
            except Exception as deep_exc:
                print(f"[auto-scan] deep scan failed (non-fatal): {deep_exc}")

        ended_at  = datetime.now(timezone.utc)
        duration  = (ended_at - started_at).total_seconds()
        scan.ended_at   = ended_at
        scan.duration_s = duration
        scan.host_count = len(parsed_devices)
        scan.status     = "complete"
        db.commit()

        # Diff against previous scan
        prev_scan = (
            db.query(Scan)
            .filter(Scan.status == "complete", Scan.id != scan.id)
            .order_by(desc(Scan.id)).first()
        )
        change_count = 0
        if prev_scan:
            curr_sds = db.query(ScanDevice).filter(ScanDevice.scan_id == scan.id).all()
            changes  = compute_diff(build_snapshot(prev_scan.devices), build_snapshot(curr_sds))
            change_count = len(changes)
            for ch in changes:
                db.add(ChangeEvent(scan_id=scan.id, prev_scan_id=prev_scan.id, **ch))
            db.commit()

        write_log(
            "info", "scan", "scan_completed",
            f"Scan complete — {len(parsed_devices)} device(s), {new_dev_count} new, {change_count} change(s) [{round(duration,1)}s]",
            detail={"scan_id": scan.id, "hosts": len(parsed_devices),
                    "new_devices": new_dev_count, "changes": change_count, "duration_s": round(duration, 1)},
        )

        # Log each new device as its own warning-level entry
        for nd in new_devices:
            write_log(
                "warning", "scan", "device_new",
                f"New device detected: {nd['ip']} (MAC: {nd['mac']}, hostname: {nd['hostname'] or 'none'})",
                detail=nd, device_ip=nd["ip"], device_id=nd["device_id"],
            )

        scan_end(scan.id, len(parsed_devices), new_dev_count, change_count)
        print(f"[auto-scan] {len(parsed_devices)} hosts, {new_dev_count} new, {change_count} changes [{round(duration,1)}s]")
        return {"hosts": len(parsed_devices), "new": new_dev_count, "changes": change_count}

    except Exception as exc:
        msg = str(exc)
        if scan:
            try:
                scan.status = "failed"
                scan.error  = msg
                db.commit()
            except Exception:
                pass
        scan_end(scan.id if scan else 0, error=msg)
        write_log("warning", "scan", "scan_failed", f"Scheduled scan failed: {msg}")
        print(f"[auto-scan] scan failed: {exc}")
        return {"error": msg}
    finally:
        db.close()


async def auto_scan_loop() -> None:
    """
    Background coroutine: runs a network scan every N hours.
    Interval is controlled by the 'auto_scan_interval_h' setting (default 4).
    Can be disabled with 'auto_scan_enabled = false'.
    """
    loop = asyncio.get_running_loop()

    # Wait for the rest of startup before the first scan
    await asyncio.sleep(30)

    # Only run a startup scan if no recent scan exists within the configured interval
    db = SessionLocal()
    try:
        from models.tables import Scan
        from sqlalchemy import desc as _desc
        enabled    = _get_str(db, "auto_scan_enabled", "true").lower()
        interval_h = _get_float(db, "auto_scan_interval_h", 1.0)
        last_scan  = (
            db.query(Scan)
            .filter(Scan.status == "complete")
            .order_by(_desc(Scan.ended_at))
            .first()
        )
    finally:
        db.close()

    if enabled == "true":
        age_h = None
        if last_scan and last_scan.ended_at:
            ended = last_scan.ended_at
            if ended.tzinfo is None:
                ended = ended.replace(tzinfo=timezone.utc)
            age_h = (datetime.now(timezone.utc) - ended).total_seconds() / 3600

        if age_h is None or age_h >= interval_h:
            print(f"[auto-scan] startup scan (last was {f'{age_h:.1f}h ago' if age_h is not None else 'never'})")
            try:
                await loop.run_in_executor(_executor, _run_auto_scan)
            except Exception as exc:
                print(f"[auto-scan] initial scan error: {exc}")
        else:
            print(f"[auto-scan] skipping startup scan — last ran {age_h:.1f}h ago (interval={interval_h}h)")

    while True:
        db = SessionLocal()
        try:
            enabled    = _get_str(db, "auto_scan_enabled",    "true").lower()
            interval_h = _get_float(db, "auto_scan_interval_h", 1.0)  # 1 hour default
        finally:
            db.close()

        interval_s = max(300, interval_h * 3600)   # floor at 5 minutes

        # Poll every 60 s within the interval — break early on immediate scan request
        elapsed = 0
        scan_requested = False
        while elapsed < interval_s:
            chunk = min(60, interval_s - elapsed)
            try:
                await asyncio.sleep(chunk)
            except asyncio.CancelledError:
                print("[auto-scan] Scheduler cancelled — shutting down.")
                return
            elapsed += chunk
            from monitoring.state import consume_scan_request
            if consume_scan_request():
                print("[auto-scan] Immediate scan triggered by anomaly detection")
                scan_requested = True
                break

        if enabled != "true":
            continue

        try:
            await loop.run_in_executor(_executor, _run_auto_scan)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[auto-scan] Loop error: {exc}")
            await asyncio.sleep(60)


async def health_check_loop() -> None:
    """
    Main background coroutine. Runs indefinitely until the app shuts down.

    Called once via asyncio.create_task() in main.py's lifespan handler.
    Cancellation (on shutdown) is handled via asyncio.CancelledError.
    """
    loop = asyncio.get_running_loop()

    # Brief startup delay — let uvicorn, routes, and DB finish initialising
    await asyncio.sleep(STARTUP_DELAY_S)

    # Run an immediate check so the dashboard has data right away
    try:
        await loop.run_in_executor(_executor, _run_and_save)
    except Exception as e:
        print(f"[health] Initial check failed: {e}")

    while True:
        # Re-read interval each cycle so settings changes take effect
        db = SessionLocal()
        try:
            interval_s = _get_int(db, "health_check_interval_s", 300)
        finally:
            db.close()

        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            print("[health] Scheduler cancelled — shutting down.")
            break

        try:
            await loop.run_in_executor(_executor, _run_and_save)
        except asyncio.CancelledError:
            print("[health] Scheduler cancelled during check — shutting down.")
            break
        except Exception as e:
            print(f"[health] Scheduled check failed: {e}")
            # Back off briefly on error to avoid hammering the system
            await asyncio.sleep(30)


# ── Anomaly detection loop ────────────────────────────────────────────────────

def _run_anomaly_checks() -> None:
    """Synchronous wrapper — runs in ThreadPoolExecutor."""
    from monitoring.anomaly import run_anomaly_checks
    run_anomaly_checks()


async def anomaly_loop() -> None:
    """
    Background coroutine: runs behavioral anomaly checks every 60 seconds.
    Detects traffic spikes, port scans, sustained outages.
    """
    loop = asyncio.get_running_loop()
    await asyncio.sleep(20)   # let other startup tasks settle first

    while True:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            print("[anomaly] Scheduler cancelled — shutting down.")
            break

        try:
            await loop.run_in_executor(_executor, _run_anomaly_checks)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[anomaly] Loop error: {exc}")


# ── ntfy command poll loop ────────────────────────────────────────────────────

def _poll_and_execute_commands() -> None:
    """
    Synchronous: check ntfy reply topic for pending commands and execute them.
    Runs in ThreadPoolExecutor every 60 seconds.
    """
    from monitoring.notifier import poll_commands
    from monitoring.activity import write_log

    commands = poll_commands()
    for raw in commands:
        cmd = raw.strip().lower()
        print(f"[command] Received: {raw!r}")
        _execute_command(cmd, raw)


def _execute_command(cmd: str, raw: str) -> None:
    """Parse and execute a single command string."""
    from monitoring.activity import write_log
    import subprocess
    from traffic.interfaces import _no_window
    from monitoring.notifier import alert as _notify

    try:
        if cmd.startswith("block "):
            ip = cmd[6:].strip()
            rule = f"NetMon-RemoteBlock-{ip}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule}", "dir=out", "action=block",
                 f"remoteip={ip}", "enable=yes", "profile=any"],
                check=True, capture_output=True, text=True,
                creationflags=_no_window(),
            )
            write_log("action", "firewall", "remote_block",
                      f"Remote command: blocked {ip}", device_ip=ip,
                      actor="ntfy_command",
                      revert={"action_type": "unblock_by_rule_names",
                              "params": {"rule_names": [rule], "ip": ip}})
            _notify(f"Blocked {ip}", f"Outbound traffic from your network to {ip} is now blocked.", level="action")

        elif cmd.startswith("block-all "):
            ip = cmd[10:].strip()
            created_rules: list[str] = []
            for direction in ("out", "in"):
                rule = f"NetMon-RemoteBlock-{direction}-{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule}", f"dir={direction}", "action=block",
                     f"remoteip={ip}", "enable=yes", "profile=any"],
                    check=True, capture_output=True, text=True,
                    creationflags=_no_window(),
                )
                created_rules.append(rule)
            write_log("action", "firewall", "remote_block_all",
                      f"Remote command: blocked all traffic {ip}", device_ip=ip,
                      actor="ntfy_command",
                      revert={"action_type": "unblock_by_rule_names",
                              "params": {"rule_names": created_rules, "ip": ip}})
            _notify(f"Fully blocked {ip}", f"All inbound and outbound traffic to {ip} is now blocked.", level="action")

        elif cmd.startswith("unblock "):
            ip = cmd[8:].strip()
            for suffix in ("", "-out", "-in", f"-out-{ip}", f"-in-{ip}"):
                rule = f"NetMon-RemoteBlock{suffix}-{ip}" if suffix.startswith("-") else f"NetMon-RemoteBlock-{ip}"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                    capture_output=True, text=True,
                    creationflags=_no_window(),
                )
            write_log("action", "firewall", "remote_unblock",
                      f"Remote command: unblocked {ip}", device_ip=ip)
            _notify(f"Unblocked {ip}", f"Firewall rules for {ip} have been removed.", level="action")

        elif cmd.startswith("investigate "):
            ip = cmd[12:].strip()
            # Signal the AI investigation queue — trigger via HTTP to the running server
            # (avoids importing routes here and creating circular deps)
            import urllib.request, json as _json
            payload = _json.dumps({"target": ip, "source": "remote_command"}).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:8000/api/ai/investigate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Fire-and-forget (no auth needed from localhost in most setups)
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass   # investigation queued via state flag instead
            write_log("action", "ai", "remote_investigate",
                      f"Remote command: investigate {ip}", device_ip=ip)

        elif cmd == "scan":
            # Schedule an immediate scan on the next anomaly cycle
            from monitoring.state import scan_state
            if not scan_state["running"]:
                from concurrent.futures import ThreadPoolExecutor as _TPE
                import threading
                threading.Thread(target=_run_auto_scan, daemon=True, name="remote-scan").start()
                write_log("action", "scan", "remote_scan", "Remote command: immediate scan triggered")
                _notify("Scan started", "Network scan triggered by remote command.", level="info")

        elif cmd.startswith("dismiss"):
            # Just acknowledge — alert dismissal requires knowing the alert ID
            write_log("info", "alert", "remote_dismiss", f"Remote dismiss command received: {raw}")

        else:
            print(f"[command] Unknown command: {raw!r}")

    except Exception as exc:
        print(f"[command] Execute error for {raw!r}: {exc}")
        write_log("warning", "system", "command_error",
                  f"Failed to execute remote command: {raw}", detail={"error": str(exc)})


async def command_poll_loop() -> None:
    """
    Background coroutine: poll ntfy reply topic for remote commands every 60 s.
    Two-way control: user taps action button in ntfy app → NetMon executes.
    """
    loop = asyncio.get_running_loop()
    await asyncio.sleep(25)   # stagger relative to anomaly loop

    while True:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            print("[command] Poll loop cancelled — shutting down.")
            break

        try:
            await loop.run_in_executor(_executor, _poll_and_execute_commands)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[command] Poll loop error: {exc}")


# ── Autonomous security report loop ───────────────────────────────────────────

def _run_autonomous_report() -> None:
    """
    Synchronous: ask Qwen to analyze the last hour of network activity.
    Saves a SecurityReport row with headline, body, anomalies, and recommendations.
    Runs in ThreadPoolExecutor — safe to block.
    """
    from models.tables import SecurityReport, TrafficSummary, HealthCheck, ActivityLog, Setting
    from monitoring.activity import write_log as _wlog

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    try:
        # Respect both ai_enabled and auto_report_enabled settings
        def _s(key, default="false"):
            row = db.query(Setting).filter(Setting.key == key).first()
            return row.value if (row and row.value is not None) else default

        if _s("ai_enabled") != "true":
            return
        if _s("auto_report_enabled", "true") != "true":
            return

        # Gather last-hour data ────────────────────────────────────────────
        traffic_rows = (
            db.query(TrafficSummary)
            .filter(TrafficSummary.created_at >= one_hour_ago)
            .order_by(TrafficSummary.id.desc())
            .limit(10)
            .all()
        )
        health_rows = (
            db.query(HealthCheck)
            .filter(HealthCheck.checked_at >= one_hour_ago)
            .order_by(HealthCheck.id.desc())
            .limit(12)
            .all()
        )
        log_rows = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.created_at >= one_hour_ago,
                ActivityLog.level.in_(["warning", "critical", "action", "threat"]),
            )
            .order_by(ActivityLog.id.desc())
            .limit(20)
            .all()
        )

        # Build compact context for the prompt
        traffic_ctx = []
        for t in traffic_rows[:3]:
            try:
                traffic_ctx.append({
                    "total_packets": t.total_packets,
                    "total_bytes_mb": round((t.total_bytes or 0) / 1_048_576, 1),
                    "top_talkers":      json.loads(t.top_talkers or "[]")[:5],
                    "top_destinations": json.loads(t.top_destinations or "[]")[:5],
                    "top_domains":      json.loads(t.top_domains or "[]")[:8],
                })
            except Exception:
                pass

        health_ctx = [
            {"status": h.status, "latency_ms": h.latency_ms, "packet_loss": h.packet_loss}
            for h in health_rows
        ]
        log_ctx = [
            {"level": l.level, "category": l.category, "event": l.event, "summary": l.summary}
            for l in log_rows
        ]
        dns_blocked = [l for l in log_rows if l.category == "dns" and l.event == "dns_blocked"]
        non_dns_security = [l for l in log_rows if l.category != "dns"]
        confirmed_threats = [
            l for l in log_rows
            if l.level == "threat" or l.event in ("threat_intel_hit", "malware_domain", "c2_detected")
        ]

        context = json.dumps({
            "period": f"{one_hour_ago.strftime('%Y-%m-%d %H:%M')} – {now.strftime('%H:%M')} UTC",
            "traffic_samples": traffic_ctx,
            "health_samples":  health_ctx,
            "security_events": log_ctx,
            "dns_blocking_context": {
                "enabled_by_user": _s("dns_blocker_enabled", "false") == "true",
                "purpose": "NetMon intentionally blocks ad, tracker, telemetry, and malware-list domains at DNS level.",
                "blocked_event_count": len(dns_blocked),
                "standalone_dns_blocks_are_expected": True,
            },
            "corroboration": {
                "non_dns_security_event_count": len(non_dns_security),
                "confirmed_threat_event_count": len(confirmed_threats),
            },
        }, indent=2)

        prompt = (
            "You are an autonomous network security analyst for a home network.\n\n"
            "Analyze this 1-hour network snapshot and write a brief security report.\n\n"
            "Important DNS rule:\n"
            "- DNS blocked events are expected when NetMon's DNS ad blocker is enabled.\n"
            "- A blocked DNS query by itself means the blocker worked; do NOT call it malware, a security threat, or an infection.\n"
            "- Treat DNS blocks as benign filtering/noise unless corroborated by confirmed threat-intel hits, unknown devices, repeated unusual traffic to the same suspicious destination, or non-DNS critical events.\n"
            "- For normal DNS blocking, recommendations should be quiet operational suggestions such as reviewing top blocked domains or lowering notification priority, not virus scans or new security products.\n\n"
            f"Data:\n{context}\n\n"
            "Respond with ONLY valid JSON (no markdown) containing:\n"
            '  "severity": "low"|"medium"|"high"|"critical"\n'
            '  "headline": one sentence, max 100 chars\n'
            '  "body": 2-3 paragraphs (traffic summary, health, any threats)\n'
            '  "anomalies": [] or array of specific anomaly strings found\n'
            '  "recommendations": 1-3 short actionable strings\n\n'
            "Be concise and plain-English. No markdown in body text."
        )

        from ai.provider import get_provider
        provider = get_provider()
        ai_result = provider.analyze({}, prompt=prompt, kind="report")

        if ai_result.get("error"):
            raise ValueError(f"AI error: {ai_result['error']}")

        raw = ai_result.get("raw_response") or ""

        # Extract JSON from response
        import re
        match = re.search(r'\{[\s\S]*\}', raw)
        if not match:
            raise ValueError(f"No JSON in AI response: {raw[:200]}")
        data = json.loads(match.group(0))

        # Deterministic guardrail: if the only notable events were DNS blocks,
        # do not let the model turn expected ad/tracker blocking into malware.
        only_dns_noise = bool(dns_blocked) and not non_dns_security and not confirmed_threats
        if only_dns_noise:
            sev = (data.get("severity") or "low").lower()
            if sev not in ("low", "medium", "high", "critical"):
                sev = "low"
            data["severity"] = "low" if sev in ("medium", "high", "critical") else sev

            anomalies = data.get("anomalies") or []
            data["anomalies"] = [
                a for a in anomalies
                if "dns blocked" not in str(a).lower()
                and "malware" not in str(a).lower()
                and "virus" not in str(a).lower()
            ]

            body = data.get("body") or ""
            scary = ("malware", "infected", "infection", "virus", "security threats")
            if any(word in body.lower() for word in scary):
                data["body"] = (
                    "Network health was stable during this snapshot. NetMon recorded DNS blocked events, "
                    "which is expected when the DNS ad blocker is intentionally filtering ads, trackers, "
                    "and telemetry domains. No corroborating threat-intel hits or non-DNS critical events "
                    "were present in this report window."
                )
            data["recommendations"] = [
                "Treat routine DNS blocked entries as ad/tracker filtering noise.",
                "Review top blocked domains only if one device suddenly becomes unusually noisy.",
            ]

        report = SecurityReport(
            report_type      = "hourly",
            period_start     = one_hour_ago,
            period_end       = now,
            severity         = data.get("severity", "low"),
            headline         = (data.get("headline") or "")[:200],
            body             = data.get("body") or "",
            anomalies        = json.dumps(data.get("anomalies", [])),
            recommendations  = json.dumps(data.get("recommendations", [])),
            model            = ai_result.get("model") or getattr(provider, "_fast_model", None) or provider.name,
        )
        db.add(report)
        db.commit()

        # Prune: keep last 168 reports (1 week hourly)
        count = db.query(SecurityReport).count()
        if count > 168:
            cutoff = (
                db.query(SecurityReport.id)
                .order_by(SecurityReport.id.desc())
                .offset(167)
                .limit(1)
                .scalar()
            )
            if cutoff:
                db.query(SecurityReport).filter(SecurityReport.id < cutoff).delete()
                db.commit()

        sev = data.get("severity", "low")
        hl  = data.get("headline", "")
        print(f"[report] Hourly report: [{sev.upper()}] {hl}")
        _wlog("info", "ai", "security_report", f"Autonomous report: [{sev.upper()}] {hl}")

    except Exception as exc:
        print(f"[report] Autonomous report error: {exc}")
        try:
            db.add(SecurityReport(
                report_type="hourly", period_start=one_hour_ago, period_end=now,
                error=str(exc),
            ))
            db.commit()
        except Exception:
            pass
    finally:
        db.close()


def _run_log_cleanup() -> None:
    """
    Delete old ActivityLog entries to keep storage under control.
    Runs daily.
      - DNS blocked entries: keep 7 days  (high volume, low long-term value)
      - All other entries:   keep 30 days
    """
    from models.tables import ActivityLog

    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        # DNS entries older than 7 days
        dns_cutoff = now - timedelta(days=7)
        dns_deleted = db.query(ActivityLog).filter(
            ActivityLog.category == "dns",
            ActivityLog.created_at < dns_cutoff,
        ).delete(synchronize_session=False)

        # All other entries older than 30 days
        gen_cutoff = now - timedelta(days=30)
        gen_deleted = db.query(ActivityLog).filter(
            ActivityLog.category != "dns",
            ActivityLog.created_at < gen_cutoff,
        ).delete(synchronize_session=False)

        db.commit()
        if dns_deleted or gen_deleted:
            print(f"[cleanup] Pruned logs: {dns_deleted} DNS entries (>7d), {gen_deleted} general entries (>30d)")
    except Exception as exc:
        print(f"[cleanup] Log cleanup error: {exc}")
    finally:
        db.close()


async def log_cleanup_loop() -> None:
    """Run log cleanup once daily."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(3600)   # first run after 1 hour

    while True:
        try:
            await loop.run_in_executor(_executor, _run_log_cleanup)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[cleanup] Loop error: {exc}")

        try:
            await asyncio.sleep(86400)   # daily
        except asyncio.CancelledError:
            print("[cleanup] Cleanup loop cancelled — shutting down.")
            break


async def autonomous_report_loop() -> None:
    """
    Background coroutine: runs Qwen security analysis every hour.
    First report fires after the server has been running for one hour.
    Skipped silently if ai_enabled=false or auto_report_enabled=false.
    """
    loop = asyncio.get_running_loop()
    await asyncio.sleep(3600)   # first report after 1 hour uptime

    while True:
        try:
            await loop.run_in_executor(_executor, _run_autonomous_report)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[report] Loop error: {exc}")

        try:
            await asyncio.sleep(3600)   # hourly
        except asyncio.CancelledError:
            print("[report] Report loop cancelled — shutting down.")
            break
