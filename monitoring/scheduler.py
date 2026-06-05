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
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from app.database import SessionLocal
from models.tables import HealthCheck, Setting, TrafficSummary

# Worker threads — sized so a slow port-refresh or SSL-cert deep scan can run
# without blocking any other loop. Loops: health, traffic, auto-scan, anomaly,
# command-poll, autonomous-report, log-cleanup, dns-health, port-refresh,
# ssl-cert, doh-leak, deep-scan-ai, hunt = 13 active loops.
_executor = ThreadPoolExecutor(max_workers=15, thread_name_prefix="netmon")

MAX_ROWS    = 2000   # prune when we exceed this
KEEP_ROWS   = 1000   # keep this many after pruning
STARTUP_DELAY_S = 8  # wait for server to fully start before first check
AI_HUB_MAINTENANCE_FILE = Path(os.environ.get(
    "AI_HUB_MAINTENANCE_FILE",
    r"C:\Users\lock_\AppData\Local\AI-Hub\service_maintenance.json",
))


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


def _netmon_enabled(db) -> bool:
    if _get_str(db, "netmon_enabled", "true").lower() != "true":
        return False
    try:
        data = json.loads(AI_HUB_MAINTENANCE_FILE.read_text(encoding="utf-8"))
        entry = (data.get("services") or {}).get("netmon") or {}
        if entry.get("disabled"):
            return False
    except Exception:
        pass
    return True


def _run_and_save() -> None:
    """
    Synchronous: run one health check and persist the result.
    Designed to run inside a ThreadPoolExecutor worker thread.
    """
    # Import here to avoid circular import at module load time
    from monitoring.health import run_ping

    db = SessionLocal()
    try:
        if not _netmon_enabled(db):
            return
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
        from monitoring.uptime_stats import record_health_check
        record_health_check(db, result["status"])
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

        # ── Geo-anomaly sweep (Phase 2) ───────────────────────────────────
        # For each src↔dst conversation, look up the country of the external
        # IP. If the LAN device has NEVER reached this country before, fire
        # a `geo_anomaly` warning. Per-device history accumulates so it
        # self-trains over time.
        try:
            from network.geo import country_for_ip, is_unusual_destination, record_device_country
            from monitoring.activity import write_log as _wlog
            from models.tables import Device, ScanDevice

            conv_geo_warnings = 0
            for conv in result.get("conversations", [])[:30]:
                src = conv.get("src") or ""
                dst = conv.get("dst") or ""
                if not src or not dst:
                    continue
                # src should be LAN; dst external. Skip when not.
                if any(dst.startswith(p) for p in _PRIVATE):
                    continue
                cc = country_for_ip(dst)
                if not cc:
                    continue
                # Resolve the LAN-side device by latest ScanDevice ip.
                sd = (
                    db.query(ScanDevice).join(Device)
                    .filter(ScanDevice.ip == src)
                    .order_by(ScanDevice.id.desc()).first()
                )
                if not sd or not sd.device_id:
                    continue
                if is_unusual_destination(sd.device_id, cc, db):
                    # Honor per-device allow_json.allowed_countries if set.
                    allow_cc = set()
                    try:
                        allow_cc = set((json.loads(sd.device.allow_json or "{}") or {}).get("allowed_countries", []))
                    except Exception:
                        pass
                    if cc not in allow_cc:
                        _wlog(
                            "warning", "traffic", "geo_anomaly",
                            f"Device {src} contacted a NEW country ({cc}) — first time we've seen this.",
                            detail={
                                "src": src, "dst": dst, "country": cc,
                                "device_id": sd.device_id,
                                "bytes": conv.get("bytes", 0),
                            },
                            device_ip=src, device_id=sd.device_id,
                            actor="anomaly_auto",
                        )
                        conv_geo_warnings += 1
                record_device_country(sd.device_id, cc, db, bytes_added=int(conv.get("bytes", 0)))
            if conv_geo_warnings:
                db.commit()
                print(f"[traffic] geo: {conv_geo_warnings} unusual-country event(s)")
            else:
                db.commit()
        except Exception as _geo_exc:
            print(f"[traffic] Geo sweep error: {_geo_exc}")

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
    from scanner.presence import window_scan_ids, window_snapshot
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
                # `is_new` from _resolve_device means we created a new Device
                # row in the DB — i.e. we've literally never seen this MAC
                # before. This is the only case that warrants a push under the
                # new policy.
                new_dev_count += 1
                new_ips.append(d["ip"])
                new_devices.append({"ip": d["ip"], "mac": d.get("mac") or "unknown",
                                    "hostname": d.get("hostname") or "", "device_id": device.id})
                db.add(Alert(
                    alert_type="new_device",
                    message=f"New device: {d.get('hostname') or d['ip']} (MAC: {d.get('mac') or 'unknown'})",
                    device_id=device.id,
                ))
                # Truly-new MAC notification policy:
                #   • Day  → warning level, but force_push=True so it goes
                #            through regardless of the user's ntfy_min_level
                #            (previously these silently dropped on default min=critical).
                #   • Night → critical level + force_push for higher phone priority.
                # Returning known MACs do NOT push — they just log in the dashboard.
                # Suspicious activity from any device is handled by the anomaly loop.
                from monitoring.anomaly import _is_night
                from monitoring.notifier import alert as _notify, investigate_action, dismiss_action
                is_night = _is_night()
                _notify(
                    title=("NEW DEVICE (overnight): " if is_night else "New device: ")
                          + (d.get("hostname") or d["ip"]),
                    body=(
                        f"A MAC we've never seen before joined your network.\n"
                        f"IP: {d['ip']}\n"
                        f"MAC: {d.get('mac') or 'unknown'}\n"
                        f"Hostname: {d.get('hostname') or '(none)'}\n"
                        + ("This is overnight — review carefully." if is_night else "")
                    ),
                    level="critical" if is_night else "warning",
                    actions=[investigate_action(d["ip"]), dismiss_action()],
                    force_push=True,
                )
            # Quick scans (-sn) return no port data. Carry forward the last
            # known ports for this device so the ScanDevice row reflects the
            # best-known state instead of clobbering it with []. The downstream
            # /api/devices view uses this — without the carry-forward every
            # device shows "0 open ports" between deep scans.
            quick_ports = d.get("open_ports") or []
            if not quick_ports:
                last_known = (
                    db.query(ScanDevice)
                    .filter(
                        ScanDevice.device_id == device.id,
                        ScanDevice.open_ports.notin_(["[]", ""]),
                        ScanDevice.open_ports.isnot(None),
                    )
                    .order_by(desc(ScanDevice.id))
                    .first()
                )
                if last_known:
                    try:
                        quick_ports = json.loads(last_known.open_ports or "[]")
                    except Exception:
                        quick_ports = []
            db.add(ScanDevice(
                scan_id=scan.id, device_id=device.id,
                ip=d["ip"], hostname=d.get("hostname"),
                open_ports=json.dumps(quick_ports),
            ))

        # Deep scan new devices — get their open ports and services.
        # We do this AFTER the quick scan so discovery is never blocked by
        # a slow per-host port scan.
        new_web_devices: list[dict] = []  # collected for auto-Nikto trigger (Phase 3)
        if new_ips:
            print(f"[auto-scan] {len(new_ips)} new device(s) — running deep scan: {', '.join(new_ips)}")
            try:
                deep_xml     = run_scan(" ".join(new_ips), quick=False)
                deep_devices = parse_nmap_xml(deep_xml)
                deep_map     = {d["ip"]: d for d in deep_devices}
                # Update the ScanDevice rows we just created with real port data
                for sd in db.query(ScanDevice).filter(ScanDevice.scan_id == scan.id).all():
                    if sd.ip in deep_map:
                        port_list = deep_map[sd.ip].get("open_ports", [])
                        sd.open_ports = json.dumps(port_list)
                        sd.hostname   = deep_map[sd.ip].get("hostname") or sd.hostname
                        # Freeze the deep-scan ports as the device's known baseline.
                        # _run_periodic_port_refresh() does the same for known devices.
                        dev = db.query(Device).filter(Device.id == sd.device_id).first()
                        if dev:
                            dev.known_ports_json = json.dumps(sorted(
                                int(p) if isinstance(p, int) else p.get("port")
                                for p in port_list
                                if isinstance(p, int) or (isinstance(p, dict) and p.get("port"))
                            ))
                            dev.baseline_set_at = datetime.now(timezone.utc)
                        # Collect web-port devices for the Phase 3 auto-Nikto hook.
                        web_ports = {80, 443, 8080, 8443, 8000, 8888, 5000}
                        device_ports = {
                            int(p) if isinstance(p, int) else p.get("port")
                            for p in port_list
                            if isinstance(p, int) or isinstance(p, dict)
                        }
                        if device_ports & web_ports:
                            new_web_devices.append({
                                "ip": sd.ip,
                                "device_id": sd.device_id,
                                "web_ports": sorted(device_ports & web_ports),
                            })
                db.commit()
            except Exception as deep_exc:
                print(f"[auto-scan] deep scan failed (non-fatal): {deep_exc}")

        # Fire auto-Nikto on any new web-port devices the deep scan turned up.
        # Throttled inside _auto_nikto_enqueue.
        try:
            _auto_nikto_enqueue(new_web_devices)
        except Exception as _nik_exc:
            print(f"[auto-nikto] orchestration error: {_nik_exc}")

        ended_at  = datetime.now(timezone.utc)
        duration  = (ended_at - started_at).total_seconds()
        scan.ended_at   = ended_at
        scan.duration_s = duration
        scan.host_count = len(parsed_devices)
        scan.status     = "complete"
        db.commit()

        # Diff against the previous scan — but over merged windows, not single
        # scans, so quick/full alternation doesn't spam spurious change events.
        # The current window includes this scan; the previous window is anchored
        # at prev_scan so the new scan can't leak into it.
        prev_scan = (
            db.query(Scan)
            .filter(Scan.status == "complete", Scan.id != scan.id)
            .order_by(desc(Scan.id)).first()
        )
        change_count = 0
        if prev_scan:
            changes = compute_diff(
                window_snapshot(db, window_scan_ids(db, prev_scan)),
                window_snapshot(db, window_scan_ids(db, scan)),
            )
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
        netmon_on  = _netmon_enabled(db)
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

    if netmon_on and enabled == "true":
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
            netmon_on  = _netmon_enabled(db)
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

        if not netmon_on or enabled != "true":
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
            netmon_on = _netmon_enabled(db)
        finally:
            db.close()

        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            print("[health] Scheduler cancelled — shutting down.")
            break

        if not netmon_on:
            continue

        try:
            await loop.run_in_executor(_executor, _run_and_save)
        except asyncio.CancelledError:
            print("[health] Scheduler cancelled during check — shutting down.")
            break
        except Exception as e:
            print(f"[health] Scheduled check failed: {e}")
            # Back off briefly on error to avoid hammering the system
            await asyncio.sleep(30)


# ── Uptime Guardian (auto-heal) loop ──────────────────────────────────────────

def _run_autoheal_cycle() -> None:
    """Synchronous wrapper — runs one auto-heal cycle in a worker thread."""
    db = SessionLocal()
    try:
        if not _netmon_enabled(db):
            return
    finally:
        db.close()
    from monitoring.autoheal import run_cycle
    run_cycle()


async def autoheal_loop() -> None:
    """
    Background coroutine: detects sustained internet outages and (when enabled)
    reboots the router to restore connectivity. Runs frequently so outages are
    caught quickly; the cycle itself is a no-op cost when the feature is off.
    """
    loop = asyncio.get_running_loop()
    await asyncio.sleep(STARTUP_DELAY_S + 4)   # settle after health loop's first run

    while True:
        db = SessionLocal()
        try:
            interval_s = _get_int(db, "autoheal_interval_s", 30)
        finally:
            db.close()

        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            print("[autoheal] Scheduler cancelled — shutting down.")
            break

        try:
            await loop.run_in_executor(_executor, _run_autoheal_cycle)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[autoheal] Loop error: {exc}")
            await asyncio.sleep(30)


# ── Anomaly detection loop ────────────────────────────────────────────────────

def _run_anomaly_checks() -> None:
    """Synchronous wrapper — runs in ThreadPoolExecutor."""
    db = SessionLocal()
    try:
        if not _netmon_enabled(db):
            return
    finally:
        db.close()
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
    from network.protection import validate_block_target

    try:
        if cmd.startswith("block "):
            ip = cmd[6:].strip()
            try:
                ip = validate_block_target(ip)
            except ValueError as exc:
                write_log("warning", "firewall", "remote_block_refused",
                          f"Remote block refused for {ip}: {exc}", device_ip=ip,
                          actor="ntfy_command")
                _notify("Block refused", f"NetMon refused to block {ip}: {exc}", level="warning")
                return
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
            try:
                ip = validate_block_target(ip)
            except ValueError as exc:
                write_log("warning", "firewall", "remote_block_refused",
                          f"Remote block-all refused for {ip}: {exc}", device_ip=ip,
                          actor="ntfy_command")
                _notify("Block refused", f"NetMon refused to block-all {ip}: {exc}", level="warning")
                return
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
    Ask the AI chain to analyze the last 2 hours of network activity and save
    a SecurityReport row. Token-conscious behavior:

      • Skip the LLM entirely when the window had zero warning/critical/threat/
        action events — write a tiny deterministic "all quiet" SecurityReport
        instead so the dashboard still shows the loop is alive.
      • Force one real LLM-backed report at least every 24h regardless of
        activity, so quiet stretches still produce a periodic summary.
    """
    from models.tables import SecurityReport, TrafficSummary, HealthCheck, ActivityLog, Setting
    from monitoring.activity import write_log as _wlog
    from sqlalchemy import desc as _desc

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=2)

    try:
        # Respect both ai_enabled and auto_report_enabled settings
        def _s(key, default="false"):
            row = db.query(Setting).filter(Setting.key == key).first()
            return row.value if (row and row.value is not None) else default

        if _s("ai_enabled") != "true":
            return
        if _s("auto_report_enabled", "true") != "true":
            return

        # ── Skip-gate: count meaningful events in the window. ─────────────
        event_count = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.created_at >= window_start,
                ActivityLog.level.in_(["warning", "critical", "action", "threat"]),
            )
            .count()
        )

        # Force a heartbeat LLM report if it's been > 24h since the last
        # real (non-skipped) report. Skipped reports have report_type
        # "hourly_skip" so we can tell them apart.
        last_real = (
            db.query(SecurityReport)
            .filter(SecurityReport.report_type == "hourly")
            .order_by(_desc(SecurityReport.id))
            .first()
        )
        last_real_age_h = None
        if last_real and last_real.period_end:
            end = last_real.period_end
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            last_real_age_h = (now - end).total_seconds() / 3600.0

        force_heartbeat = last_real_age_h is None or last_real_age_h >= 24.0

        if event_count == 0 and not force_heartbeat:
            # All quiet — skip the LLM, write a cheap deterministic row.
            db.add(SecurityReport(
                report_type="hourly_skip",
                period_start=window_start,
                period_end=now,
                severity="low",
                headline="All quiet — no warning/critical events in the last 2 hours.",
                body="Skipped LLM analysis to conserve tokens; deterministic monitors (anomaly, dns_health, threat intel) reported nothing actionable in this window.",
                anomalies=json.dumps([]),
                recommendations=json.dumps([]),
                model="skip-gate",
            ))
            db.commit()
            print(f"[report] Quiet window — LLM skipped (last real report {last_real_age_h:.1f}h ago)" if last_real_age_h is not None else "[report] Quiet window — LLM skipped")
            return

        # Gather last-2h data ──────────────────────────────────────────────
        traffic_rows = (
            db.query(TrafficSummary)
            .filter(TrafficSummary.created_at >= window_start)
            .order_by(TrafficSummary.id.desc())
            .limit(10)
            .all()
        )
        health_rows = (
            db.query(HealthCheck)
            .filter(HealthCheck.checked_at >= window_start)
            .order_by(HealthCheck.id.desc())
            .limit(12)
            .all()
        )
        log_rows = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.created_at >= window_start,
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
            "period": f"{window_start.strftime('%Y-%m-%d %H:%M')} – {now.strftime('%H:%M')} UTC",
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
            "Analyze this 2-hour network snapshot and write a brief security report.\n\n"
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
            period_start     = window_start,
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

        # Prune: keep last 200 reports (covers >2 weeks at 2h cadence,
        # plus any "hourly_skip" rows mixed in).
        count = db.query(SecurityReport).count()
        if count > 200:
            cutoff = (
                db.query(SecurityReport.id)
                .order_by(SecurityReport.id.desc())
                .offset(199)
                .limit(1)
                .scalar()
            )
            if cutoff:
                db.query(SecurityReport).filter(SecurityReport.id < cutoff).delete()
                db.commit()

        sev = data.get("severity", "low")
        hl  = data.get("headline", "")
        tag = "Forced 24h heartbeat" if force_heartbeat and event_count == 0 else "Autonomous report"
        print(f"[report] {tag}: [{sev.upper()}] {hl}")
        _wlog("info", "ai", "security_report", f"{tag}: [{sev.upper()}] {hl}")

    except Exception as exc:
        print(f"[report] Autonomous report error: {exc}")
        try:
            db.add(SecurityReport(
                report_type="hourly", period_start=window_start, period_end=now,
                error=str(exc),
            ))
            db.commit()
        except Exception:
            pass
    finally:
        db.close()


# ── DNS health monitoring loop ────────────────────────────────────────────────
#
# Replaces the old manual "Learn DNS noise" button. Runs every 30 minutes and
# inspects the dns_blocked ActivityLog entries to:
#   • verify the blocker is actually blocking when enabled (block-rate sanity)
#   • flag a single domain spiking far above its 24h baseline (runaway tracker
#     or beaconing behavior)
#   • flag a single client making abnormal DNS volume vs. its own baseline
#   • flag a brand-new domain showing up with unusually high initial volume
# Writes a single dns_health ActivityLog entry only when something is worth
# surfacing — staying silent on healthy windows keeps the feed quiet.

def _run_dns_health_check() -> None:
    from collections import Counter
    from models.tables import ActivityLog, Setting
    from monitoring.activity import write_log

    db = SessionLocal()
    try:
        def _s(key: str, default: str = "") -> str:
            row = db.query(Setting).filter(Setting.key == key).first()
            return row.value if (row and row.value is not None) else default

        blocker_enabled = _s("dns_blocker_enabled", "false").lower() == "true"

        try:
            from dns_blocker.server import is_running as _blocker_running
            blocker_alive = _blocker_running()
        except Exception:
            blocker_alive = False

        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago  = now - timedelta(hours=24)

        recent = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.category == "dns",
                ActivityLog.event == "dns_blocked",
                ActivityLog.created_at >= hour_ago,
            )
            .all()
        )
        baseline_24h = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.category == "dns",
                ActivityLog.event == "dns_blocked",
                ActivityLog.created_at >= day_ago,
                ActivityLog.created_at <  hour_ago,
            )
            .all()
        )

        def _detail(row) -> dict:
            try:
                return json.loads(row.detail) if row.detail else {}
            except Exception:
                return {}

        recent_count   = len(recent)
        baseline_count = len(baseline_24h)
        baseline_hourly_avg = baseline_count / 23.0 if baseline_24h else 0.0

        anomalies: list[str] = []
        details: dict = {
            "window":        "1h",
            "blocked_count": recent_count,
            "baseline_hourly_avg": round(baseline_hourly_avg, 1),
            "blocker_enabled": blocker_enabled,
            "blocker_running": blocker_alive,
        }

        # 1) Blocker enabled but dead, or block rate collapsed unexpectedly.
        if blocker_enabled and not blocker_alive:
            anomalies.append("DNS blocker is enabled in settings but the server is not running.")
        elif (
            blocker_enabled
            and baseline_hourly_avg >= 20
            and recent_count < max(2, baseline_hourly_avg * 0.1)
        ):
            anomalies.append(
                f"DNS block rate dropped sharply — {recent_count} in the last hour vs. "
                f"~{baseline_hourly_avg:.0f}/h baseline. Possible bypass or upstream resolver change."
            )

        # 2) Per-domain spike detection.
        domain_recent = Counter(_detail(r).get("domain", "") for r in recent)
        domain_recent.pop("", None)
        domain_baseline = Counter(_detail(r).get("domain", "") for r in baseline_24h)
        domain_baseline.pop("", None)

        top_domains: list[dict] = []
        for domain, count in domain_recent.most_common(5):
            base_hourly = domain_baseline.get(domain, 0) / 23.0
            top_domains.append({
                "domain": domain,
                "count_1h": count,
                "baseline_hourly_avg": round(base_hourly, 1),
            })
            # Spike rules:
            #   never seen before in 24h AND >= 30/hr → likely new beacon/tracker
            #   seen before AND >= 5x its baseline AND >= 20/hr → spike worth noting
            if count >= 30 and base_hourly == 0:
                anomalies.append(
                    f"Domain '{domain}' is new in the last 24h but already queried {count}× this hour — "
                    f"possible runaway tracker, telemetry, or beacon."
                )
            elif base_hourly > 0 and count >= max(20, base_hourly * 5):
                anomalies.append(
                    f"Domain '{domain}' spiked to {count}/h (baseline ~{base_hourly:.1f}/h) — "
                    f"check which device is querying it."
                )
        details["top_domains_1h"] = top_domains

        # 3) Per-client volume detection.
        client_recent = Counter(_detail(r).get("client_ip", "") for r in recent)
        client_recent.pop("", None)
        client_baseline = Counter(_detail(r).get("client_ip", "") for r in baseline_24h)
        client_baseline.pop("", None)

        top_clients: list[dict] = []
        for client, count in client_recent.most_common(5):
            base_hourly = client_baseline.get(client, 0) / 23.0
            top_clients.append({
                "client_ip": client,
                "count_1h": count,
                "baseline_hourly_avg": round(base_hourly, 1),
            })
            if count >= 100 and (base_hourly == 0 or count >= base_hourly * 4):
                anomalies.append(
                    f"Client {client} made {count} blocked DNS queries this hour "
                    f"(baseline ~{base_hourly:.0f}/h) — that device may have a runaway tracker or ad library."
                )
        details["top_clients_1h"] = top_clients
        details["anomalies"] = anomalies

        if anomalies:
            level = "warning" if any(
                "not running" in a or "dropped sharply" in a for a in anomalies
            ) else "info"
            summary = "DNS health: " + " | ".join(anomalies[:3])
            write_log(level, "dns", "dns_health", summary, detail=details, actor="ai_auto")
            print(f"[dns_health] {len(anomalies)} anomaly/anomalies — logged")
        else:
            # Silent on healthy windows. Print a single console line for ops visibility.
            print(
                f"[dns_health] OK — {recent_count} blocked/last hour, "
                f"baseline ~{baseline_hourly_avg:.1f}/h, blocker_alive={blocker_alive}"
            )

    except Exception as exc:
        print(f"[dns_health] check error: {exc}")
    finally:
        db.close()


async def dns_health_loop() -> None:
    """Run a DNS-health check every 30 minutes."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(180)   # first check 3 minutes after startup

    while True:
        try:
            await loop.run_in_executor(_executor, _run_dns_health_check)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[dns_health] Loop error: {exc}")

        try:
            await asyncio.sleep(1800)   # 30 minutes
        except asyncio.CancelledError:
            print("[dns_health] Loop cancelled — shutting down.")
            break


# ── Auto-Nikto orchestration (Phase 3) ────────────────────────────────────────
#
# When the hourly auto-scan finds a NEW device with web ports (80/443/8080/
# 8443/8000/8888/5000), we automatically enqueue a Nikto scan against it.
# Throttled to keep CPU usage sane: max 3 runs/day across the whole network,
# max 1 concurrent. The result feeds the standard SecurityToolRun pipeline
# + AI explanation; only fires ntfy push when Nikto reports findings.
#
# Per-device opt-out: set Device.allow_json.skip_auto_nikto=true.

_NIKTO_DAILY_COUNTER: dict = {"date": None, "count": 0}
_NIKTO_LOCK = __import__("threading").Lock()
_NIKTO_DAILY_CAP = 3


def _auto_nikto_enqueue(new_web_devices: list[dict]) -> None:
    if not new_web_devices:
        return
    from app.database import SessionLocal as _SL
    from models.tables import Device
    from monitoring.activity import write_log

    today = datetime.now(timezone.utc).date().isoformat()
    with _NIKTO_LOCK:
        if _NIKTO_DAILY_COUNTER.get("date") != today:
            _NIKTO_DAILY_COUNTER["date"] = today
            _NIKTO_DAILY_COUNTER["count"] = 0
        remaining = _NIKTO_DAILY_CAP - _NIKTO_DAILY_COUNTER["count"]
        if remaining <= 0:
            print(f"[auto-nikto] daily cap reached ({_NIKTO_DAILY_CAP}); skipping {len(new_web_devices)} candidates")
            return

    queued = 0
    db = _SL()
    try:
        for d in new_web_devices[:remaining]:
            ip = d.get("ip")
            device_id = d.get("device_id")
            web_ports = d.get("web_ports", [])
            if not ip:
                continue

            # Per-device opt-out via allow_json.skip_auto_nikto
            dev = db.query(Device).filter(Device.id == device_id).first()
            if dev and dev.allow_json:
                try:
                    if json.loads(dev.allow_json).get("skip_auto_nikto"):
                        continue
                except Exception:
                    pass

            # Pick the best port: prefer 443 (ssl) > 80 > others; only one run per device.
            target_port = next((p for p in (443, 80, 8443, 8080, 8000, 8888, 5000) if p in web_ports), None)
            if target_port is None:
                continue
            use_ssl = target_port in (443, 8443)

            try:
                from api.routes import create_security_run
                run_id = create_security_run(
                    db, tool="nikto", tab="vulnerability_scan",
                    target=ip, target_type="device_ip",
                    is_attack_tool=False, authorization_confirmed=True,
                    device_id=device_id,
                )
                import threading as _thr
                from security.nikto import run_nikto as _run_nikto
                _thr.Thread(
                    target=_run_nikto,
                    kwargs={
                        "run_id":  run_id,
                        "target":  ip,
                        "port":    target_port,
                        "use_ssl": use_ssl,
                        "distro":  "kali-linux",
                    },
                    daemon=True,
                    name=f"auto-nikto-{ip}",
                ).start()
                write_log("info", "scan", "auto_nikto_started",
                          f"Auto-Nikto enqueued for new web device {ip}:{target_port}",
                          detail={"ip": ip, "port": target_port, "use_ssl": use_ssl, "run_id": run_id},
                          device_ip=ip, device_id=device_id, actor="anomaly_auto")
                queued += 1
                with _NIKTO_LOCK:
                    _NIKTO_DAILY_COUNTER["count"] += 1
            except Exception as exc:
                print(f"[auto-nikto] enqueue failed for {ip}: {exc}")
    finally:
        db.close()
    if queued:
        print(f"[auto-nikto] queued {queued} run(s) (daily count now {_NIKTO_DAILY_COUNTER['count']}/{_NIKTO_DAILY_CAP})")


# ── Daily port refresh (Phase 0.3) ────────────────────────────────────────────
#
# Deep-scans every currently-live device once a day so port data doesn't
# go stale. Without this, devices that were discovered before the upgrade
# (or whose only deep scan was a long time ago) would never get their open
# ports refreshed — the hourly loop only deep-scans NEW devices.
#
# Token-free. Just nmap. ~30s per device, runs at low priority.

def _run_periodic_port_refresh() -> None:
    from models.tables import Scan, ScanDevice, Device
    from scanner.runner import run_scan
    from scanner.parser import parse_nmap_xml
    from monitoring.activity import write_log

    db = SessionLocal()
    try:
        # Collect current-scan IPs (devices that showed up in the most recent
        # completed scan — so we don't waste time on devices that have left
        # the network).
        latest_scan = (
            db.query(Scan).filter(Scan.status == "complete")
            .order_by(Scan.id.desc()).first()
        )
        if not latest_scan:
            return
        scan_devs = db.query(ScanDevice).filter(ScanDevice.scan_id == latest_scan.id).all()
        ips = [sd.ip for sd in scan_devs if sd.ip]
        if not ips:
            return

        print(f"[port-refresh] deep -sV across {len(ips)} current device(s)")
        try:
            deep_xml = run_scan(" ".join(ips), quick=False)
        except Exception as exc:
            print(f"[port-refresh] nmap failed: {exc}")
            return

        parsed = parse_nmap_xml(deep_xml)
        deep_map = {d["ip"]: d for d in parsed}

        changes_detected = 0
        for sd in scan_devs:
            if sd.ip not in deep_map:
                continue
            new_ports = deep_map[sd.ip].get("open_ports", [])
            sd.open_ports = json.dumps(new_ports)
            if deep_map[sd.ip].get("hostname"):
                sd.hostname = deep_map[sd.ip]["hostname"]

            dev = db.query(Device).filter(Device.id == sd.device_id).first()
            if not dev:
                continue
            # parse_nmap_xml returns open_ports as a list of ints; handle
            # both int and legacy dict-with-"port"-key formats.
            new_port_nums = sorted(
                int(p) if isinstance(p, int) else p.get("port")
                for p in new_ports
                if isinstance(p, int) or (isinstance(p, dict) and p.get("port"))
            )
            # First-time baseline — set it.
            if not dev.known_ports_json:
                dev.known_ports_json = json.dumps(new_port_nums)
                dev.baseline_set_at = datetime.now(timezone.utc)
                continue
            # Compare against baseline to detect port-anomalies (Phase 2).
            try:
                baseline = set(json.loads(dev.known_ports_json or "[]"))
            except Exception:
                baseline = set()
            current = set(new_port_nums)
            opened = current - baseline
            closed = baseline - current
            if opened or closed:
                changes_detected += 1
                # Honor per-device allow-list — Phase 1.5
                allow = {}
                try:
                    allow = json.loads(dev.allow_json or "{}")
                except Exception:
                    pass
                allowed_ports = set(allow.get("allowed_ports") or [])
                surprising_opened = opened - allowed_ports
                if surprising_opened:
                    critical_ports = surprising_opened & {22, 23, 21, 445, 3389, 5900, 3306, 5432, 6379, 27017}
                    level = "critical" if critical_ports else "warning"
                    write_log(
                        level, "scan", "port_change_detected",
                        f"Device {sd.ip} opened new port(s): {sorted(surprising_opened)}"
                        + (f" — closed: {sorted(closed)}" if closed else ""),
                        detail={
                            "ip": sd.ip,
                            "device_id": dev.id,
                            "opened": sorted(surprising_opened),
                            "closed": sorted(closed),
                            "baseline": sorted(baseline),
                            "current": sorted(current),
                            "critical_ports": sorted(critical_ports),
                        },
                        device_ip=sd.ip, device_id=dev.id,
                        actor="anomaly_auto",
                    )
        db.commit()
        print(f"[port-refresh] complete — {changes_detected} device(s) with port changes")

    except Exception as exc:
        print(f"[port-refresh] error: {exc}")
    finally:
        db.close()


async def port_refresh_loop() -> None:
    """Run a deep -sV refresh against all current devices once a day."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(7200)  # first refresh 2h after startup (let auto-scan settle first)

    while True:
        try:
            await loop.run_in_executor(_executor, _run_periodic_port_refresh)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[port-refresh] Loop error: {exc}")

        try:
            await asyncio.sleep(86400)   # daily
        except asyncio.CancelledError:
            print("[port-refresh] Loop cancelled — shutting down.")
            break


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


# ── SSL/TLS cert scan (Phase 3.5) ─────────────────────────────────────────────
#
# Once a week, nmap --script=ssl-cert across all current devices that have
# HTTPS-style ports open. Flags expired certs, self-signed certs, and weak
# signature algorithms. Token-free. Quiet on healthy results.

def _run_ssl_cert_scan() -> None:
    from models.tables import Scan, ScanDevice, Device
    from scanner.runner import find_nmap
    from monitoring.activity import write_log
    import subprocess
    import re

    db = SessionLocal()
    try:
        latest_scan = (
            db.query(Scan).filter(Scan.status == "complete")
            .order_by(Scan.id.desc()).first()
        )
        if not latest_scan:
            return
        scan_devs = db.query(ScanDevice).filter(ScanDevice.scan_id == latest_scan.id).all()

        nmap_path = find_nmap()
        if not nmap_path:
            print("[ssl-cert] nmap not found — skipping")
            return

        targets: list[tuple[str, list[int]]] = []
        for sd in scan_devs:
            try:
                ports = [p.get("port") for p in (sd.ports_list or []) if isinstance(p, dict)]
            except Exception:
                ports = []
            https_ports = [p for p in ports if p in (443, 8443, 9443, 4443)]
            if https_ports:
                targets.append((sd.ip, https_ports))

        if not targets:
            return
        print(f"[ssl-cert] scanning {len(targets)} HTTPS-capable device(s)")

        findings = 0
        now = datetime.now(timezone.utc)
        for ip, ports in targets:
            ports_arg = ",".join(str(p) for p in ports)
            try:
                r = subprocess.run(
                    [nmap_path, "-sV", "--script=ssl-cert", "-p", ports_arg,
                     "--host-timeout", "60s", ip],
                    capture_output=True, text=True, timeout=120,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception as exc:
                print(f"[ssl-cert] {ip} scan failed: {exc}")
                continue
            out = r.stdout or ""

            # Detect expiry: "Not valid after: 2024-09-12T..."
            issues: list[str] = []
            m = re.search(r"Not valid after:\s*([\d\-T:Z]+)", out)
            if m:
                try:
                    exp = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    if exp < now:
                        issues.append(f"expired ({exp.date()})")
                    elif (exp - now).days < 14:
                        issues.append(f"expires soon ({exp.date()})")
                except Exception:
                    pass
            if "self-signed" in out.lower() or "self signed" in out.lower():
                issues.append("self-signed")
            if re.search(r"signed.+(sha1|md5)", out, flags=re.IGNORECASE):
                issues.append("weak signature algorithm")

            if issues:
                findings += 1
                write_log(
                    "warning", "scan", "ssl_cert_issue",
                    f"{ip} TLS cert issue: {', '.join(issues)}",
                    detail={"ip": ip, "ports": ports, "issues": issues,
                            "nmap_excerpt": out[-1500:]},
                    device_ip=ip, actor="anomaly_auto",
                )
        print(f"[ssl-cert] complete — {findings} device(s) with cert issues")
    except Exception as exc:
        print(f"[ssl-cert] error: {exc}")
    finally:
        db.close()


async def ssl_cert_scan_loop() -> None:
    """Run SSL/TLS cert scan against HTTPS-capable devices once a week."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(3600)  # 1h after startup so other loops settle first
    while True:
        try:
            await loop.run_in_executor(_executor, _run_ssl_cert_scan)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[ssl-cert] Loop error: {exc}")
        try:
            await asyncio.sleep(604800)   # 7 days
        except asyncio.CancelledError:
            break


# ── DoH leak detection (Phase 4.8) ────────────────────────────────────────────
#
# NetMon's DNS blocker only sees plaintext UDP/53 queries. If a device sneaks
# its DNS through DNS-over-HTTPS (TCP/443 to a known public resolver), we
# can't block it — but we CAN detect it from the traffic conversations.
#
# Heuristic: any sustained TCP/443 traffic from a LAN device to one of the
# well-known DoH endpoints, when the device is NOT the NetMon server itself.

_KNOWN_DOH_ENDPOINTS = {
    # Cloudflare
    "1.1.1.1", "1.0.0.1", "162.159.36.1", "162.159.46.1",
    # Google
    "8.8.8.8", "8.8.4.4",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # NextDNS
    "45.90.28.0", "45.90.30.0",
    # OpenDNS
    "208.67.222.222", "208.67.220.220",
    # AdGuard
    "94.140.14.14", "94.140.15.15",
}


def _run_doh_leak_check() -> None:
    from models.tables import TrafficSummary, Setting, ScanDevice, Device
    from monitoring.activity import write_log

    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "dns_blocker_enabled").first()
        if not row or row.value != "true":
            return  # nothing to enforce if blocker isn't on

        # Look at the last hour of traffic summaries for DoH-looking flows.
        from datetime import timedelta as _td
        cutoff = datetime.now(timezone.utc) - _td(hours=1)
        recents = (
            db.query(TrafficSummary)
            .filter(TrafficSummary.created_at >= cutoff)
            .order_by(TrafficSummary.id.desc())
            .limit(60).all()
        )
        if not recents:
            return

        # Aggregate (lan_src, doh_dst) → bytes
        per_pair: dict[tuple[str, str], int] = {}
        for s in recents:
            try:
                # We may have conversations directly if the analyzer added them.
                top_dests = json.loads(s.top_destinations or "[]")
            except Exception:
                top_dests = []
            for dest in top_dests:
                ip = dest.get("ip", "")
                if ip in _KNOWN_DOH_ENDPOINTS:
                    per_pair[("any_lan", ip)] = per_pair.get(("any_lan", ip), 0) + dest.get("bytes", 0)

        # Threshold: > 50KB/h to a DoH endpoint counts as active DoH use.
        flagged: list[tuple[str, str, int]] = []
        for (src, dst), byt in per_pair.items():
            if byt >= 50_000:
                flagged.append((src, dst, byt))

        for src, dst, byt in flagged:
            write_log(
                "warning", "dns", "doh_leak_suspected",
                f"Possible DNS-over-HTTPS leak: {byt} bytes/hr to {dst} (NetMon's blocker can't see queries inside HTTPS).",
                detail={"endpoint": dst, "bytes_per_hour": byt,
                        "remediation": "Block this IP at the firewall to force plaintext DNS through NetMon."},
                actor="anomaly_auto",
            )
        if flagged:
            print(f"[doh] {len(flagged)} suspected DoH leak(s)")
    except Exception as exc:
        print(f"[doh] check error: {exc}")
    finally:
        db.close()


async def doh_leak_loop() -> None:
    """Check for DoH bypass every hour. Deterministic, no tokens."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(900)  # 15 min after startup
    while True:
        try:
            await loop.run_in_executor(_executor, _run_doh_leak_check)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[doh] Loop error: {exc}")
        try:
            await asyncio.sleep(3600)   # hourly
        except asyncio.CancelledError:
            break


# ── Deep-scan AI analysis (Phase 6) ───────────────────────────────────────────
#
# Every 4h. Pulls port changes, geo anomalies, threat hits, recent
# port_change_detected events; asks the AI chain to produce a focused
# "did anything change that matters?" report. Skip-gate + 24h heartbeat
# pattern (same as autonomous_report_loop).

def _run_deep_scan_ai_analysis() -> None:
    from models.tables import ActivityLog, SecurityReport, Setting
    from sqlalchemy import desc as _desc
    from datetime import timedelta as _td

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    window_start = now - _td(hours=4)

    try:
        def _s(key, default="false"):
            row = db.query(Setting).filter(Setting.key == key).first()
            return row.value if (row and row.value is not None) else default
        if _s("ai_enabled") != "true":
            return
        if _s("deep_scan_ai_enabled", "true") != "true":
            return

        # Events we care about for deep-scan analysis.
        notable_events = (
            db.query(ActivityLog)
            .filter(
                ActivityLog.created_at >= window_start,
                ActivityLog.event.in_([
                    "port_change_detected", "geo_anomaly", "threat_intel_hit",
                    "doh_leak_suspected", "ssl_cert_issue", "auto_nikto_started",
                    "device_new",
                ]),
            ).all()
        )

        # 24h heartbeat tracking
        last_real = (
            db.query(SecurityReport)
            .filter(SecurityReport.report_type == "deep_scan")
            .order_by(_desc(SecurityReport.id)).first()
        )
        force_hb = True
        if last_real and last_real.period_end:
            end = last_real.period_end
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            force_hb = (now - end).total_seconds() / 3600.0 >= 24.0

        if not notable_events and not force_hb:
            db.add(SecurityReport(
                report_type="deep_scan_skip",
                period_start=window_start, period_end=now,
                severity="low",
                headline="Deep scan window quiet — no port/geo/threat changes.",
                body="Skipped LLM analysis (token-conservation gate). Deterministic monitors reported nothing in the last 4 hours.",
                anomalies=json.dumps([]),
                recommendations=json.dumps([]),
                model="skip-gate",
            ))
            db.commit()
            return

        # Build the compact context.
        events_ctx = [
            {"event": e.event, "summary": e.summary, "level": e.level,
             "device_ip": e.device_ip, "detail": (json.loads(e.detail) if e.detail else None)}
            for e in notable_events[:30]
        ]
        prompt = (
            "You are a network-security analyst reviewing the last 4 hours of changes on a home network.\n\n"
            f"Window: {window_start.isoformat()} to {now.isoformat()} UTC\n\n"
            "Events:\n" + json.dumps(events_ctx, indent=2, default=str) + "\n\n"
            "Produce a brief assessment as JSON ONLY:\n"
            '  "severity": "low"|"medium"|"high"|"critical"\n'
            '  "headline": one sentence (<=100 chars)\n'
            '  "body": 2 short paragraphs\n'
            '  "anomalies": list of specific concerning items\n'
            '  "recommendations": 1-3 specific actions\n'
            "Be concise. DNS-blocked rows alone are NOT suspicious — ignore them unless corroborated."
        )

        from ai.provider import get_provider
        provider = get_provider()
        ai_result = provider.analyze({}, prompt=prompt, kind="deep_scan")
        if ai_result.get("error"):
            print(f"[deep-scan-ai] AI error: {ai_result['error']}")
            return

        raw = ai_result.get("raw_response") or ""
        import re as _re
        m = _re.search(r"\{[\s\S]*\}", raw)
        if not m:
            print("[deep-scan-ai] no JSON in response")
            return
        try:
            data = json.loads(m.group(0))
        except Exception:
            return

        db.add(SecurityReport(
            report_type="deep_scan",
            period_start=window_start, period_end=now,
            severity=(data.get("severity") or "low"),
            headline=(data.get("headline") or "")[:200],
            body=data.get("body") or "",
            anomalies=json.dumps(data.get("anomalies", [])),
            recommendations=json.dumps(data.get("recommendations", [])),
            model=ai_result.get("model") or provider.name,
        ))
        db.commit()
        print(f"[deep-scan-ai] saved {data.get('severity', 'low')} report: {data.get('headline', '')[:80]}")
    except Exception as exc:
        print(f"[deep-scan-ai] error: {exc}")
    finally:
        db.close()


async def deep_scan_ai_loop() -> None:
    """Every 4 hours, AI synthesis of port/geo/threat changes. Skip-gate + heartbeat."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(14400)  # first run 4h after start
    while True:
        try:
            await loop.run_in_executor(_executor, _run_deep_scan_ai_analysis)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[deep-scan-ai] Loop error: {exc}")
        try:
            await asyncio.sleep(14400)  # 4h
        except asyncio.CancelledError:
            break


# ── Hunt-mode rule engine (Phase 8) ───────────────────────────────────────────
#
# User-defined detection rules in a simple YAML form. Evaluated every 60 s
# against the most recent ActivityLog window. Each match writes a hunt_match
# log entry at the rule's severity.
#
# Rule shape:
#   name: my-rule
#   enabled: true
#   severity: warning
#   match:
#     any_of:
#       - event: geo_anomaly
#       - event: doh_leak_suspected
#       - device_ip: "192.168.1.45"
#     within_minutes: 60
#   action: notify   # notify | log_only

def _run_hunt_rules() -> None:
    from models.tables import HuntRule, ActivityLog
    from monitoring.activity import write_log
    from datetime import timedelta as _td

    # YAML is optional — pyyaml isn't a hard dep. Fall back to JSON if needed.
    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    try:
        rules = db.query(HuntRule).filter(HuntRule.enabled == True).all()  # noqa: E712
        for rule in rules:
            try:
                spec = _yaml.safe_load(rule.yaml_body) if _yaml else json.loads(rule.yaml_body)
            except Exception as exc:
                print(f"[hunt] rule '{rule.name}' parse error: {exc}")
                continue
            if not isinstance(spec, dict):
                continue
            match = spec.get("match", {}) or {}
            within = int(match.get("within_minutes", 60))
            window_start = now - _td(minutes=within)

            # Build the query
            q = db.query(ActivityLog).filter(ActivityLog.created_at >= window_start)

            conds = []
            for any_clause in (match.get("any_of") or []):
                if "event" in any_clause:
                    conds.append(ActivityLog.event == any_clause["event"])
                if "device_ip" in any_clause:
                    conds.append(ActivityLog.device_ip == any_clause["device_ip"])
                if "actor" in any_clause:
                    conds.append(ActivityLog.actor == any_clause["actor"])
                if "level" in any_clause:
                    conds.append(ActivityLog.level == any_clause["level"])
            if conds:
                from sqlalchemy import or_ as _or
                q = q.filter(_or(*conds))

            count = q.count()
            min_count = int(match.get("min_count", 1))
            if count >= min_count:
                # Only fire once per (rule, window) to avoid spam.
                if rule.last_fired_at and rule.last_fired_at.replace(tzinfo=timezone.utc) > window_start:
                    continue
                rule.last_fired_at = now
                rule.fire_count = (rule.fire_count or 0) + 1
                db.commit()
                write_log(
                    rule.severity or "warning", "system", "hunt_match",
                    f"Hunt rule '{rule.name}' matched ({count} events in last {within}m)",
                    detail={"rule": rule.name, "count": count, "spec": spec},
                    actor="anomaly_auto",
                )
                if (spec.get("action") or "notify") == "notify":
                    from monitoring.notifier import alert as _notify
                    _notify(
                        title=f"Hunt rule fired: {rule.name}",
                        body=rule.description or f"{count} matching events in the last {within} minutes.",
                        level=rule.severity or "warning",
                        force_push=True,
                    )
    except Exception as exc:
        print(f"[hunt] error: {exc}")
    finally:
        db.close()


async def hunt_loop() -> None:
    """Evaluate user-defined hunt rules every 60 s."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(30)
    while True:
        try:
            await loop.run_in_executor(_executor, _run_hunt_rules)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[hunt] Loop error: {exc}")
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            break


# ── Daily incident pcap cleanup ───────────────────────────────────────────────

def _run_incident_cleanup() -> None:
    from models.tables import Setting
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "incident_retention_days").first()
        days = int(row.value) if row and row.value else 30
    finally:
        db.close()
    try:
        from traffic.incident_capture import prune_old_incidents
        n = prune_old_incidents(days)
        if n:
            print(f"[incident] pruned {n} old incident pcap(s) (>{days}d)")
    except Exception as exc:
        print(f"[incident] cleanup error: {exc}")


async def log_cleanup_loop() -> None:
    """Run log + incident cleanup once daily."""
    loop = asyncio.get_running_loop()
    await asyncio.sleep(3600)   # first run after 1 hour

    while True:
        try:
            await loop.run_in_executor(_executor, _run_log_cleanup)
            await loop.run_in_executor(_executor, _run_incident_cleanup)
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
    Background coroutine: runs autonomous security analysis every 2 hours.
    First report fires 2 hours after server startup. The work function gates
    LLM calls on actual event volume and forces a heartbeat at most every 24h,
    so quiet days cost ~1 call instead of 12.
    Skipped silently if ai_enabled=false or auto_report_enabled=false.
    """
    loop = asyncio.get_running_loop()
    await asyncio.sleep(7200)   # first report after 2h uptime

    while True:
        try:
            await loop.run_in_executor(_executor, _run_autonomous_report)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            print(f"[report] Loop error: {exc}")

        try:
            await asyncio.sleep(7200)   # every 2 hours
        except asyncio.CancelledError:
            print("[report] Report loop cancelled — shutting down.")
            break
