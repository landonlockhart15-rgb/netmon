"""
main.py — FastAPI application factory and entry point.

Startup sequence:
  1. Create new tables (CREATE TABLE IF NOT EXISTS)
  2. Run column-level migrations
  3. Seed default settings (first run only)
  4. Start background health check loop
  5. Mount static files, register routes, serve dashboard

Auth:
  AuthMiddleware runs before every request. It checks for a valid
  session cookie. Unauthenticated browser requests are redirected to
  /login. Unauthenticated API requests get 401 JSON (so the JS
  polling doesn't silently receive HTML and break).

  /login, /auth/login, and /auth/logout are always exempt so the
  user can actually reach the login page.
"""

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from dotenv import load_dotenv

from app.database import engine, Base, run_migrations, seed_default_settings
from app.auth import validate_session, COOKIE_NAME
from api.routes import router
from api.auth_routes import router as auth_router

load_dotenv()

import models.tables  # noqa: F401 — registers all ORM models with Base


# ── Auth Middleware ────────────────────────────────────────────────────────────

# Paths that are ALWAYS accessible without a session.
# Keep this list minimal — only what the login page itself needs.
_EXEMPT_PATHS = {"/login", "/auth/login", "/auth/logout"}


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Intercepts every request and checks for a valid session cookie.

    Why middleware instead of a FastAPI dependency?
      A dependency only protects routes that explicitly declare it.
      Middleware protects everything including mounted static files,
      which is important — we don't want unauthenticated users
      downloading app.js and reverse-engineering the API.

    Two rejection modes:
      /api/* routes  → 401 JSON  (JS fetch() handles this gracefully)
      everything else → 303 redirect to /login
    """
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Always let login/logout through
        if path in _EXEMPT_PATHS:
            return await call_next(request)

        token = request.cookies.get(COOKIE_NAME)
        if not validate_session(token):
            if path.startswith("/api/"):
                # Return JSON 401 so fetch() in app.js doesn't receive HTML
                return JSONResponse(
                    {"detail": "Not authenticated"},
                    status_code=401,
                )
            # Browser navigation — redirect to login page
            return JSONResponse(
                None,
                status_code=303,
                headers={"Location": "/login"},
            )

        return await call_next(request)


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: initialise DB, seed settings, launch background health checker.
    Shutdown: cancel the background task cleanly.
    """
    Base.metadata.create_all(bind=engine)
    run_migrations()
    seed_default_settings()

    # Auto-detect current network and store in app.state for scheduler use
    from network.autodetect import get_network_info
    app.state.network_info = get_network_info()
    print(f"[main] Network: {app.state.network_info.get('local_ip')} "
          f"subnet={app.state.network_info.get('scan_target')} "
          f"gateway={app.state.network_info.get('gateway')}")

    from monitoring.scheduler import (
        health_check_loop, traffic_analysis_loop, auto_scan_loop,
        anomaly_loop, command_poll_loop, autonomous_report_loop,
        log_cleanup_loop, dns_health_loop, port_refresh_loop,
        ssl_cert_scan_loop, doh_leak_loop, deep_scan_ai_loop, hunt_loop,
        autoheal_loop,
    )
    health_task    = asyncio.create_task(health_check_loop())
    traffic_task   = asyncio.create_task(traffic_analysis_loop())
    auto_scan_task = asyncio.create_task(auto_scan_loop())
    anomaly_task   = asyncio.create_task(anomaly_loop())
    command_task   = asyncio.create_task(command_poll_loop())
    report_task    = asyncio.create_task(autonomous_report_loop())
    cleanup_task   = asyncio.create_task(log_cleanup_loop())
    dns_health_task = asyncio.create_task(dns_health_loop())
    port_refresh_task = asyncio.create_task(port_refresh_loop())
    ssl_cert_task   = asyncio.create_task(ssl_cert_scan_loop())
    doh_task        = asyncio.create_task(doh_leak_loop())
    deep_ai_task    = asyncio.create_task(deep_scan_ai_loop())
    hunt_task       = asyncio.create_task(hunt_loop())
    autoheal_task   = asyncio.create_task(autoheal_loop())
    print("[main] Schedulers started: health, traffic, auto-scan, anomaly, command, report, log-cleanup, dns-health, port-refresh, ssl-cert, doh-leak, deep-scan-ai, hunt, autoheal.")

    # Auto-resume capture if it was enabled before the server restarted
    _maybe_resume_capture()

    # Pre-warm the AI model in a background thread so the FIRST user-facing
    # call doesn't pay the 30s "load model into RAM" penalty. Fire-and-forget;
    # if it fails (Ollama not running, model not pulled, AI disabled) we just
    # log it and move on.
    _warm_ai_model_async()

    # Pre-fetch threat intelligence blocklists so the first investigation
    # doesn't wait on network downloads. Cached to disk; refreshes every 4h.
    from ai.threat_intel import warm_cache as _warm_threat_intel
    _warm_threat_intel()
    print("[main] Threat intel cache warming started in background.")

    # Warm the offline OUI vendor database in a background thread so the first
    # scan after install (or after monthly staleness) doesn't block. Silent on
    # network failure — the rest of NetMon works fine without vendor labels.
    def _warm_oui():
        try:
            from network.oui import init_oui_db
            init_oui_db()
        except Exception as _exc:
            print(f"[oui] warm-up failed (non-fatal): {_exc}")
    import threading as _thr
    _thr.Thread(target=_warm_oui, daemon=True, name="oui-warmer").start()

    # Warm the offline GeoIP database (Phase 2 geo-anomaly).
    def _warm_geo():
        try:
            from network.geo import init_geo_db
            init_geo_db()
        except Exception as _exc:
            print(f"[geo] warm-up failed (non-fatal): {_exc}")
    _thr.Thread(target=_warm_geo, daemon=True, name="geo-warmer").start()

    # Passive mDNS + SSDP discovery (Phase 4.6) — names IoT devices from
    # their own broadcasts. No probing, just listening.
    try:
        from network.discovery import start_passive_discovery
        start_passive_discovery()
    except Exception as _exc:
        print(f"[discovery] start failed (non-fatal): {_exc}")

    # Start DNS ad blocker if enabled
    _start_dns_blocker_if_enabled()

    # Sweep orphan pcap files on startup. The traffic loop only runs cleanup
    # while capture is active, so old rings can pile up across restarts when
    # capture has been disabled. Bounded retention keeps disk use predictable.
    _cleanup_orphan_captures()

    # Log the startup event
    from monitoring.activity import write_log as _write_log
    _write_log("info", "system", "service_started",
               "NetMon started — health check, traffic analysis, and auto-scan schedulers active")

    yield

    # Stop DNS blocker on shutdown
    from dns_blocker import server as _dns_srv
    _dns_srv.stop()

    # Stop capture cleanly on shutdown
    from traffic.capture import capture_engine
    from app.database import SessionLocal as _SL
    if capture_engine.get_status()["running"]:
        capture_engine.stop(session_factory=_SL)
        print("[main] Capture engine stopped on shutdown.")

    for task in (health_task, traffic_task, auto_scan_task, anomaly_task,
                 command_task, report_task, cleanup_task, dns_health_task,
                 port_refresh_task, ssl_cert_task, doh_task, deep_ai_task,
                 hunt_task, autoheal_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    print("[main] Schedulers stopped.")


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="NetMon",
    description="Local home network monitor",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(AuthMiddleware)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(auth_router)
app.include_router(router)


@app.get("/")
def serve_dashboard():
    return FileResponse(
        "static/index.html",
        headers={"Cache-Control": "no-store, must-revalidate"},
    )


@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    """Serve React SPA for all non-API browser routes (React Router handles them client-side)."""
    import os
    # Let static files and login pass through to the static mount / auth middleware
    if full_path.startswith("api/") or full_path.startswith("auth/") or full_path == "login":
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    static_file = os.path.join("static", full_path)
    if os.path.isfile(static_file):
        return FileResponse(static_file)
    return FileResponse(
        "static/index.html",
        headers={"Cache-Control": "no-store, must-revalidate"},
    )


# ── Capture auto-resume ────────────────────────────────────────────────────────

def _maybe_resume_capture():
    """
    Re-start passive capture if it was enabled when the server last shut down.
    Called once during lifespan startup, after the DB is ready.
    Does nothing if capture_enabled != "true" or capture_interface is blank.
    """
    from app.database import SessionLocal as _SL
    from models.tables import Setting

    db = _SL()
    try:
        def _get(key, default=""):
            row = db.query(Setting).filter(Setting.key == key).first()
            return row.value if (row and row.value) else default

        enabled   = _get("capture_enabled",    "false").lower()
        interface = _get("capture_interface",  "").strip()
        try:
            size_mb = int(_get("capture_file_size_mb", "10"))
        except (ValueError, TypeError):
            size_mb = 10
        try:
            count = int(_get("capture_file_count", "5"))
        except (ValueError, TypeError):
            count = 5
    finally:
        db.close()

    # Phase 4: capture_auto_start defaults true on fresh installs. If
    # capture_enabled is unset but capture_auto_start is true, infer the
    # interface from autodetect and start anyway. "It just works."
    db2 = _SL()
    try:
        def _g2(key, default=""):
            row = db2.query(Setting).filter(Setting.key == key).first()
            return row.value if (row and row.value) else default
        auto_start = _g2("capture_auto_start", "false").lower() == "true"
    finally:
        db2.close()

    if enabled != "true" and auto_start:
        # Try to autodetect a sensible interface.
        try:
            from network.autodetect import get_network_info
            info = get_network_info() or {}
            interface = info.get("interface_name") or interface
        except Exception:
            pass
        if interface:
            enabled = "true"
            print(f"[main] Auto-capture: starting on detected interface '{interface}'.")

    if enabled == "true" and interface:
        from traffic.capture import capture_engine
        result = capture_engine.start(
            interface=interface,
            file_size_mb=size_mb,
            file_count=count,
            session_factory=_SL,
        )
        # Persist enabled+interface so next restart resumes cleanly.
        try:
            db3 = _SL()
            for k, v in [("capture_enabled", "true"), ("capture_interface", interface)]:
                row = db3.query(Setting).filter(Setting.key == k).first()
                if row:
                    row.value = v
                else:
                    db3.add(Setting(key=k, value=v))
            db3.commit()
            db3.close()
        except Exception:
            pass
        print(f"[main] Auto-resumed/auto-started capture: {result}")
    else:
        print("[main] Capture auto-resume skipped (disabled or no interface configured).")


# ── DNS Blocker startup ───────────────────────────────────────────────────────

def _start_dns_blocker_if_enabled():
    """Start the DNS ad-blocking server if dns_blocker_enabled=true."""
    import threading
    from app.database import SessionLocal as _SL
    from models.tables import Setting

    def _bg():
        db = _SL()
        try:
            def _g(k, d=""):
                row = db.query(Setting).filter(Setting.key == k).first()
                return row.value if (row and row.value) else d
            enabled  = _g("dns_blocker_enabled", "false")
            upstream = _g("dns_upstream", "8.8.8.8")
        finally:
            db.close()

        if enabled != "true":
            print("[main] DNS blocker disabled — skipping.")
            return

        from dns_blocker import blocklist, server as dns_srv
        blocklist.load_user_whitelist()   # merge persisted user exceptions first
        blocklist.refresh()
        blocklist.start_auto_refresh()
        ok = dns_srv.start(upstream=upstream)
        if not ok:
            print("[main] DNS blocker failed to start — port 53 may be in use.")

    threading.Thread(target=_bg, daemon=True, name="dns-blocker-init").start()


# ── Orphan capture cleanup (runs once on startup) ─────────────────────────────

def _cleanup_orphan_captures():
    """Delete .pcapng files older than capture_retention_days from data/captures."""
    from app.database import SessionLocal as _SL
    from models.tables import Setting
    from traffic.capture import CAPTURE_DIR
    from traffic.analyzer import cleanup_old_captures

    db = _SL()
    try:
        row = db.query(Setting).filter(Setting.key == "capture_retention_days").first()
        try:
            retention = int(row.value) if row and row.value else 3
        except (ValueError, TypeError):
            retention = 3
    finally:
        db.close()

    try:
        deleted = cleanup_old_captures(CAPTURE_DIR, retention)
        if deleted:
            print(f"[main] Startup pcap sweep: removed {deleted} files older than {retention} days.")
    except Exception as e:
        print(f"[main] Startup pcap sweep failed (non-fatal): {e}")


# ── AI model warmup ───────────────────────────────────────────────────────────

def _warm_ai_model_async():
    """
    Fire a tiny prompt at the configured fast AI model so Ollama loads it
    into RAM before the user makes their first real call. Without this, the
    FIRST analysis pays a 30+ second model-load penalty on a 2-3GB model.

    Runs in a daemon thread so it never blocks startup. Silent on failure
    (AI disabled, Ollama not running, etc).
    """
    import threading
    from app.database import SessionLocal as _SL
    from models.tables import Setting

    def _warm():
        try:
            db = _SL()
            try:
                row = db.query(Setting).filter(Setting.key == "ai_enabled").first()
                if not row or (row.value or "").lower() != "true":
                    print("[ai] Warmup skipped — AI is disabled.")
                    return
            finally:
                db.close()

            from ai.provider import get_provider
            provider = get_provider()
            if provider.name != "ollama":
                print(f"[ai] Warmup skipped — provider is {provider.name}, not ollama.")
                return

            import urllib.request, json as _json
            import time as _time
            t0 = _time.time()
            payload = _json.dumps({
                "model":    provider._fast_model,
                "messages": [{"role": "user", "content": "ok"}],
                "stream":   False,
                "options":  {"temperature": 0.1, "num_predict": 4},
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{provider._host}/api/chat",
                data    = payload,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                resp.read()
            print(f"[ai] Warmup OK — {provider._fast_model} loaded in {_time.time()-t0:.1f}s")
        except Exception as e:
            print(f"[ai] Warmup failed (non-fatal): {e}")

    threading.Thread(target=_warm, daemon=True, name="ai-warmup").start()
