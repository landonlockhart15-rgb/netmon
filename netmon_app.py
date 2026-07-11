"""
netmon_app.py — PyInstaller entry point for the packaged NetMon app.

Order matters: bootstrap the runtime (writable paths, logging, .env, first-run
login) BEFORE importing anything under ``app.*`` / ``launch`` so the database
URL and password hash are in place when those modules import.

Source runs do not use this file — they start from ``launch.py`` / ``start.bat``.
"""

import sys
import traceback


def _fatal(msg: str) -> None:
    """Last-resort error surface for a windowed build (no console)."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, "NetMon — startup error", 0x10)
    except Exception:
        pass
    try:
        print(msg)
    except Exception:
        pass


def main() -> None:
    import os
    import netmon_runtime as rt

    rt.setup_logging()              # redirect stdout/stderr to a log file first
    creds = rt.bootstrap_env()      # paths, .env, DB url, first-run password

    if os.environ.get("NETMON_SELFTEST") == "1":
        # Serve-only smoke path: start uvicorn directly with no tray, no
        # instance lock, and no duplicate-killer — so it can verify the frozen
        # bundle boots and serves without disturbing a running source instance.
        import uvicorn
        from app.main import app as fastapi_app
        host = (os.getenv("BIND_HOST", "127.0.0.1").strip() or "127.0.0.1")
        try:
            port = int(os.getenv("APP_PORT", "8000"))
        except ValueError:
            port = 8000
        print(f"[selftest] serving on http://{host}:{port}")
        uvicorn.run(fastapi_app, host=host, port=port, reload=False, log_config=None)
        return

    if creds:
        rt.show_first_run_dialog(*creds)

    # The app remains useful without nmap, but its core discovery/port-scan
    # features do not. Give packaged users an actionable preflight instead of
    # waiting for their first scan to fail with a technical error.
    rt.show_nmap_preflight()

    # Safe to import the app now — DATABASE_URL + .env are configured.
    import launch
    launch.run_tray()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        _fatal("NetMon failed to start:\n\n" + traceback.format_exc())
        sys.exit(1)
