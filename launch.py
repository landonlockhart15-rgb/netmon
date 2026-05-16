"""
tray.py — NetMon system tray launcher.

Starts the uvicorn server AND the ntfy notification server as hidden
background processes, then shows a single tray icon in the Windows
notification area.

Right-click: Open Dashboard, Open ntfy Web UI, Stop NetMon.
Double-click: Open Dashboard.

Run via start.bat (handles UAC elevation automatically).
"""

import os
import sys
import subprocess
import threading
import webbrowser
import shutil
from pathlib import Path

# Must run from the project directory so uvicorn finds app.main
BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

CREATE_NO_WINDOW = 0x08000000

# ── ntfy server config ────────────────────────────────────────────────────────
DATA_DIR = Path(os.getenv("NETMON_DATA_DIR", str(BASE_DIR / "data")))


def _path_from_env(key: str) -> Path | None:
    value = os.getenv(key, "").strip().strip('"')
    return Path(value).expanduser() if value else None


def _find_ntfy_exe() -> Path | None:
    configured = _path_from_env("NTFY_EXE")
    if configured and configured.is_file():
        return configured

    found = shutil.which("ntfy") or shutil.which("ntfy.exe")
    if found:
        return Path(found)

    for candidate in (
        BASE_DIR / "ntfy.exe",
        BASE_DIR / "tools" / "ntfy.exe",
        Path(r"C:\ntfy\ntfy.exe"),
    ):
        if candidate.is_file():
            return candidate
    return None


def _find_ntfy_config(ntfy_dir: Path | None) -> Path | None:
    configured = _path_from_env("NTFY_CONFIG")
    if configured:
        return configured

    for candidate in (
        BASE_DIR / "config" / "ntfy" / "server.yml",
        (ntfy_dir / "server.yml") if ntfy_dir else None,
        Path(r"C:\ntfy\server.yml"),
    ):
        if candidate and candidate.is_file():
            return candidate
    return None


_NTFY_EXE    = _find_ntfy_exe()
_NTFY_DIR    = _NTFY_EXE.parent if _NTFY_EXE else None
_NTFY_CONFIG = _find_ntfy_config(_NTFY_DIR)
_NTFY_URL    = os.getenv("NTFY_URL", os.getenv("NTFY_SERVER", "http://localhost:2586")).rstrip("/")
_NTFY_LOG    = _path_from_env("NTFY_LOG") or (DATA_DIR / "logs" / "ntfy_error.log")

_ntfy_proc:   subprocess.Popen | None = None
_ntfy_log_fh: object | None = None   # kept alive so ntfy's stdout never closes
_ntfy_lock  = threading.Lock()
_ntfy_alive = True   # set False when user clicks Stop to end watchdog


def _alert(msg: str) -> None:
    """Show a Windows error popup — used when tray.py crashes silently."""
    import ctypes
    ctypes.windll.user32.MessageBoxW(0, msg, "NetMon Error", 0x10)


# ── ntfy lifecycle ────────────────────────────────────────────────────────────

def _start_ntfy() -> None:
    global _ntfy_proc, _ntfy_log_fh
    with _ntfy_lock:
        if _ntfy_proc and _ntfy_proc.poll() is None:
            return  # already running
        if not _NTFY_EXE or not _NTFY_EXE.is_file():
            print("[ntfy] ntfy.exe not found — skipping. Set NTFY_EXE in .env to enable it.")
            return
        if not _NTFY_CONFIG or not _NTFY_CONFIG.is_file():
            print("[ntfy] server.yml not found — skipping. Set NTFY_CONFIG in .env to enable it.")
            return
        # Kill any stray ntfy.exe left over from a previous Python session.
        # CREATE_NO_WINDOW processes survive terminal/Python exit and keep
        # holding port 2586, causing every fresh start to fail immediately.
        subprocess.run(["taskkill", "/F", "/IM", "ntfy.exe"], capture_output=True,
                       creationflags=CREATE_NO_WINDOW)
        try:
            # Keep the file handle in a global so Python's GC never closes it.
            # A closed handle makes ntfy lose stdout/stderr on Windows and crash.
            _NTFY_LOG.parent.mkdir(parents=True, exist_ok=True)
            _ntfy_log_fh = open(_NTFY_LOG, "w", encoding="utf-8")
            command = [str(_NTFY_EXE), "serve", "--config", str(_NTFY_CONFIG)]
            _ntfy_proc = subprocess.Popen(
                command,
                stdout=_ntfy_log_fh,
                stderr=_ntfy_log_fh,
                cwd=str(_NTFY_DIR or BASE_DIR),
                creationflags=CREATE_NO_WINDOW,
            )
            print(f"[ntfy] Started {_NTFY_EXE} (pid {_ntfy_proc.pid})")
        except Exception as exc:
            print(f"[ntfy] Failed to start ntfy.exe: {exc}")


def _stop_ntfy() -> None:
    global _ntfy_proc
    with _ntfy_lock:
        proc = _ntfy_proc
        _ntfy_proc = None
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("[ntfy] ntfy.exe stopped")


def _ntfy_watchdog() -> None:
    """Restart ntfy.exe if it exits unexpectedly. Runs in a daemon thread."""
    import time
    while _ntfy_alive:
        time.sleep(10)
        if not _ntfy_alive:
            break
        with _ntfy_lock:
            dead = _ntfy_proc is not None and _ntfy_proc.poll() is not None
        if dead:
            print("[ntfy] ntfy.exe exited unexpectedly — restarting...")
            _start_ntfy()


# ── icon ──────────────────────────────────────────────────────────────────────

def _create_icon_image():
    """Draw the NetMon tray icon — green hexagon on dark circle."""
    from PIL import Image, ImageDraw
    import math

    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    draw.ellipse([2, 2, size - 2, size - 2], fill=(18, 22, 30, 255))

    cx, cy, r = size // 2, size // 2, size // 2 - 8
    pts = [
        (cx + r * math.cos(math.radians(60 * i - 30)),
         cy + r * math.sin(math.radians(60 * i - 30)))
        for i in range(6)
    ]
    draw.polygon(pts, outline=(0, 220, 130, 255), fill=None, width=3)

    d = 5
    draw.ellipse([cx - d, cy - d, cx + d, cy + d], fill=(0, 220, 130, 255))

    return img


# ── uvicorn ───────────────────────────────────────────────────────────────────

def _start_uvicorn() -> None:
    """Run uvicorn (blocking). Called in a daemon thread.

    BIND_HOST defaults to 0.0.0.0 so the dashboard stays reachable from
    other devices on the home LAN. Set BIND_HOST=127.0.0.1 in .env to
    lock it down to this machine only.
    """
    try:
        import uvicorn
        from dotenv import load_dotenv
        load_dotenv()  # launch.py runs before app.main, so .env isn't loaded yet
        host = os.getenv("BIND_HOST", "0.0.0.0").strip() or "0.0.0.0"
        try:
            port = int(os.getenv("APP_PORT", "8000"))
        except ValueError:
            port = 8000
        uvicorn.run(
            "app.main:app",
            host       = host,
            port       = port,
            reload     = False,
            log_config = None,
        )
    except Exception as exc:
        _alert(f"NetMon server crashed:\n\n{exc}")


# ── tray actions ──────────────────────────────────────────────────────────────

def _app_port() -> int:
    try:
        return int(os.getenv("APP_PORT", "8000"))
    except ValueError:
        return 8000


def _dashboard_url() -> str:
    return f"http://localhost:{_app_port()}"


def _open_dashboard(icon=None, item=None):
    webbrowser.open(_dashboard_url())


def _open_ntfy(icon=None, item=None):
    webbrowser.open(_NTFY_URL)


def _stop(icon, item=None):
    global _ntfy_alive
    _ntfy_alive = False
    _stop_ntfy()
    icon.stop()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    try:
        import pystray
    except ImportError:
        _alert("pystray is not installed.\n\nRun:  pip install pystray pillow")
        sys.exit(1)

    try:
        icon_image = _create_icon_image()
    except Exception as exc:
        _alert(f"Failed to create tray icon:\n\n{exc}")
        sys.exit(1)

    # Start ntfy first (fast)
    _start_ntfy()
    threading.Thread(target=_ntfy_watchdog, daemon=True, name="ntfy-watchdog").start()

    # Start the FastAPI/uvicorn server
    threading.Thread(target=_start_uvicorn, daemon=True, name="uvicorn").start()

    # Open the browser once the server is ready
    def _delayed_open():
        import time
        time.sleep(3)
        _open_dashboard()

    threading.Thread(target=_delayed_open, daemon=True).start()

    # Single tray icon — blocks until user clicks Stop NetMon
    try:
        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard",   _open_dashboard, default=True),
            pystray.MenuItem("Open ntfy Web UI", _open_ntfy),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Stop NetMon",      _stop),
        )
        icon = pystray.Icon("NetMon", icon_image, "NetMon [LIVE]", menu)
        icon.run()
    except Exception as exc:
        _alert(f"Tray icon failed:\n\n{exc}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        _alert(f"Unexpected error:\n\n{exc}")
        sys.exit(1)
