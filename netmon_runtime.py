"""
netmon_runtime.py — frozen-aware runtime bootstrap for NetMon.

This module is intentionally dependency-light so it can run *before*
``app.database`` / ``app.main`` are imported (those read ``DATABASE_URL`` and
the password hash at import time). The packaged (PyInstaller) entry point
``netmon_app.py`` calls these helpers first to set up writable data paths,
logging, the ``.env`` file, and first-run credentials.

Path model when frozen:
  - **Read-only bundled assets** (static/, .env.example, config/) live in the
    PyInstaller bundle → ``resource_root()`` (``sys._MEIPASS``).
  - **Writable, persistent user data** (DB, .env, logs, captures) lives in
    ``%LOCALAPPDATA%\\NetMon`` → ``data_home()``.

Source runs (``start.bat`` / ``python launch.py``) keep the original behavior:
everything lives in the repository directory and nothing here changes it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_log_fh = None  # keep the redirected log handle alive for the process lifetime


def is_frozen() -> bool:
    """True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """Directory holding bundled read-only assets (static/, .env.example, config/)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", None) or Path(sys.executable).parent)
    return Path(__file__).resolve().parent


def data_home() -> Path:
    """Writable, persistent per-user directory for DB, .env, logs, captures."""
    if is_frozen():
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "NetMon"
    else:
        base = Path(__file__).resolve().parent
    base.mkdir(parents=True, exist_ok=True)
    return base


def setup_logging() -> "Path | None":
    """
    Redirect stdout/stderr to a log file when frozen.

    A windowed (``console=False``) PyInstaller build has ``sys.stdout`` and
    ``sys.stderr`` set to ``None``; NetMon's many ``print()`` calls would then
    raise ``AttributeError`` and crash the app. Pointing both at a log file
    fixes that and gives us a real diagnostic trail. No-op for source runs.
    """
    global _log_fh
    if not is_frozen():
        return None
    logs = data_home() / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / "netmon.log"
    try:
        _log_fh = open(log_path, "a", encoding="utf-8", buffering=1)  # line-buffered
        sys.stdout = _log_fh
        sys.stderr = _log_fh
        _log_fh.write("\n=== NetMon start ===\n")
        _log_fh.flush()
    except Exception:
        pass
    return log_path


def _load_env_file(env_path: Path) -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path, override=False)
    except Exception:
        pass


def _readable_password(length: int = 16) -> str:
    """A strong but transcribable password (no ambiguous characters)."""
    import secrets
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _write_env(path: Path, values: dict[str, str]) -> None:
    """Update-or-append keys in a .env file, preserving comments and order."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if key in values and not stripped.startswith("#"):
            out.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            out.append(line)
    if out and out[-1].strip():
        out.append("")
    for key, value in values.items():
        if key not in seen:
            out.append(f"{key}={value}")
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def _ensure_password(env_path: Path) -> "tuple[str, str] | None":
    """
    Guarantee a dashboard login exists. On first run (no APP_PASSWORD_HASH),
    generate a strong random password, bcrypt-hash it into .env, and return
    ``(username, plaintext_password)`` so the caller can show it once. Returns
    ``None`` when credentials already exist.
    """
    user = os.getenv("APP_USERNAME", "").strip()
    hsh = os.getenv("APP_PASSWORD_HASH", "").strip()
    if user and hsh:
        return None
    import bcrypt
    username = user or "admin"
    password = _readable_password()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    _write_env(env_path, {"APP_USERNAME": username, "APP_PASSWORD_HASH": hashed})
    os.environ["APP_USERNAME"] = username
    os.environ["APP_PASSWORD_HASH"] = hashed
    # Also drop a recoverable note next to the data so the user isn't locked out
    # if they dismiss the dialog. Clearly labeled; safe to delete.
    try:
        note = env_path.parent / "FIRST-RUN-LOGIN.txt"
        note.write_text(
            "NetMon dashboard login (created on first run)\n"
            f"  Username: {username}\n"
            f"  Password: {password}\n\n"
            "Change it any time by deleting APP_PASSWORD_HASH from .env and\n"
            "restarting, or with tools/set_password.py. You can delete this file.\n",
            encoding="utf-8",
        )
    except Exception:
        pass
    return (username, password)


def bootstrap_env() -> "tuple[str, str] | None":
    """
    Prepare the environment + filesystem so ``app.*`` imports resolve to
    writable paths. MUST be called before importing ``app.database`` /
    ``app.main``. Returns first-run credentials (or ``None``).

    No-op-ish for source runs: ``data_home()`` is the repo dir, so this just
    ensures data/ exists and a .env is present, matching existing behavior.
    """
    home = data_home()
    (home / "data").mkdir(parents=True, exist_ok=True)

    # Writable SQLite DB unless the user explicitly set DATABASE_URL.
    if not os.environ.get("DATABASE_URL"):
        db_path = (home / "data" / "netmon.db").as_posix()
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    os.environ.setdefault("NETMON_DATA_DIR", str(home / "data"))
    scapy_cache = home / "data" / "scapy_cache"
    scapy_cache.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("SCAPY_CACHE_DIR", str(scapy_cache))

    # Seed a writable .env from the bundled template on first run.
    env_path = home / ".env"
    if not env_path.exists():
        template = resource_root() / ".env.example"
        try:
            env_path.write_text(
                template.read_text(encoding="utf-8") if template.exists() else "",
                encoding="utf-8",
            )
        except Exception:
            pass
    _load_env_file(env_path)

    # Relative "data/..." writes from any module should land in the writable home.
    try:
        os.chdir(home)
    except Exception:
        pass

    return _ensure_password(env_path)


def show_first_run_dialog(username: str, password: str) -> None:
    """Show the generated login once, via a native message box (best-effort)."""
    msg = (
        "NetMon created your dashboard login:\n\n"
        f"    Username:  {username}\n"
        f"    Password:  {password}\n\n"
        "Write this down — you'll need it to sign in at http://localhost:8000.\n"
        "It's also saved to FIRST-RUN-LOGIN.txt in your NetMon data folder."
    )
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, "NetMon — your login", 0x40)
    except Exception:
        print(msg)
