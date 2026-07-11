# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for NetMon (one-dir, windowed, admin-elevated).

Build:
    python -m PyInstaller NetMon.spec --noconfirm --clean

Toggles (env vars, for testing):
    NETMON_UAC=0      -> do NOT embed the admin manifest (run unelevated; lets
                         a smoke test launch it without a UAC prompt)
    NETMON_CONSOLE=1  -> build with a console window (see stdout while testing)

Output: dist/NetMon/NetMon.exe  (+ dist/NetMon/_internal/...)
"""

import os
from PyInstaller.utils.hooks import collect_submodules

_uac     = os.environ.get("NETMON_UAC", "1") != "0"
_console = os.environ.get("NETMON_CONSOLE", "0") == "1"

# ── Hidden imports ──────────────────────────────────────────────────────────
# uvicorn/scapy load a lot lazily; our own packages use some function-level and
# dynamic imports (e.g. the scheduler loops) that static analysis can miss.
hiddenimports = []
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("scapy")
for pkg in ("app", "api", "ai", "monitoring", "network",
            "scanner", "security", "dns_blocker", "traffic", "models"):
    hiddenimports += collect_submodules(pkg)
hiddenimports += [
    "anyio", "h11", "click", "starlette",
    "bcrypt", "dnslib", "psutil", "pynetgear",
    "pystray", "pystray._win32", "PIL", "PIL.Image", "PIL.ImageDraw",
    "dotenv",
    # Optional AI SDKs — only used if the user enables a cloud provider, but
    # bundle them so enabling one at runtime never ImportErrors.
    "anthropic", "openai",
]

# ── Bundled read-only data ──────────────────────────────────────────────────
datas = [
    ("static", "static"),          # built React dashboard (required to boot)
    ("config", "config"),          # ntfy/server.example.yml (optional template)
    (".env.example", "."),         # template copied to %LOCALAPPDATA%\NetMon\.env
]

a = Analysis(
    ["netmon_app.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "pytest", "PyInstaller"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="NetMon",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=_console,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=_uac,                # embed "requireAdministrator" manifest
    icon="static/netmon.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="NetMon",
)
