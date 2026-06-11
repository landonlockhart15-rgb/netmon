# Contributing to NetMon

Thanks for your interest in NetMon! It's a local-first home network security
console for Windows — a FastAPI + SQLite backend with a React dashboard, run
from a system-tray app. Contributions of all sizes are welcome.

> **Authorized use only.** NetMon includes active scanning and a Security Lab.
> Only use it against networks and devices you own or are explicitly authorized
> to test. Don't submit features whose primary purpose is unauthorized access.

## Project layout

| Path | What's there |
|---|---|
| `app/` | FastAPI app factory (`main.py`), DB/session (`database.py`), auth, path helpers |
| `api/` | HTTP routes (`routes.py`, `auth_routes.py`) |
| `monitoring/` | Background scheduler loops (health, traffic, anomaly, autoheal, …) |
| `network/` | Autodetect, discovery, OUI/GeoIP, firewall protection |
| `scanner/` | nmap-based device discovery |
| `dns_blocker/` | Local DNS ad-blocking server + blocklists |
| `traffic/` | Packet capture + analysis (scapy/dumpcap) |
| `security/` | Security Lab tool wrappers (WSL/Kali) |
| `ai/` | Provider chain, prompts, threat intel, knowledge |
| `static/` | **Built** React dashboard (committed; build it from `frontend/`) |
| `frontend/` | React/Vite source for the dashboard |

See [ARCHITECTURE.md](ARCHITECTURE.md) for how these fit together.

## Dev setup

```powershell
git clone https://github.com/landonlockhart15-rgb/netmon.git
cd netmon
powershell -ExecutionPolicy Bypass -File .\tools\setup.ps1
.\start.bat
```

`setup.ps1` creates `.venv`, installs `requirements.txt`, seeds `.env`, and
prompts for a dashboard login. Run from source with `.\start.bat` (it requests
admin, which several features need) or directly:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Frontend

The dashboard in `static/` is the built output of `frontend/`. To work on it:

```powershell
cd frontend
npm install
npm run dev        # dev server on :5173, proxies the API
npm run build      # rebuilds into ..\static\  (commit the result)
```

## Building the installer

The packaged app freezes with PyInstaller and is wrapped by Inno Setup.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
winget install JRSoftware.InnoSetup       # one time
powershell -ExecutionPolicy Bypass -File .\tools\build_installer.ps1
```

This produces `dist\NetMon\NetMon.exe` (the frozen app) and
`installer\Output\NetMon-Setup-<version>.exe` (the double-click installer).

How freezing works (worth knowing before you touch paths):

- `netmon_app.py` is the frozen entry point. It calls `netmon_runtime.py` to set
  up **writable** user data under `%LOCALAPPDATA%\NetMon` (DB, `.env`, logs,
  captures) and to redirect stdout/stderr to a log file, **before** importing
  anything under `app.*`.
- Read-only bundled assets (`static/`, `.env.example`, `config/`) live in the
  PyInstaller bundle and are resolved via `app/paths.py:static_dir()`.
- Because of that split, **never hard-code a relative path to `static/`** for
  serving, and **never write data under the bundle** — use the helpers.
- `NETMON_SELFTEST=1` runs a serve-only path (no tray, no instance lock) — handy
  for smoke-testing a build without disturbing a running instance.

## Validation and Testing

To verify changes before committing, run the standardized validation runner:

```powershell
powershell -ExecutionPolicy Bypass -File .\validate.ps1
```

This script automates:
1. Environment detection (resolving virtual environment `.venv` or system Python installs).
2. Python compilation checks (`compileall`) to catch syntax/import errors.
3. Test database creation, schema migrations, and default settings seeding.
4. Running unit tests (`python -m unittest discover -s tests -v`).
5. Running Uptime Guardian (Autoheal) dry-runs (`python tools/test_autoheal.py`).

### Script Command Options

You can pass the following parameters to `validate.ps1` to customize its execution:

- `-CompileOnly`
  Only run compilation checks on python source files (very fast; useful for quick checks).
- `-SkipCompile`
  Skip the compilation checks and jump straight to DB initialization and tests.
- `-TestFile <path>`
  Run a specific unit test file (e.g. `tests/test_anomaly.py`) instead of discovering all tests.
- `-ListTests`
  Show a list of all available test files under the `tests` directory along with usage help.
- `-IncludeSecurity`
  Include WSL/Kali Linux security lab integration tests (requires WSL and Kali installed locally).

### Manual Individual Runs

If you prefer to run specific validation tasks manually:

- **Compilation check only**:
  ```powershell
  python -m compileall ai api app monitoring network scanner traffic
  ```
- **Unit tests only**:
  ```powershell
  python -m unittest discover -s tests -v
  ```
- **Autoheal guardian tests only**:
  ```powershell
  python tools/test_autoheal.py
  ```
- **Security integration tests only** (requires WSL/Kali):
  ```powershell
  python security_test.py
  ```

## Coding conventions

- Match the surrounding style; keep changes focused and self-contained.
- No dead code or unused imports — clean up in the same pass.
- Keep secrets out of the repo. Real values go in a local, gitignored `.env`;
  only `.env.example` (with empty/commented keys) is committed.
- Background loops live in `monitoring/scheduler.py`; keep them cancellable.

## Pull requests

1. Branch from `master`.
2. Make your change; verify it runs (`.\start.bat`) and, for build changes,
   that `tools\build_installer.ps1` still succeeds.
3. Open a PR describing what changed and how you tested it.
