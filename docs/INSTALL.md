# NetMon Install Guide

This guide is the happy path for getting NetMon running on a Windows machine.

## Supported environment

- Windows 10 or Windows 11
- Administrator access for network scans, firewall actions, DNS binding, and packet capture features

The downloadable installer includes NetMon and its Python runtime. You only
need Python 3.10+ and PowerShell when running NetMon from source.

## Required for network scans

NetMon needs [nmap](https://nmap.org/download.html#windows) for device discovery
and port scanning. On startup, the installed app checks for nmap and offers to
open its official download page if it is missing. It never installs external
software silently. You can continue without nmap, but scans will be unavailable.

Use the standard Windows nmap installer. NetMon detects both `PATH` and the
normal `C:\Program Files\Nmap` installation folders. Restart NetMon after
installing nmap.

Verify it from PowerShell:

```powershell
nmap --version
```

## Optional dependencies

NetMon can run without these, but some features depend on them:

- Ollama for local AI explanations
- **Npcap** for packet capture and deep traffic analysis (the scapy-based features)
- Wireshark for `dumpcap` / `tshark` traffic summaries
- ntfy for local push notifications
- WSL + Kali tools for Security Lab workflows

### Npcap (deep traffic analysis)

Device discovery, health, and DNS blocking work **without** Npcap. But the
Traffic Analysis / deep packet inspection features rely on
[scapy](https://scapy.net/), which on Windows needs the **Npcap** capture driver
to actually see packets — without it those features load but capture nothing.

Install it from <https://npcap.com> (Wireshark's installer also bundles it). On
the Npcap installer screen, leave **"Install Npcap in WinPcap API-compatible
mode"** checked. Traffic Analysis is off by default; you only need Npcap if you
turn it on.

## Option A — installer (no Python required)

Download `NetMon-Setup-<version>.exe` from the
[latest release](https://github.com/landonlockhart15-rgb/netmon/releases/latest)
and run it. NetMon installs to Program Files and adds a Start Menu shortcut.
User data (database, captures, logs, `.env`) is stored under
`%LOCALAPPDATA%\NetMon`. On first launch it generates a dashboard login and
displays it (also saved to `FIRST-RUN-LOGIN.txt` in that data folder).

The installer is unsigned, so Windows SmartScreen may warn — choose
**More info → Run anyway**. At first launch:

1. NetMon creates a strong dashboard login and offers to copy its password to the clipboard.
2. It shows the exact recovery-file path under `%LOCALAPPDATA%\NetMon`.
3. It checks for nmap and offers the official download page if needed.
4. The sign-in page opens automatically at <http://localhost:8000>.

Delete `FIRST-RUN-LOGIN.txt` after signing in and saving the login in your
password manager. NetMon keeps only the password hash in `.env` after that.

## Option B — from source

Source installs require Python 3.10+, PowerShell, git, and nmap.

```powershell
git clone https://github.com/landonlockhart15-rgb/netmon.git
cd netmon
powershell -ExecutionPolicy Bypass -File .\tools\setup.ps1
.\start.bat
```

The setup script creates a Python virtual environment, installs dependencies, copies `.env.example` to `.env`, prompts you to set a dashboard login, and creates a desktop shortcut.

## First run checklist

1. Start NetMon from the Start Menu (installer) or with `start.bat` (source).
2. Accept the administrator prompt when Windows asks.
3. Open the dashboard at <http://localhost:8000>.
4. Confirm the Settings or Network panel shows your active adapter, local IP, gateway, subnet, DNS servers, and public IP.
5. Run a scan against your own LAN only.
6. Check the discovered devices and open-port results.

## Local AI setup

Install and start Ollama, then pull a small model:

```powershell
ollama pull qwen2.5:3b
```

Set these values in `.env`:

```dotenv
AI_PROVIDER=ollama
AI_FAST_MODEL=qwen2.5:3b
OLLAMA_HOST=http://localhost:11434
```

Cloud AI providers are optional. Keep provider keys in local environment variables or a gitignored `.env` file.

## Forcing a scan range

By default, NetMon can autodetect the active network:

```dotenv
SCAN_TARGET=auto
```

If autodetection does not choose the right network, set a CIDR range manually:

```dotenv
SCAN_TARGET=192.168.1.0/24
```

## Notifications (ntfy)

NetMon can start a local ntfy server from the tray app when `ntfy.exe` is
available. Put ntfy on `PATH`, or set these in `.env`:

```dotenv
NTFY_EXE=C:\ntfy\ntfy.exe
NTFY_CONFIG=C:\ntfy\server.yml
NTFY_URL=http://localhost:2586
```

An example config lives at `config\ntfy\server.example.yml` — copy it to
`config\ntfy\server.yml` or point `NTFY_CONFIG` at your own. For phone action
buttons, the phone must reach the ntfy URL over your LAN, so use the NetMon PC's
LAN IP (for example `http://192.168.1.64:2586`) instead of `localhost`.

## Troubleshooting

### `nmap not found`

Install nmap from its [official Windows download page](https://nmap.org/download.html#windows),
then restart NetMon. NetMon checks `PATH` and both standard Program Files
locations. To verify it manually, open a new PowerShell window and run:

```powershell
nmap --version
```

### Dashboard says no password is set

Run:

```powershell
.\.venv\Scripts\python.exe tools\set_password.py --write
```

### DNS blocker will not start

Another service may already be using port 53. Stop the conflicting DNS service or disable the DNS blocker feature.

### ntfy action buttons cannot connect

Use the NetMon PC's LAN IP in the ntfy URL instead of `localhost`, for example:

```text
http://192.168.1.64:2586
```

## Safety reminder

Only scan networks and devices you own or have explicit permission to test.
