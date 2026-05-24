# NetMon Install Guide

This guide is the happy path for getting NetMon running on a Windows machine.

## Supported environment

- Windows 10 or Windows 11
- Python 3.10 or newer
- PowerShell
- Administrator access for network scans, firewall actions, DNS binding, and packet capture features

## Required dependency

Install nmap and make sure it is available on `PATH`:

- <https://nmap.org/download.html>

Verify it from PowerShell:

```powershell
nmap --version
```

## Optional dependencies

NetMon can run without these, but some features depend on them:

- Ollama for local AI explanations
- Wireshark for `dumpcap` / `tshark` traffic summaries
- ntfy for local push notifications
- WSL + Kali tools for Security Lab workflows

## Quick install

```powershell
git clone https://github.com/landonlockhart15-rgb/netmon.git
cd netmon
powershell -ExecutionPolicy Bypass -File .\tools\setup.ps1
.\start.bat
```

The setup script creates a Python virtual environment, installs dependencies, copies `.env.example` to `.env`, prompts you to set a dashboard login, and creates a desktop shortcut.

## First run checklist

1. Start NetMon with `start.bat`.
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

## Troubleshooting

### `nmap not found`

Install nmap and add it to `PATH`, then open a new PowerShell window and run:

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
