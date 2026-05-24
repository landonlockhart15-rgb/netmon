# NetMon

**Status:** Active personal project / usable local prototype  
**Audience:** Windows users who want local network visibility, defensive security tooling, and AI-assisted explanations without sending routine network data to a cloud dashboard.  
**Safety note:** NetMon is intended for networks you own or are explicitly authorized to test.

NetMon is a local-first network security console for Windows. It discovers
devices on your LAN, monitors connection health, summarizes traffic, runs a DNS
ad blocker, provides a Security Lab for authorized testing, and can use local AI
models to explain what it sees.

The app is designed to run from a tray icon with a browser dashboard at
<http://localhost:8000>.

## Why this exists

Most home-network tools are either too shallow, too cloud-dependent, or aimed at
professional SOC teams. NetMon is a practical middle ground: a local dashboard
for understanding what is on your network, what changed, what looks suspicious,
and what you can do next.

## Features

- Device discovery with nmap, device history, change detection, and open ports
- Health checks for internet and router latency
- Traffic capture summaries with Wireshark `dumpcap` / `tshark`
- DNS ad blocking with StevenBlack, OISD, and AdGuard blocklists
- Anomaly detection, threat-intel checks, and reversible firewall actions
- Local AI analysis through Ollama, with optional cloud provider fallbacks
- Security Lab wrappers for authorized tests through WSL/Kali tools
- Optional ntfy push notifications with action buttons

## Requirements

- Windows 10/11
- Python 3.10+
- [nmap](https://nmap.org/download.html) on PATH
- Optional:
  - [Ollama](https://ollama.com) for local AI models
  - [Wireshark](https://www.wireshark.org/) for traffic capture
  - [ntfy](https://docs.ntfy.sh/install/) for self-hosted push notifications
  - WSL + Kali for Security Lab tools such as Nikto, Hydra, John, Metasploit,
    Aircrack-ng, and Shodan checks

## Quick Start

```powershell
git clone https://github.com/landonlockhart15-rgb/netmon.git
cd netmon
powershell -ExecutionPolicy Bypass -File .\tools\setup.ps1
.\start.bat
```

The setup script creates a `.venv`, installs Python dependencies, copies
`.env.example` to `.env`, prompts you to create the dashboard login, and creates
a desktop shortcut.

`start.bat` asks for administrator permission because some features need it:
nmap discovery, firewall actions, DNS service binding on port 53, and capture
tools.

## Local AI Setup

NetMon can run without AI, but the investigation features expect a configured
provider. For local-only AI:

```powershell
ollama pull qwen2.5:3b
```

Then set this in `.env`:

```dotenv
AI_PROVIDER=ollama
AI_FAST_MODEL=qwen2.5:3b
OLLAMA_HOST=http://localhost:11434
```

You can also set `AI_DEEP_MODEL` to a larger local model if your PC can run it.
Cloud provider API keys are optional. Keep them private as Windows environment
variables or in a local gitignored `.env` file.

## Network Detection

By default, `.env.example` uses:

```dotenv
SCAN_TARGET=auto
```

On startup and before scans, NetMon asks Windows for the active adapter, gateway,
and subnet. If autodetect fails or you want to force a range, set `SCAN_TARGET`
to a CIDR or nmap range:

```dotenv
SCAN_TARGET=192.168.1.0/24
```

The dashboard Settings and Network panels show the detected adapter, local IP,
gateway, subnet, DNS servers, and public IP.

## Optional ntfy Notifications

NetMon can start a local ntfy server from the tray app when `ntfy.exe` is
available. Put ntfy on PATH or set these values in `.env`:

```dotenv
NTFY_EXE=C:\ntfy\ntfy.exe
NTFY_CONFIG=C:\ntfy\server.yml
NTFY_URL=http://localhost:2586
```

An example server config is available at
`config\ntfy\server.example.yml`. Copy it to `config\ntfy\server.yml` or point
`NTFY_CONFIG` to your own file.

For phone action buttons, the phone must be able to reach the ntfy URL from your
LAN. In the Settings tab, use a LAN URL such as `http://192.168.1.64:2586`
instead of `localhost`.

## Privacy And Local Data

NetMon keeps runtime data on your PC. These files are intentionally ignored by
git and should not be published:

- `.env`
- `data/`
- `*.db`, `*.sqlite`, `*.sqlite3`
- packet captures such as `*.pcap` and `*.pcapng`
- `security_uploads/`
- DNS blocklist caches under `dns_blocker/.cache/`
- Python caches and logs

Do not commit your `.env`, database, ntfy auth/cache databases, packet captures,
or uploaded wordlists.

API keys and notification passwords should be provided as private local
environment variables. A local `.env` file is supported for convenience on a
single PC, but it must remain gitignored. The public repo should contain only
`.env.example` with blank placeholder values.

## Useful Commands

```powershell
# Start with the tray icon
.\start.bat

# Start the web server directly from the virtual environment
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Create or update the dashboard login
.\.venv\Scripts\python.exe tools\set_password.py --write

# Register the optional background scheduled task
powershell -ExecutionPolicy Bypass -File .\install_task.ps1
```

## Troubleshooting

- `nmap not found`: install nmap and add it to PATH.
- Scan returns the wrong devices: check the Network panel. If needed, set
  `SCAN_TARGET` in `.env`.
- Dashboard login says no password is set: run
  `.\.venv\Scripts\python.exe tools\set_password.py --write`.
- AI says it is not configured: start Ollama and set `AI_PROVIDER=ollama`, or
  add the provider API key you want to use.
- DNS blocker will not start: another service is using port 53. Run as Admin and
  stop the conflicting DNS service.
- ntfy action buttons cannot connect: use the NetMon PC's LAN IP in the ntfy
  server URL, not `localhost`.
