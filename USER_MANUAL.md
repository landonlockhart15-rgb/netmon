# NetMon — User & Developer Manual

A complete reference to your home network monitoring, security, and AI investigation platform.

---

**Version:** 1.0
**Audience:** End user (Part I) and developer / power-user (Part II)
**Project root:** `C:\Projects\netmon`
**Stack:** Python (FastAPI) + SQLite + plain HTML/CSS/JS
**Repo:** https://github.com/landonlockhart15-rgb/netmon

---

## Table of Contents

### Part I — User Manual

1. [What NetMon Is](#1-what-netmon-is)
2. [Quick Start](#2-quick-start)
3. [The Dashboard at a Glance](#3-the-dashboard-at-a-glance)
4. [Devices](#4-devices)
5. [Network Health & Speed](#5-network-health--speed)
6. [Traffic Capture & Analysis](#6-traffic-capture--analysis)
7. [DNS Ad/Tracker Blocker](#7-dns-adtracker-blocker)
8. [Security Shield](#8-security-shield)
9. [AI Investigation](#9-ai-investigation)
10. [Activity Log & History](#10-activity-log--history)
11. [Security Lab](#11-security-lab)
12. [Phone Notifications & Remote Control (ntfy)](#12-phone-notifications--remote-control-ntfy)
13. [Settings Reference](#13-settings-reference)
14. [Companion: AI Services Dashboard & Sentinel](#14-companion-ai-services-dashboard--sentinel)

### Part II — Developer Manual

15. [Architecture Overview](#15-architecture-overview)
16. [Process & Startup Lifecycle](#16-process--startup-lifecycle)
17. [Background Loops (Scheduler)](#17-background-loops-scheduler)
18. [Database Schema](#18-database-schema)
19. [API Surface](#19-api-surface)
20. [AI Provider Chain](#20-ai-provider-chain)
21. [Anomaly Detection Internals](#21-anomaly-detection-internals)
22. [DNS Blocker Internals](#22-dns-blocker-internals)
23. [Security Lab Internals](#23-security-lab-internals)
24. [Autonomous Actions & Revert System](#24-autonomous-actions--revert-system)
25. [Frontend Architecture](#25-frontend-architecture)
26. [Files & Modules Map](#26-files--modules-map)
27. [Troubleshooting & Operations](#27-troubleshooting--operations)

---
---

# Part I — User Manual

---

## 1. What NetMon Is

NetMon is a **self-hosted home network monitor and security console** that runs on a single Windows PC and watches your entire LAN. It is designed to feel like a tiny SOC (Security Operations Center) for a home network — without sending any data to a cloud provider you don't control.

**It does six big things:**

1. **Discovers and tracks every device** on your network (continuously, automatically)
2. **Watches the health** of your internet connection and router (latency, packet loss, outages)
3. **Captures and analyzes traffic** so you can see what your devices are actually talking to
4. **Blocks ads, trackers, and malware domains** at the DNS level (network-wide, no per-device setup)
5. **Detects anomalies** (port scans, traffic spikes, sustained heavy use, degraded health) and acts on them
6. **Investigates suspicious activity using AI** — and can autonomously take low-risk actions (block an IP, dismiss noise)

It also talks to your phone via **ntfy** push notifications, so you get alerts wherever you are and can issue commands like `investigate 192.168.1.45` or `block 1.2.3.4` from the notification itself.

**Privacy posture:** All data is local. The AI investigation uses a "free-first" provider chain (Cerebras → Groq → SambaNova → OpenRouter → Gemini → local Ollama Qwen). You can run AI entirely on your own machine if you want.

---

## 2. Quick Start

### Starting NetMon

The simplest way:

```
launch.py           # Tray icon (recommended) — starts ntfy + uvicorn together
```

Or directly:

```
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

> **Admin required.** NetMon uses `nmap` (raw packets), `netsh advfirewall` (firewall rules), and binds UDP port 53 for the DNS blocker. All three need elevation. Run from an elevated PowerShell or use the included tray-icon launcher that prompts for elevation.

### Opening the Dashboard

Browse to: **http://localhost:8000** (or `http://<your-PC's-LAN-IP>:8000` from another device on the same network).

Default behavior: NetMon binds to `0.0.0.0` so it's reachable from your phone on the same Wi-Fi. Lock that down by setting `BIND_HOST=127.0.0.1` in `.env`.

### First Time

1. Set a dashboard password (the setup script `tools/setup.ps1` will prompt; or `tools/set_password.py` manually).
2. Sign in.
3. Wait ~30 seconds for the first nmap scan to populate the **Devices** tab.
4. Label your known devices ("Mom's laptop", "Living room TV", etc.) — this stops them showing as "unknown" and prevents nighttime alerts on them.

---

## 3. The Dashboard at a Glance

The left sidebar holds the navigation. Each section corresponds to a primary capability:

| Section | What It Shows |
|---|---|
| **Shield** | The "current state of the network" view: threat level, autonomous actions, anomaly feed, firewall blocks, AI investigations |
| **Devices** | Every device ever seen, with current/all filter, list/map views, per-device modal |
| **Health** | Continuous ping graph (internet + router), latency, packet loss, on-demand speed test |
| **Traffic** | Live capture controls, packet/byte totals, top talkers, top destinations, protocol mix, DNS counts |
| **DNS** | Ad/tracker blocker status, top blocked domains, blocklist sources, whitelist editor |
| **Logs** | Unified activity log (every automated action, scan, AI verdict, firewall change, threat hit) |
| **Security Lab** | Offensive-security toolbox (Nikto, Hydra, John, Metasploit, Aircrack, Shodan) |
| **Settings** | All thresholds, intervals, AI provider, ntfy config |

**Quick navigation tip:** The current state of every device, every block, and every alert is one click away from the Shield. If you want to know whether "anything is happening right now," go to Shield. If you want to know what happened over the last 7 days, go to Logs.

---

## 4. Devices

### What it does

Runs `nmap` against your subnet (auto-detected from your active network adapter) and remembers every device it has ever seen, keyed by MAC address where possible.

### How to use it

**Filter bar:**
- `All | Current` — toggle between "everything we've ever seen" and "showing up in the most recent scan"
- `List | Map` — table view vs. visual network map

**Per-device modal** (click any device row):
- **Label** — give it a friendly name. NetMon remembers labels forever.
- **Trust** — mark as known so it stops triggering "new device" alerts.
- **Scan history** — when this device first appeared, every scan it was seen in, every IP change.
- **Open ports** — services currently listening on the device.
- **Investigate** — kick off an AI investigation of this device (see §9).

### What runs automatically

- **Quick discovery scan** (`nmap -sn`) every hour — finds live hosts fast.
- **Deep scan** (`nmap -sV`) immediately whenever a new device appears — captures open ports and service versions.
- **New device alert** — pushes an ntfy notification (warning by day, **critical** by night).

### Why this matters

If a stranger or an unauthorized device hops on your Wi-Fi, you'll know within an hour (sooner if traffic anomalies wake the scan up). You'll also see immediately if a known device suddenly has open ports it shouldn't (e.g. a printer that magically starts hosting telnet).

---

## 5. Network Health & Speed

### What it does

Pings your configured internet target (default `8.8.8.8`) **and** your router every 5 minutes. Records latency, packet loss, and status (`online` / `degraded` / `offline`). Also runs on-demand speed tests.

### How to use it

**Health graph:** Scroll through latency and packet-loss history. Two lines: one for the internet, one for the router. If the router line stays flat but the internet line spikes, the problem is upstream of you (your ISP). If both spike, it's local.

**Speed test button:** Triggers a real-world multi-stream download (4 parallel TCP streams, 8-second wall-clock window) plus a single-stream upload test. Default URL is sized at 500 MB per stream so even multi-gigabit links can't EOF before the deadline.

**Thresholds (settable in Settings):**
- `latency_warn_ms` — above this, status = `degraded` (default 100)
- `latency_crit_ms` — informational only (default 300)
- `packet_loss_warn_pct` — above this, status = `degraded` (default 10%)

### What runs automatically

- Health check every `health_check_interval_s` seconds (default 300)
- Retention: ~2000 rows; oldest pruned automatically (~7 days at 5-min intervals)

---

## 6. Traffic Capture & Analysis

### What it does

Uses **dumpcap** (from Wireshark) to write a ring buffer of `.pcapng` files in `captures/`, and uses **tshark** to analyze them every 20 seconds, producing per-window snapshots of who talked to whom, how much, and what protocols.

### How to use it

**Start capture** — pick the interface (NetMon auto-detects active ones), set ring-file size and count, click start. NetMon keeps no packet payload; only summaries are persisted to the DB.

**Live view:**
- **Total packets / bytes** for the current window
- **Top talkers** (IPs on your LAN by bytes sent)
- **Top destinations** (external IPs by bytes received)
- **Protocol mix** (TCP/UDP/DNS/QUIC/etc.)
- **DNS counts** + **top domains** (DNS-name and TLS-SNI extraction)

**Cleanup:** Old captures are auto-deleted after `capture_retention_days` (default 3). A startup sweep also removes orphaned `*.pcapng` files left behind by crashes.

### What runs automatically

- **Capture watchdog** — if you had capture enabled and the dumpcap process dies unexpectedly, NetMon restarts it automatically.
- **Threat intel sweep** — top 10 external destinations are checked against blocklist feeds (AlienVault, Spamhaus, etc.). A confirmed hit triggers an auto-block, a notification, and a `threat_intel_hit` activity-log entry.

### Why this matters

If one of your devices suddenly starts beaconing to an unfamiliar IP every few seconds — say, a compromised IoT camera phoning home — you'll see it in the top-destinations list and the anomaly system will flag a `sustained_bandwidth` event.

---

## 7. DNS Ad/Tracker Blocker

### What it does

NetMon ships its own UDP DNS server (port 53). When you point your router or specific devices at it, every DNS query gets checked against a merged blocklist (StevenBlack hosts, OISD, AdGuard) plus your custom additions. Blocked domains return `NXDOMAIN` (the domain "does not exist"), so the device gives up immediately and never reaches the ad/tracker/malware server.

### How to use it

**Enable** in Settings: `dns_blocker_enabled = true`. Then either:
- Point your **router's DNS** at the NetMon PC's IP — covers every device on the network in one stroke
- Or point **specific devices** (a single TV, a kid's tablet) — for targeted blocking

**Top blocked domains** is the most useful day-to-day view: it shows what ads/trackers each device on your network is *trying* to call out to. This is also a great way to spot a misbehaving app (e.g., a "free" mobile game beaconing 400 times an hour).

**Whitelist editor:** add domains you don't want blocked (e.g., a legitimate analytics endpoint you need for work).

### What runs automatically

- **Auto DNS-health check** every 30 minutes (no AI tokens used). It looks at the last hour vs. the last 24h baseline of blocked queries and flags:
  - Blocker enabled but the server isn't running
  - Block rate collapsed (possible bypass / upstream change)
  - A single domain spiking ≥5× its baseline (or new domain hitting ≥30/hour)
  - A single client IP making ≥100 blocked queries/hour (probably a runaway tracker library in an app)

These findings, when found, write a single `dns_health` activity-log entry — silent on healthy windows.

### Why this matters

Network-wide ad blocking improves speed, reduces data usage, and stops surveillance trackers. The auto-monitor turns the blocker into an early-warning system: if your TV suddenly tries to contact a brand-new tracking domain 60 times an hour, you'll know.

---

## 8. Security Shield

### What it does

The Shield is the **command center**. It pulls the most important real-time signals into one place:

- **Threat banner** — green ("NETWORK SECURE"), yellow ("ANOMALY DETECTED"), red ("THREAT ACTIVE")
- **Layered status cards** — auto-scan, health, anomaly, threat intel, nighttime mode, traffic, AI, autonomous report, notifications
- **Autonomous Actions table** — every action NetMon took without you clicking (auto-blocks, AI auto-execute, ntfy commands) with an **Undo** button
- **Active firewall blocks** — current `NetMon-AutoBlock-*` rules from `netsh advfirewall`
- **Anomaly feed** — recent traffic spikes, port scans, outages
- **Recent AI investigations** — quick-glance verdicts

### How to use it

**Glance, don't read.** The banner color tells you everything in 1 second. If it's green and the autonomous-actions table is empty, your network is quiet.

**Click Undo** on any autonomous action to revert it (e.g., remove an auto-block firewall rule). The revert is replayed through the same `ai_resolve` path that originally executed it, so it works regardless of how the rule was named.

### What runs automatically

The Shield is *read-only display* — the work happens in the background loops (anomaly detection, threat intel, scheduled scans). It auto-refreshes every 5 seconds while open, but pauses refresh while an AI investigation is streaming so the live token feed doesn't get torn out from under you.

---

## 9. AI Investigation

### What it does

When you click **Investigate** on a device, a Shield event, or a security log entry, NetMon:

1. Gathers structured evidence (device history, recent traffic, open ports, threat-intel hits, related log entries)
2. Builds a focused prompt
3. Streams it to the AI provider chain (free models first; local Ollama as the final fallback)
4. Renders the result live token-by-token via `/api/ai/progress` polling
5. Saves the verdict to the database

### The verdict structure

Each investigation returns:

- **Verdict** — `normal` | `noise` | `suspicious`
- **What** — plain-English description of what the AI thinks is happening
- **Findings** — itemized observations from the evidence
- **Proposed resolutions** — specific actions (e.g., "block IP 1.2.3.4", "label this device", "dismiss this alert as noise")
- **Auto-execute** — for safe, low-risk actions (e.g., dismissing a benign-looking DNS noise alert), NetMon may apply the resolution automatically and write a paired `ai_auto` audit-log row with a revert payload

### How to use it

**Click Investigate** anywhere it appears (device modal, Shield event, security log row). Watch the result stream in. Pick which (if any) proposed resolutions to apply.

**Cost:** Free by default — the chain prefers Cerebras/Groq/SambaNova/OpenRouter/Gemini free tiers. If you've set `ANTHROPIC_API_KEY` and `AI_PROVIDER=anthropic`, it uses Claude instead (paid).

### What runs automatically

- **Hourly Autonomous Report** runs every 2 hours by default (token-conscious). It synthesizes the last 2 hours of traffic, health, and security events into a plain-English summary. If nothing notable happened in the window, it skips the LLM call entirely and writes a deterministic "all quiet" record. A forced 24h heartbeat guarantees at least one real report per day even on quiet stretches.
- **Bandwidth anomaly auto-investigate** — when the anomaly loop detects a `traffic_spike` or `sustained_bandwidth` event, an investigation is fired automatically (fire-and-forget HTTP to the running server).

---

## 10. Activity Log & History

### What it does

Every meaningful event in NetMon — scans, AI verdicts, firewall changes, threat hits, capture starts/stops, autonomous actions — writes a row to a unified **activity_log** table. The Logs section is your audit trail.

### How to use it

**Filters:**
- Level: `info` / `warning` / `critical` / `action` / `threat`
- Category: `scan` / `traffic` / `ai` / `firewall` / `threat` / `system` / `alert` / `dns`
- Event name, actor, device IP — typed as filters
- Free-text search across summary, detail, event, actor, device IP

**AI history synthesis** — click "Analyze last 7 days" to ask the AI to summarize the last week of activity (common issues, repeated patterns, safe autonomous suggestions). This is on-demand; it doesn't run automatically.

**Insights endpoint** — `GET /api/logs/insights?days=7` returns a deterministic (no-AI) summary if you want to script against it.

### What runs automatically

- **Log cleanup** runs daily:
  - DNS entries older than 7 days are deleted (high volume, low long-term value)
  - All other entries older than 30 days are deleted

- The previously-existing "Learn DNS noise" button was **removed** (it was always token-free, but its job is now done continuously by the new auto DNS-health loop — see §7).

### Retention

| Table | Retention |
|---|---|
| `activity_log` (DNS) | 7 days |
| `activity_log` (other) | 30 days (or hard cap of 10,000 rows) |
| `health_checks` | ~2000 rows (~7 days at 5-min) |
| `traffic_summaries` | ~500 rows |
| `security_reports` | last 200 rows |

---

## 11. Security Lab

### What it does

A point-and-click offensive-security toolbox for testing **your own** devices. NetMon shells out to industry-standard tools running under **WSL/Kali**. Every run is logged, streamed live, and gets a plain-English AI explanation when it finishes.

### Tabs

| Tab | Tool | Purpose |
|---|---|---|
| **Vulnerability Scan** | Nikto | Probe a web server for known weaknesses, default files, missing headers |
| **Password Test** | Hydra + John | Test password strength against your services (SSH, FTP, etc.) and crack hashes |
| **Exploit Test** | Metasploit (limited) | Run safe modules against your own devices |
| **WiFi Test** | Aircrack-ng | Capture WPA handshakes from your own AP and verify your password isn't weak |
| **Internet Exposure** | Shodan API | See what the public internet can see about your IP |

### How to use it

**Authorization checkbox required.** Attack tools require you to explicitly confirm you own / have permission to test the target. NetMon stores `authorization_confirmed=true` on the run row.

**Live output streams** through `/api/security/run/stream` while the tool runs. You'll see the scan happen in real time.

**AI explanation** — when the run completes, a fast local model (`qwen2.5:3b`) writes a plain-English summary of findings and safe fix suggestions. A "chat" panel lets you ask follow-ups (uses a stronger model like `gemma4` for better quality).

**History** — every past run is in the run table. Click a row to see the full output, AI explanation, and any cracked credentials/handshakes.

### Why this matters

This is white-hat home security: instead of *hoping* your router admin password is strong, *prove* it by running Hydra against it. Instead of guessing if your IP is exposing services to the public internet, *check* with Shodan. Instead of trusting that your camera doesn't have known CVEs, *scan* it with Nikto.

### Safety

- Tools execute through `_wsl_exe()` from `security/wsl.py` — never bare `wsl` strings (avoids injection)
- `stdin=subprocess.DEVNULL` everywhere to stop hangs
- Risk-level tagging on each tool; user must reconfirm for high-risk modes
- Output is text only; binary artifacts (handshakes, cracked hashes) are stored in `security/files/` with SHA256 deduplication

---

## 12. Phone Notifications & Remote Control (ntfy)

### What it does

NetMon ships with **ntfy** (a free open-source push notification server) running as a child process. Critical events fire push notifications to your phone via the ntfy mobile app. Each notification can carry **action buttons** ("Block", "Investigate", "Dismiss") that POST back to NetMon over a reply topic.

### How to use it

**On your phone:** install the ntfy app, subscribe to your two topics:
- `<topic>` — outgoing notifications from NetMon
- `<topic>-reply` — where your action-button taps land (polled every 60s)

**Action buttons** in notifications:
- **Block** — adds an outbound firewall rule, logs as `actor="ntfy_command"` with a revert payload
- **Block-all** — outbound + inbound
- **Unblock** — removes matching `NetMon-RemoteBlock-*` rules
- **Investigate** — fires an AI investigation
- **Scan** — triggers an immediate nmap scan
- **Dismiss** — acknowledges the alert

### What runs automatically

- **Nighttime mode** elevates "new device detected" alerts to `critical` between (configurable) hours — because nobody legitimately joins your network at 3 AM.
- **Outage notification** — sustained packet loss / 3 consecutive degraded checks triggers a critical push.
- **Threat-intel hit** — auto-blocked, then notified with severity = critical.

### Auth

If your ntfy is configured with credentials, NetMon includes a `Basic <base64>` Authorization header in action-button HTTP entries — so your phone can actually POST back. Secrets live in `.env` (`NTFY_PASS`), never the DB.

---

## 13. Settings Reference

Settings are stored in the `settings` SQLite table (key/value strings). Edit them in the Settings UI; changes take effect on the next loop tick (no restart needed for most).

### Core monitoring

| Key | Default | Effect |
|---|---|---|
| `health_check_interval_s` | 300 | Seconds between ping checks |
| `health_target` | `8.8.8.8` | Internet host to ping |
| `health_local_target` | (auto) | Router/gateway IP — autodetected |
| `latency_warn_ms` | 100 | Above this = `degraded` |
| `latency_crit_ms` | 300 | Informational |
| `packet_loss_warn_pct` | 10 | Above this = `degraded` |
| `health_alerts_enabled` | true | Create Alert rows on outage |
| `speed_test_url` | (500MB) | Speed test source URL |

### Scans

| Key | Default | Effect |
|---|---|---|
| `auto_scan_enabled` | true | Run hourly nmap scan |
| `auto_scan_interval_h` | 1.0 | Hours between scans (min 5 min) |
| `SCAN_TARGET` env | (auto) | Override subnet (e.g. `192.168.1.0/24`) |

### Traffic

| Key | Default | Effect |
|---|---|---|
| `traffic_summary_interval_s` | 20 | How often to summarize pcap |
| `capture_enabled` | false | Persist capture across restarts |
| `capture_interface` | — | Saved interface name |
| `capture_file_size_mb` | 10 | Ring-buffer file size |
| `capture_file_count` | 5 | Ring-buffer file count |
| `capture_retention_days` | 3 | Auto-delete old pcaps |

### DNS

| Key | Default | Effect |
|---|---|---|
| `dns_blocker_enabled` | false | Start UDP DNS server |
| `dns_blocker_upstream` | `1.1.1.1` | Upstream resolver for non-blocked queries |
| `dns_whitelist` | (custom) | Per-user allowlist additions |

### AI

| Key | Default | Effect |
|---|---|---|
| `ai_enabled` | true | Master switch |
| `auto_report_enabled` | true | Run 2h autonomous report |
| `AI_PROVIDER` env | `chain` | `chain` / `ollama` / `anthropic` |
| `AI_FAST_MODEL` env | `qwen2.5:3b` | Local Ollama fast model |
| `AI_DEEP_MODEL` env | (fast) | Local Ollama deep model |

### Anomaly

| Key | Default | Effect |
|---|---|---|
| `anomaly_spike_multiplier` | 4.0 | Spike = current ≥ N× baseline |

---

## 14. Companion: AI Services Dashboard & Sentinel

NetMon has two companions that live in the same project hub (`C:\Projects\_dashboard\` and a separate Sentinel watchdog). They are **separate apps**, not NetMon code, but they're part of your day-to-day operating environment.

### AI Services Dashboard

A small web page that surfaces the status of your local AI infrastructure:

- Local Ollama models loaded and warm
- Bridges (Groq, Gemini, GPT, OpenRouter, Cerebras, SambaNova, HF, Kasa) — up/down, rate-limit cooldowns, latency
- Recent prompts and which bridge handled them

It's where you go to check "is my AI stack healthy?" without digging through logs.

### Sentinel

A small Python watchdog that:

1. Polls your local services (NetMon, dashboard, ntfy, Ollama, bridges) on a schedule
2. Detects downtime — process not running, port not accepting connections, model not responding
3. Uses AI to **diagnose** the failure (read the relevant logs, look for the root cause)
4. **Attempts a repair** — restart the process, clear a stuck lock, requeue
5. Sends a **postmortem** to your phone summarizing what broke, what it tried, what worked

In effect: it watches the watchers. NetMon watches your network; Sentinel watches NetMon.

### Why they're not in this manual in depth

They're separate projects with separate docs. This section is just to orient you: when you see the Sentinel ping you about NetMon being down, that's how it knew.

---
---

# Part II — Developer Manual

This half is for hacking on NetMon, debugging it, or extending it. It assumes Python literacy and basic FastAPI / SQLAlchemy knowledge.

---

## 15. Architecture Overview

```
┌────────────────────────────────────────────────────────────────────┐
│                          NetMon Process                            │
│                                                                    │
│   ┌──────────────────────────────────────────────────────────┐    │
│   │ FastAPI (uvicorn)        app/main.py + api/routes.py     │    │
│   └──────────────────────────────────────────────────────────┘    │
│           │                                                        │
│   ┌───────┴────────────────────────────────────────────────┐      │
│   │  Background Loops (asyncio.create_task in lifespan)    │      │
│   │   • health_check_loop          (5 min)                 │      │
│   │   • traffic_analysis_loop      (20 s)                  │      │
│   │   • auto_scan_loop             (1 h)                   │      │
│   │   • anomaly_loop               (60 s)                  │      │
│   │   • command_poll_loop          (60 s, ntfy)            │      │
│   │   • autonomous_report_loop     (2 h, token-conscious)  │      │
│   │   • log_cleanup_loop           (daily)                 │      │
│   │   • dns_health_loop            (30 min, deterministic) │      │
│   └────────────────────────────────────────────────────────┘      │
│                                                                    │
│   ┌─────────────────┐  ┌────────────┐  ┌──────────────────┐       │
│   │ DNS Blocker     │  │ Capture    │  │ AI Provider Chain│       │
│   │ (UDP :53 thread)│  │ (dumpcap   │  │ Cerebras→Groq→...│       │
│   │                 │  │  subprocs) │  │ →Ollama (local)  │       │
│   └─────────────────┘  └────────────┘  └──────────────────┘       │
│                                                                    │
│   ┌──────────────────────────────────────────────────────────┐    │
│   │  SQLite (single file, WAL mode) — netmon.db              │    │
│   └──────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
              │                              │
              ▼                              ▼
       Static frontend                 ntfy (child process)
       (HTML/CSS/JS)                   → phone push
```

**Key choices and why:**

- **Single process, no microservices.** Every loop runs in the same uvicorn process. State sharing through SQLite + module globals. Simpler ops; works fine for a home network.
- **ThreadPoolExecutor for blocking work.** All loops `run_in_executor()` for blocking calls (nmap, tshark, urllib, sqlite writes) so the asyncio event loop never blocks.
- **No frontend framework.** Static `*.html`, `*.css`, `*.js` served by FastAPI. The dashboard is plain DOM manipulation; no React/Vue build step.
- **Free-first AI chain.** Investigation and chat go through a fallback chain that exhausts free providers before paying. Ollama (local Qwen) is the always-on floor.
- **SQLite with additive migrations.** All schema changes are additive — never destructive. Migrations live in `app/database.py` and run idempotently on every startup.

---

## 16. Process & Startup Lifecycle

`app/main.py` defines a FastAPI `lifespan` async context manager. On startup:

1. **DB init** — `app/database.py` creates tables (`Base.metadata.create_all`) and runs additive migrations (e.g., adds `actor` / `revert_json` / `reverted_at` / `reverted_by` columns to `activity_log` if missing).
2. **Seed defaults** — `seed_default_settings()` writes initial settings if absent.
3. **Auto-detect network** — `network/autodetect.get_network_info()` finds the active adapter via `netsh` + `route print`, prefers connected adapters with default routes, skips "Media disconnected" interfaces.
4. **Start scheduler loops** via `asyncio.create_task()`:
   ```python
   health_task    = asyncio.create_task(health_check_loop())
   traffic_task   = asyncio.create_task(traffic_analysis_loop())
   auto_scan_task = asyncio.create_task(auto_scan_loop())
   anomaly_task   = asyncio.create_task(anomaly_loop())
   command_task   = asyncio.create_task(command_poll_loop())
   report_task    = asyncio.create_task(autonomous_report_loop())
   cleanup_task   = asyncio.create_task(log_cleanup_loop())
   dns_health_task = asyncio.create_task(dns_health_loop())
   ```
5. **Resume capture** if it was enabled before the last restart.
6. **Warm the AI model** in a background thread (loads Ollama into RAM so the first user-facing call doesn't pay a 30s cold-start).
7. **Warm threat-intel cache** — pre-downloads blocklist feeds in the background.
8. **Start DNS blocker** if `dns_blocker_enabled=true`.
9. **Sweep orphan pcaps** — `cleanup_old_captures()` deletes any `*.pcapng` files left behind by crashed runs.

On shutdown:

- Stop dumpcap cleanly (`capture_engine.stop()`)
- Cancel every background task and `await` each so they catch `CancelledError`

---

## 17. Background Loops (Scheduler)

All loops live in `monitoring/scheduler.py`. They share an `_executor = ThreadPoolExecutor(max_workers=8)`.

### health_check_loop

- Runs `monitoring/health.run_ping()` against the internet target + router every `health_check_interval_s` seconds.
- Persists a `HealthCheck` row with status/latency/loss.
- Prunes at >2000 rows down to 1000.

### traffic_analysis_loop

- Every `traffic_summary_interval_s` (default 20):
  1. `capture_engine.check_alive()` — detects dead dumpcap and marks the session.
  2. `_watchdog_capture()` — restarts dumpcap if it should be running but isn't.
  3. `run_analysis()` — tshark over the current ring files; aggregates top talkers/destinations, protocol mix, DNS counts.
  4. Persists a `TrafficSummary` row.
  5. **Threat intel sweep** — top 10 non-private external destinations → `ai.threat_intel.check_ip()`; confirmed hits trigger `_auto_block()` and a critical notification.

### auto_scan_loop

- Runs `_run_auto_scan()` every `auto_scan_interval_h` hours.
- Step 1: fast `nmap -sn` ping scan across the subnet → discover live hosts.
- Step 2: for each *new* device, immediate `nmap -sV` deep scan to capture open ports and service versions.
- Resolves devices by MAC (via `_resolve_device()` in `api/routes.py`), persists `Scan`, `ScanDevice`, `Alert`, `ChangeEvent` rows.
- Diffs against previous scan to produce change events.
- Triggers `nighttime_device_alert` for unknown devices found at night.

### anomaly_loop

Runs every 60s. Calls five deterministic check functions:

1. `check_traffic_spikes(db)` — per-IP bytes ≥ 4× rolling 12-window baseline AND > 5MB → `warning`.
2. `check_port_scans()` — tshark TCP-SYN analysis: ≥20 ports on one host (vertical) or ≥15 distinct hosts (horizontal) → `critical`, auto-block.
3. `check_health_outage(db)` — 3 consecutive offline/degraded checks + ≥40% packet loss → `critical`.
4. `check_sustained_bandwidth(db)` — IP in top talkers for 6 windows at ≥8MB each → `warning`.
5. `check_degraded_health(db)` — loss ≥8% & 3× baseline, OR latency ≥80ms & 2× baseline → `warning`.

Each detector has a per-event cooldown (`_is_cooled_down`/`_stamp`) so we don't spam the user with the same anomaly.

Post-processing in `run_anomaly_checks()`:
- `critical` port scans → `_auto_block(ip)` (unless it's our own IP)
- `critical` anything → `request_immediate_scan()` (next anomaly tick fires nmap)
- `traffic_spike` / `sustained_bandwidth` → fire-and-forget HTTP POST to `/api/ai/investigate` (auto-investigate)

### command_poll_loop

Every 60s, polls the ntfy reply topic for incoming commands. Executes:

| Command | Action |
|---|---|
| `block <ip>` | Add outbound `netsh advfirewall` rule, log with revert payload |
| `block-all <ip>` | Add outbound + inbound rules, log with revert |
| `unblock <ip>` | Delete matching `NetMon-RemoteBlock-*` rules |
| `investigate <ip>` | POST to `/api/ai/investigate` |
| `scan` | Trigger immediate nmap scan |
| `dismiss` | Acknowledge (no-op, logs only) |

All firewall mutations go through `subprocess.run(["netsh", ...], creationflags=_no_window())` so no console window flashes.

### autonomous_report_loop (token-conscious)

Runs every **2 hours**. Flow:

1. Check `ai_enabled` and `auto_report_enabled` — abort silently if either is off.
2. Count `warning`/`critical`/`threat`/`action` events in the last 2 hours.
3. Find the most recent **real** report (`report_type="hourly"`, not `"hourly_skip"`).
4. **Decision:**
   - If 0 events AND last real report < 24h ago → **skip the LLM**. Write a deterministic `SecurityReport(report_type="hourly_skip", model="skip-gate")` row.
   - Otherwise (events present OR 24h heartbeat due) → run the full LLM analysis.
5. For real runs: gather traffic + health + log context, build prompt, call `provider.analyze()`, parse JSON response.
6. **Deterministic guardrail** — if only DNS-blocked events were present (no non-DNS security, no threat intel), force severity back to `low` and strip malware/virus language. DNS blocking is intentional ad/tracker filtering; we don't let the model panic about it.
7. Save a `SecurityReport` row, prune at >200 rows.

### log_cleanup_loop

Daily:
- Delete `category="dns"` rows older than 7 days
- Delete other rows older than 30 days

### dns_health_loop (token-free, deterministic)

Runs every 30 minutes (first run 3 min after startup). For each tick:

1. Read `dns_blocker_enabled` from settings, `is_running()` from `dns_blocker.server`.
2. Pull `dns_blocked` activity-log entries from the last 1h and the prior 23h (baseline).
3. Compute hourly baseline averages.
4. Apply five rules:
   - **Blocker enabled but not alive** → warning
   - **Block rate collapsed** (baseline ≥20/h, recent < 10% of baseline) → warning
   - **Domain spike** (new domain with ≥30/h, OR seen-before domain ≥5× baseline at ≥20/h) → info
   - **Client volume anomaly** (≥100 queries/h AND 4× client baseline) → info
5. If any anomaly → write a single `dns_health` activity-log entry. Otherwise → silent (one console line for ops).

---

## 18. Database Schema

SQLite via SQLAlchemy. All tables defined in `models/tables.py`. Notable choices:

- **`utcnow()`** column default everywhere — never naive datetimes.
- **Additive migrations** in `app/database.py` — `ALTER TABLE ADD COLUMN` only, no destructive ops.
- **Relationships** keep foreign-key joins ergonomic (`Scan.devices`, `Device.appearances`, `Scan.change_events`).
- **JSON-in-Text** for arrays/dicts (top talkers, ports, anomaly details). Parsed on read; never queried by JSON path (SQLite predates JSON1 in our minimum target).

### Tables

| Table | Purpose |
|---|---|
| `scans` | One row per nmap run |
| `devices` | One row per MAC ever seen |
| `scan_devices` | Per-scan snapshot of a device |
| `change_events` | Diff between two adjacent scans |
| `alerts` | User-facing pending alerts |
| `settings` | Key/value config |
| `health_checks` | Ping results |
| `speed_tests` | On-demand speed test results |
| `capture_sessions` | dumpcap runs |
| `traffic_summaries` | Per-window tshark aggregates |
| `ai_summaries` | AI scan/traffic analysis results |
| `security_reports` | 2h autonomous reports (incl. `hourly_skip` rows) |
| `activity_log` | Unified audit trail with `actor` + `revert_json` |
| `security_tool_runs` | Security Lab runs |
| `security_tool_output_chunks` | Streaming output chunks per run |
| `security_ai_explanations` | AI summary per run |
| `security_files` | Hash-deduped artifacts (handshakes, hashes) |
| `security_wsl_checks` | Cached WSL/Kali detection |
| `shodan_exposure_results` | Shodan query results |
| `wifi_security_results` | Aircrack results |
| `password_crack_results` | John/Hydra results |

---

## 19. API Surface

All routes live in `api/routes.py` (+ `api/auth_routes.py`). Major groups:

### Auth
- `POST /auth/login` — bcrypt password check + rate-limited (5 attempts / 60s per IP)
- `POST /auth/logout`
- `GET /auth/whoami`

### Scans & devices
- `GET /api/scans` — paginated scan history
- `POST /api/scans` — manual scan
- `GET /api/devices?filter=current|all` — device list
- `GET /api/devices/{id}` — device detail + history
- `PATCH /api/devices/{id}` — set label, trust

### Health / speed
- `GET /api/health` — recent ping history
- `POST /api/health/check-now` — manual ping
- `POST /api/health/speed-test` — run on-demand test

### Traffic
- `GET /api/traffic/status` — capture state
- `POST /api/traffic/start` / `POST /api/traffic/stop`
- `GET /api/traffic/summaries` — recent windows

### DNS
- `GET /api/dns/status` — server up/down, top blocked
- `GET /api/dns/blocked-domains?days=...`
- `POST /api/dns/whitelist` — add/remove custom whitelist entries
- `POST /api/dns/refresh-blocklists`

### Shield
- `GET /api/shield` — bundled state (threat level, autonomous actions, anomaly feed, AI investigations)
- `GET /api/autonomous-actions?status=active|reverted|all`
- `POST /api/autonomous-actions/{id}/revert`

### Activity log
- `GET /api/logs` — paginated with filters (event, actor, device_ip, search)
- `GET /api/logs/facets` — filter counts
- `GET /api/logs/insights?days=N` — deterministic summary
- `DELETE /api/logs` — clear all

### AI
- `POST /api/ai/investigate` — start investigation (returns immediately; stream via progress endpoint)
- `GET /api/ai/progress` — poll the live token feed (UI polls 700ms)
- `POST /api/ai/history-synthesis` — synthesize last 7 days via AI
- `POST /api/autonomy/learn-noise` — internal endpoint (no longer surfaced in UI; auto DNS-health loop covers this)
- `POST /api/ai/chat` — conversational endpoint
- `GET /api/ai/reports` — autonomous report history

### Firewall
- `GET /api/firewall/blocks` — current `NetMon-*` rules
- `POST /api/firewall/block` / `POST /api/firewall/unblock`

### Security Lab
- `POST /api/security/run` — start a tool run
- `GET /api/security/run/{id}` — status
- `GET /api/security/run/stream/{id}` — Server-Sent Events live output
- `GET /api/security/runs?tool=...` — history
- `POST /api/security/chat` — chat about a specific run
- `GET /api/security/wsl-check` — WSL/Kali detection

### Settings
- `GET /api/settings` — masked env-locked keys
- `POST /api/settings` — bulk update; returns `ignored_env_backed` for env-only keys

---

## 20. AI Provider Chain

`ai/provider.py` defines a `BaseProvider` interface and concrete implementations:

- `OllamaProvider` — local, free, slow on CPU
- `AnthropicProvider` — paid, optional advisor-tool beta
- `GroqProvider`, `CerebrasProvider`, `SambaNovaProvider`, `OpenRouterProvider`, `GeminiProvider` — free-tier cloud, OpenAI-compatible
- `NullProvider` — returns a structured "disabled" result
- `ChainProvider` — walks an ordered list, advances on transient errors

### Chain behavior

`get_investigation_provider()` order:

```
Cerebras → Groq → SambaNova → OpenRouter → Gemini → Ollama
```

Providers missing API keys are silently skipped at construction. Each `ChainProvider.analyze()` call:

1. For each provider in order:
   - Skip if on cooldown (60s after transient failure)
   - Call `provider.analyze()`
   - On success → return immediately
   - On transient error (rate limit / 429 / 5xx / timeout) → `_mark_cooldown()`, advance
   - On non-transient error (bad prompt, auth failure) → return error to caller (don't burn the chain on a request that will never succeed)

### Streaming

Every provider's `analyze()` accepts a streaming response and pumps tokens through `progress_append()` which updates the module-global `_PROGRESS` dict. The UI polls `/api/ai/progress` every 700ms.

### Token-efficiency rules

- The hourly report skips the LLM on quiet windows (see §17).
- DNS health uses zero tokens (deterministic).
- Anomaly detection uses zero tokens; auto-investigate fires only on real spikes.
- The "free chain" prefers cheap/fast providers (Cerebras, Groq, SambaNova) over slower ones (Gemini).
- Investigation prompts include only the relevant evidence — not the whole DB.

---

## 21. Anomaly Detection Internals

`monitoring/anomaly.py`. Detectors are deterministic Python — no AI. Each returns a list of event dicts:

```python
{
    "type":    "traffic_spike",
    "ip":      "192.168.1.45",
    "level":   "warning" | "critical",
    "title":   "...",
    "body":    "...",
    "actions": [notifier.investigate_action(ip), ...],
}
```

### Cooldowns

`_is_cooled_down(key, event_type)` looks up the last fire time per anomaly key. Cooldowns prevent the same event from firing every 60s once it's been raised.

### Auto-actions

After detectors run, `run_anomaly_checks()`:

- For `level=critical` `type=port_scan` events from a non-self IP → `_auto_block()`:
  - Inserts an outbound `netsh advfirewall` rule named `NetMon-AutoBlock-<ip>`
  - Writes `ActivityLog(actor="anomaly_auto", revert_json={action_type:"unblock_by_rule_names", params:{rule_names:[...], ip:ip}})`
- For any `level=critical` → `request_immediate_scan()` (a flag the auto-scan loop consumes on its next 60s polling tick).
- For `traffic_spike`/`sustained_bandwidth` → fire-and-forget HTTP `POST /api/ai/investigate` with `source="anomaly_auto"`.

### Self-IP check

`_is_this_machine(ip)` prevents NetMon from blocking itself when its own nmap scans look like port scans to the detector.

---

## 22. DNS Blocker Internals

`dns_blocker/server.py` + `dns_blocker/blocklist.py`.

### Server

- Listens on UDP `0.0.0.0:53` in a daemon thread.
- Parses incoming DNS queries (very lightweight — just enough to extract the query name).
- If the domain is in the blocklist AND not in the whitelist → respond with `NXDOMAIN`.
- Otherwise → forward the query to the upstream resolver (`dns_blocker_upstream`, default `1.1.1.1`) and pass the response back.

### Blocklist

Merged from multiple sources:

- StevenBlack hosts
- OISD
- AdGuard
- User custom additions (`dns_whitelist` for removals, separate user-blocked list for additions)

`load_user_whitelist()` reads from settings on each refresh. `refresh()` re-downloads the upstream lists.

### Logging

Every blocked query writes an `ActivityLog` row:

```python
{
    "level":    "warning",
    "category": "dns",
    "event":    "dns_blocked",
    "summary":  f"DNS blocked: {domain} (from {client_ip})",
    "detail":   {"domain": domain, "client_ip": client_ip},
}
```

The `detail` JSON is what `dns_health_loop` reads to detect anomalies.

### Status

`is_running()` returns `_server_instance is not None`. Used by `dns_health_loop` to detect a dead blocker when settings say it should be on.

---

## 23. Security Lab Internals

### Subprocess pattern

Every tool runs via:

```python
from security.wsl import _wsl_exe
cmd = _wsl_exe(["nikto", "-h", target, ...])
proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    stdin=subprocess.DEVNULL,                # CRITICAL — else `script` hangs
    text=True, bufsize=1,
    creationflags=_no_window(),
)
```

### Live streaming

`/api/security/run/stream/{id}` is a Server-Sent Events endpoint. The route reads from a queue that the subprocess pumper writes into; the frontend (`static/seclab.js:_seclabStartRun`) consumes the SSE stream and appends lines to the live output panel.

### Nikto-specific fix

Nikto is a Perl script that buffers stdout when piped. To force line-by-line flush, the actual invocation is:

```bash
script -q -c "nikto ..." /dev/null
```

`script` creates a pseudo-TTY, fooling nikto into flushing each line.

### WSL detection

`wsl --list --verbose` outputs **UTF-16 LE** (no BOM) on Windows. `security/wsl.py` reads as bytes and decodes as `utf-16-le` (not utf-8 — that fails on every other character).

### AI explanation isolation

`security/ai_explain.py:explain_tool_output()` opens its own `SessionLocal()`. **It never shares the caller's DB session** — sharing was the cause of the "run stuck at running" bug, because the caller's session would commit/rollback under the AI thread's feet.

### Risk + authorization gating

`is_attack_tool=True` runs require `authorization_confirmed=true` to be set on the run row. The frontend forces a checkbox; the backend revalidates.

---

## 24. Autonomous Actions & Revert System

Every action NetMon takes without explicit user click writes an `ActivityLog` row with:

- `actor` ∈ `{ "anomaly_auto", "ai_auto", "ntfy_command", "system" }`
- `revert_json` — a payload that can be replayed to undo

### Revert payload format

```json
{
  "action_type": "unblock_by_rule_names",
  "params": {
    "rule_names": ["NetMon-AutoBlock-1.2.3.4"],
    "ip": "1.2.3.4"
  }
}
```

`action_type` values currently in use:

| action_type | Used by | Effect of revert |
|---|---|---|
| `unblock_by_rule_names` | anomaly_auto, ntfy_command | Removes the named firewall rules via `netsh advfirewall delete rule` |
| `undo_label` | ai_auto | Restores previous device label |
| `unblock_dns` | ai_auto | Removes a domain from user blocklist |
| (more in `api/routes.py:ai_resolve`) | | |

### Endpoints

- `GET /api/autonomous-actions?status=active|reverted|all`
- `POST /api/autonomous-actions/{id}/revert` — replays revert payload through `ai_resolve()`, sets `reverted_at` and `reverted_by`

### Paired-row pattern

For AI auto-execute we write **two** rows:

1. Original `actor="user"` row from `ai_resolve()` (the action being applied)
2. A paired `actor="ai_auto"` row carrying the `revert_json`

This was chosen over refactoring `ai_resolve` because it keeps existing user-triggered behavior untouched.

### Pre-existing (legacy) rules

`NetMon-AutoBlock-*` rules from before the revert system was added have no payload. They still appear in **Active Firewall Blocks** and can be removed there manually.

---

## 25. Frontend Architecture

- **`static/index.html`** — single page, all sections (devices, traffic, shield, etc.) hidden/shown via `display:none`.
- **`static/app.js`** — main controller. Section loaders (`loadDevicesSection`, `loadShieldSection`, etc.) attach event handlers, fetch data, render DOM.
- **`static/seclab.js`** — Security Lab frontend. Owns its own SSE consumption, history modal, chat panel.
- **`static/style.css`** — all styling. Mobile-responsive; no framework.
- **`static/lib/echarts.min.js`** — vendored offline for the health graph.

### Polling vs. SSE

| Surface | Mechanism |
|---|---|
| Shield refresh | `setInterval(loadShieldSection, 5000)` |
| AI progress (live token stream) | `setInterval(pollProgress, 700)` |
| Security Lab live output | Server-Sent Events |
| Logs list | Manual + on filter change |

### State management

No framework, no store. Each section keeps its own module-level state (`_shieldTimer`, `_logsState.offset`, `_shieldInvestigating`). Re-renders are full section rebuilds.

---

## 26. Files & Modules Map

```
C:\Projects\netmon\
├── launch.py                      # Tray icon launcher; starts uvicorn + ntfy
├── app/
│   ├── main.py                    # FastAPI app, lifespan, loop registration
│   ├── database.py                # SQLAlchemy engine, sessions, migrations
│   └── auth.py                    # bcrypt + rate-limited login
├── api/
│   ├── routes.py                  # All HTTP endpoints
│   └── auth_routes.py             # Login/logout
├── models/
│   └── tables.py                  # ORM models
├── monitoring/
│   ├── scheduler.py               # All background loops
│   ├── health.py                  # ping + speed test
│   ├── activity.py                # write_log() helper
│   ├── anomaly.py                 # 5 anomaly detectors + auto-block
│   ├── notifier.py                # ntfy push + action buttons + command poll
│   └── state.py                   # tiny in-memory scan-trigger flag
├── scanner/
│   ├── runner.py                  # subprocess nmap
│   ├── parser.py                  # nmap XML → device dicts
│   └── diff.py                    # compute_diff() between snapshots
├── traffic/
│   ├── capture.py                 # dumpcap engine
│   ├── analyzer.py                # tshark windowed analysis
│   ├── interfaces.py              # find_tool + adapter listing
│   └── mitm.py                    # (advanced) MITM helper
├── ai/
│   ├── provider.py                # BaseProvider, Ollama, Anthropic, Groq, etc., ChainProvider
│   ├── analyst.py                 # build context, call provider, persist AISummary
│   ├── prompt.py                  # prompt templates
│   ├── threat_intel.py            # blocklist downloads + IP lookups
│   ├── history.py                 # build_history_context for synthesis
│   ├── investigation_tools.py     # tool definitions for AI investigations
│   └── knowledge_bridge.py        # cross-session memory bridge
├── dns_blocker/
│   ├── server.py                  # UDP DNS server
│   └── blocklist.py               # merged blocklist + whitelist
├── security/
│   ├── wsl.py                     # WSL detection + _wsl_exe()
│   ├── nikto.py / hydra.py / john.py / metasploit.py / aircrack.py / shodan_check.py / tshark_ext.py
│   ├── ai_explain.py              # AI summary of tool output
│   ├── fixes.py                   # auto-remediation suggestions
│   ├── validators.py              # auth/risk validation
│   └── common.py                  # shared helpers
├── network/
│   └── autodetect.py              # active adapter + subnet detection
├── static/
│   ├── index.html / login.html
│   ├── app.js / seclab.js
│   ├── style.css
│   └── lib/echarts.min.js
├── tools/
│   ├── setup.ps1                  # First-run setup
│   ├── set_password.py
│   ├── backup.py
│   └── test_ollama.py
├── captures/                      # pcapng ring buffer
├── config/ntfy/                   # ntfy server config
├── .env / .env.example
├── README.md
└── USER_MANUAL.md                 # this document
```

---

## 27. Troubleshooting & Operations

### "AI panel says disabled"

Either `AI_PROVIDER` is empty in `.env`, or no API keys are set and Ollama isn't running. Run `python tools/test_ollama.py` to verify local model is reachable.

### "DNS blocker port 53 in use"

Windows DNS Client or another resolver is bound. Stop the service or set `dns_blocker_enabled=false`. (NetMon won't crash — `NullProvider`-style behavior; it just won't block.)

### "Scan target keeps picking the wrong subnet"

Run `network/autodetect.get_network_info()` in a REPL. If it picks Tailscale / a stale Ethernet adapter over your active Wi-Fi:
1. Disable the unused adapter
2. Or set `SCAN_TARGET=192.168.1.0/24` in `.env` to override
3. Check the `[autodetect]` startup log line for the chosen subnet

### "Run stuck at running" in Security Lab

Almost always means a DB session was poisoned by an exception. `get_db()` has try/except rollback before close — confirm `explain_tool_output()` is still using its own session.

### "Ntfy action buttons don't work"

If ntfy requires auth, the action-button HTTP entry needs `headers.Authorization=Basic <b64>`. Verify `NTFY_PASS` is in `.env` and that `_basic_auth_header()` is called in the action builder.

### "I want to wipe and start over"

```powershell
# Stop NetMon
# Delete:
Remove-Item C:\Projects\netmon\netmon.db
Remove-Item C:\Projects\netmon\captures\*.pcapng
# Start NetMon — migrations re-create the schema, seed defaults
```

### Reading logs

- `[health]`, `[traffic]`, `[anomaly]`, `[auto-scan]`, `[report]`, `[dns_health]`, `[cleanup]`, `[command]` — per-loop tags in stdout
- All persisted in `activity_log` (also visible in the Logs UI)

### Token / cost monitoring

Token usage is recorded per AI call in `ai_summaries.input_tokens` / `output_tokens` and `security_reports` doesn't track tokens directly but the model name is logged. Audit cost with:

```sql
SELECT provider, model, SUM(input_tokens), SUM(output_tokens), COUNT(*)
FROM ai_summaries WHERE created_at > date('now','-7 days')
GROUP BY provider, model;
```

---

## Appendix A — Environment Variables

```
# Core
APP_PORT=8000
BIND_HOST=0.0.0.0           # 127.0.0.1 to lock down

# AI
AI_PROVIDER=chain            # chain | ollama | anthropic
AI_FAST_MODEL=qwen2.5:3b
AI_DEEP_MODEL=gemma4:latest
OLLAMA_HOST=http://localhost:11434

# Provider API keys (any subset — chain skips missing ones)
ANTHROPIC_API_KEY=
GROQ_API_KEY=
CEREBRAS_API_KEY=
SAMBANOVA_API_KEY=
OPENROUTER_API_KEY=
GEMINI_API_KEY=

# ntfy
NTFY_EXE=
NTFY_CONFIG=
NTFY_TOPIC=
NTFY_REPLY_TOPIC=
NTFY_USER=
NTFY_PASS=

# SMTP (optional)
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=

# Shodan (Security Lab)
SHODAN_API_KEY=

# Scan
SCAN_TARGET=                 # leave empty for auto-detect
```

---

## Appendix B — Glossary

| Term | Meaning |
|---|---|
| **Anomaly loop** | The 60-second background check for traffic spikes, port scans, outages, etc. |
| **Autonomous action** | Any change NetMon makes without you clicking — has an `Undo` button in the Shield. |
| **Chain provider** | The AI fallback ladder: Cerebras → Groq → SambaNova → OpenRouter → Gemini → Ollama. |
| **Cooldown** | Per-event throttle that prevents the same anomaly firing repeatedly. |
| **dumpcap** | The headless packet-capture binary from Wireshark. Writes the ring buffer. |
| **Investigate** | Send evidence about a device or event to the AI for a verdict. |
| **NXDOMAIN** | DNS response meaning "this domain doesn't exist" — how the blocker silently kills lookups. |
| **ntfy** | Free open-source push notification server bundled with NetMon. |
| **Ring buffer** | Capture mode where dumpcap keeps the latest N files of M MB each, deleting old ones. |
| **Shield** | The main "what's happening right now?" page. |
| **tshark** | Wireshark's CLI analyzer. Used to summarize captured pcap windows. |
| **Verdict** | The AI's classification of an investigation: `normal` / `noise` / `suspicious`. |

---

*End of manual. ~16,000 words. Print double-sided to save trees.*
