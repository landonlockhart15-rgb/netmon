# NetMon Architecture

NetMon is a local-first Windows network visibility and defensive security console.

This document describes the intended system shape at a high level. It is meant to help contributors and future maintainers understand the project without reading every file first.

## Core principles

- **Local-first:** Runtime data should stay on the user's machine unless the user explicitly configures an external provider.
- **Defensive use:** NetMon is for networks the user owns or has permission to test.
- **Inspectable:** Configuration, logs, and local data should be understandable by a technical user.
- **Reversible actions:** Firewall and network actions should be designed so users can undo changes.
- **Optional AI:** AI features should enhance explanations and investigation, not be required for basic scanning and monitoring.

## Runtime shape

NetMon is designed to run as a local Windows app with:

1. A tray entry point.
2. A browser dashboard at `http://localhost:8000`.
3. Local services for discovery, monitoring, DNS blocking, notifications, and AI-assisted analysis.
4. Local runtime data stored outside git-tracked source files.

## Major responsibilities

### Device discovery

Discovers devices on the local network, tracks device history, detects changes, and records visible open ports. Discovery depends on nmap and the configured scan target.

### Network health

Checks internet and router latency so the user can tell whether problems are local, router-level, or upstream.

### Traffic summaries

Uses Wireshark tooling such as `dumpcap` and `tshark` when available to summarize local traffic captures.

### DNS blocking

Runs a local DNS ad-blocking workflow using blocklists such as StevenBlack, OISD, and AdGuard lists. Cache and runtime data should stay out of git.

### AI analysis

Uses local Ollama models by default when configured, with optional cloud provider fallbacks. AI output should explain observations and suggest next steps; it should not be the sole source of truth for security decisions.

### Security Lab

Wraps authorized testing tools through WSL/Kali workflows. These features are intended only for owned or explicitly authorized networks and systems.

### Notifications

Optionally integrates with ntfy for local push notifications and action buttons.

## Data boundaries

The following should remain local and gitignored:

- `.env`
- `data/`
- SQLite databases
- packet captures
- uploaded wordlists or security test files
- DNS blocklist caches
- logs and Python caches

## Configuration flow

1. `.env.example` documents safe placeholder settings.
2. The setup script creates a local `.env`.
3. The user can keep `SCAN_TARGET=auto` or set an explicit CIDR/range.
4. Optional integrations are enabled only when their dependencies and config values are present.

## Operational model

A typical run looks like this:

1. User starts NetMon.
2. NetMon detects the active adapter, gateway, subnet, DNS servers, and public IP.
3. User opens the dashboard.
4. User runs discovery or monitoring actions.
5. NetMon records local results.
6. Optional AI analysis explains what changed or what looks suspicious.
7. Optional notifications alert the user when configured conditions are met.

## Future architecture notes

Useful future improvements:

- Add a module map that points to exact source files once the project structure stabilizes.
- Add a data-flow diagram showing dashboard, local services, databases, and external optional tools.
- Add smoke tests for startup, config loading, and scan-target detection.
- Add screenshots for the dashboard and settings panels.
