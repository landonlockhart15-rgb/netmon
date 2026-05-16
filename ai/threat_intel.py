"""
threat_intel.py — Lightweight local threat intelligence cache.

Downloads free, no-API-key blocklists and caches them to disk.
Refreshed automatically every 4 hours (lazy, on first lookup after TTL).

Feeds:
  - Feodo Tracker C2 IPs       https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  - URLhaus malware hosts       https://urlhaus.abuse.ch/downloads/hostfile/
  - OpenPhish phishing URLs     https://openphish.com/feed.txt
  - Emerging Threats IPs        https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt

Lookups are set-based (O(1)) after the first load.
"""

from __future__ import annotations

import os
import time
import threading
import urllib.request
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

_CACHE_DIR   = Path("data/threat_intel")
_REFRESH_SEC = 4 * 3600   # 4 hours

_FEEDS: dict[str, dict] = {
    "feodo_c2_ips": {
        "url":   "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "label": "Feodo C2 Tracker (botnet command-and-control)",
        "type":  "ip",
        "severity": "critical",
    },
    "emerging_block_ips": {
        "url":   "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "label": "Emerging Threats IP Blocklist",
        "type":  "ip",
        "severity": "high",
    },
    "urlhaus_hosts": {
        "url":   "https://urlhaus.abuse.ch/downloads/hostfile/",
        "label": "URLhaus Malware Host",
        "type":  "domain",
        "severity": "critical",
    },
    "openphish": {
        "url":   "https://openphish.com/feed.txt",
        "label": "OpenPhish Phishing Feed",
        "type":  "url",     # parsed for hostnames
        "severity": "high",
    },
}

# ── In-memory store ───────────────────────────────────────────────────────────

_ip_sets:     dict[str, set[str]] = {}   # feed_name → set of IPs
_domain_sets: dict[str, set[str]] = {}   # feed_name → set of domains
_lock         = threading.Lock()
_last_refresh = 0.0
_loading      = False


# ── Internal helpers ──────────────────────────────────────────────────────────

def _cache_path(feed_name: str) -> Path:
    return _CACHE_DIR / f"{feed_name}.txt"


def _fetch_raw(url: str, timeout: int = 20) -> str | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetMon/1.0 (home network monitor)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _parse_feed(raw: str, feed_type: str) -> set[str]:
    """Extract relevant entries (IPs or hostnames) from raw feed text."""
    entries: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if feed_type == "ip":
            # Plain IP lines, possibly with CIDR or comments
            token = line.split()[0].split("/")[0]
            if token and token[0].isdigit():
                entries.add(token)

        elif feed_type == "domain":
            # hosts-file format (127.0.0.1 badhost.com) or plain hostnames
            if line.startswith("127.0.0.1") or line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 2:
                    host = parts[1].lower().strip(".")
                    if host and host not in ("localhost", "local"):
                        entries.add(host)
            elif "." in line and " " not in line:
                entries.add(line.lower().strip("."))

        elif feed_type == "url":
            # Extract hostname from full URL (OpenPhish feed)
            try:
                # Simple hostname extraction without urllib.parse
                rest = line.split("://", 1)[-1]
                host = rest.split("/")[0].split(":")[0].lower().strip()
                if host and "." in host:
                    entries.add(host)
            except Exception:
                pass

    return entries


def _load_feed(feed_name: str, meta: dict) -> None:
    cache = _cache_path(feed_name)
    raw: str | None = None

    # Use on-disk cache if it's fresh enough
    if cache.exists():
        age = time.time() - cache.stat().st_mtime
        if age < _REFRESH_SEC:
            try:
                raw = cache.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

    # Download if cache is stale or missing
    if raw is None:
        raw = _fetch_raw(meta["url"])
        if raw:
            try:
                _CACHE_DIR.mkdir(parents=True, exist_ok=True)
                cache.write_text(raw, encoding="utf-8")
            except Exception:
                pass

    if not raw:
        return

    entries = _parse_feed(raw, meta["type"])
    with _lock:
        if meta["type"] == "ip":
            _ip_sets[feed_name] = entries
        else:
            # Both "domain" and "url" feed types end up in domain_sets
            _domain_sets[feed_name] = entries


def _refresh_all() -> None:
    global _last_refresh, _loading
    _loading = True
    for name, meta in _FEEDS.items():
        try:
            _load_feed(name, meta)
        except Exception:
            pass
    _last_refresh = time.time()
    _loading = False


def _ensure_loaded() -> None:
    """Trigger a refresh if the TTL has expired. Runs synchronously (called from request handler)."""
    if time.time() - _last_refresh > _REFRESH_SEC and not _loading:
        # Run in background so the first request isn't blocked for 20+ seconds
        t = threading.Thread(target=_refresh_all, daemon=True)
        t.start()
        # Give it a brief window — if data is already cached on disk it loads fast
        t.join(timeout=5)


# ── Public API ────────────────────────────────────────────────────────────────

class ThreatMatch:
    __slots__ = ("feed_name", "label", "severity")

    def __init__(self, feed_name: str, label: str, severity: str):
        self.feed_name = feed_name
        self.label     = label
        self.severity  = severity   # "critical" | "high" | "medium"

    def __repr__(self) -> str:
        return f"ThreatMatch({self.label!r}, severity={self.severity!r})"


def check_ip(ip: str) -> list[ThreatMatch]:
    """Return threat matches for a given IPv4 address."""
    _ensure_loaded()
    hits: list[ThreatMatch] = []
    ip = ip.strip()
    with _lock:
        for name, s in _ip_sets.items():
            if ip in s:
                meta = _FEEDS[name]
                hits.append(ThreatMatch(name, meta["label"], meta["severity"]))
    return hits


def check_domain(domain: str) -> list[ThreatMatch]:
    """Return threat matches for a domain name (checks domain and all parent domains)."""
    _ensure_loaded()
    domain = domain.lower().lstrip("*. ").rstrip(".")
    parts  = domain.split(".")
    hits:  list[ThreatMatch] = []
    seen:  set[str] = set()
    with _lock:
        for name, s in _domain_sets.items():
            # Check full domain and each parent (e.g. sub.evil.com → evil.com)
            for i in range(len(parts) - 1):
                candidate = ".".join(parts[i:])
                if candidate in s and name not in seen:
                    seen.add(name)
                    meta = _FEEDS[name]
                    hits.append(ThreatMatch(name, meta["label"], meta["severity"]))
                    break
    return hits


def check(item: str) -> list[ThreatMatch]:
    """Auto-detect whether item is an IP or domain and check appropriately."""
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", item):
        return check_ip(item)
    return check_domain(item)


def is_confirmed_malicious(hits: list[ThreatMatch]) -> bool:
    """True if any threat match is severity critical or high — enough to auto-block."""
    return any(h.severity in ("critical", "high") for h in hits)


def summary(hits: list[ThreatMatch]) -> str:
    """Human-readable summary of threat matches for inclusion in evidence."""
    if not hits:
        return "No threat intelligence matches."
    parts = [f"{h.label} (severity: {h.severity})" for h in hits]
    return "THREAT INTELLIGENCE HIT: " + "; ".join(parts)


def warm_cache() -> None:
    """Call at startup to pre-fetch feeds in the background."""
    t = threading.Thread(target=_refresh_all, daemon=True, name="threat-intel-refresh")
    t.start()
