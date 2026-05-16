"""
blocklist.py — Download and cache ad/tracker blocklists.

Sources:
  StevenBlack unified hosts  (ads + malware + tracking)
  OISD small                 (conservative, low false-positives)
  AdGuard DNS filter         (aggressive ad networks)

All three are merged into a single Python set of lowercase FQDNs.
The set is rebuilt every 24 hours automatically.
"""

import os
import re
import time
import threading
import urllib.request
from datetime import datetime, timezone

# ── Blocklist URLs ─────────────────────────────────────────────────────────────

SOURCES = {
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "oisd_small":  "https://small.oisd.nl/",
    "adguard":     "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
}

CACHE_DIR   = os.path.join(os.path.dirname(__file__), ".cache")
CACHE_TTL   = 24 * 3600   # seconds

# ── Whitelist — domains that are NEVER blocked regardless of blocklists ───────
# Add any domain here to always allow it through (covers subdomains too).
WHITELIST: set[str] = {
    # Amazon device services (Echo, Alexa, Fire TV, Kindle, Ring)
    "a2z.com",
    "amazon.com",
    "amazonaws.com",
    "amazonvideo.com",
    "primevideo.com",
    # Apple device services
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    # Google device / phone services
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "android.com",
    "googleusercontent.com",
    # Microsoft / Windows Update
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "live.com",
    "msftconnecttest.com",
    # ntfy push notifications (self-hosted)
    "localhost",
    # Tailscale
    "tailscale.com",
    "ts.net",
}


def load_user_whitelist() -> None:
    """Load the user-managed whitelist from the NetMon settings DB and merge into WHITELIST."""
    try:
        import json as _json
        from app.database import SessionLocal as _SL
        from models.tables import Setting as _Setting
        db = _SL()
        try:
            row = db.query(_Setting).filter(_Setting.key == "dns_user_whitelist").first()
            if row and row.value:
                for d in _json.loads(row.value):
                    WHITELIST.add(str(d).strip().lower())
        finally:
            db.close()
    except Exception:
        pass  # never crash DNS on DB errors


# ── Module state ──────────────────────────────────────────────────────────────

_lock           = threading.RLock()
_blocked: set   = set()
_last_refresh   = 0.0        # epoch
_stats          = {
    "total_domains": 0,
    "last_updated":  None,
    "sources":       {},
    "queries_today": 0,
    "blocked_today": 0,
    "top_blocked":   {},      # domain → count
}


# ── Parsers ───────────────────────────────────────────────────────────────────

_HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)", re.MULTILINE)
_DOMAIN_RE = re.compile(r"^(?:\|\|)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\^?$")


def _parse_hosts(text: str) -> set:
    """Parse /etc/hosts-style file (StevenBlack format)."""
    domains = set()
    for m in _HOSTS_RE.finditer(text):
        d = m.group(1).strip().lower()
        if d and d not in ("localhost", "broadcasthost", "0.0.0.0"):
            domains.add(d)
    return domains


def _parse_adblock(text: str) -> set:
    """Parse Adblock Plus / AdGuard filter list format."""
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        # Strip adblock syntax: ||domain^ or plain domain
        line = line.lstrip("|").rstrip("^").strip()
        m = _DOMAIN_RE.match(line)
        if m:
            domains.add(m.group(1))
    return domains


def _fetch(url: str, name: str) -> str | None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = os.path.join(CACHE_DIR, f"{name}.txt")

    # Use cache if fresh
    if os.path.exists(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < CACHE_TTL:
            with open(cache_path, encoding="utf-8", errors="replace") as f:
                return f.read()

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetMon-AdBlocker/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[dns_blocker] fetched {name}: {len(text):,} bytes")
        return text
    except Exception as exc:
        print(f"[dns_blocker] failed to fetch {name}: {exc}")
        # Return stale cache if available
        if os.path.exists(cache_path):
            with open(cache_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        return None


# ── Refresh ───────────────────────────────────────────────────────────────────

def refresh(force: bool = False) -> int:
    """
    Download / parse all blocklists.  Returns total blocked domain count.
    Thread-safe; skips if called within CACHE_TTL unless force=True.
    """
    global _blocked, _last_refresh

    with _lock:
        if not force and (time.time() - _last_refresh) < CACHE_TTL:
            return len(_blocked)

        merged: set = set()
        source_counts: dict = {}

        raw = _fetch(SOURCES["stevenblack"], "stevenblack")
        if raw:
            d = _parse_hosts(raw)
            merged |= d
            source_counts["stevenblack"] = len(d)

        raw = _fetch(SOURCES["oisd_small"], "oisd_small")
        if raw:
            d = _parse_adblock(raw)
            merged |= d
            source_counts["oisd_small"] = len(d)

        raw = _fetch(SOURCES["adguard"], "adguard")
        if raw:
            d = _parse_adblock(raw)
            merged |= d
            source_counts["adguard"] = len(d)

        _blocked        = merged
        _last_refresh   = time.time()
        _stats["total_domains"] = len(merged)
        _stats["last_updated"]  = datetime.now(timezone.utc).isoformat()
        _stats["sources"]       = source_counts

        print(f"[dns_blocker] blocklist ready: {len(merged):,} domains")
        return len(merged)


def is_blocked(domain: str) -> bool:
    """
    Return True if *domain* or any of its parent domains is on the blocklist.
    Whitelist takes priority — whitelisted domains always pass through.
    """
    d = domain.lower().rstrip(".")
    parts = d.split(".")
    # Check whitelist first — any parent domain match = always allow
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in WHITELIST:
            return False
    # Check blocklist
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in _blocked:
            return True
    return False


# ── Stats helpers ─────────────────────────────────────────────────────────────

def record_query(domain: str, blocked: bool) -> None:
    with _lock:
        _stats["queries_today"] += 1
        if blocked:
            _stats["blocked_today"] += 1
            top = _stats["top_blocked"]
            top[domain] = top.get(domain, 0) + 1
            # Keep only top 50
            if len(top) > 50:
                _stats["top_blocked"] = dict(
                    sorted(top.items(), key=lambda x: x[1], reverse=True)[:50]
                )


def get_stats() -> dict:
    with _lock:
        top = sorted(
            _stats["top_blocked"].items(), key=lambda x: x[1], reverse=True
        )[:10]
        return {
            "total_domains": _stats["total_domains"],
            "last_updated":  _stats["last_updated"],
            "sources":       dict(_stats["sources"]),
            "queries_today": _stats["queries_today"],
            "blocked_today": _stats["blocked_today"],
            "top_blocked":   [{"domain": d, "count": c} for d, c in top],
        }


def reset_daily_stats() -> None:
    with _lock:
        _stats["queries_today"] = 0
        _stats["blocked_today"] = 0
        _stats["top_blocked"]   = {}


# ── Auto-refresh background thread ───────────────────────────────────────────

def _auto_refresh_loop() -> None:
    """Refresh blocklist every 24 h in a daemon thread."""
    while True:
        try:
            refresh()
        except Exception as exc:
            print(f"[dns_blocker] auto-refresh error: {exc}")
        time.sleep(CACHE_TTL)


def start_auto_refresh() -> None:
    t = threading.Thread(target=_auto_refresh_loop, daemon=True, name="dns-bl-refresh")
    t.start()
