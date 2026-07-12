"""
health.py — Lightweight network and internet health checks.

PING CHECK
  Uses the Windows ping command via subprocess.
  No extra packages. No admin rights required.
  Parses the text output to extract average RTT and packet loss.

  Why subprocess ping instead of a Python ICMP library?
    - Windows ICMP sockets require administrator rights.
    - The OS ping command works for any user.
    - Output format is predictable enough to parse reliably.

SPEED TEST
  Uses urllib (Python stdlib) to download a fixed-size block of data
  from Cloudflare's edge and measures throughput.
  - Run on demand only (button click) — not on the health check timer.
  - Download only in V1. Upload requires a cooperative server endpoint.
  - The test URL is configurable via settings.

THRESHOLDS
  Passed in as parameters so the scheduler can read them from the
  settings table and pass them through. health.py itself has no DB access.

  status values:
    "online"   — all packets received, latency within normal range
    "degraded" — some packet loss OR latency above critical threshold
    "offline"  — 100% packet loss (no response at all)
"""

import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# PING / LATENCY
# ─────────────────────────────────────────────────────────────────────────────

DNS_PROBE_TARGET = "example.com"
CAPTIVE_PORTAL_PROBE_URLS = (
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://clients3.google.com/generate_204",
)


def test_dns_resolution(target: str = DNS_PROBE_TARGET, timeout: float = 5.0) -> dict:
    """
    Resolve a hostname without leaving process-wide socket timeout changes behind.

    socket.getaddrinfo has no per-call timeout argument, so this uses a worker
    future for the timeout boundary instead of socket.setdefaulttimeout().
    """
    previous_timeout = socket.getdefaulttimeout()
    ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix="netmon-dns")
    try:
        future = ex.submit(socket.getaddrinfo, target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        try:
            records = future.result(timeout=max(0.1, float(timeout)))
        except FutureTimeoutError:
            future.cancel()
            return {
                "status": "offline",
                "target": target,
                "resolved_ips": [],
                "error": f"DNS resolution timed out after {timeout:.0f}s",
            }

        resolved_ips = sorted({item[4][0] for item in records if item and item[4]})
        return {
            "status": "online" if resolved_ips else "offline",
            "target": target,
            "resolved_ips": resolved_ips,
            "error": None if resolved_ips else "DNS resolution returned no addresses",
        }
    except Exception as e:
        return {
            "status": "offline",
            "target": target,
            "resolved_ips": [],
            "error": str(e),
        }
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
        if socket.getdefaulttimeout() != previous_timeout:
            socket.setdefaulttimeout(previous_timeout)


def check_captive_portal(urls: tuple[str, ...] | list[str] | None = None, timeout: float = 5.0) -> dict:
    """
    Probe generate_204 endpoints and report likely captive portals.

    A real captive portal typically returns 200/redirect/auth-required content
    instead of 204. Upstream server errors such as HTTP 500 are probe failures,
    not evidence of a portal.
    """
    probe_urls = tuple(urls or CAPTIVE_PORTAL_PROBE_URLS)
    errors: list[str] = []

    for url in probe_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetMon/1.0 CaptiveCheck"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                body = resp.read(256) if status != 204 else b""
        except urllib.error.HTTPError as e:
            status = int(getattr(e, "code", 0) or 0)
            if status in (300, 301, 302, 303, 307, 308, 401, 403, 511):
                return {
                    "status": "captive",
                    "captive": True,
                    "url": url,
                    "http_status": status,
                    "error": None,
                }
            errors.append(f"{url}: HTTP {status}")
            continue
        except Exception as e:
            errors.append(f"{url}: {e}")
            continue

        if status == 204:
            return {
                "status": "open",
                "captive": False,
                "url": url,
                "http_status": status,
                "error": None,
            }
        if 500 <= int(status or 0) <= 599:
            errors.append(f"{url}: HTTP {status}")
            continue
        if int(status or 0) in (200, 301, 302, 303, 307, 308, 401, 403, 511) or body:
            return {
                "status": "captive",
                "captive": True,
                "url": url,
                "http_status": status,
                "error": None,
            }

    return {
        "status": "unknown",
        "captive": False,
        "url": None,
        "http_status": None,
        "error": "; ".join(errors) if errors else "No captive portal probe URLs configured",
    }


probe_captive_portal = check_captive_portal
test_captive_portal = check_captive_portal

# ─────────────────────────────────────────────────────────────────────────────
# CAPTIVE PORTAL PAGE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

# Cap on how much of a portal page body we read/analyze by default. Portal login
# pages are small; anything larger is almost certainly not a login form and we do
# not want to buffer megabytes of interception junk into memory.
CAPTIVE_PORTAL_MAX_BYTES = 65536

# Cap on the stored title so a hostile/oversized <title> cannot bloat the result.
_CAPTIVE_PORTAL_TITLE_CAP = 256

_IDENTITY_HINTS = (
    "user", "email", "e-mail", "login", "phone", "mobile",
    "account", "room", "guest", "member", "msisdn",
)
_OTP_HINTS = (
    "otp", "one-time", "one time", "onetime", "totp", "2fa",
    "verification code", "verify code", "auth code", "passcode",
)


class _PortalHTMLParser(HTMLParser):
    """Tolerant HTML scanner that collects the title, forms, and input fields.

    Uses the stdlib HTMLParser so malformed portal markup does not raise; it best
    -effort extracts <title>, counts <form> elements, and records every input-like
    control (including ones outside a <form>, which real portals frequently use).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._title_parts: list[str] = []
        self._in_title = False
        self.form_count = 0
        self.inputs: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        t = tag.lower()
        if t == "title":
            self._in_title = True
        elif t == "form":
            self.form_count += 1
        elif t in ("input", "select", "textarea"):
            self.inputs.append({(k or "").lower(): (v or "") for k, v in attrs})

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    @property
    def title(self) -> str:
        return "".join(self._title_parts).strip()


def _classify_input(attr: dict[str, str]) -> Optional[str]:
    """Return a coarse field kind (password/otp/username) or None for the input."""
    field_type = (attr.get("type") or "text").lower()
    if field_type == "hidden":
        return "hidden"
    if field_type == "password":
        return "password"

    name = attr.get("name", "").lower()
    identifier = attr.get("id", "").lower()
    placeholder = attr.get("placeholder", "").lower()
    blob = " ".join((name, identifier, placeholder))

    if any(hint in blob for hint in _OTP_HINTS) or "code" in name:
        return "otp"
    if any(hint in blob for hint in _IDENTITY_HINTS):
        return "username"
    return None


def _parse_portal_forms(html_text: str) -> dict:
    """Analyze portal HTML into a structured summary of its login affordances.

    Returns title, form count, per-field descriptors, and boolean flags for the
    identity/password/OTP inputs a captive portal login form typically requires.
    Never raises on malformed input — a best-effort empty summary is returned.
    """
    parser = _PortalHTMLParser()
    try:
        parser.feed(html_text or "")
        parser.close()
    except Exception:
        # HTMLParser is tolerant, but guard against pathological inputs anyway.
        pass

    fields: list[dict] = []
    hidden_field_count = 0
    requires_identity = requires_password = requires_otp = False

    for attr in parser.inputs:
        kind = _classify_input(attr)
        if kind == "hidden":
            hidden_field_count += 1
            continue
        if kind == "password":
            requires_password = True
        elif kind == "otp":
            requires_otp = True
        elif kind == "username":
            requires_identity = True
        fields.append(
            {
                "name": attr.get("name", ""),
                "type": (attr.get("type") or "text").lower(),
                "kind": kind,
            }
        )

    title = parser.title[:_CAPTIVE_PORTAL_TITLE_CAP] if parser.title else None
    return {
        "title": title,
        "form_count": parser.form_count,
        "requires_identity": requires_identity,
        "requires_password": requires_password,
        "requires_otp": requires_otp,
        "hidden_field_count": hidden_field_count,
        "fields": fields,
    }


def _charset_from_content_type(content_type: str) -> Optional[str]:
    """Extract a charset token from a Content-Type header value, if present."""
    if not content_type or "charset=" not in content_type.lower():
        return None
    charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip()
    return charset.strip('"\'') or None


def _decode_portal_body(raw: bytes, content_type: str) -> str:
    """Decode a portal response body, tolerating unknown or wrong charsets.

    The declared charset may be unrecognized (LookupError) or simply wrong for the
    bytes (UnicodeDecodeError). Both are caught here so an unusual portal cannot
    crash the analyzer; decoding always falls back to a lossy UTF-8 decode.
    """
    for encoding in (_charset_from_content_type(content_type), "utf-8"):
        if not encoding:
            continue
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError, ValueError):
            continue
    return raw.decode("utf-8", errors="replace")


def analyze_captive_portal_page(
    urls: tuple[str, ...] | list[str] | None = None,
    timeout: float = 5.0,
    max_bytes: int = CAPTIVE_PORTAL_MAX_BYTES,
) -> dict:
    """Probe captive-portal endpoints and analyze any intercepting login page.

    Extends check_captive_portal: on a captured page it fetches the (size-capped)
    body and parses it into a structured `page` summary describing the login form.
    A clean 204 is reported as open with no page; upstream 5xx responses are probe
    failures and fall through to the next URL.
    """
    probe_urls = tuple(urls) if urls else tuple(CAPTIVE_PORTAL_PROBE_URLS)
    if not probe_urls:
        return {
            "status": "unknown",
            "captive": False,
            "url": None,
            "final_url": None,
            "http_status": None,
            "error": "No captive portal probe URLs configured",
            "page": None,
        }

    errors: list[str] = []
    read_cap = max(0, int(max_bytes)) if max_bytes else 0

    for url in probe_urls:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            errors.append(f"{url}: unsupported URL scheme")
            continue

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetMon/1.0 CaptiveCheck"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode() or 0)
                final_url = _safe_geturl(resp, url)
                if status == 204:
                    return {
                        "status": "open",
                        "captive": False,
                        "url": url,
                        "final_url": final_url,
                        "http_status": status,
                        "error": None,
                        "page": None,
                    }
                # Read one byte past the cap so we can tell if the body was clipped.
                raw = resp.read(read_cap + 1) if read_cap else resp.read()
                content_type = ""
                try:
                    content_type = resp.headers.get("content-type", "") or ""
                except Exception:
                    content_type = ""
        except urllib.error.HTTPError as e:
            status = int(getattr(e, "code", 0) or 0)
            if status in (300, 301, 302, 303, 307, 308, 401, 403, 511):
                return {
                    "status": "captive",
                    "captive": True,
                    "url": url,
                    "final_url": _safe_geturl(e, url),
                    "http_status": status,
                    "error": None,
                    "page": None,
                }
            errors.append(f"{url}: HTTP {status}")
            continue
        except Exception as e:
            errors.append(f"{url}: {e}")
            continue

        if 500 <= status <= 599:
            errors.append(f"{url}: HTTP {status}")
            continue

        truncated = bool(read_cap) and len(raw) > read_cap
        if truncated:
            raw = raw[:read_cap]
        bytes_read = len(raw)

        page = _parse_portal_forms(_decode_portal_body(raw, content_type))
        page["truncated"] = truncated
        page["bytes_read"] = bytes_read

        return {
            "status": "captive",
            "captive": True,
            "url": url,
            "final_url": final_url,
            "http_status": status,
            "error": None,
            "page": page,
        }

    return {
        "status": "unknown",
        "captive": False,
        "url": None,
        "final_url": None,
        "http_status": None,
        "error": "; ".join(errors) if errors else "No captive portal probe URLs configured",
        "page": None,
    }


def _safe_geturl(resp, fallback: str) -> str:
    """Return resp.geturl() when available, else the requested URL."""
    try:
        geturl = getattr(resp, "geturl", None)
        if callable(geturl):
            value = geturl()
            if value:
                return value
    except Exception:
        pass
    return fallback


# In-process cache of the last analyze_captive_portal_page() result, so a cheap
# "what's the status right now" read (e.g. a dashboard poll) does not have to
# fire a fresh network probe on every request. Same short-term, in-memory
# pattern as autoheal._STATE — not persisted across a restart.
_CAPTIVE_PORTAL_CACHE: dict = {
    "result": None,      # last analyze_captive_portal_page() result dict, or None
    "checked_at": None,  # datetime the cache was last refreshed, or None
}


def get_cached_captive_portal_status() -> dict:
    """Return the last analyze_captive_portal_page() result without probing again.

    Read-only: callers that want a fresh probe should call
    analyze_and_cache_captive_portal() (or analyze_captive_portal_page()
    directly) instead.
    """
    result = _CAPTIVE_PORTAL_CACHE["result"]
    checked_at = _CAPTIVE_PORTAL_CACHE["checked_at"]
    if result is None:
        return {
            "status": "unknown",
            "captive": False,
            "url": None,
            "final_url": None,
            "http_status": None,
            "error": "No captive portal check has run yet",
            "page": None,
            "checked_at": None,
        }
    return {**result, "checked_at": checked_at.isoformat() if checked_at else None}


def analyze_and_cache_captive_portal(
    urls: tuple[str, ...] | list[str] | None = None,
    timeout: float = 5.0,
    max_bytes: int = CAPTIVE_PORTAL_MAX_BYTES,
) -> dict:
    """Run analyze_captive_portal_page() and cache the result for get_cached_captive_portal_status()."""
    result = analyze_captive_portal_page(urls=urls, timeout=timeout, max_bytes=max_bytes)
    _CAPTIVE_PORTAL_CACHE["result"] = result
    _CAPTIVE_PORTAL_CACHE["checked_at"] = datetime.now(timezone.utc)
    return {**result, "checked_at": _CAPTIVE_PORTAL_CACHE["checked_at"].isoformat()}


def run_ping(
    target: str = "8.8.8.8",
    count: int = 4,
    warn_latency_ms: float = 100.0,
    crit_latency_ms: float = 300.0,
    warn_loss_pct: float = 10.0,
) -> dict:
    """
    Run a Windows ping and return parsed results.

    Windows ping output we parse:
      "Packets: Sent = 4, Received = 3, Lost = 1 (25% loss)"
      "Minimum = 12ms, Maximum = 18ms, Average = 14ms"

    Args:
        target:          Host to ping (IP or hostname)
        count:           Number of ICMP packets to send
        warn_latency_ms: Latency above this → "degraded"
        crit_latency_ms: (unused in status — just informational for now)
        warn_loss_pct:   Packet loss % above this → "degraded"

    Returns:
        {
          status:      "online" | "degraded" | "offline"
          latency_ms:  float | None
          packet_loss: float (0–100)
          target:      str
          error:       str | None
        }
    """
    try:
        # Belt-and-suspenders window suppression: CREATE_NO_WINDOW alone can still
        # let a console flash on some Windows builds when the parent is windowless
        # (pythonw). A hidden STARTUPINFO (SW_HIDE) guarantees no visible terminal.
        _si = subprocess.STARTUPINFO()
        _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        _si.wShowWindow = 0  # SW_HIDE
        result = subprocess.run(
            ["ping", "-n", str(count), target],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
            startupinfo=_si,
        )
        output = result.stdout

        # ── Parse packet loss ────────────────────────────────────────────
        # "Lost = 4 (100% loss)" or "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        loss_match = re.search(r"Lost = \d+ \((\d+)% loss\)", output)
        loss_pct = float(loss_match.group(1)) if loss_match else 100.0

        # ── Parse average RTT ────────────────────────────────────────────
        # "Average = 14ms"
        avg_match = re.search(r"Average = (\d+)ms", output)
        latency_ms = float(avg_match.group(1)) if avg_match else None

        # ── Determine status ─────────────────────────────────────────────
        if loss_pct >= 100:
            status = "offline"
            error = "No reply from target — internet may be down"
        elif loss_pct > warn_loss_pct or (latency_ms is not None and latency_ms > warn_latency_ms):
            status = "degraded"
            error = None
        else:
            status = "online"
            error = None

        return {
            "status":      status,
            "latency_ms":  latency_ms,
            "packet_loss": loss_pct,
            "target":      target,
            "error":       error,
        }

    except subprocess.TimeoutExpired:
        return {
            "status":      "offline",
            "latency_ms":  None,
            "packet_loss": 100.0,
            "target":      target,
            "error":       "Ping command timed out after 30s",
        }
    except FileNotFoundError:
        # ping.exe not found — shouldn't happen on Windows
        return {
            "status":      "offline",
            "latency_ms":  None,
            "packet_loss": 100.0,
            "target":      target,
            "error":       "ping.exe not found",
        }
    except Exception as e:
        return {
            "status":      "offline",
            "latency_ms":  None,
            "packet_loss": 100.0,
            "target":      target,
            "error":       str(e),
        }


def run_dns_lookup(target: str = DNS_PROBE_TARGET, timeout: float = 8.0) -> dict:
    """
    Run a DNS lookup through the system resolver and return a compact result.

    We use nslookup because it exercises the same resolver path the OS uses for
    browser/app hostname lookups, which is what we need for DNS-blackout
    detection. The function returns a failure quickly when the resolver is dead
    instead of waiting on the router reboot path.
    """
    try:
        _si = subprocess.STARTUPINFO()
        _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        _si.wShowWindow = 0  # SW_HIDE
        result = subprocess.run(
            ["nslookup", "-timeout=5", "-retry=1", target],
            capture_output=True,
            text=True,
            timeout=max(5.0, float(timeout)),
            creationflags=subprocess.CREATE_NO_WINDOW,
            startupinfo=_si,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        failure_patterns = (
            "Non-existent domain",
            "timed out",
            "server failed",
            "can't find",
            "can't be found",
            "no response from server",
        )
        resolved_ips = re.findall(r"(?im)^\s*Address(?:es)?:\s*([0-9a-fA-F\.:]+)\s*$", output)
        name_match = re.search(r"(?im)^\s*Name:\s*(.+?)\s*$", output)
        success = bool(name_match and resolved_ips and not any(p.lower() in output.lower() for p in failure_patterns))
        if success:
            return {
                "status": "online",
                "target": target,
                "resolved_ips": resolved_ips,
                "error": None,
            }
        return {
            "status": "offline",
            "target": target,
            "resolved_ips": resolved_ips,
            "error": (output.strip() or "DNS lookup failed"),
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "offline",
            "target": target,
            "resolved_ips": [],
            "error": f"DNS lookup timed out after {timeout:.0f}s",
        }
    except FileNotFoundError:
        return {
            "status": "offline",
            "target": target,
            "resolved_ips": [],
            "error": "nslookup not found",
        }
    except Exception as e:
        return {
            "status": "offline",
            "target": target,
            "resolved_ips": [],
            "error": str(e),
        }


# ─────────────────────────────────────────────────────────────────────────────
# SPEED TEST (download only)
# ─────────────────────────────────────────────────────────────────────────────

# Speed-test tuning. The download phase opens DOWNLOAD_STREAMS parallel TCP
# connections to Cloudflare's CDN, lets each one drain DOWNLOAD_WARMUP_BYTES
# (so TCP slow-start finishes before we time anything), then measures all of
# them together for DOWNLOAD_MEASURE_SECONDS. Result is sum-of-bytes divided
# by wall-clock elapsed.
#
# Why parallel + time-bounded?
#   A single TCP stream is rate-limited by the per-flow congestion window and
#   any per-flow shaping the ISP applies. On a 1 Gbps line a single stream
#   commonly tops out around 300-500 Mbps. 4 streams in parallel is what
#   Cloudflare's own speedtest, Ookla, and fast.com all use to recover the
#   real link rate. Time-bounded (vs byte-bounded) means the test always
#   gives TCP enough time to ramp regardless of how fast the link is.
#
# URL bytes parameter: Cloudflare's __down endpoint caps at 50 MB per request
# (verified: ≥100 MB returns 403, regardless of User-Agent). When a stream
# drains its 50 MB before the measurement deadline, it opens a new request
# and keeps reading — so the cap doesn't limit the test, the wall-clock
# window does. The User-Agent must be non-default — Python's stock
# "Python-urllib/X.Y" is blocked outright by Cloudflare. "NetMon/0.1 SpeedTest"
# is fine.
DEFAULT_SPEED_URL          = "https://speed.cloudflare.com/__down?bytes=50000000"
DEFAULT_UPLOAD_URL         = "https://speed.cloudflare.com/__up"
UPLOAD_SIZE_BYTES          = 25_000_000   # 25 MB upload (single stream)
DOWNLOAD_STREAMS           = 4
DOWNLOAD_WARMUP_BYTES      = 5_000_000    # per-stream warmup; not timed
DOWNLOAD_MEASURE_SECONDS   = 8            # wall-clock window after all warmups complete
DOWNLOAD_WARMUP_TIMEOUT_S  = 30           # safety: bail if a stream can't finish warmup
# Backwards-compat alias for any external caller that imported WARMUP_BYTES
WARMUP_BYTES               = DOWNLOAD_WARMUP_BYTES


def _measure_one_download_stream(
    url:           str,
    warmup_bytes:  int,
    ready_event:   "threading.Event",
    start_event:   "threading.Event",
    measure_secs:  float,
) -> int:
    """
    One worker for the parallel download test. Opens a connection, drains
    `warmup_bytes` (untimed), signals ready, waits for the synchronized
    start signal, then reads as fast as possible until the wall-clock
    deadline. Returns measured bytes (0 on failure).
    """
    import threading  # noqa: F401 — typing hint for the parameter
    measured = 0
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetMon/0.1 SpeedTest"},
        )
        resp = urllib.request.urlopen(req, timeout=60)
    except Exception:
        ready_event.set()  # release coordinator even on failure
        return 0

    try:
        # Phase 1: warmup
        remaining = warmup_bytes
        while remaining > 0:
            chunk = resp.read(min(65536, remaining))
            if not chunk:
                ready_event.set()
                return 0
            remaining -= len(chunk)

        ready_event.set()
        # Wait for all streams to be warm before any of them starts timing
        if not start_event.wait(timeout=DOWNLOAD_WARMUP_TIMEOUT_S + 5):
            return 0

        # Measurement phase. Cloudflare caps each __down response at 100 MB,
        # so if our request EOFs before the deadline we just open another one
        # and keep going. From the user's perspective it's one continuous read.
        deadline = time.perf_counter() + measure_secs
        while time.perf_counter() < deadline:
            chunk = resp.read(65536)
            if chunk:
                measured += len(chunk)
                continue
            # EOF — request exhausted. Open a fresh one and keep reading.
            try:
                resp.close()
            except Exception:
                pass
            try:
                resp = urllib.request.urlopen(
                    urllib.request.Request(url, headers={"User-Agent": "NetMon/0.1 SpeedTest"}),
                    timeout=15,
                )
            except Exception:
                return measured  # connection failed mid-test; report what we got
        return measured
    finally:
        try:
            resp.close()
        except Exception:
            pass


def run_speed_test(url: str = DEFAULT_SPEED_URL, router_cfg: Optional[dict] = None) -> dict:
    """
    Measure download and upload speed.

    First attempts to run the test directly on a Netgear Orbi router via SOAP if configured.
    Falls back to client-side Cloudflare speed test on any failure.

    Download: DOWNLOAD_STREAMS parallel TCP connections, synchronized start,
              DOWNLOAD_MEASURE_SECONDS wall-clock window, sum of bytes
              divided by actual elapsed time.

    Upload:   single stream, untimed connection setup, timed body+ack.

    Returns:
        {
          download_mbps: float | None
          upload_mbps:   float | None
          latency_ms:    float | None
          error:         str | None
        }
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, wait

    download_mbps = None
    upload_mbps   = None
    latency_ms    = None
    error         = None

    # ── Attempt Router-level Speed Test first ────────────────────────────────
    if router_cfg and router_cfg.get("password"):
        try:
            from pynetgear import Netgear
            host = router_cfg.get("host") or "192.168.1.1"
            user = router_cfg.get("user") or "admin"
            password = router_cfg.get("password")

            # Try HTTPS (port 443) first, as required by newer Orbi firmware
            ng = Netgear(password=password, host=host, user=user, port=443, ssl=True)
            if not ng.login():
                # Fallback to HTTP (port 80)
                ng = Netgear(password=password, host=host, user=user)
                if not ng.login():
                    raise Exception("Router login failed on both HTTPS and HTTP")

            res = ng.get_new_speed_test_result()
            if res is not None:
                try:
                    download_mbps = float(res.get("NewOOKLADownlinkBandwidth") or 0.0)
                    upload_mbps = float(res.get("NewOOKLAUplinkBandwidth") or 0.0)
                    avg_ping = res.get("AveragePing")
                    latency_ms = float(avg_ping) if avg_ping is not None else None
                    
                    return {
                        "download_mbps": download_mbps,
                        "upload_mbps":   upload_mbps,
                        "latency_ms":    latency_ms,
                        "error":         None,
                    }
                except ValueError as ve:
                    raise Exception(f"Failed to parse speed test results: {res} - {ve}")
            else:
                raise Exception("Router speed test returned no results (None)")

        except Exception as e:
            print(f"Router speed test failed: {e}. Falling back to client-side speed test.")

    # ── Client-side Fallback Speed Test ──────────────────────────────────────
    ping_result = run_ping()
    latency_ms  = ping_result.get("latency_ms")

    # ── Download (parallel, time-bounded) ────────────────────────────────────
    try:
        ready_events = [threading.Event() for _ in range(DOWNLOAD_STREAMS)]
        start_event  = threading.Event()

        with ThreadPoolExecutor(max_workers=DOWNLOAD_STREAMS,
                                thread_name_prefix="netmon-speed") as ex:
            futures = [
                ex.submit(
                    _measure_one_download_stream,
                    url,
                    DOWNLOAD_WARMUP_BYTES,
                    ready_events[i],
                    start_event,
                    DOWNLOAD_MEASURE_SECONDS,
                )
                for i in range(DOWNLOAD_STREAMS)
            ]

            # Wait for every stream to either complete its warmup or fail.
            warmup_deadline = time.perf_counter() + DOWNLOAD_WARMUP_TIMEOUT_S
            for ev in ready_events:
                remaining = warmup_deadline - time.perf_counter()
                if remaining <= 0 or not ev.wait(timeout=remaining):
                    break  # one stream stalled — release whatever we have

            # Synchronized start: every still-running stream begins timing now.
            measure_start = time.perf_counter()
            start_event.set()

            # Give threads up to (measure + 5s) to drain.
            wait(futures, timeout=DOWNLOAD_MEASURE_SECONDS + 5)
            measure_elapsed = time.perf_counter() - measure_start

            total_bytes = sum(f.result() for f in futures if f.done())

        if measure_elapsed > 0 and total_bytes > 0:
            download_mbps = round((total_bytes * 8) / (measure_elapsed * 1_000_000), 1)

    except Exception as e:
        error = f"Download error: {e}"

    # ── Upload ────────────────────────────────────────────────────────────────
    # POST random bytes to Cloudflare's upload endpoint.
    # We time only the write phase (same exclusion logic as download).
    # os.urandom is slow for 25MB so we use a repeated block instead.
    try:
        block      = os.urandom(65536)                  # 64 KB random seed block
        repeats    = UPLOAD_SIZE_BYTES // len(block)
        payload    = block * repeats                    # 25 MB of pseudo-random data

        req = urllib.request.Request(
            DEFAULT_UPLOAD_URL,
            data    = payload,
            method  = "POST",
            headers = {
                "Content-Type":   "application/octet-stream",
                "Content-Length": str(len(payload)),
                "User-Agent":     "NetMon/0.1 SpeedTest",
            },
        )
        # Open connection first, then time the actual data send + server ack
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()   # wait for server to acknowledge receipt
        elapsed = time.perf_counter() - start

        if elapsed > 0:
            upload_mbps = round((len(payload) * 8) / (elapsed * 1_000_000), 1)

    except Exception as e:
        if not error:
            error = f"Upload error: {e}"

    return {
        "download_mbps": download_mbps,
        "upload_mbps":   upload_mbps,
        "latency_ms":    latency_ms,
        "error":         error,
    }
