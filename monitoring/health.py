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
import subprocess
import time
import urllib.request
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# PING / LATENCY
# ─────────────────────────────────────────────────────────────────────────────

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
