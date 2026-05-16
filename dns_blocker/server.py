"""
server.py — UDP DNS server that blocks ad/tracker domains.

How it works:
  1. Listens on 0.0.0.0:53 (UDP).
  2. For each query: check domain against blocklist.
       Blocked → reply NXDOMAIN  (domain doesn't exist)
       Clean   → forward to upstream DNS (default 8.8.8.8), relay answer back.
  3. All queries/results recorded for stats.

The server runs in a daemon thread started by main.py when dns_blocker_enabled=true.
"""

import socket
import threading
import time

from dnslib import DNSRecord, QTYPE, RR, RCODE
from dnslib.server import DNSServer, BaseResolver, DNSLogger

from . import blocklist as bl


def _log_blocked(client_ip: str, domain: str) -> None:
    """Persist blocked DNS queries to ActivityLog so they survive restarts."""
    try:
        from monitoring.activity import write_log
        write_log(
            "warning", "dns", "dns_blocked",
            f"DNS blocked: {domain} (from {client_ip})",
            detail={"domain": domain, "client_ip": client_ip},
            device_ip=client_ip,
        )
    except Exception:
        pass  # never let logging break DNS


# ── Resolver ──────────────────────────────────────────────────────────────────

class BlockingResolver(BaseResolver):
    def __init__(self, upstream: str = "8.8.8.8", upstream_port: int = 53):
        self.upstream      = upstream
        self.upstream_port = upstream_port

    def resolve(self, request, handler):
        qname     = str(request.q.qname).rstrip(".")
        qtype     = QTYPE[request.q.qtype]
        reply     = request.reply()
        client_ip = getattr(handler, "client_address", ("unknown",))[0]

        if bl.is_blocked(qname):
            bl.record_query(qname, blocked=True)
            # Log to DB in background — don't slow down DNS response
            threading.Thread(
                target=_log_blocked, args=(client_ip, qname),
                daemon=True, name="dns-log"
            ).start()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        bl.record_query(qname, blocked=False)

        # Forward to upstream
        try:
            proxy_r = DNSRecord.parse(
                request.send(self.upstream, self.upstream_port, timeout=5)
            )
            reply.add_answer(*proxy_r.rr)
            reply.add_auth(*proxy_r.auth)
            reply.add_ar(*proxy_r.ar)
            reply.header.rcode = proxy_r.header.rcode
        except Exception as exc:
            print(f"[dns_blocker] upstream error for {qname}: {exc}")
            reply.header.rcode = RCODE.SERVFAIL

        return reply


# ── Server lifecycle ──────────────────────────────────────────────────────────

_server_instance: DNSServer | None = None
_server_lock = threading.Lock()


def start(upstream: str = "8.8.8.8", port: int = 53) -> bool:
    """
    Start the DNS server.  Returns True on success, False if port is unavailable.
    Must be called *after* blocklist.refresh() so the set is populated.
    """
    global _server_instance

    with _server_lock:
        if _server_instance is not None:
            return True   # already running

        resolver = BlockingResolver(upstream=upstream, upstream_port=53)
        # Suppress verbose dnslib logging
        logger   = DNSLogger(prefix=False, logf=lambda *a, **k: None)

        try:
            srv = DNSServer(
                resolver,
                port=port,
                address="0.0.0.0",
                logger=logger,
            )
            srv.start_thread()
            _server_instance = srv
            print(f"[dns_blocker] DNS server listening on 0.0.0.0:{port} → upstream {upstream}")
            return True
        except Exception as exc:
            print(f"[dns_blocker] failed to start DNS server: {exc}")
            return False


def stop() -> None:
    global _server_instance
    with _server_lock:
        if _server_instance is not None:
            try:
                _server_instance.stop()
            except Exception:
                pass
            _server_instance = None
            print("[dns_blocker] DNS server stopped")


def is_running() -> bool:
    return _server_instance is not None
