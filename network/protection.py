"""Protection helpers for NetMon autonomous actions.

This module is intentionally stdlib-only and side-effect-light. It gives every
firewall/blocking path the same answer to one question: "is this target too
important to block automatically?"
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from functools import lru_cache


DEFAULT_PROTECTED_IPS = {"192.168.1.64"}


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _env_protected_ips() -> set[str]:
    raw = os.environ.get("NETMON_PROTECTED_IPS", "")
    values = {x.strip() for x in raw.split(",") if x.strip()}
    return values | DEFAULT_PROTECTED_IPS


@lru_cache(maxsize=1)
def local_machine_ips() -> set[str]:
    """Best-effort set of addresses assigned to this machine."""
    ips = {"127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"}
    try:
        hostname = socket.gethostname()
        ips.update(socket.gethostbyname_ex(hostname)[2])
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass

    for probe in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.2)
                s.connect((probe, 80))
                ips.add(s.getsockname()[0])
        except Exception:
            pass
    return {ip for ip in ips if _parse_ip(ip)}


@lru_cache(maxsize=1)
def gateway_ips() -> set[str]:
    """Best-effort default gateway detection on Windows."""
    found: set[str] = set()
    try:
        proc = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                if _parse_ip(parts[2]):
                    found.add(parts[2])
    except Exception:
        pass
    return found


def protected_ips() -> set[str]:
    return _env_protected_ips() | local_machine_ips() | gateway_ips()


def explain_protected_target(ip: str) -> str | None:
    """Return a human-readable block reason, or None if the IP may be blocked."""
    parsed = _parse_ip(ip)
    if parsed is None:
        return f"invalid IP address: {ip!r}"
    if parsed.version != 4:
        return f"IPv6 firewall automation is not supported here: {ip}"
    if str(parsed) in protected_ips():
        return f"{ip} is protected (this PC, configured protected IP, or gateway)"
    if parsed.is_loopback:
        return f"{ip} is loopback"
    if parsed.is_unspecified:
        return f"{ip} is unspecified"
    if parsed.is_multicast:
        return f"{ip} is multicast"
    if parsed.is_link_local:
        return f"{ip} is link-local"
    if str(parsed) == "255.255.255.255":
        return f"{ip} is broadcast"
    return None


def validate_block_target(ip: str) -> str:
    """Return normalized IPv4 string or raise ValueError with a clear reason."""
    reason = explain_protected_target(ip)
    if reason:
        raise ValueError(reason)
    return str(_parse_ip(ip))


def filter_blockable_ips(ips: list[str]) -> tuple[list[str], list[str]]:
    """Split candidate IPs into (safe_to_block, skipped_reasons)."""
    safe: list[str] = []
    skipped: list[str] = []
    for ip in ips:
        reason = explain_protected_target(ip)
        if reason:
            skipped.append(reason)
        else:
            safe.append(str(_parse_ip(ip)))
    return safe, skipped
