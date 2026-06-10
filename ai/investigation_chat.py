"""
investigation_chat.py — Interactive AI device-identification chat.

Companion to api/routes.py ai_investigate(). Where ai_investigate runs a
single-shot evidence sweep + verdict, this module powers a back-and-forth
conversation: user asks questions, the AI can request tools (passive
read-only by default; active ones gated behind a user approval), and the
AI proposes identity updates (name/category/OS) that auto-apply at high
confidence.

All tools are fail-safe — they return a string result no matter what.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any


# ── Tool registry ─────────────────────────────────────────────────────────────
# Every tool returns a plain string (markdown/text) that's appended to the
# chat thread as a "tool" turn. `active=True` tools require the user to
# explicitly approve them in the UI before they fire.

PASSIVE_TOOLS = {
    "oui_lookup",
    "dhcp_fingerprint_history",
    "recent_traffic_summary",
    "talked_to_hosts",
    "mdns_ssdp_hostnames",
    "tls_sni_history",
    "http_user_agents",
    "mac_randomization_check",
    "device_history",
    "port_history",
    "device_notes_list",
}

ACTIVE_TOOLS = {
    "nmap_quick",
    "nmap_deep",
    "nmap_os_detect",
    "banner_grab",
    "http_probe",
    "mdns_active_query",
    "ssdp_active_query",
    "snmp_public_probe",
    "wireguard_endpoint_probe",
    "arp_ping",
    "tcp_port_scan",
}


def tool_catalog() -> list[dict]:
    """Catalog the LLM sees so it knows what it can ask for."""
    return [
        # Passive
        {"name": "oui_lookup", "active": False,
         "desc": "Resolve MAC OUI vendor (more thorough than the row's vendor field)."},
        {"name": "dhcp_fingerprint_history", "active": False,
         "desc": "Pull DHCP option 55 fingerprint and hostname seen in captures."},
        {"name": "recent_traffic_summary", "active": False,
         "desc": "Top protocols, destination ports, byte counts for this device in last 3 pcap files."},
        {"name": "talked_to_hosts", "active": False,
         "desc": "Domains/IPs the device has contacted (DNS+SNI+HTTP host headers)."},
        {"name": "mdns_ssdp_hostnames", "active": False,
         "desc": "Any mDNS/SSDP/LLMNR/NBNS hostname announcements seen passively."},
        {"name": "tls_sni_history", "active": False,
         "desc": "TLS Server Name Indication values from outbound HTTPS traffic."},
        {"name": "http_user_agents", "active": False,
         "desc": "User-Agent strings from any plaintext HTTP this device sent."},
        {"name": "mac_randomization_check", "active": False,
         "desc": "Check if MAC has the locally-administered bit set (private/random MAC)."},
        {"name": "device_history", "active": False,
         "desc": "First seen, last seen, recent name/label history for this device."},
        {"name": "port_history", "active": False,
         "desc": "Listening ports observed across all past scans of this device."},
        {"name": "device_notes_list", "active": False,
         "desc": "Durable facts you've previously written about this device."},
        # Active
        {"name": "nmap_quick", "active": True,
         "desc": "nmap -sV --top-ports 200 — quick service/version on the most common ports."},
        {"name": "nmap_deep", "active": True,
         "desc": "nmap -sV -A -p- --script default,discovery — full port + script scan. SLOW (minutes)."},
        {"name": "nmap_os_detect", "active": True,
         "desc": "nmap -O --osscan-guess — OS fingerprint pass."},
        {"name": "banner_grab", "active": True,
         "desc": "Connect to a specific port and read its banner. Args: {port:int}."},
        {"name": "http_probe", "active": True,
         "desc": "GET http(s)://ip:port/ and read Server header, title, redirect targets. Args: {port:int}."},
        {"name": "mdns_active_query", "active": True,
         "desc": "Send mDNS _services._dns-sd._udp query to elicit Bonjour responses."},
        {"name": "ssdp_active_query", "active": True,
         "desc": "Send SSDP M-SEARCH to elicit UPnP device descriptions."},
        {"name": "snmp_public_probe", "active": True,
         "desc": "Try SNMP v1/v2c with 'public' community — sysDescr / sysName."},
        {"name": "wireguard_endpoint_probe", "active": True,
         "desc": "If WireGuard observed, attempt to identify the remote endpoint's host."},
        {"name": "arp_ping", "active": True,
         "desc": "Send an ARP probe to confirm device is currently online."},
        {"name": "tcp_port_scan", "active": True,
         "desc": "Connect-scan a port range. Args: {start:int, end:int}."},
    ]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _no_window():
    import os as _os
    if _os.name == "nt":
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    return 0


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=_no_window(),
        )
        out = (r.stdout or "") + (("\nSTDERR:\n" + r.stderr) if r.stderr.strip() else "")
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"(timeout after {timeout}s)"
    except FileNotFoundError:
        return f"(tool not installed: {cmd[0]})"
    except Exception as ex:
        return f"(error: {type(ex).__name__}: {ex})"


# ── Tool implementations ──────────────────────────────────────────────────────

def _tool_oui_lookup(db, device, args) -> str:
    mac = (device.mac or "").lower()
    if not mac:
        return "No MAC on file for this device."
    # First 24 bits
    prefix = "".join(c for c in mac if c in "0123456789abcdef")[:6]
    if len(prefix) < 6:
        return f"MAC {mac} too short for OUI lookup."
    # Attempt online lookup (best-effort, fail open).
    try:
        import urllib.request
        url = f"https://api.macvendors.com/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "NetMon/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            vendor = r.read().decode("utf-8", errors="replace").strip()
            return f"OUI {prefix.upper()} → {vendor or '(no vendor returned)'}"
    except Exception as ex:
        return f"OUI lookup failed for {prefix.upper()}: {ex}. Existing vendor field: {device.vendor or '(none)'}"


def _tool_dhcp_fingerprint_history(db, device, args) -> str:
    # Pull recent pcaps and grep for DHCP option 55 + Host Name from this MAC.
    from traffic.interfaces import find_tool
    from traffic.analyzer import get_readable_files, CAPTURE_DIR
    tshark = find_tool("tshark")
    if not tshark:
        return "tshark not available."
    mac = (device.mac or "").lower().replace("-", ":")
    if not mac:
        return "No MAC to filter on."
    files = get_readable_files(CAPTURE_DIR, max_files=5)
    findings: list[str] = []
    for pcap in files:
        try:
            r = subprocess.run(
                [tshark, "-r", str(pcap), "-Y", f"dhcp and eth.src=={mac}",
                 "-T", "fields", "-e", "dhcp.option.hostname",
                 "-e", "dhcp.option.parameter_request_list"],
                capture_output=True, text=True, timeout=15,
                creationflags=_no_window(),
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line and line not in findings:
                    findings.append(line)
        except Exception:
            continue
    if not findings:
        return "No DHCP packets from this MAC in the recent capture window."
    return "DHCP fingerprints seen:\n" + "\n".join(f"  - {f}" for f in findings[:20])


def _device_ip(db, device) -> str | None:
    from models.tables import ScanDevice
    from sqlalchemy import desc
    sd = (db.query(ScanDevice)
            .filter(ScanDevice.device_id == device.id)
            .order_by(desc(ScanDevice.id)).first())
    return sd.ip if sd else None


def _tool_recent_traffic_summary(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file for this device."
    from traffic.interfaces import find_tool
    from traffic.analyzer import get_readable_files, CAPTURE_DIR
    tshark = find_tool("tshark")
    if not tshark:
        return "tshark not available."
    files = get_readable_files(CAPTURE_DIR, max_files=3)
    protos: dict[str, int] = {}
    dports: dict[str, int] = {}
    total = 0
    for p in files:
        try:
            r = subprocess.run(
                [tshark, "-r", str(p), "-Y", f"ip.addr == {ip}",
                 "-T", "fields", "-e", "frame.protocols",
                 "-e", "tcp.dstport", "-e", "udp.dstport"],
                capture_output=True, text=True, timeout=20,
                creationflags=_no_window(),
            )
            for line in r.stdout.splitlines():
                if not line.strip():
                    continue
                total += 1
                tp = line.split("\t")
                proto = (tp[0].split(":")[-1] if tp else "").strip()
                if proto:
                    protos[proto] = protos.get(proto, 0) + 1
                port = (tp[1] if len(tp) > 1 and tp[1] else
                        tp[2] if len(tp) > 2 else "").strip()
                if port:
                    dports[port] = dports.get(port, 0) + 1
        except Exception:
            continue
    if total == 0:
        return f"No packets for {ip} in recent captures."
    top_p = sorted(protos.items(), key=lambda x: -x[1])[:6]
    top_d = sorted(dports.items(), key=lambda x: -x[1])[:10]
    return (f"Recent traffic for {ip} ({total} pkts):\n"
            f"  Protocols: {', '.join(f'{p}({c})' for p, c in top_p)}\n"
            f"  Dest ports: {', '.join(f'{p}({c})' for p, c in top_d)}")


def _tool_talked_to_hosts(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    from traffic.interfaces import find_tool
    from traffic.analyzer import get_readable_files, CAPTURE_DIR
    tshark = find_tool("tshark")
    if not tshark:
        return "tshark not available."
    hosts: set[str] = set()
    for p in get_readable_files(CAPTURE_DIR, max_files=4):
        try:
            r = subprocess.run(
                [tshark, "-r", str(p), "-Y", f"ip.src == {ip}",
                 "-T", "fields",
                 "-e", "dns.qry.name",
                 "-e", "http.host",
                 "-e", "tls.handshake.extensions_server_name"],
                capture_output=True, text=True, timeout=20,
                creationflags=_no_window(),
            )
            for line in r.stdout.splitlines():
                for f in line.split("\t"):
                    f = f.strip()
                    if f:
                        hosts.add(f)
        except Exception:
            continue
    if not hosts:
        return f"No outbound hostnames captured for {ip}."
    sample = sorted(hosts)[:40]
    return f"Hosts {ip} talked to ({len(hosts)} unique):\n" + "\n".join(f"  - {h}" for h in sample)


def _tool_mdns_ssdp_hostnames(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    from traffic.interfaces import find_tool
    from traffic.analyzer import get_readable_files, CAPTURE_DIR
    tshark = find_tool("tshark")
    if not tshark:
        return "tshark not available."
    names: set[str] = set()
    for p in get_readable_files(CAPTURE_DIR, max_files=5):
        try:
            r = subprocess.run(
                [tshark, "-r", str(p),
                 "-Y", f"(ip.src == {ip}) and (mdns or ssdp or llmnr or nbns)",
                 "-T", "fields",
                 "-e", "dns.resp.name",
                 "-e", "dns.qry.name",
                 "-e", "nbns.name",
                 "-e", "http.request.full_uri"],
                capture_output=True, text=True, timeout=20,
                creationflags=_no_window(),
            )
            for line in r.stdout.splitlines():
                for f in line.split("\t"):
                    f = f.strip()
                    if f and f not in names:
                        names.add(f)
        except Exception:
            continue
    if not names:
        return f"No mDNS/SSDP/LLMNR/NBNS announcements from {ip}."
    return f"Discovery-protocol hostnames from {ip}:\n" + "\n".join(f"  - {n}" for n in sorted(names)[:30])


def _tool_tls_sni_history(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    from traffic.interfaces import find_tool
    from traffic.analyzer import get_readable_files, CAPTURE_DIR
    tshark = find_tool("tshark")
    if not tshark:
        return "tshark not available."
    snis: dict[str, int] = {}
    for p in get_readable_files(CAPTURE_DIR, max_files=4):
        try:
            r = subprocess.run(
                [tshark, "-r", str(p), "-Y", f"ip.src == {ip} and tls.handshake",
                 "-T", "fields", "-e", "tls.handshake.extensions_server_name"],
                capture_output=True, text=True, timeout=20,
                creationflags=_no_window(),
            )
            for line in r.stdout.splitlines():
                n = line.strip()
                if n:
                    snis[n] = snis.get(n, 0) + 1
        except Exception:
            continue
    if not snis:
        return f"No TLS SNI values captured for {ip}."
    top = sorted(snis.items(), key=lambda x: -x[1])[:30]
    return f"TLS SNI from {ip}:\n" + "\n".join(f"  - {n} ({c})" for n, c in top)


def _tool_http_user_agents(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    from traffic.interfaces import find_tool
    from traffic.analyzer import get_readable_files, CAPTURE_DIR
    tshark = find_tool("tshark")
    if not tshark:
        return "tshark not available."
    uas: set[str] = set()
    for p in get_readable_files(CAPTURE_DIR, max_files=4):
        try:
            r = subprocess.run(
                [tshark, "-r", str(p), "-Y", f"ip.src == {ip} and http.user_agent",
                 "-T", "fields", "-e", "http.user_agent"],
                capture_output=True, text=True, timeout=20,
                creationflags=_no_window(),
            )
            for line in r.stdout.splitlines():
                n = line.strip()
                if n:
                    uas.add(n)
        except Exception:
            continue
    if not uas:
        return f"No plaintext HTTP User-Agent strings from {ip}."
    return f"HTTP User-Agents from {ip}:\n" + "\n".join(f"  - {u}" for u in sorted(uas)[:20])


def _tool_mac_randomization_check(db, device, args) -> str:
    mac = (device.mac or "").lower()
    if not mac:
        return "No MAC on file."
    # Parse first octet
    first = mac.split(":")[0] if ":" in mac else mac[:2]
    try:
        b = int(first, 16)
    except ValueError:
        return f"Could not parse MAC: {mac}"
    locally_admin = bool(b & 0x02)
    multicast = bool(b & 0x01)
    if locally_admin:
        return (f"MAC {mac} has the locally-administered bit SET — this is a "
                "randomized/private MAC. Common on modern iOS/Android/macOS for privacy. "
                "Vendor OUI lookups won't be meaningful.")
    return (f"MAC {mac} is a globally-unique (vendor-assigned) address. "
            f"OUI-based vendor identification is reliable.")


def _tool_device_history(db, device, args) -> str:
    fs = device.first_seen.isoformat() if device.first_seen else "?"
    ls = device.last_seen.isoformat() if device.last_seen else "?"
    return (f"Device #{device.id}\n"
            f"  MAC: {device.mac}\n"
            f"  Vendor: {device.vendor or '(unknown)'}\n"
            f"  Current label: {device.label or '(unlabeled)'}\n"
            f"  OS guess: {device.os_guess or '(none)'}\n"
            f"  First seen: {fs}\n"
            f"  Last seen: {ls}")


def _tool_port_history(db, device, args) -> str:
    from models.tables import ScanDevice
    from sqlalchemy import desc
    seen: set[int] = set()
    for sd in (db.query(ScanDevice)
                  .filter(ScanDevice.device_id == device.id)
                  .order_by(desc(ScanDevice.id)).limit(30).all()):
        try:
            for p in sd.ports_list or []:
                seen.add(int(p))
        except Exception:
            pass
    if not seen:
        return "No listening ports recorded for this device in any past scan."
    return f"Listening ports ever seen: {sorted(seen)}"


def _tool_device_notes_list(db, device, args) -> str:
    from models.tables import DeviceNote
    from sqlalchemy import desc
    notes = (db.query(DeviceNote)
                .filter(DeviceNote.device_id == device.id)
                .order_by(desc(DeviceNote.id)).limit(30).all())
    if not notes:
        return "No durable notes saved yet for this device."
    out = []
    for n in notes:
        c = f" ({n.confidence:.0%})" if n.confidence else ""
        out.append(f"  [{n.kind}{c}] {n.body}")
    return "Saved notes:\n" + "\n".join(out)


# ── Active tools ──────────────────────────────────────────────────────────────

def _tool_nmap_quick(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    return _run(["nmap", "-sV", "--top-ports", "200", "-T4", "-Pn", ip], timeout=180)


def _tool_nmap_deep(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    return _run(["nmap", "-sV", "-A", "-p-", "--script", "default,discovery",
                 "-T4", "-Pn", ip], timeout=900)


def _tool_nmap_os_detect(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    return _run(["nmap", "-O", "--osscan-guess", "-Pn", ip], timeout=180)


def _tool_banner_grab(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    port = int(args.get("port") or 0)
    if not port:
        return "banner_grab requires {port:int}."
    try:
        with socket.create_connection((ip, port), timeout=5) as s:
            # Send a small nudge for protocols that don't speak first
            try:
                s.sendall(b"\r\n")
            except Exception:
                pass
            s.settimeout(3)
            data = b""
            try:
                data = s.recv(2048)
            except socket.timeout:
                pass
            text = data.decode("utf-8", errors="replace").strip()
            return f"Banner on {ip}:{port}:\n{text or '(no banner — connection opened but server stayed silent)'}"
    except Exception as ex:
        return f"banner_grab {ip}:{port} failed: {type(ex).__name__}: {ex}"


def _tool_http_probe(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    port = int(args.get("port") or 80)
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    import urllib.request, ssl
    ctx = ssl._create_unverified_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetMon/1.0 device-id"})
        with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
            headers = dict(r.headers.items())
            body = r.read(4096).decode("utf-8", errors="replace")
            title = ""
            m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
            if m:
                title = m.group(1).strip()
            return (f"HTTP {url} → {r.status}\n"
                    f"Server: {headers.get('Server','(none)')}\n"
                    f"Content-Type: {headers.get('Content-Type','(none)')}\n"
                    f"Title: {title or '(none)'}\n"
                    f"Headers: {json.dumps({k: v for k, v in headers.items() if k.lower() in ('server','x-powered-by','via','location','www-authenticate')})}")
    except Exception as ex:
        return f"HTTP probe {url} failed: {type(ex).__name__}: {ex}"


def _tool_mdns_active_query(db, device, args) -> str:
    # Send mDNS query packet and listen briefly
    ip = _device_ip(db, device)
    try:
        import struct, time
        # DNS-SD meta-query: PTR _services._dns-sd._udp.local
        # Build a minimal DNS query packet
        tx_id = b"\x12\x34"
        flags = b"\x00\x00"
        q_count = b"\x00\x01"
        rest = b"\x00\x00\x00\x00\x00\x00"
        def encname(n):
            out = b""
            for label in n.split("."):
                out += bytes([len(label)]) + label.encode()
            return out + b"\x00"
        qname = encname("_services._dns-sd._udp.local")
        qtype = b"\x00\x0c"  # PTR
        qclass = b"\x00\x01"
        pkt = tx_id + flags + q_count + rest + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.settimeout(3)
        sock.sendto(pkt, ("224.0.0.251", 5353))
        responses: list[str] = []
        start = time.time()
        while time.time() - start < 3:
            try:
                data, addr = sock.recvfrom(2048)
                if ip and addr[0] != ip:
                    continue
                # Naïve label-string extraction
                strings = re.findall(rb"[ -~]{4,64}", data)
                for s in strings:
                    decoded = s.decode("ascii", errors="replace")
                    if "local" in decoded or "_tcp" in decoded or "_udp" in decoded:
                        responses.append(f"{addr[0]}: {decoded}")
            except socket.timeout:
                break
            except Exception:
                continue
        sock.close()
        if not responses:
            return f"mDNS query sent but no responses from {ip or 'target'} in 3s."
        return "mDNS responses:\n" + "\n".join(f"  - {r}" for r in responses[:30])
    except Exception as ex:
        return f"mDNS active query failed: {ex}"


def _tool_ssdp_active_query(db, device, args) -> str:
    try:
        import time
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               "HOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               "ST: ssdp:all\r\n\r\n").encode()
        ip = _device_ip(db, device)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(3)
        sock.sendto(msg, ("239.255.255.250", 1900))
        responses: list[str] = []
        start = time.time()
        while time.time() - start < 3:
            try:
                data, addr = sock.recvfrom(4096)
                if ip and addr[0] != ip:
                    continue
                responses.append(f"{addr[0]}:\n{data.decode('utf-8', errors='replace').strip()}")
            except socket.timeout:
                break
            except Exception:
                continue
        sock.close()
        if not responses:
            return f"SSDP query sent but no responses from {ip or 'target'}."
        return "SSDP responses:\n\n" + "\n\n---\n".join(responses[:6])
    except Exception as ex:
        return f"SSDP active query failed: {ex}"


def _tool_snmp_public_probe(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    # Try snmpget for v2c public
    out = _run(["snmpget", "-v", "2c", "-c", "public", "-t", "2", "-r", "1",
                ip, "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"], timeout=15)
    if "tool not installed" in out:
        # Fallback: raw socket attempt
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x00\x00\x01"
                     b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
                     (ip, 161))
            data, _ = s.recvfrom(2048)
            s.close()
            return f"SNMP v2c public responded with {len(data)} bytes (decode the SEQUENCE for full info)."
        except Exception as ex:
            return f"SNMP probe failed (and snmpget not installed): {ex}"
    return out


def _tool_wireguard_endpoint_probe(db, device, args) -> str:
    return ("WireGuard endpoint resolution requires either traffic capture analysis "
            "or kernel-side wg-tools. Suggest: review tls_sni_history / talked_to_hosts "
            "for the IP this device sent UDP to on port 51820 or other custom WG ports. "
            "If the endpoint resolves to a known VPN provider's IP range, that confirms.")


def _tool_arp_ping(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    # arp-ping fallback to regular ping
    import platform
    if platform.system() == "Windows":
        return _run(["ping", "-n", "2", "-w", "1000", ip], timeout=8)
    return _run(["ping", "-c", "2", "-W", "1", ip], timeout=8)


def _tool_tcp_port_scan(db, device, args) -> str:
    ip = _device_ip(db, device)
    if not ip:
        return "No IP on file."
    start = max(1, int(args.get("start") or 1))
    end   = min(65535, int(args.get("end") or 1024))
    if end - start > 2000:
        return f"Range too large ({end-start} ports). Pick ≤2000."
    open_ports: list[int] = []
    for p in range(start, end + 1):
        try:
            with socket.create_connection((ip, p), timeout=0.3):
                open_ports.append(p)
        except Exception:
            pass
    if not open_ports:
        return f"No open TCP ports in {start}-{end} on {ip}."
    return f"Open TCP ports {start}-{end} on {ip}: {open_ports}"


TOOL_FUNCS: dict[str, Any] = {
    "oui_lookup":              _tool_oui_lookup,
    "dhcp_fingerprint_history": _tool_dhcp_fingerprint_history,
    "recent_traffic_summary":  _tool_recent_traffic_summary,
    "talked_to_hosts":         _tool_talked_to_hosts,
    "mdns_ssdp_hostnames":     _tool_mdns_ssdp_hostnames,
    "tls_sni_history":         _tool_tls_sni_history,
    "http_user_agents":        _tool_http_user_agents,
    "mac_randomization_check": _tool_mac_randomization_check,
    "device_history":          _tool_device_history,
    "port_history":            _tool_port_history,
    "device_notes_list":       _tool_device_notes_list,
    "nmap_quick":              _tool_nmap_quick,
    "nmap_deep":               _tool_nmap_deep,
    "nmap_os_detect":          _tool_nmap_os_detect,
    "banner_grab":             _tool_banner_grab,
    "http_probe":              _tool_http_probe,
    "mdns_active_query":       _tool_mdns_active_query,
    "ssdp_active_query":       _tool_ssdp_active_query,
    "snmp_public_probe":       _tool_snmp_public_probe,
    "wireguard_endpoint_probe": _tool_wireguard_endpoint_probe,
    "arp_ping":                _tool_arp_ping,
    "tcp_port_scan":           _tool_tcp_port_scan,
}


def execute_tool(db, device, name: str, args: dict | None = None) -> str:
    """Run a registered tool. Always returns a string."""
    if name not in TOOL_FUNCS:
        return f"Unknown tool: {name}"
    args = args or {}
    try:
        return TOOL_FUNCS[name](db, device, args)
    except Exception as ex:
        return f"Tool {name} crashed: {type(ex).__name__}: {ex}"


# ── Chat orchestration ────────────────────────────────────────────────────────

CHAT_SYSTEM_PROMPT = """You are NetMon's device-identification assistant. The user owns this network and wants to identify every device on it as precisely as possible. You can request tools to gather more evidence and propose name/category/OS updates.

Reply ONLY with a single JSON object (no markdown fences) in this shape:

{
  "reply": "your chat message to the user — concise, plain text",
  "tool_request": null OR {"name": "tool_name", "args": {...}, "rationale": "why you want to run it"},
  "proposal": null OR {"name": "Landon's iPhone", "category": "phone", "os": "iOS 17", "confidence": 0.85, "reasoning": "..."},
  "notes": [ "durable fact 1", "durable fact 2" ]
}

Rules:
- Only ONE tool_request per turn. If you need multiple, ask for them in sequence.
- Passive tools run immediately. Active tools require user approval (the UI handles this — just request them).
- Confidence ≥0.80 will auto-apply name+category. Below 0.80 surfaces an Accept card.
- "notes" are durable facts about THIS device. Only write what's worth keeping forever (identity clues, observed behavior). Keep each note one sentence.
- Categories must be one of: phone, tablet, computer, laptop, iot, camera, speaker, tv, router, printer, console, vehicle, vacuum, light, plug, sensor, hub, server, unknown
- Be concise. The user is technical.

CRITICAL — when to propose vs. keep digging:
- COMMIT to a proposal as soon as evidence is strong, even if not airtight. Strong signals include:
  * mDNS/Bonjour service names (_googlecast._tcp → Chromecast/Google-Cast device; _airplay._tcp → Apple TV/HomePod; _hap._tcp → HomeKit accessory; _spotify-connect._tcp → speaker; _printer._tcp → printer; _ipp._tcp → printer; _raop._tcp → AirPlay receiver)
  * DHCP hostname strings (e.g. "iPhone-of-Foo", "android-...", "HP3A2F8C")
  * TLS SNI to vendor-specific endpoints (push.apple.com → Apple device; mtalk.google.com / android.googleapis.com → Android; xboxlive.com → Xbox; nintendo.net → Switch; roku.com → Roku)
  * HTTP User-Agent strings
  * Distinctive open ports (e.g. 8009 + Google Cast → Chromecast; 62078 → iPhone lockdown; 9100 → printer)
- Use confidence ≥0.80 only when at least one strong signal above is present.
- If hostname/service strongly indicates a vendor/family, propose at 0.80–0.95 even when the exact model is unknown (e.g. "Google Chromecast / Cast-enabled device" is a fine name; the user can edit).

ANTI-REPETITION (HARD RULE):
- Do NOT restate a conclusion the user has already seen in the immediately preceding turn(s).
- If you discovered a fact and stated it once, the next turn should move forward — propose, run a more specific tool, or ask the user — not re-summarize.

ROUTING / TOOL HINTS:
- After `oui_lookup` fails with HTTP 404 or "no vendor": ALWAYS run `mac_randomization_check` next. A locally-administered MAC explains the OUI failure and is itself useful evidence (modern Apple/Google/Android privacy MAC).
- After observing a `_*._tcp.local` mDNS host, that alone is usually enough to identify the device family — propose, don't keep scanning.
- Reserve active scans (nmap, banner_grab) for cases where passive evidence is genuinely ambiguous.

NEVER write a `reply` that just summarizes the most recent tool output verbatim. The user already sees it expanded. Add something new each turn.

NO DEAD-END REPLIES (HARD RULE):
- If your reply says or implies "let's try X" / "let me check Y" / "I'll look at Z" / "more digging needed" — you MUST set `tool_request` to the next tool to run in the SAME turn. Words without an action are forbidden.
- If you have nothing left to try, do ONE of these instead:
  (a) Set `proposal` with your best guess at lower confidence (0.4–0.7) so the user gets an Accept card.
  (b) Ask the user a SPECIFIC question in `reply` ("Is this device near your TV?" / "Do you have a smart bulb?") — phrased so they can answer in one sentence.
  (c) State plainly in `reply` that passive evidence is exhausted and recommend a specific active tool by name.
- Vague filler ("let's keep looking", "let's try other clues", "more analysis needed") with no `tool_request`, no `proposal`, and no specific user question is the worst possible reply. Do not produce it.

Each turn must DO something: run a tool, commit to a proposal, or ask the user a concrete question."""


def build_chat_prompt(device, evidence_bundle: str, notes: list[str],
                      history: list[dict], user_message: str,
                      tool_result: dict | None = None) -> str:
    """
    Compose a full prompt for the chat turn. `history` is the prior turns
    (already pruned). `tool_result` is set when this turn is a follow-up after
    a tool just ran.
    """
    catalog = tool_catalog()
    tools_text = "\n".join(
        f"  - {t['name']} {'(ACTIVE: requires user approval)' if t['active'] else '(passive)'} — {t['desc']}"
        for t in catalog
    )

    notes_text = "\n".join(f"  - {n}" for n in notes) if notes else "  (none yet)"

    history_lines: list[str] = []
    for turn in history[-20:]:  # cap context
        role = turn.get("role", "user")
        content = turn.get("content", "")
        history_lines.append(f"[{role}] {content}")
    history_text = "\n".join(history_lines) if history_lines else "(no prior turns)"

    parts = [
        CHAT_SYSTEM_PROMPT,
        "",
        "AVAILABLE TOOLS:",
        tools_text,
        "",
        "DEVICE UNDER INVESTIGATION:",
        evidence_bundle,
        "",
        "DURABLE NOTES FROM PRIOR SESSIONS:",
        notes_text,
        "",
        "CONVERSATION HISTORY:",
        history_text,
    ]

    if tool_result:
        parts += [
            "",
            f"TOOL RESULT — `{tool_result['name']}` just finished:",
            "```",
            (tool_result.get("output") or "")[:4000],
            "```",
            "",
            "Now respond as JSON. The user did not type anything — this is a tool-result follow-up.",
        ]
    else:
        parts += [
            "",
            f"USER: {user_message}",
            "",
            "Respond as JSON.",
        ]

    return "\n".join(parts)


def build_evidence_bundle(db, device) -> str:
    """Compact snapshot of what we know about the device. Reused each turn."""
    ip = _device_ip(db, device) or "(no IP)"
    parts = [
        f"IP: {ip}",
        f"MAC: {device.mac or '(unknown)'}",
        f"Vendor (from MAC OUI): {device.vendor or '(unknown)'}",
        f"Current label: {device.label or '(unlabeled)'}",
        f"Hostname (DHCP/mDNS): {device.hostname or '(unknown)'}",
        f"OS guess: {device.os_guess or '(none)'}",
        f"Marked trusted: {bool(device.is_known)}",
        f"First seen: {device.first_seen.isoformat() if device.first_seen else '?'}",
        f"Last seen: {device.last_seen.isoformat() if device.last_seen else '?'}",
    ]
    # Loud hint when the current label or hostname is itself an identification.
    identifying = (device.label or "") + " " + (device.hostname or "")
    identifying_l = identifying.lower()
    for keyword, family in [
        ("iphone", "Apple iPhone"), ("ipad", "Apple iPad"),
        ("macbook", "Apple MacBook"), ("imac", "Apple iMac"),
        ("airpods", "Apple AirPods"),
        ("android", "Android phone/tablet"), ("pixel", "Google Pixel"),
        ("galaxy", "Samsung Galaxy"),
        ("chromecast", "Google Chromecast"), ("google-home", "Google Home"),
        ("nest", "Google Nest"),
        ("echo", "Amazon Echo"), ("kindle", "Amazon Kindle"),
        ("firetv", "Amazon Fire TV"),
        ("roku", "Roku"), ("appletv", "Apple TV"),
        ("xbox", "Xbox"), ("playstation", "PlayStation"), ("nintendo", "Nintendo"),
        ("roborock", "Roborock vacuum"), ("ring", "Ring camera"),
        ("wyze", "Wyze camera"),
    ]:
        if keyword in identifying_l:
            parts.append(
                f"*** STRONG IDENTITY SIGNAL: the label/hostname contains '{keyword}' — "
                f"this device is almost certainly a {family}. You should propose at "
                f"confidence ≥0.90 immediately unless contradicted by other evidence. ***"
            )
            break
    # Add known listening ports
    try:
        from models.tables import ScanDevice
        from sqlalchemy import desc
        sd = (db.query(ScanDevice)
                  .filter(ScanDevice.device_id == device.id,
                          ScanDevice.open_ports.notin_(["[]", ""]))
                  .order_by(desc(ScanDevice.id)).first())
        if sd:
            parts.append(f"Latest open ports: {sd.ports_list}")
    except Exception:
        pass
    return "\n".join(parts)


def parse_chat_response(raw: str) -> dict:
    """Extract the JSON object from the LLM's raw text. Lenient — falls back
    to wrapping plain text as a reply if JSON parsing fails."""
    raw = (raw or "").strip()
    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```\s*$", "", raw)
    # Try to find the first balanced JSON object
    start = raw.find("{")
    if start == -1:
        return {"reply": raw, "tool_request": None, "proposal": None, "notes": []}
    depth = 0
    end = -1
    in_str = False
    esc = False
    for i, c in enumerate(raw[start:], start=start):
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end == -1:
        return {"reply": raw, "tool_request": None, "proposal": None, "notes": []}
    try:
        obj = json.loads(raw[start:end])
        # Defensive defaults
        return {
            "reply":        obj.get("reply") or "",
            "tool_request": obj.get("tool_request") or None,
            "proposal":     obj.get("proposal") or None,
            "notes":        obj.get("notes") or [],
        }
    except Exception:
        return {"reply": raw, "tool_request": None, "proposal": None, "notes": []}


def build_explanation_prompt(device, turn_role: str, turn_content: str, meta: dict | None = None) -> str:
    """Compose a prompt for the AI to explain a specific chat turn (like a tool output or assistant reply)."""
    device_info = (
        f"Device ID: {device.id}\n"
        f"Name/Label: {device.label or 'Unknown'}\n"
        f"IP Address: {device.ip_addr or 'Unknown'}\n"
        f"MAC Address: {device.mac_addr or 'Unknown'}\n"
        f"OS: {device.os_guess or 'Unknown'}"
    )

    if turn_role == "tool":
        tool_name = (meta or {}).get("tool", "Unknown Tool")
        args = (meta or {}).get("args", {})
        return (
            f"You are NetMon's network assistant. A user has run the tool '{tool_name}' (with args: {args}) "
            f"on the following network device:\n"
            f"{device_info}\n\n"
            f"The raw tool output is:\n"
            f"---START TOOL OUTPUT---\n"
            f"{turn_content}\n"
            f"---END TOOL OUTPUT---\n\n"
            f"Explain in clear, friendly, and non-technical language:\n"
            f"1. What this tool does and what these results mean for this device.\n"
            f"2. Any interesting findings, warnings, or anomalies discovered in the output.\n"
            f"3. Practical next steps or recommendations for the user.\n"
            f"Keep your explanation concise, direct, and structured. Avoid heavy technical jargon."
        )
    elif turn_role == "assistant":
        return (
            f"You are NetMon's network assistant. A user is asking for a clear, plain-English explanation of your "
            f"message in the context of device investigation:\n"
            f"Message:\n"
            f"{turn_content}\n\n"
            f"Context: The message is about this network device:\n"
            f"{device_info}\n\n"
            f"Explain this message clearly, concisely, and in simple terms, highlighting why it is important for the "
            f"user to know, and what actions they can take."
        )
    else:
        return (
            f"You are NetMon's network assistant. A user is asking for a clear, plain-English explanation of this "
            f"chat message (role: {turn_role}):\n"
            f"Message:\n"
            f"{turn_content}\n\n"
            f"Context: The message is about this network device:\n"
            f"{device_info}\n\n"
            f"Explain this message clearly and concisely."
        )
