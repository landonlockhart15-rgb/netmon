"""
network/discovery.py — Passive name resolution for LAN devices.

Three discovery channels:
  • mDNS (UDP 5353)  — Bonjour / zeroconf. Common on Apple/IoT (cameras, TVs,
                       printers). Source IP + query/response carry the friendly
                       name like "living-room-roku.local".
  • SSDP (UDP 1900)  — UPnP. Routers, smart TVs, game consoles, IoT hubs.
                       NOTIFY messages carry NT/USN/SERVER strings.
  • NBNS (UDP 137)   — old Windows naming, used by some printers/NAS.

We only LISTEN — no broadcasts, no probes. Whatever the device chooses to
announce, we record. If we learn a better hostname or vendor string than
what's on the Device row, we update it.

Token-free, no AI involvement.

Two threads run as daemons started from main.py.
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
from typing import Optional

from app.database import SessionLocal
from models.tables import Device

# ── mDNS ─────────────────────────────────────────────────────────────────────

_MDNS_GROUP = "224.0.0.251"
_MDNS_PORT  = 5353

_MDNS_NAME_RE = re.compile(rb"(?:[\x00-\x3f][a-zA-Z0-9_\-]+)+")


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name with compression starting at offset. Returns (name, new_offset)."""
    parts = []
    visited = set()
    cur = offset
    advance = None
    while cur < len(data):
        length = data[cur]
        if length == 0:
            cur += 1
            break
        if length & 0xC0 == 0xC0:
            # Pointer
            if advance is None:
                advance = cur + 2
            if cur in visited:
                break
            visited.add(cur)
            cur = ((length & 0x3F) << 8) | data[cur + 1]
            continue
        cur += 1
        parts.append(data[cur:cur + length].decode("utf-8", errors="replace"))
        cur += length
    if advance is None:
        advance = cur
    return ".".join(parts), advance


def _mdns_listener() -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", _MDNS_PORT))
        mreq = struct.pack("=4sl", socket.inet_aton(_MDNS_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"[mdns] cannot bind 5353 (probably in use): {exc}")
        return

    print("[mdns] listening on 5353")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            client_ip = addr[0]
            # Parse the most likely useful PTR/SRV record name.
            try:
                # DNS header is 12 bytes; questions + answers follow.
                # Decode first question name as a low-cost hint.
                name, _ = _decode_dns_name(data, 12)
            except Exception:
                continue
            if not name or "." not in name:
                continue
            hostname_hint = name.split(".")[0] if name.endswith(".local") else None
            if hostname_hint and len(hostname_hint) > 1:
                _update_device_hostname(client_ip, hostname_hint, source="mdns")
        except socket.timeout:
            continue
        except Exception as exc:
            print(f"[mdns] loop error: {exc}")
            time.sleep(1.0)


# ── SSDP ─────────────────────────────────────────────────────────────────────

_SSDP_GROUP = "239.255.255.250"
_SSDP_PORT  = 1900

_SSDP_SERVER_RE = re.compile(rb"SERVER:\s*([^\r\n]+)", re.IGNORECASE)
_SSDP_USN_RE    = re.compile(rb"USN:\s*([^\r\n]+)",    re.IGNORECASE)


def _ssdp_listener() -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", _SSDP_PORT))
        mreq = struct.pack("=4sl", socket.inet_aton(_SSDP_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"[ssdp] cannot bind 1900: {exc}")
        return

    print("[ssdp] listening on 1900")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            client_ip = addr[0]
            server = _SSDP_SERVER_RE.search(data)
            if server:
                hint = server.group(1).strip().decode("utf-8", errors="replace")
                # Take the most-specific token (last segment usually has the device model).
                pieces = [p for p in hint.split() if p]
                vendor_hint = pieces[-1] if pieces else hint
                _update_device_vendor(client_ip, vendor_hint[:128], source="ssdp")
        except socket.timeout:
            continue
        except Exception as exc:
            print(f"[ssdp] loop error: {exc}")
            time.sleep(1.0)


# ── DB helpers ────────────────────────────────────────────────────────────────

def _update_device_hostname(ip: str, hostname: str, source: str) -> None:
    db = SessionLocal()
    try:
        from models.tables import ScanDevice
        sd = (
            db.query(ScanDevice).join(Device)
            .filter(ScanDevice.ip == ip)
            .order_by(ScanDevice.id.desc()).first()
        )
        if not sd or not sd.device:
            return
        dev = sd.device
        if not dev.hostname or dev.hostname.lower() == hostname.lower():
            return  # nothing new
        # Prefer mDNS hostnames as they're typically the friendly name.
        if not dev.hostname or len(hostname) > len(dev.hostname or ""):
            dev.hostname = hostname
            db.commit()
    except Exception as exc:
        print(f"[discovery] hostname update error ({source}): {exc}")
    finally:
        db.close()


def _update_device_vendor(ip: str, vendor: str, source: str) -> None:
    db = SessionLocal()
    try:
        from models.tables import ScanDevice
        sd = (
            db.query(ScanDevice).join(Device)
            .filter(ScanDevice.ip == ip)
            .order_by(ScanDevice.id.desc()).first()
        )
        if not sd or not sd.device:
            return
        dev = sd.device
        # Only overwrite if our current vendor looks weak ("unknown" / empty)
        if not dev.vendor or dev.vendor.strip().lower() in ("", "unknown"):
            dev.vendor = vendor
            db.commit()
    except Exception as exc:
        print(f"[discovery] vendor update error ({source}): {exc}")
    finally:
        db.close()


def start_passive_discovery() -> None:
    """Start mDNS + SSDP listener threads. Idempotent."""
    threading.Thread(target=_mdns_listener, daemon=True, name="netmon-mdns").start()
    threading.Thread(target=_ssdp_listener, daemon=True, name="netmon-ssdp").start()


# ── Active Discovery Sweep ───────────────────────────────────────────────────

def parse_dns_packet(data: bytes) -> list[str]:
    names = []
    try:
        if len(data) < 12:
            return names
        
        qdcount = struct.unpack("!H", data[4:6])[0]
        ancount = struct.unpack("!H", data[6:8])[0]
        nscount = struct.unpack("!H", data[8:10])[0]
        arcount = struct.unpack("!H", data[10:12])[0]
        
        offset = 12
        
        def decode_name(cur_offset: int) -> tuple[str, int]:
            parts = []
            visited = set()
            cur = cur_offset
            advance = None
            while cur < len(data):
                length = data[cur]
                if length == 0:
                    cur += 1
                    break
                if length & 0xC0 == 0xC0:
                    if cur + 1 >= len(data):
                        break
                    if advance is None:
                        advance = cur + 2
                    if cur in visited:
                        break
                    visited.add(cur)
                    cur = ((length & 0x3F) << 8) | data[cur + 1]
                    continue
                cur += 1
                if cur + length > len(data):
                    break
                parts.append(data[cur:cur + length].decode("utf-8", errors="replace"))
                cur += length
            if advance is None:
                advance = cur
            return ".".join(parts), advance

        for _ in range(qdcount):
            name, offset = decode_name(offset)
            if name:
                names.append(name)
            offset += 4
            
        total_rrs = ancount + nscount + arcount
        for _ in range(total_rrs):
            if offset >= len(data):
                break
            name, offset = decode_name(offset)
            if name:
                names.append(name)
            if offset + 10 > len(data):
                break
            rr_type, rr_class, rr_ttl, rdlen = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            
            if rr_type == 12:
                ptr_name, _ = decode_name(offset)
                if ptr_name:
                    names.append(ptr_name)
            elif rr_type == 33:
                if offset + 6 < len(data):
                    srv_name, _ = decode_name(offset + 6)
                    if srv_name:
                        names.append(srv_name)
            
            offset += rdlen
    except Exception:
        pass
    return names


def _resolve_upnp_details(ip: str, location_url: str) -> None:
    try:
        import urllib.request as urllib_req
        import re as xml_re
        req = urllib_req.Request(location_url, headers={"User-Agent": "NetMon/1.0 home-network-monitor"})
        with urllib_req.urlopen(req, timeout=3.0) as response:
            xml_content = response.read().decode("utf-8", errors="replace")
            
        def get_tag(tag_name: str) -> str:
            match = xml_re.search(fr"<{tag_name}[^>]*>([^<]+)</{tag_name}>", xml_content, xml_re.I)
            return match.group(1).strip() if match else ""
            
        manufacturer = get_tag("manufacturer") or get_tag("manufacturerName")
        model = get_tag("modelName") or get_tag("modelDescription")
        friendly_name = get_tag("friendlyName")
        
        if manufacturer:
            vendor_str = f"{manufacturer} {model}".strip() if model else manufacturer
            _update_device_vendor(ip, vendor_str[:128], source="upnp_xml")
            
        if friendly_name:
            _update_device_hostname(ip, friendly_name, source="upnp_xml")
            
    except Exception:
        pass


def _send_active_ssdp_query() -> None:
    try:
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               "HOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               "ST: ssdp:all\r\n\r\n").encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(3.0)
        sock.sendto(msg, ("239.255.255.250", 1900))
        
        start_time = time.time()
        while time.time() - start_time < 3.0:
            try:
                data, addr = sock.recvfrom(4096)
                client_ip = addr[0]
                
                server_match = _SSDP_SERVER_RE.search(data)
                if server_match:
                    hint = server_match.group(1).strip().decode("utf-8", errors="replace")
                    pieces = [p for p in hint.split() if p]
                    vendor_hint = pieces[-1] if pieces else hint
                    _update_device_vendor(client_ip, vendor_hint[:128], source="active_ssdp")
                
                location_match = re.search(rb"LOCATION:\s*([^\r\n]+)", data, re.IGNORECASE)
                if location_match:
                    location_url = location_match.group(1).strip().decode("utf-8", errors="replace")
                    _resolve_upnp_details(client_ip, location_url)
                    
            except socket.timeout:
                break
            except Exception:
                continue
        sock.close()
    except Exception as exc:
        print(f"[active-ssdp] query error: {exc}")


def _send_active_mdns_query() -> None:
    try:
        tx_id = b"\x12\x34"
        flags = b"\x00\x00"
        qdcount = b"\x00\x01"
        rest = b"\x00\x00\x00\x00\x00\x00"
        
        def encname(n):
            out = b""
            for label in n.split("."):
                out += bytes([len(label)]) + label.encode()
            return out + b"\x00"
            
        qname = encname("_services._dns-sd._udp.local")
        qtype = b"\x00\x0c"  # PTR
        qclass = b"\x00\x01"
        pkt = tx_id + flags + qdcount + rest + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(3.0)
        sock.sendto(pkt, ("224.0.0.251", 5353))
        
        start_time = time.time()
        while time.time() - start_time < 3.0:
            try:
                data, addr = sock.recvfrom(4096)
                client_ip = addr[0]
                
                names = parse_dns_packet(data)
                for name in names:
                    if name.endswith(".local"):
                        hostname_hint = name.split(".")[0]
                        if hostname_hint and not hostname_hint.startswith("_") and len(hostname_hint) > 1:
                            _update_device_hostname(client_ip, hostname_hint, source="active_mdns")
            except socket.timeout:
                break
            except Exception:
                continue
        sock.close()
    except Exception as exc:
        print(f"[active-mdns] query error: {exc}")


def run_active_discovery_sweep() -> None:
    """Perform a scheduled active SSDP and mDNS sweep across the local network."""
    _send_active_ssdp_query()
    _send_active_mdns_query()


# ── Tunnel-interface awareness (Phase 4.7) ───────────────────────────────────

_TUNNEL_HINTS = ("tailscale", "wireguard", "wg", "tun", "tap", "openvpn", "zerotier")


def is_tunnel_interface(name: str) -> bool:
    """Heuristic: does this interface look like a VPN/tunnel?"""
    n = (name or "").lower()
    return any(h in n for h in _TUNNEL_HINTS)


def list_tunnel_interfaces() -> list[dict]:
    """
    Return a list of [{"name": str, "kind": "tailscale"|"wireguard"|"vpn"}, ...]
    by parsing `netsh interface show interface`. Empty list on error.
    """
    import subprocess
    try:
        r = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return []
    tunnels: list[dict] = []
    for line in (r.stdout or "").splitlines()[3:]:
        parts = [p for p in line.split() if p]
        if len(parts) < 4:
            continue
        name = " ".join(parts[3:])
        if is_tunnel_interface(name):
            n = name.lower()
            kind = ("tailscale" if "tailscale" in n
                    else "wireguard" if ("wireguard" in n or "wg" in n)
                    else "zerotier" if "zerotier" in n
                    else "openvpn" if "openvpn" in n
                    else "vpn")
            tunnels.append({"name": name, "kind": kind})
    return tunnels
