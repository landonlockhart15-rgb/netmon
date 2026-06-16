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
from urllib.parse import urlparse

from datetime import datetime, timezone

from app.database import SessionLocal
from models.tables import Device


def _sanitize_string(s: str, max_len: int = 128) -> str:
    """Strip control characters, HTML/XML-like tags, and truncate to max_len."""
    if not s:
        return ""
    # Filter printable characters only
    s = "".join(c for c in s if c.isprintable())
    # Strip HTML tags
    s = re.sub(r"<[^>]*>", "", s)
    # Remove any remaining raw angle brackets to prevent HTML tag tricks
    s = s.replace("<", "").replace(">", "")
    # Normalize multiple whitespaces into a single space
    s = " ".join(s.split())
    return s[:max_len].strip()

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
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", _MDNS_PORT))
        mreq = struct.pack("=4sl", socket.inet_aton(_MDNS_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"[mdns] cannot bind 5353 (probably in use): {exc}")
        if sock:
            sock.close()
        return

    print("[mdns] listening on 5353")
    try:
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
    finally:
        sock.close()


# ── SSDP ─────────────────────────────────────────────────────────────────────

_SSDP_GROUP = "239.255.255.250"
_SSDP_PORT  = 1900

_SSDP_SERVER_RE = re.compile(rb"SERVER:\s*([^\r\n]+)", re.IGNORECASE)
_SSDP_USN_RE    = re.compile(rb"USN:\s*([^\r\n]+)",    re.IGNORECASE)


def _ssdp_listener() -> None:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", _SSDP_PORT))
        mreq = struct.pack("=4sl", socket.inet_aton(_SSDP_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"[ssdp] cannot bind 1900: {exc}")
        if sock:
            sock.close()
        return

    print("[ssdp] listening on 1900")
    try:
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
                    _update_device_vendor(client_ip, vendor_hint, source="ssdp")
            except socket.timeout:
                continue
            except Exception as exc:
                print(f"[ssdp] loop error: {exc}")
                time.sleep(1.0)
    finally:
        sock.close()


# ── DB helpers ────────────────────────────────────────────────────────────────

def _update_device_hostname(ip: str, hostname: str, source: str) -> None:
    hostname = _sanitize_string(hostname, 128)
    if not hostname:
        return
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
        if dev.hostname and dev.hostname.lower() == hostname.lower():
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
    vendor = _sanitize_string(vendor, 128)
    if not vendor:
        return
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


def parse_dhcp_packet(data: bytes) -> Optional[dict]:
    """
    Parse BOOTP/DHCP request/inform packet.
    Returns a dict with mac, hostname, vendor_class, param_list, requested_ip, message_type
    or None if invalid/not a client boot request.
    """
    if len(data) < 240:
        return None
    # Check BOOTP op: 1 = Boot Request (client to server)
    op = data[0]
    if op != 1:
        return None
    
    # htype = data[1], hlen = data[2]
    htype = data[1]
    hlen = data[2]
    if htype != 1 or hlen != 6:
        return None # Only Ethernet MAC support for now
    
    # Client MAC address is in chaddr (offset 28 to 34)
    mac_bytes = data[28:34]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)
    
    # Check magic cookie at offset 236: 99.130.83.99
    if data[236:240] != b"\x63\x82\x53\x63":
        return None
        
    options = {}
    cur = 240
    while cur + 2 <= len(data):
        opt_code = data[cur]
        if opt_code == 255:
            break
        if opt_code == 0:
            cur += 1
            continue
        opt_len = data[cur + 1]
        if cur + 2 + opt_len > len(data):
            break  # malformed option len
        opt_val = data[cur + 2 : cur + 2 + opt_len]
        
        options[opt_code] = opt_val
        cur += 2 + opt_len
        
    # Option 53: DHCP Message Type (1 byte)
    msg_type = None
    if 53 in options and len(options[53]) == 1:
        msg_type = options[53][0]
        
    # Option 12: Host Name
    hostname = None
    if 12 in options:
        try:
            hostname = options[12].decode("utf-8", errors="replace").strip()
        except Exception:
            pass
            
    # Option 60: Vendor Class Identifier
    vendor_class = None
    if 60 in options:
        try:
            vendor_class = options[60].decode("utf-8", errors="replace").strip()
        except Exception:
            pass
            
    # Option 55: Parameter Request List
    param_list = None
    if 55 in options:
        param_list = ",".join(str(b) for b in options[55])
        
    # Option 50: Requested IP
    requested_ip = None
    if 50 in options and len(options[50]) == 4:
        requested_ip = ".".join(str(b) for b in options[50])
        
    return {
        "mac": mac,
        "hostname": hostname,
        "vendor_class": vendor_class,
        "param_list": param_list,
        "requested_ip": requested_ip,
        "message_type": msg_type
    }


def _update_device_dhcp(info: dict, sender_ip: str) -> None:
    mac = info["mac"].lower()
    db = SessionLocal()
    try:
        from models.tables import Device, Alert
        from network.oui import enrich_vendor
        
        # Check if the device exists by MAC
        dev = db.query(Device).filter(Device.mac == mac).first()
        
        # Determine vendor/OS guess from option 60 and 55 fingerprints
        vendor_guess = None
        os_guess = None
        
        vc = info["vendor_class"] or ""
        prl = info["param_list"] or ""
        
        # Option 60 rules
        vc_lower = vc.lower()
        if "android" in vc_lower:
            os_guess = "Android"
            vendor_guess = "Android Device"
        elif any(x in vc_lower for x in ("iphone", "ipad", "apple", "ipod")):
            os_guess = "iOS"
            vendor_guess = "Apple"
        elif any(x in vc_lower for x in ("macintosh", "macbook", "os x")):
            os_guess = "macOS"
            vendor_guess = "Apple"
        elif "msft 5.0" in vc_lower:
            os_guess = "Windows"
            vendor_guess = "Microsoft"
        elif "nintendo" in vc_lower:
            os_guess = "Nintendo OS"
            vendor_guess = "Nintendo"
        elif "playstation" in vc_lower:
            os_guess = "PlayStation OS"
            vendor_guess = "Sony"
        elif "xbox" in vc_lower:
            os_guess = "Xbox OS"
            vendor_guess = "Microsoft"
        elif "chromecast" in vc_lower:
            os_guess = "Cast OS"
            vendor_guess = "Google"
        elif "sonos" in vc_lower:
            os_guess = "Sonos OS"
            vendor_guess = "Sonos"
            
        # Option 55 rules (fallback)
        if not os_guess and prl:
            if prl.startswith("1,3,6,15") and any(x in prl for x in ("119", "95", "252")):
                os_guess = "macOS/iOS"
                vendor_guess = "Apple"
            elif any(x in prl for x in ("31", "33", "43", "44", "46", "47")) or "249,252" in prl:
                os_guess = "Windows"
                vendor_guess = "Microsoft"
            elif any(x in prl for x in ("26", "28", "51", "58", "59")):
                os_guess = "Android"
                
        # If still no vendor guess, try OUI lookup
        enriched_vendor = enrich_vendor(mac, vendor_guess)
        if enriched_vendor and enriched_vendor.lower() != "unknown":
            vendor_guess = enriched_vendor
            
        now = datetime.now(timezone.utc)
        
        if not dev:
            # Create a new Device entry!
            dev = Device(
                mac=mac,
                vendor=vendor_guess or "Unknown",
                hostname=info["hostname"] or "",
                dhcp_hostname=info["hostname"],
                dhcp_option60=info["vendor_class"],
                dhcp_option55=info["param_list"],
                os_guess=os_guess,
                first_seen=now,
                last_seen=now
            )
            db.add(dev)
            db.flush() # Populate dev.id
            
            # Log the discovery event
            from monitoring.activity import write_log
            write_log("info", "system", "new_device_detected",
                      f"New device fingerprint discovered via DHCP: MAC={mac}, Hostname={dev.hostname or 'unknown'}")
                      
            # Add Alert
            db.add(Alert(
                alert_type="new_device",
                message=f"New device (DHCP): {dev.hostname or sender_ip or 'unknown'} (MAC: {mac})",
                device_id=dev.id,
            ))
        else:
            # Update existing device!
            dev.last_seen = now
            if info["hostname"]:
                dev.hostname = info["hostname"]
                dev.dhcp_hostname = info["hostname"]
            if info["vendor_class"]:
                dev.dhcp_option60 = info["vendor_class"]
            if info["param_list"]:
                dev.dhcp_option55 = info["param_list"]
            if os_guess and not dev.os_guess:
                dev.os_guess = os_guess
            if vendor_guess and (not dev.vendor or dev.vendor.lower() in ("", "unknown")):
                dev.vendor = vendor_guess
                
        # Update ScanDevice row if we have IP
        target_ip = info["requested_ip"] or (sender_ip if sender_ip and sender_ip != "0.0.0.0" else None)
        if target_ip:
            from models.tables import Scan, ScanDevice
            latest_scan = db.query(Scan).filter(Scan.status == "complete").order_by(Scan.id.desc()).first()
            if latest_scan:
                sd = db.query(ScanDevice).filter(ScanDevice.scan_id == latest_scan.id, ScanDevice.device_id == dev.id).first()
                if sd:
                    sd.ip = target_ip
                    if info["hostname"]:
                        sd.hostname = info["hostname"]
                else:
                    sd = ScanDevice(
                        scan_id=latest_scan.id,
                        device_id=dev.id,
                        ip=target_ip,
                        hostname=info["hostname"] or ""
                    )
                    db.add(sd)
                    
        db.commit()
    except Exception as exc:
        print(f"[dhcp] database update error: {exc}")
    finally:
        db.close()


def _dhcp_listener() -> None:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 67))
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"[dhcp] cannot bind 67 (probably in use or permission denied): {exc}")
        if sock:
            sock.close()
        return

    print("[dhcp] listening on 67")
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                sender_ip = addr[0]
                info = parse_dhcp_packet(data)
                if info:
                    _update_device_dhcp(info, sender_ip)
            except socket.timeout:
                continue
            except Exception as exc:
                print(f"[dhcp] loop error: {exc}")
                time.sleep(1.0)
    finally:
        sock.close()


def start_passive_discovery() -> None:
    """Start mDNS + SSDP + DHCP listener threads. Idempotent."""
    threading.Thread(target=_mdns_listener, daemon=True, name="netmon-mdns").start()
    threading.Thread(target=_ssdp_listener, daemon=True, name="netmon-ssdp").start()
    threading.Thread(target=_dhcp_listener, daemon=True, name="netmon-dhcp").start()


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
            if offset >= len(data):
                break
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
        from urllib.parse import urlparse
        import urllib.request as urllib_req
        import re as xml_re
        
        parsed = urlparse(location_url)
        if parsed.scheme not in ("http", "https"):
            return
            
        # SSRF Protection: Ensure location URL host matches the responding device IP exactly.
        if parsed.hostname != ip:
            return
            
        req = urllib_req.Request(location_url, headers={"User-Agent": "NetMon/1.0 home-network-monitor"})
        with urllib_req.urlopen(req, timeout=2.0) as response:
            # Prevent DoS by reading at most 1 MB of XML content
            xml_content_bytes = response.read(1024 * 1024)
            xml_content = xml_content_bytes.decode("utf-8", errors="replace")
            
        def get_tag(tag_name: str) -> str:
            match = xml_re.search(fr"<{tag_name}[^>]*>([^<]+)</{tag_name}>", xml_content, xml_re.I)
            return match.group(1).strip() if match else ""
            
        manufacturer = get_tag("manufacturer") or get_tag("manufacturerName")
        model = get_tag("modelName") or get_tag("modelDescription")
        friendly_name = get_tag("friendlyName")
        
        if manufacturer:
            vendor_str = f"{manufacturer} {model}".strip() if model else manufacturer
            _update_device_vendor(ip, vendor_str, source="upnp_xml")
            
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
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(3.0)
            sock.sendto(msg, ("239.255.255.250", 1900))
            
            processed_ips = set()
            processed_urls = set()
            resolved_count = 0
            max_resolves = 10
            
            start_time = time.time()
            while time.time() - start_time < 3.0:
                try:
                    data, addr = sock.recvfrom(4096)
                    client_ip = addr[0]
                    
                    if client_ip in processed_ips and len(processed_ips) > 20:
                        continue
                    
                    server_match = _SSDP_SERVER_RE.search(data)
                    if server_match:
                        hint = server_match.group(1).strip().decode("utf-8", errors="replace")
                        pieces = [p for p in hint.split() if p]
                        vendor_hint = pieces[-1] if pieces else hint
                        _update_device_vendor(client_ip, vendor_hint, source="active_ssdp")
                        processed_ips.add(client_ip)
                    
                    location_match = re.search(rb"LOCATION:\s*([^\r\n]+)", data, re.IGNORECASE)
                    if location_match:
                        location_url = location_match.group(1).strip().decode("utf-8", errors="replace")
                        if location_url not in processed_urls:
                            processed_urls.add(location_url)
                            if resolved_count < max_resolves:
                                _resolve_upnp_details(client_ip, location_url)
                                resolved_count += 1
                                processed_ips.add(client_ip)
                                
                except socket.timeout:
                    break
                except Exception:
                    continue
        finally:
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
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(3.0)
            sock.sendto(pkt, ("224.0.0.251", 5353))
            
            processed_ips = set()
            
            start_time = time.time()
            while time.time() - start_time < 3.0:
                try:
                    data, addr = sock.recvfrom(4096)
                    client_ip = addr[0]
                    
                    if client_ip in processed_ips and len(processed_ips) > 20:
                        continue
                        
                    names = parse_dns_packet(data)
                    for name in names:
                        if name.endswith(".local"):
                            hostname_hint = name.split(".")[0]
                            if hostname_hint and not hostname_hint.startswith("_") and len(hostname_hint) > 1:
                                _update_device_hostname(client_ip, hostname_hint, source="active_mdns")
                                processed_ips.add(client_ip)
                except socket.timeout:
                    break
                except Exception:
                    continue
        finally:
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
