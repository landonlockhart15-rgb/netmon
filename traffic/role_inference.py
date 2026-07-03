"""
traffic/role_inference.py — Passive device role classification based on traffic analysis.

Overview:
This module performs passive classification of network device roles (e.g., Smart TV, Work Laptop,
Mobile Phone, Gaming Console, IoT Camera, Smart Home Device) by analyzing traffic patterns.
It operates in four heuristic phases:
1. HTTP User-Agent classification.
2. Domain query analysis (using HTTP request hosts, TLS SNI, and DNS queries).
3. Passive TCP/IP header analysis (IP Time-to-Live, TCP Window Size) and flow characteristics
   (volume, average packet size, destination ports) extracted from pcap files via tshark.
4. Fallback hostname and domain keyword matching.

Performance & Optimization Design:
To avoid significant CPU and I/O overhead on the host machine, the flow statistics extraction (tshark)
is designed to run a single, combined fields query per pcap file. This reduces subprocess spawns
by 3x (from 3 separate tshark runs per file to 1), significantly speeding up background scheduling and HTTP handlers.

Security Boundaries:
Input validation is enforced using python's `ipaddress` library to ensure that only syntactically
valid IP addresses are processed. This acts as a strict security barrier against potential command
injection vulnerabilities via tshark filters or subprocess execution.
"""

import ipaddress
import re
import subprocess
from pathlib import Path
from typing import Dict, List

from traffic.interfaces import find_tool, _no_window
from traffic.analyzer import get_readable_files, CAPTURE_DIR


def extract_flow_stats(device_ip: str, capture_dir: Path = CAPTURE_DIR, max_files: int = 5) -> Dict:
    """
    Run tshark on recent pcap files to extract packet header fields and flow patterns.
    Safe to fail silent and return empty stats if tshark is unavailable.

    Optimized implementation:
    Runs a single combined tshark command per capture file to extract all required
    fields (TTL, Window Size, TCP SYN flags, Destination TCP/UDP ports, frame length)
    in a single pass, cutting execution overhead and subprocess spawns by 3x.
    """
    # 1. Strict Input Validation (Command Injection Prevention)
    if not isinstance(device_ip, str):
        return {}

    try:
        ipaddress.ip_address(device_ip.strip())
    except ValueError:
        return {}

    tshark = find_tool("tshark")
    if not tshark:
        return {}

    files = get_readable_files(capture_dir, max_files=max_files)
    if not files:
        return {}

    ttls: List[int] = []
    window_sizes: List[int] = []
    dst_ports: List[int] = []
    pkt_lengths: List[int] = []

    for pcap in files:
        try:
            # Query all required packet fields in a single tshark call to minimize IO/CPU overhead.
            # Tab-separated output matches the sequence of -e parameters in order:
            # ip.ttl, tcp.window_size, tcp.flags.syn, tcp.flags.ack, tcp.dstport, udp.dstport, frame.len
            r = subprocess.run(
                [tshark, "-r", str(pcap),
                 "-Y", f"ip.src == {device_ip}",
                 "-T", "fields",
                 "-e", "ip.ttl",
                 "-e", "tcp.window_size",
                 "-e", "tcp.flags.syn",
                 "-e", "tcp.flags.ack",
                 "-e", "tcp.dstport",
                 "-e", "udp.dstport",
                 "-e", "frame.len"],
                capture_output=True, text=True, timeout=15,
                creationflags=_no_window(),
            )
            
            for ln in r.stdout.splitlines():
                parts = ln.split("\t")
                if len(parts) < 7:
                    continue

                # Parse IP Time-To-Live (TTL)
                ttl_str = parts[0].strip()
                if ttl_str:
                    try:
                        # Extract the first element in case of nested IP headers (comma-separated values)
                        ttls.append(int(ttl_str.split(",")[0]))
                    except ValueError:
                        pass

                # Parse destination ports (TCP or UDP)
                dst_port = None
                tcp_port_str = parts[4].strip()
                udp_port_str = parts[5].strip()
                if tcp_port_str:
                    dst_port = tcp_port_str.split(",")[0]
                elif udp_port_str:
                    dst_port = udp_port_str.split(",")[0]

                if dst_port:
                    try:
                        dst_ports.append(int(dst_port))
                    except ValueError:
                        pass

                # Parse packet size length
                pkt_len_str = parts[6].strip()
                if pkt_len_str:
                    try:
                        pkt_lengths.append(int(pkt_len_str.split(",")[0]))
                    except ValueError:
                        pass

                # Parse TCP SYN flags and TCP Window Size to fingerprint OS characteristics
                syn_str = parts[2].strip()
                ack_str = parts[3].strip()
                win_str = parts[1].strip()
                
                # We only gather TCP Window Sizes on SYN-only packets (syn == 1 and ack == 0)
                if syn_str == "1" and ack_str == "0" and win_str:
                    try:
                        window_sizes.append(int(win_str.split(",")[0]))
                    except ValueError:
                        pass
        except Exception:
            pass

    return {
        "ttls": ttls,
        "window_sizes": window_sizes,
        "destination_ports": dst_ports,
        "packet_lengths": pkt_lengths,
    }


def infer_device_role(device_ip: str, activity_data: dict, flow_stats: dict) -> str:
    """
    Classify the role of a device by analyzing its passive traffic patterns,
    including User-Agent strings, DNS query domains, destination ports,
    and TCP/IP packet headers (TTL, Window Size).
    """
    # 1. Gather and normalize all DNS/TLS/HTTP domain queries to construct a domain context string
    domains = []
    browser_header_hits = []
    if activity_data:
        http_requests = activity_data.get("http_requests", [])
        tls_sessions = activity_data.get("tls_sessions", [])
        dns_queries = activity_data.get("dns_queries", [])
        
        domains.extend([r.get("host", "").lower() for r in http_requests if r.get("host")])
        domains.extend([s.get("sni", "").lower() for s in tls_sessions if s.get("sni")])
        domains.extend([q.get("domain", "").lower() for q in dns_queries if q.get("domain")])
        
        top_domains = activity_data.get("summary", {}).get("top_domains", [])
        domains.extend([d.get("domain", "").lower() for d in top_domains if d.get("domain")])

        for req in http_requests:
            accept = req.get("accept", "")
            accept_language = req.get("accept_language", "")
            accept_encoding = req.get("accept_encoding", "")
            referer = req.get("referer", "")
            connection = req.get("connection", "")
            if accept or accept_language or accept_encoding or referer or connection:
                browser_header_hits.append(" ".join(
                    part.lower()
                    for part in [accept, accept_language, accept_encoding, referer, connection]
                    if part
                ))
        
    domains = list(set(domains))
    dom_str = " ".join(domains)
    header_str = " ".join(browser_header_hits)

    # 2. Gather User-Agent strings
    user_agents = []
    if activity_data:
        http_requests = activity_data.get("http_requests", [])
        user_agents.extend([r.get("ua", "") for r in http_requests if r.get("ua")])
    user_agents = list(set(user_agents))

    # --- Heuristic Phase 1: HTTP User-Agents ---
    # User-Agent headers contain explicit software/OS fingerprints which are highly reliable.
    for ua in user_agents:
        ua_l = ua.lower()
        if any(x in ua_l for x in ["roku", "tizen", "webos", "smarttv", "smart-tv", "vizio", "appletv", "chromecast"]):
            return "Smart TV"
        if any(x in ua_l for x in ["windows nt", "macintosh", "ubuntu", "fedora", "linux x86_64"]):
            return "Work Laptop"
        if any(x in ua_l for x in ["iphone", "ipad", "ipod", "android"]):
            return "Mobile Phone"
        if any(x in ua_l for x in ["playstation", "nintendo", "xbox"]):
            return "Gaming Console"
        if any(x in ua_l for x in ["blink", "ring", "nest", "wyzecam", "arlo"]):
            return "IoT Camera"

    # --- Heuristic Phase 2: Domain queries ---
    # Classify the device role based on DNS requests and server names (SNI) accessed by the device.
    if any(x in dom_str for x in ["netflix.com", "hulu.com", "hbogo.com", "roku.com", "hbb.tv", "vizio.com", "plex.tv", "disneyplus.com", "youtube.com", "ytimg.com"]):
        return "Smart TV"
    if any(x in dom_str for x in ["github.com", "gitlab.com", "slack.com", "teams.microsoft.com", "office.com", "zoom.us", "aws.amazon.com", "jira", "atlassian", "bitbucket", "okta.com"]):
        return "Work Laptop"
    if any(x in dom_str for x in ["ring.com", "ring-door", "blinkap.com", "dropcam.com", "wyzecam.com", "arlo.netgear.com", "camera"]):
        return "IoT Camera"
    if any(x in dom_str for x in ["playstation", "sony.com", "xbox", "nintendo", "steampowered.com", "epicgames.com", "origin.com"]):
        return "Gaming Console"
    if any(x in dom_str for x in ["tuya", "smartlife", "meethue", "kasa", "tp-link", "tplink-smarthome", "wemo", "sonos"]):
        return "Smart Home Device"
    if any(x in dom_str for x in ["courier.push.apple", "fcm.googleapis.com", "mtalk.google.com", "crashlytics.com", "firebase"]):
        return "Mobile Phone"
    if header_str and any(x in dom_str for x in ["github.com", "gitlab.com", "slack.com", "teams.microsoft.com", "office.com", "zoom.us", "aws.amazon.com", "jira", "atlassian", "bitbucket", "okta.com"]):
        return "Work Laptop"
    if header_str and any(x in dom_str for x in ["courier.push.apple", "fcm.googleapis.com", "mtalk.google.com", "crashlytics.com", "firebase", "icloud.com", "apple.com"]):
        return "Mobile Phone"

    # --- Heuristic Phase 3: Flow characteristics and headers ---
    # Classify roles using statistical patterns of the network flow (port distributions, volume, average length, TTL).
    if flow_stats:
        dst_ports = flow_stats.get("destination_ports", [])
        pkt_lengths = flow_stats.get("packet_lengths", [])
        ttls = flow_stats.get("ttls", [])
        win_sizes = flow_stats.get("window_sizes", [])

        # Count destination port frequencies to find top ports
        port_counts = {}
        for p in dst_ports:
            port_counts[p] = port_counts.get(p, 0) + 1
        top_ports = sorted(port_counts.keys(), key=lambda p: port_counts[p], reverse=True)[:5]

        is_low_volume = len(pkt_lengths) < 200
        avg_pkt_len = sum(pkt_lengths) / len(pkt_lengths) if pkt_lengths else 0

        # Check for camera or smart home ports
        if is_low_volume:
            # IoT Cameras often use MQTT (8883/1883) for telemetry
            if any(p in [8883, 1883] for p in top_ports) or "cam" in dom_str:
                return "IoT Camera"
            # Smart Home Devices typically use UPnP (1900), mDNS (5353), or NTP (123)
            if any(p in [1900, 5353, 123] for p in top_ports) or any(x in dom_str for x in ["iot", "smart"]):
                return "Smart Home Device"

        # Game consoles (often utilize STUN port 3478 or dynamic high ports for multiplayer matchmaking)
        if any(p == 3478 for p in top_ports) or (any(p > 30000 for p in top_ports) and not is_low_volume):
            if avg_pkt_len > 500:
                return "Gaming Console"

        # Smart TV (large average packet size due to streaming media over TCP/UDP)
        if not is_low_volume and avg_pkt_len > 700:
            return "Smart TV"

        # Windows / Mac Desktop/Laptop (identified by standard OS TTL = 128 or TCP Window Size/TTL combinations)
        has_desktop_ttl = any(ttl == 128 for ttl in ttls) or (any(ttl == 64 for ttl in ttls) and any(w > 30000 for w in win_sizes))
        if has_desktop_ttl:
            distinct_ports = len(set(dst_ports))
            browserish_headers = bool(header_str)
            # Work Laptops exhibit highly diverse outbound ports compared to Mobile Phones
            if distinct_ports > 5 or (browserish_headers and distinct_ports > 1):
                return "Work Laptop"
            else:
                return "Mobile Phone"

    # --- Heuristic Phase 4: Fallback checks on IP/Domain hints ---
    # Basic keyword classification based on domain name tags
    if "pc" in dom_str or "laptop" in dom_str:
        return "Work Laptop"
    if "tv" in dom_str or "media" in dom_str:
        return "Smart TV"
    if "phone" in dom_str or "mobile" in dom_str:
        return "Mobile Phone"
    if "cam" in dom_str:
        return "IoT Camera"

    return ""
