"""
traffic/role_inference.py — Passive device role classification based on traffic analysis.

Analyzes packet headers (TTL, TCP Window Size) and flow patterns (volume, average packet size,
destination ports, domain query history) using tshark.
"""

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
    """
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
        # 1. TCP SYN parameters (TTL, Window Size)
        try:
            r = subprocess.run(
                [tshark, "-r", str(pcap),
                 "-Y", f"ip.src == {device_ip} and tcp.flags.syn == 1 and tcp.flags.ack == 0",
                 "-T", "fields", "-e", "ip.ttl", "-e", "tcp.window_size"],
                capture_output=True, text=True, timeout=15,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                parts = ln.strip().split("\t")
                if len(parts) >= 1 and parts[0].strip():
                    try:
                        ttls.append(int(parts[0].strip()))
                    except ValueError:
                        pass
                if len(parts) >= 2 and parts[1].strip():
                    try:
                        window_sizes.append(int(parts[1].strip()))
                    except ValueError:
                        pass
        except Exception:
            pass

        # 2. Destination ports
        try:
            r = subprocess.run(
                [tshark, "-r", str(pcap),
                 "-Y", f"ip.src == {device_ip}",
                 "-T", "fields", "-e", "tcp.dstport", "-e", "udp.dstport"],
                capture_output=True, text=True, timeout=15,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                parts = ln.strip().split("\t")
                for port_str in parts:
                    if port_str.strip():
                        try:
                            dst_ports.append(int(port_str.strip()))
                        except ValueError:
                            pass
        except Exception:
            pass

        # 3. Packet length distribution
        try:
            r = subprocess.run(
                [tshark, "-r", str(pcap),
                 "-Y", f"ip.src == {device_ip}",
                 "-T", "fields", "-e", "frame.len"],
                capture_output=True, text=True, timeout=15,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                if ln.strip():
                    try:
                        pkt_lengths.append(int(ln.strip()))
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
    # 1. Gather all domains
    domains = []
    if activity_data:
        http_requests = activity_data.get("http_requests", [])
        tls_sessions = activity_data.get("tls_sessions", [])
        dns_queries = activity_data.get("dns_queries", [])
        
        domains.extend([r.get("host", "").lower() for r in http_requests if r.get("host")])
        domains.extend([s.get("sni", "").lower() for s in tls_sessions if s.get("sni")])
        domains.extend([q.get("domain", "").lower() for q in dns_queries if q.get("domain")])
        
        top_domains = activity_data.get("summary", {}).get("top_domains", [])
        domains.extend([d.get("domain", "").lower() for d in top_domains if d.get("domain")])
        
    domains = list(set(domains))
    dom_str = " ".join(domains)

    # 2. Gather User-Agents
    user_agents = []
    if activity_data:
        http_requests = activity_data.get("http_requests", [])
        user_agents.extend([r.get("ua", "") for r in http_requests if r.get("ua")])
    user_agents = list(set(user_agents))

    # --- Heuristic Phase 1: HTTP User-Agents ---
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

    # --- Heuristic Phase 3: Flow characteristics and headers ---
    if flow_stats:
        dst_ports = flow_stats.get("destination_ports", [])
        pkt_lengths = flow_stats.get("packet_lengths", [])
        ttls = flow_stats.get("ttls", [])
        win_sizes = flow_stats.get("window_sizes", [])

        # Top destination ports
        port_counts = {}
        for p in dst_ports:
            port_counts[p] = port_counts.get(p, 0) + 1
        top_ports = sorted(port_counts.keys(), key=lambda p: port_counts[p], reverse=True)[:5]

        is_low_volume = len(pkt_lengths) < 200
        avg_pkt_len = sum(pkt_lengths) / len(pkt_lengths) if pkt_lengths else 0

        # Check for camera ports / domains
        if is_low_volume:
            if any(p in [8883, 1883] for p in top_ports) or "cam" in dom_str:
                return "IoT Camera"
            if any(p in [1900, 5353, 123] for p in top_ports) or any(x in dom_str for x in ["iot", "smart"]):
                return "Smart Home Device"

        # Game consoles
        if any(p == 3478 for p in top_ports) or (any(p > 30000 for p in top_ports) and not is_low_volume):
            if avg_pkt_len > 500:
                return "Gaming Console"

        # Smart TV (large average packet size due to streaming media over TCP/UDP)
        if not is_low_volume and avg_pkt_len > 700:
            return "Smart TV"

        # Windows / Mac Desktop/Laptop (TTL or high TCP Window Size + diverse ports)
        has_desktop_ttl = any(ttl == 128 for ttl in ttls) or (any(ttl == 64 for ttl in ttls) and any(w > 30000 for w in win_sizes))
        if has_desktop_ttl:
            distinct_ports = len(set(dst_ports))
            if distinct_ports > 5:
                return "Work Laptop"
            else:
                return "Mobile Phone"

    # --- Heuristic Phase 4: Fallback checks on IP/Domain hints ---
    if "pc" in dom_str or "laptop" in dom_str:
        return "Work Laptop"
    if "tv" in dom_str or "media" in dom_str:
        return "Smart TV"
    if "phone" in dom_str or "mobile" in dom_str:
        return "Mobile Phone"
    if "cam" in dom_str:
        return "IoT Camera"

    return ""
