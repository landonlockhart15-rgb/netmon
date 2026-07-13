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
    dst_ips: List[str] = []
    timestamps: List[float] = []

    for pcap in files:
        try:
            # Query all required packet fields in a single tshark call to minimize IO/CPU overhead.
            # Tab-separated output matches the sequence of -e parameters in order:
            # ip.ttl, tcp.window_size, tcp.flags.syn, tcp.flags.ack, tcp.dstport, udp.dstport, frame.len, ip.dst, frame.time_epoch
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
                 "-e", "frame.len",
                 "-e", "ip.dst",
                 "-e", "frame.time_epoch"],
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

                # Parse destination IP address
                if len(parts) > 7:
                    dst_ip_str = parts[7].strip()
                    if dst_ip_str:
                        try:
                            dst_ips.append(dst_ip_str.split(",")[0])
                        except Exception:
                            pass

                # Parse timestamp for packet frequency
                if len(parts) > 8:
                    time_str = parts[8].strip()
                    if time_str:
                        try:
                            timestamps.append(float(time_str.split(",")[0]))
                        except ValueError:
                            pass
        except Exception:
            pass

    packet_frequency = 0.0
    if len(timestamps) > 1:
        duration = max(timestamps) - min(timestamps)
        if duration > 0:
            packet_frequency = len(timestamps) / duration

    return {
        "ttls": ttls,
        "window_sizes": window_sizes,
        "destination_ports": dst_ports,
        "packet_lengths": pkt_lengths,
        "destination_ips": dst_ips,
        "timestamps": timestamps,
        "packet_frequency": packet_frequency,
    }


def infer_behavior_profile(device_ip: str, activity_data: dict, flow_stats: dict) -> str:
    """
    Classify the role of a device by analyzing its passive traffic patterns,
    including User-Agent strings, DNS query domains, destination ports,
    and TCP/IP packet headers (TTL, Window Size).
    """
    # Defensive programming: ensure activity_data and flow_stats are dictionaries
    if not isinstance(activity_data, dict):
        activity_data = {}
    if not isinstance(flow_stats, dict):
        flow_stats = {}

    # 1. Gather and normalize all DNS/TLS/HTTP domain queries to construct a domain context string
    domains = []
    browser_header_hits = []

    # Extract lists safely
    http_requests = activity_data.get("http_requests")
    if not isinstance(http_requests, list):
        http_requests = []
        
    tls_sessions = activity_data.get("tls_sessions")
    if not isinstance(tls_sessions, list):
        tls_sessions = []
        
    dns_queries = activity_data.get("dns_queries")
    if not isinstance(dns_queries, list):
        dns_queries = []

    # Process http_requests
    for r in http_requests:
        if isinstance(r, dict):
            host = r.get("host")
            if host and isinstance(host, str):
                domains.append(host.lower())

            # Parse headers for browser_header_hits
            accept = r.get("accept")
            accept_language = r.get("accept_language")
            accept_encoding = r.get("accept_encoding")
            referer = r.get("referer")
            connection = r.get("connection")
            
            accept = accept if isinstance(accept, str) else ""
            accept_language = accept_language if isinstance(accept_language, str) else ""
            accept_encoding = accept_encoding if isinstance(accept_encoding, str) else ""
            referer = referer if isinstance(referer, str) else ""
            connection = connection if isinstance(connection, str) else ""
            
            if accept or accept_language or accept_encoding or referer or connection:
                browser_header_hits.append(" ".join(
                    part.lower()
                    for part in [accept, accept_language, accept_encoding, referer, connection]
                    if part
                ))

    # Process tls_sessions
    for s in tls_sessions:
        if isinstance(s, dict):
            sni = s.get("sni")
            if sni and isinstance(sni, str):
                domains.append(sni.lower())

    # Process dns_queries
    for q in dns_queries:
        if isinstance(q, dict):
            domain = q.get("domain")
            if domain and isinstance(domain, str):
                domains.append(domain.lower())

    # Process summary top_domains
    summary = activity_data.get("summary")
    if isinstance(summary, dict):
        top_domains = summary.get("top_domains")
        if isinstance(top_domains, list):
            for d in top_domains:
                if isinstance(d, dict):
                    domain = d.get("domain")
                    if domain and isinstance(domain, str):
                        domains.append(domain.lower())

    domains = list(set(domains))
    dom_str = " ".join(domains)
    header_str = " ".join(browser_header_hits)

    # 2. Gather User-Agent strings
    user_agents = []
    for r in http_requests:
        if isinstance(r, dict):
            ua = r.get("ua")
            if ua and isinstance(ua, str):
                user_agents.append(ua)
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
    if any(x in dom_str for x in ["honeypot", "cowrie", "kippo", "dshield.org", "honeynet.org"]):
        return "Honeypot"
    if any(x in dom_str for x in ["sensor", "telemetry", "weather", "aqi", "temp", "humidity", "coap", "dht"]):
        return "IoT Sensor"
    if header_str and any(x in dom_str for x in ["github.com", "gitlab.com", "slack.com", "teams.microsoft.com", "office.com", "zoom.us", "aws.amazon.com", "jira", "atlassian", "bitbucket", "okta.com"]):
        return "Work Laptop"
    if header_str and any(x in dom_str for x in ["courier.push.apple", "fcm.googleapis.com", "mtalk.google.com", "crashlytics.com", "firebase", "icloud.com", "apple.com"]):
        return "Mobile Phone"

    # --- Heuristic Phase 3: Flow characteristics and headers ---
    # Classify roles using statistical patterns of the network flow (port distributions, volume, average length, TTL).
    dst_ports = flow_stats.get("destination_ports")
    if not isinstance(dst_ports, list):
        dst_ports = []
    # Filter out non-integers, keep only integers or digit strings converted to int
    dst_ports = [int(p) for p in dst_ports if isinstance(p, int) or (isinstance(p, str) and p.isdigit())]

    pkt_lengths = flow_stats.get("packet_lengths")
    if not isinstance(pkt_lengths, list):
        pkt_lengths = []
    pkt_lengths = [int(l) for l in pkt_lengths if isinstance(l, int) or (isinstance(l, str) and l.isdigit())]

    ttls = flow_stats.get("ttls")
    if not isinstance(ttls, list):
        ttls = []
    ttls = [int(t) for t in ttls if isinstance(t, int) or (isinstance(t, str) and t.isdigit())]

    win_sizes = flow_stats.get("window_sizes")
    if not isinstance(win_sizes, list):
        win_sizes = []
    win_sizes = [int(w) for w in win_sizes if isinstance(w, int) or (isinstance(w, str) and w.isdigit())]

    destination_ips = flow_stats.get("destination_ips", [])
    if not isinstance(destination_ips, list):
        destination_ips = []
    else:
        destination_ips = [dip for dip in destination_ips if isinstance(dip, str)]

    packet_frequency = flow_stats.get("packet_frequency", 0.0)
    if not isinstance(packet_frequency, (int, float)):
        packet_frequency = 0.0

    if dst_ports or pkt_lengths or ttls or win_sizes or destination_ips:
        # Count destination port frequencies to find top ports
        port_counts = {}
        for p in dst_ports:
            port_counts[p] = port_counts.get(p, 0) + 1
        top_ports = sorted(port_counts.keys(), key=lambda p: port_counts[p], reverse=True)[:5]

        is_low_volume = len(pkt_lengths) < 200
        avg_pkt_len = sum(pkt_lengths) / len(pkt_lengths) if pkt_lengths else 0

        # Honeypot checks based on ports or destination IPs
        is_honeypot_domain = any(x in dom_str for x in ["honeypot", "cowrie", "kippo", "dshield", "honeynet"])
        is_honeypot_dest = any(any(x in dip for x in ["dshield.org", "honeynet.org"]) for dip in destination_ips)
        if is_honeypot_domain or is_honeypot_dest:
            return "Honeypot"

        # Check for camera, smart home, or sensor devices
        if is_low_volume or avg_pkt_len < 300:
            # IoT Cameras often use MQTT (8883/1883) for telemetry
            if any(p in [8883, 1883] for p in top_ports) or "cam" in dom_str:
                # If it explicitly matches sensor/telemetry keywords, classify as IoT Sensor instead
                if any(x in dom_str for x in ["sensor", "telemetry", "weather", "aqi", "temp", "humidity", "coap", "dht"]) or any(any(x in dip for x in ["thingspeak", "adafruit", "dweet", "aws-iot"]) for dip in destination_ips):
                    return "IoT Sensor"
                return "IoT Camera"

            # IoT Sensors typically use CoAP (5683/5684) or specific telemetry domains/destinations
            is_sensor_port = any(p in [5683, 5684] for p in top_ports)
            is_sensor_domain = any(x in dom_str for x in ["sensor", "telemetry", "weather", "aqi", "temp", "humidity", "coap", "dht"])
            is_sensor_dest = any(any(x in dip for x in ["thingspeak", "adafruit", "dweet", "aws-iot"]) for dip in destination_ips)
            if is_sensor_port or is_sensor_domain or is_sensor_dest:
                return "IoT Sensor"
                
            # Frequency-based heuristic for sensors: steady low frequency of small packets
            if 0.01 <= packet_frequency <= 5.0 and any(p in [123, 80, 443] for p in top_ports):
                return "IoT Sensor"

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
    if "sensor" in dom_str or "telemetry" in dom_str:
        return "IoT Sensor"
    if "honeypot" in dom_str:
        return "Honeypot"

    return ""

infer_device_role = infer_behavior_profile
