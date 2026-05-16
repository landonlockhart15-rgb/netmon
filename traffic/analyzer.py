"""
traffic/analyzer.py — Extract traffic summaries from ring-buffer capture files.

Uses tshark in read-only mode. Never touches the live capture process.
All output is metadata only: IP addresses, byte counts, packet counts,
protocol names. No payload content is extracted or stored.

What we extract per analysis run:
  top_talkers:       Top 10 internal IPs by total bytes (both directions)
  top_destinations:  Top 10 external IPs by total bytes
  protocol_mix:      Packet counts per layer-4/app protocol (TCP/UDP/DNS/TLS/HTTP...)
  dns_count:         Total DNS query count observed
  total_packets:     Total frames in analyzed files
  total_bytes:       Total bytes in analyzed files

Visibility note:
  On a switched home network this machine only sees its own traffic plus
  broadcast/multicast. It does NOT see traffic between other devices.
  Results reflect what reaches this host's NIC — not the full network.
"""

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from traffic.interfaces import find_tool, _no_window

CAPTURE_DIR = Path("data/captures")

# Layer-4 and notable application protocols to track in the protocol mix
_PROTO_WHITELIST = {
    "tcp", "udp", "icmp", "icmpv6",
    "dns", "tls", "http", "http2", "quic",
    "ntp", "mdns", "dhcp", "dhcpv6", "arp",
}


def get_readable_files(capture_dir: Path = CAPTURE_DIR, max_files: int = 3) -> List[Path]:
    """
    Return recent completed ring files, skipping the file currently being written.

    dumpcap writes ring_NNNNN_TIMESTAMP.pcapng and the active file is the
    one most recently modified. We skip it to avoid reading a partial file.
    If only one file exists we still try it (it may be complete).
    """
    files = sorted(
        [f for f in capture_dir.glob("ring*.pcapng") if f.is_file()],
        key=lambda f: f.stat().st_mtime,
    )
    if len(files) > 1:
        files = files[:-1]   # exclude active write file
    return files[-max_files:]


def run_analysis(capture_dir: Path = CAPTURE_DIR) -> Dict:
    """
    Analyze recent capture files and return a metadata summary.

    Returns an error dict (with empty lists) if tshark is unavailable
    or no files exist yet — never raises.
    """
    empty = {
        "top_talkers":      [],
        "top_destinations": [],
        "protocol_mix":     {},
        "dns_count":        0,
        "total_packets":    0,
        "total_bytes":      0,
        "files_analyzed":   0,
        "error":            None,
    }

    tshark = find_tool("tshark")
    if not tshark:
        return {**empty, "error": "tshark not found — install Wireshark to enable analysis"}

    files = get_readable_files(capture_dir)
    if not files:
        return {**empty, "error": "no capture files available yet"}

    conv_rows:    List[Dict] = []
    proto_counts: Dict[str, int] = {}
    dns_names:    Dict[str, int] = {}   # domain → query count
    tls_names:    Dict[str, int] = {}   # SNI hostname → count
    http_hosts:   Dict[str, int] = {}   # HTTP host → count
    dns_count    = 0
    total_packets = 0
    total_bytes   = 0
    last_error    = None

    for pcap in files:
        try:
            # ── IP conversations (top talkers / destinations) ─────────────
            r = subprocess.run(
                [tshark, "-r", str(pcap), "-q", "-z", "conv,ip"],
                capture_output=True, text=True, timeout=120,
                creationflags=_no_window(),
            )
            if r.returncode != 0 and r.stderr:
                last_error = r.stderr.strip().splitlines()[-1]
            conv_rows.extend(_parse_conv_ip(r.stdout))

            # ── Protocol hierarchy (mix) ──────────────────────────────────
            r = subprocess.run(
                [tshark, "-r", str(pcap), "-q", "-z", "io,phs"],
                capture_output=True, text=True, timeout=120,
                creationflags=_no_window(),
            )
            if r.returncode != 0 and r.stderr and not last_error:
                last_error = r.stderr.strip().splitlines()[-1]
            protos, pkts, byts = _parse_phs(r.stdout)
            for p, n in protos.items():
                proto_counts[p] = proto_counts.get(p, 0) + n
            total_packets += pkts
            total_bytes   += byts

            # ── DNS queries (names + count) ───────────────────────────────
            r = subprocess.run(
                [tshark, "-r", str(pcap), "-q",
                 "-Y", "dns.flags.response == 0",
                 "-T", "fields", "-e", "dns.qry.name"],
                capture_output=True, text=True, timeout=120,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                name = ln.strip().lower().rstrip(".")
                if name:
                    dns_names[name] = dns_names.get(name, 0) + 1
                    dns_count += 1

            # ── TLS SNI — what HTTPS sites devices are connecting to ──────
            r = subprocess.run(
                [tshark, "-r", str(pcap), "-q",
                 "-Y", "tls.handshake.type == 1",
                 "-T", "fields", "-e", "tls.handshake.extensions_server_name"],
                capture_output=True, text=True, timeout=120,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                name = ln.strip().lower()
                if name:
                    tls_names[name] = tls_names.get(name, 0) + 1

            # ── HTTP host headers (unencrypted traffic) ───────────────────
            r = subprocess.run(
                [tshark, "-r", str(pcap), "-q",
                 "-Y", "http.host",
                 "-T", "fields", "-e", "http.host"],
                capture_output=True, text=True, timeout=120,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                name = ln.strip().lower()
                if name:
                    http_hosts[name] = http_hosts.get(name, 0) + 1

        except subprocess.TimeoutExpired:
            last_error = "tshark analysis timed out"
        except Exception as e:
            last_error = f"analysis error: {e}"

    # Top domains: merge DNS + TLS + HTTP, sorted by frequency
    all_domains: Dict[str, int] = {}
    for d, n in dns_names.items():
        all_domains[d] = all_domains.get(d, 0) + n
    for d, n in tls_names.items():
        all_domains[d] = all_domains.get(d, 0) + n
    for d, n in http_hosts.items():
        all_domains[d] = all_domains.get(d, 0) + n

    top_domains = sorted(all_domains.items(), key=lambda x: x[1], reverse=True)[:20]

    # ── Aggregate conversations into per-host totals ──────────────────────────
    host_bytes:   Dict[str, int] = {}
    host_packets: Dict[str, int] = {}
    for row in conv_rows:
        for ip in (row["ip_a"], row["ip_b"]):
            host_bytes[ip]   = host_bytes.get(ip, 0)   + row["total_bytes"]
            host_packets[ip] = host_packets.get(ip, 0) + row["total_packets"]

    sorted_hosts = sorted(host_bytes.items(), key=lambda x: x[1], reverse=True)

    top_talkers, top_destinations = [], []
    for ip, byt in sorted_hosts[:30]:
        entry = {
            "ip":      ip,
            "bytes":   byt,
            "packets": host_packets.get(ip, 0),
            "mb":      round(byt / 1_048_576, 2),
        }
        if _is_private(ip):
            top_talkers.append(entry)
        else:
            top_destinations.append(entry)

    return {
        "top_talkers":      top_talkers[:10],
        "top_destinations": top_destinations[:10],
        "protocol_mix":     proto_counts,
        "dns_count":        dns_count,
        "top_domains":      [{"domain": d, "count": n} for d, n in top_domains],
        "total_packets":    total_packets,
        "total_bytes":      total_bytes,
        "files_analyzed":   len(files),
        "error":            last_error,
    }


def get_dns_per_device(
    capture_dir: Path = CAPTURE_DIR,
    max_files: int = 2,
) -> dict[str, list[dict]]:
    """
    Return recent DNS queries and TLS SNI grouped by source IP.

    Result: { "192.168.1.5": [{"domain": "example.com", "count": 3}, ...], ... }
    Domains are merged from DNS query names + TLS SNI hostnames.
    """
    tshark = find_tool("tshark")
    if not tshark:
        return {}

    files = get_readable_files(capture_dir, max_files=max_files)
    if not files:
        return {}

    # {src_ip: {domain: count}}
    per_device: dict[str, dict[str, int]] = {}

    for pcap in files:
        try:
            # DNS queries with source IP
            r = subprocess.run(
                [tshark, "-r", str(pcap),
                 "-Y", "dns.flags.response == 0",
                 "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"],
                capture_output=True, text=True, timeout=60,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                parts = ln.strip().split("\t")
                if len(parts) < 2:
                    continue
                src, domain = parts[0].strip(), parts[1].strip().lower().rstrip(".")
                if src and domain:
                    per_device.setdefault(src, {})
                    per_device[src][domain] = per_device[src].get(domain, 0) + 1

            # TLS SNI with source IP
            r = subprocess.run(
                [tshark, "-r", str(pcap),
                 "-Y", "tls.handshake.type == 1",
                 "-T", "fields", "-e", "ip.src", "-e", "tls.handshake.extensions_server_name"],
                capture_output=True, text=True, timeout=60,
                creationflags=_no_window(),
            )
            for ln in r.stdout.splitlines():
                parts = ln.strip().split("\t")
                if len(parts) < 2:
                    continue
                src, domain = parts[0].strip(), parts[1].strip().lower()
                if src and domain:
                    per_device.setdefault(src, {})
                    per_device[src][domain] = per_device[src].get(domain, 0) + 1

        except Exception:
            pass

    # Sort each device's domains by count desc, return top 30
    return {
        ip: sorted(
            [{"domain": d, "count": c} for d, c in domains.items()],
            key=lambda x: x["count"], reverse=True
        )[:30]
        for ip, domains in per_device.items()
    }


def cleanup_old_captures(capture_dir: Path = CAPTURE_DIR, retention_days: int = 3) -> int:
    """
    Delete pcap files older than retention_days.
    Called by the scheduler (during active capture) AND by app/main.py on
    startup (orphan sweep). Catches ring buffers, test rings, and deep-scan
    one-shots so nothing accumulates across capture-disabled periods.
    Returns the number of files removed.
    """
    import time
    cutoff = time.time() - (retention_days * 86400)
    removed = 0
    for f in capture_dir.glob("*.pcapng"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except Exception:
            pass
    if removed:
        print(f"[capture] Cleaned up {removed} old capture file(s).")
    return removed


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_conv_ip(output: str) -> List[Dict]:
    """
    Parse tshark -z conv,ip output.

    Line format (after header):
      ip_a   <->   ip_b   | left_frames  left_bytes | | right_frames  right_bytes | | total_frames  total_bytes | ...

    We extract ip_a, ip_b, total_packets (col 5), total_bytes (col 6).
    """
    rows = []
    for line in output.splitlines():
        if "<->" not in line:
            continue
        m = re.match(r'^\s*(\S+)\s+<->\s+(\S+)', line)
        if not m:
            continue
        ip_a, ip_b = m.group(1), m.group(2)
        rest = line[m.end():]

        # Extract integers only (int() rejects floats like "0.000000")
        numbers = []
        for tok in rest.replace("|", " ").split():
            try:
                numbers.append(int(tok.replace(",", "")))
            except ValueError:
                pass  # skip floats (timestamps, durations)

        # Expected order: [left_frames, left_bytes, right_frames, right_bytes,
        #                  total_frames, total_bytes, ...]
        if len(numbers) >= 6:
            rows.append({
                "ip_a":          ip_a,
                "ip_b":          ip_b,
                "total_packets": numbers[4],
                "total_bytes":   numbers[5],
            })
    return rows


def _parse_phs(output: str) -> Tuple[Dict[str, int], int, int]:
    """
    Parse tshark -z io,phs (protocol hierarchy statistics) output.
    Returns (proto_counts, total_packets, total_bytes).

    Example line:  "  tcp    frames:700 bytes:85000"
    """
    proto_counts  = {}
    total_packets = 0
    total_bytes   = 0

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or "frames:" not in stripped:
            continue
        m = re.match(r'(\w[\w\.]*)\s+frames:(\d+)\s+bytes:(\d+)', stripped)
        if not m:
            continue
        proto   = m.group(1).lower()
        frames  = int(m.group(2))
        bytecount = int(m.group(3))

        # Root protocol varies by link type:
        #   Ethernet  → "frame" / "eth"
        #   Wi-Fi     → "wlan" / "radiotap"
        #   Loopback  → "frame" / "null"
        if proto in ("eth", "frame", "wlan", "radiotap", "null"):
            if frames > total_packets:   # take the largest (outermost) count
                total_packets = frames
                total_bytes   = bytecount
        elif proto in _PROTO_WHITELIST:
            proto_counts[proto.upper()] = frames

    return proto_counts, total_packets, total_bytes


def _is_private(ip: str) -> bool:
    """Return True for RFC-1918 private addresses and loopback."""
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
            or parts[0] == 127
        )
    except Exception:
        return False
