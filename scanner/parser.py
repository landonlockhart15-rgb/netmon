"""
parser.py — Converts nmap XML output into structured Python dictionaries.

nmap XML structure (simplified):
  <nmaprun>
    <host>
      <status state="up"/>
      <address addr="192.168.1.5"  addrtype="ipv4"/>
      <address addr="AA:BB:CC:DD"  addrtype="mac" vendor="Apple"/>
      <hostnames>
        <hostname name="my-macbook.local" type="PTR"/>
      </hostnames>
      <ports>
        <port portid="80" protocol="tcp">
          <state state="open"/>
          <service name="http"/>
        </port>
      </ports>
    </host>
  </nmaprun>

Our job: walk this tree and pull out what we care about.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any


def parse_nmap_xml(xml_string: str) -> List[Dict[str, Any]]:
    """
    Parse raw nmap XML output into a list of device dictionaries.

    Each dictionary has:
      ip         (str)       : IPv4 address
      mac        (str|None)  : MAC address, or None if nmap couldn't get it
      vendor     (str|None)  : Hardware vendor from MAC OUI lookup
      hostname   (str|None)  : Reverse DNS hostname if available
      open_ports (list[int]) : List of open port numbers

    Args:
        xml_string: Raw XML string from nmap stdout.

    Returns:
        List of device dicts. Empty list if no hosts found or XML is empty.
    """
    if not xml_string or not xml_string.strip():
        return []

    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        print(f"[parser] Failed to parse nmap XML: {e}")
        return []

    devices = []

    # Each <host> element is one discovered machine
    for host in root.findall("host"):

        # Skip hosts that didn't respond (nmap includes them with state="down")
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        device: Dict[str, Any] = {
            "ip": None,
            "mac": None,
            "vendor": None,
            "hostname": None,
            "open_ports": [],
        }

        # --- Parse IP and MAC addresses ---
        # A host can have multiple <address> elements (one for IPv4, one for MAC)
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4":
                device["ip"] = addr.get("addr")
            elif addr_type == "mac":
                mac_addr = addr.get("addr")
                device["mac"] = mac_addr.lower() if mac_addr else None
                # vendor is an attribute on the MAC address element
                device["vendor"] = addr.get("vendor")

        # --- Parse hostname ---
        # <hostnames> can contain multiple entries; we take the first PTR record.
        # PTR = Pointer record = reverse DNS (IP -> name)
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                if hn.get("type") == "PTR":
                    device["hostname"] = hn.get("name")
                    break  # Take the first one only

        # --- Parse open ports ---
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                # Only include ports confirmed open
                state_el = port.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    port_num = port.get("portid")
                    if port_num and port_num.isdigit():
                        device["open_ports"].append(int(port_num))

        # Only add the device if we at least got an IP address
        if device["ip"]:
            devices.append(device)

    # Deduplicate by MAC address — phone hotspots do proxy ARP, answering
    # ARP requests for every IP in the subnet with the same MAC. This makes
    # nmap report hundreds of "hosts" that are all actually the gateway.
    # Keep only the lowest IP per MAC (the real device), drop the rest.
    seen_macs: dict = {}
    for d in devices:
        mac = d.get("mac")
        if not mac:
            continue
        if mac not in seen_macs:
            seen_macs[mac] = d
        else:
            # Keep whichever has the lower IP (gateway .1 wins over phantom .2-.254)
            if (d["ip"] or "999") < (seen_macs[mac]["ip"] or "999"):
                seen_macs[mac] = d

    deduped = [d for d in devices if not d.get("mac") or seen_macs.get(d["mac"]) is d]

    # Fallback: if MACs were absent (some nmap builds omit them on Windows) and we
    # got an implausibly large result (>64 hosts in a single scan), it is almost
    # certainly proxy ARP filling the whole subnet. Cap at hosts that have a
    # hostname or that match .1/.2 gateway-style IPs, dropping pure phantoms.
    if len(deduped) > 64 and all(not d.get("mac") for d in deduped):
        deduped = [d for d in deduped
                   if d.get("hostname") or (d.get("ip", "").rsplit(".", 1)[-1] in ("1", "2"))]
        print(f"[parser] Proxy-ARP fallback (no MACs): trimmed to {len(deduped)} hosts.")

    if len(deduped) < len(devices):
        print(f"[parser] Proxy-ARP dedup: {len(devices)} → {len(deduped)} hosts.")
    print(f"[parser] Parsed {len(deduped)} hosts from nmap output.")
    return deduped
