import os
import re
import subprocess
import time

_CACHE: dict = {}
_CACHE_TS: float = 0.0
_CACHE_TTL = 60
_AUTO_SCAN_VALUES = {"", "auto", "autodetect", "detect"}


def _cidr_from_mask(mask: str) -> int:
    return sum(bin(int(o)).count("1") for o in mask.split("."))


def _network_addr(ip: str, mask: str) -> str:
    parts = [str(int(a) & int(b)) for a, b in zip(ip.split("."), mask.split("."))]
    return ".".join(parts)


_SKIP_IFACE = ("loopback", "tunnel", "isatap", "teredo", "tailscale",
               "vpn", "virtual", "vmware", "vethernet", "wsl", "hyper-v")

def _is_usable(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith(("127.", "169.254.")):
        return False
    try:
        first, second = map(int, ip.split(".")[:2])
        if first == 100 and 64 <= second <= 127:
            return False
    except ValueError:
        pass
    return True


def _default_route_iface_ip() -> str:
    """
    Ask Windows which local interface IP is used for the default route (0.0.0.0).
    Returns the interface IP string, or "" on failure.
    Skips Tailscale/CGNAT IPs (100.64-127.x) so they don't shadow the real adapter.
    """
    try:
        raw = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                iface_ip = parts[3]
                if _is_usable(iface_ip):
                    return iface_ip
    except Exception:
        pass
    return ""


def _connected_iface_names() -> set:
    """
    Return the set of interface names that netsh reports as Connected.
    Used to filter out adapters that have a stale IP but no active link.
    """
    try:
        raw = subprocess.check_output(
            ["netsh", "interface", "show", "interface"],
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        names = set()
        for line in raw.splitlines():
            # Lines look like: "Enabled    Connected    Dedicated    Wi-Fi"
            if "connected" in line.lower() and "disconnected" not in line.lower():
                # Last token(s) are the interface name
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    names.add(parts[3].strip())
        return names
    except Exception:
        return set()


def get_network_info() -> dict:
    global _CACHE, _CACHE_TS
    if time.time() - _CACHE_TS < _CACHE_TTL and _CACHE:
        return _CACHE

    # Find the interface IP Windows is using for the default route — this
    # identifies the active adapter regardless of ipconfig output order.
    preferred_ip = _default_route_iface_ip()

    try:
        raw = subprocess.check_output(
            ["ipconfig", "/all"], text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        return _fallback()

    sections = re.split(r"\r?\n(?=\S)", raw)

    candidates = []
    for section in sections:
        first_line = section.splitlines()[0].lower() if section.strip() else ""
        if any(x in first_line for x in _SKIP_IFACE):
            continue

        # Skip adapters Windows reports as physically disconnected
        if "media disconnected" in section.lower():
            continue

        ip_m = re.search(r"IPv4 Address[\s.]+:\s*([\d.]+)", section, re.IGNORECASE)
        if not ip_m:
            continue
        ip = ip_m.group(1).strip().rstrip("(Preferred)")
        if not _is_usable(ip):
            continue

        mask_m  = re.search(r"Subnet Mask[\s.]+:\s*([\d.]+)", section, re.IGNORECASE)
        gw_m    = re.search(r"Default Gateway[\s.]+:\s*([\d.]+)", section, re.IGNORECASE)
        iface_m = re.search(r"^.*adapter (.+?):", section, re.MULTILINE)

        mask    = mask_m.group(1).strip()  if mask_m  else "255.255.255.0"
        gateway = gw_m.group(1).strip()    if gw_m    else ip.rsplit(".", 1)[0] + ".1"
        iface   = iface_m.group(1).strip() if iface_m else "Unknown"

        if not _is_usable(gateway):
            continue

        cidr   = _cidr_from_mask(mask)
        net    = _network_addr(ip, mask)
        subnet = f"{net}/{cidr}"

        candidates.append({
            "local_ip":    ip,
            "gateway":     gateway,
            "subnet":      subnet,
            "scan_target": subnet,
            "interface":   iface,
        })

    if not candidates:
        return _fallback()

    # Filter to adapters that netsh confirms are Connected (eliminates stale leases).
    connected = _connected_iface_names()
    if connected:
        active = [c for c in candidates if c["interface"] in connected]
        if active:
            candidates = active

    # Among active candidates, prefer the one whose IP matches the default route.
    best = candidates[0]
    if preferred_ip:
        for c in candidates:
            if c["local_ip"] == preferred_ip:
                best = c
                break

    print(f"[autodetect] active iface={best['interface']} ip={best['local_ip']} "
          f"subnet={best['subnet']} gateway={best['gateway']}")

    _CACHE    = best
    _CACHE_TS = time.time()
    return best


def get_scan_target() -> str:
    """
    Return the subnet/range NetMon should scan.

    SCAN_TARGET is an explicit override when set to a real range. Blank,
    "auto", "autodetect", and "detect" all mean "use the active adapter".
    """
    configured = os.getenv("SCAN_TARGET", "").strip()
    if configured.lower() not in _AUTO_SCAN_VALUES:
        return configured

    info = get_network_info()
    target = (info.get("scan_target") or "").strip()
    if target and info.get("local_ip") != "unknown":
        return target

    fallback = _fallback()
    return fallback.get("scan_target") or "192.168.1.0/24"


def invalidate_cache() -> None:
    global _CACHE, _CACHE_TS
    _CACHE    = {}
    _CACHE_TS = 0.0


def _fallback() -> dict:
    if _CACHE:
        return _CACHE
    return {
        "local_ip":    "unknown",
        "gateway":     "192.168.1.1",
        "subnet":      "192.168.1.0/24",
        "scan_target": "192.168.1.0/24",
        "interface":   "unknown",
    }
