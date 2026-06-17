"""
router_reboot.py — Pluggable "reboot the router" drivers for the Uptime Guardian.

The auto-heal loop calls reboot_router() when it has confirmed a sustained
internet outage. Rebooting is a single fire-and-forget command: we tell the
router to restart itself and it comes back on its own — so unlike a smart-plug
power-cycle there's no "turn back on" step that the (now-dead) LAN would block.

Drivers
  netgear_soap — Netgear's SOAP API via the `pynetgear` library. Covers the
                 Orbi / CBR line (the user's box is a CBR750). pynetgear handles
                 the SOAP login + DeviceConfig:Reboot action.

Adding a driver: implement a function returning the standard result dict and
register it in _DRIVERS.

All drivers return:
  {"success": bool, "method": str, "detail": str, "error": str | None}
"""

from __future__ import annotations

from typing import Optional


def _netgear_soap(
    host: str,
    user: str,
    password: str,
    timeout: int = 25,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Reboot a Netgear router via its SOAP API using pynetgear."""
    method = "netgear_soap"
    if use_ssl and port is None:
        port = 443
    if not password:
        return {"success": False, "method": method, "detail": "",
                "error": "No router admin password configured (set it in Settings or the ROUTER_PASS env var)."}
    try:
        from pynetgear import Netgear
    except ImportError:
        return {"success": False, "method": method, "detail": "",
                "error": "pynetgear is not installed. Run: pip install pynetgear"}

    try:
        # pynetgear logs in lazily on the first call. host defaults to the
        # gateway; user defaults to 'admin' on Netgear consumer firmware.
        ng = Netgear(password=password, host=host, user=user or "admin", ssl=use_ssl, port=port)
        ok = ng.reboot()
        if ok:
            return {"success": True, "method": method,
                    "detail": f"Reboot command accepted by {host}.", "error": None}
        return {"success": False, "method": method, "detail": "",
                "error": "Router rejected the reboot call (check admin user/password)."}
    except Exception as exc:  # noqa: BLE001 — surface any driver/transport error verbatim
        return {"success": False, "method": method, "detail": "", "error": f"{type(exc).__name__}: {exc}"}


_DRIVERS = {
    "netgear_soap": _netgear_soap,
}


def _tasmota_http(
    host: str,
    user: str,
    password: str,
    timeout: int = 15,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Power-cycle a router plugged into a Tasmota smart plug via HTTP backlog."""
    method = "tasmota"
    if not host:
        return {"success": False, "method": method, "detail": "",
                "error": "No smart plug host configured."}
    
    import urllib.request
    import urllib.parse
    
    # We use Backlog to turn off, delay 10 seconds, and turn back on.
    # Delay is in tenths of a second, so Delay 100 = 10 seconds.
    cmnd = "Backlog Power1 0; Delay 100; Power1 1"
    
    params = {"cmnd": cmnd}
    if user:
        params["user"] = user
    if password:
        params["password"] = password
        
    query = urllib.parse.urlencode(params)
    protocol = "https" if use_ssl else "http"
    p = port or (443 if use_ssl else 80)
    url = f"{protocol}://{host}:{p}/cm?{query}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            resp_bytes = response.read()
            resp_str = resp_bytes.decode("utf-8", errors="ignore")
            if response.status == 200:
                return {
                    "success": True,
                    "method": method,
                    "detail": f"Tasmota power-cycle backlog command sent to {host}:{p}. Response: {resp_str[:100]}",
                    "error": None
                }
            else:
                return {
                    "success": False,
                    "method": method,
                    "detail": "",
                    "error": f"Tasmota returned HTTP status {response.status}"
                }
    except Exception as exc:
        return {"success": False, "method": method, "detail": "",
                "error": f"Tasmota request failed: {type(exc).__name__}: {exc}"}


def _shelly_http(
    host: str,
    user: str,
    password: str,
    timeout: int = 15,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Power-cycle a router plugged into a Shelly smart plug via HTTP with auto-on timer."""
    method = "shelly"
    if not host:
        return {"success": False, "method": method, "detail": "",
                "error": "No smart plug host configured."}
    
    import urllib.request
    import urllib.parse
    
    protocol = "https" if use_ssl else "http"
    p = port or (443 if use_ssl else 80)
    
    auth_str = ""
    if user and password:
        auth_str = f"{urllib.parse.quote(user)}:{urllib.parse.quote(password)}@"
    elif password:
        auth_str = f"admin:{urllib.parse.quote(password)}@"
        
    url_gen1 = f"{protocol}://{auth_str}{host}:{p}/relay/0?turn=off&timer=10"
    url_gen2 = f"{protocol}://{auth_str}{host}:{p}/rpc/Switch.Set?id=0&on=false&toggle_after=10"
    
    errors = []
    # Try Gen 1
    try:
        req = urllib.request.Request(url_gen1)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                resp = response.read().decode("utf-8", errors="ignore")
                return {
                    "success": True,
                    "method": method,
                    "detail": f"Shelly Gen 1 power-cycle command sent to {host}. Response: {resp[:100]}",
                    "error": None
                }
    except Exception as exc:
        errors.append(f"Gen 1 attempt: {type(exc).__name__}: {exc}")
        
    # Try Gen 2
    try:
        req = urllib.request.Request(url_gen2)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                resp = response.read().decode("utf-8", errors="ignore")
                return {
                    "success": True,
                    "method": method,
                    "detail": f"Shelly Gen 2 power-cycle command sent to {host}. Response: {resp[:100]}",
                    "error": None
                }
    except Exception as exc:
        errors.append(f"Gen 2 attempt: {type(exc).__name__}: {exc}")
        
    return {
        "success": False,
        "method": method,
        "detail": "",
        "error": f"Shelly power-cycle failed. Errors: {'; '.join(errors)}"
    }


def _kasa_api(
    host: str,
    user: str,
    password: str,
    timeout: int = 10,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Power-cycle a router plugged into a TP-Link Kasa smart plug via local TCP protocol."""
    method = "kasa"
    if not host:
        return {"success": False, "method": method, "detail": "",
                "error": "No smart plug host configured."}
    
    import socket
    import struct
    import time
    
    p = port or 9999
    
    def encrypt_kasa(cmd: str) -> bytes:
        key = 171
        result = bytearray(struct.pack('>I', len(cmd)))
        for c in cmd:
            a = key ^ ord(c)
            key = a
            result.append(a)
        return bytes(result)
        
    def decrypt_kasa(data: bytes) -> str:
        key = 171
        result = []
        for b in data[4:]:
            a = key ^ b
            key = b
            result.append(chr(a))
        return "".join(result)
        
    def send_cmd(cmd: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            s.sendall(encrypt_kasa(cmd))
            data = s.recv(2048)
            return decrypt_kasa(data)
        finally:
            s.close()
            
    off_cmd = '{"system":{"set_relay_state":{"state":0}}}'
    on_cmd = '{"system":{"set_relay_state":{"state":1}}}'
    
    try:
        off_resp = send_cmd(off_cmd)
        if "err_code" in off_resp and '"err_code":0' not in off_resp.replace(" ", ""):
            return {"success": False, "method": method, "detail": "",
                    "error": f"Kasa rejected OFF command: {off_resp[:100]}"}
                    
        time.sleep(10)
        
        on_resp = send_cmd(on_cmd)
        if "err_code" in on_resp and '"err_code":0' not in on_resp.replace(" ", ""):
            return {"success": False, "method": method, "detail": "",
                    "error": f"Kasa OFF succeeded, but ON command failed: {on_resp[:100]}. WARNING: Plug may be stuck in OFF state!"}
                    
        return {
            "success": True,
            "method": method,
            "detail": f"Kasa power-cycled successfully. OFF response: {off_resp[:80]}, ON response: {on_resp[:80]}",
            "error": None
        }
    except Exception as exc:
        return {
            "success": False,
            "method": method,
            "detail": "",
            "error": f"Kasa power-cycle failed: {type(exc).__name__}: {exc}. WARNING: Plug status uncertain."
        }


_DRIVERS = {
    "netgear_soap": _netgear_soap,
    "tasmota": _tasmota_http,
    "shelly": _shelly_http,
    "kasa": _kasa_api,
}


def available_methods() -> list[str]:
    return list(_DRIVERS.keys())


def reboot_router(
    host: str,
    user: str,
    password: str,
    method: str = "netgear_soap",
    timeout: int = 25,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """
    Reboot the router using the named driver.

    Returns the standard result dict. Never raises — any failure is reported in
    the "error" field so the caller (auto-heal loop) can log/notify and back off
    rather than crash a background task.
    """
    driver = _DRIVERS.get(method)
    if driver is None:
        return {"success": False, "method": method, "detail": "",
                "error": f"Unknown reboot method '{method}'. Available: {', '.join(_DRIVERS)}"}
    return driver(host, user, password, timeout=timeout, use_ssl=use_ssl, port=port)
