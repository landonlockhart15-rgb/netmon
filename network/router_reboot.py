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


def _netgear_soap(host: str, user: str, password: str, timeout: int = 25) -> dict:
    """Reboot a Netgear router via its SOAP API using pynetgear."""
    method = "netgear_soap"
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
        ng = Netgear(password=password, host=host, user=user or "admin")
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


def available_methods() -> list[str]:
    return list(_DRIVERS.keys())


def reboot_router(
    host: str,
    user: str,
    password: str,
    method: str = "netgear_soap",
    timeout: int = 25,
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
    return driver(host, user, password, timeout=timeout)
