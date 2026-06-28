"""
router_firmware.py — Check and apply Netgear firmware updates via the same
SOAP API the Uptime Guardian uses to reboot the router (see router_reboot.py).

Only Netgear/pynetgear is supported today — that's the only router model the
auto-heal credentials in Settings are scoped to. Other vendors don't expose
a remote-update API NetMon can safely call, so those findings stay manual
(link to the admin UI) rather than one-click.

All functions return the standard result dict and never raise:
  {"success": bool, "detail": str, "error": str | None, ...extra fields}
"""

from __future__ import annotations

from typing import Optional


def check_firmware(
    host: str,
    user: str,
    password: str,
    timeout: int = 25,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """Ask the router whether a newer firmware version is available."""
    if not password:
        return {"success": False, "error": "No router admin password configured "
                "(set it in Settings or the ROUTER_PASS env var)."}
    try:
        from pynetgear import Netgear
    except ImportError:
        return {"success": False, "error": "pynetgear is not installed. Run: pip install pynetgear"}

    try:
        ng = Netgear(password=password, host=host, user=user or "admin", ssl=use_ssl, port=port)
        # login_try_port checks every (port, ssl) combo Netgear firmware has
        # used historically — the configured port/ssl is tried first, so this
        # is a no-op if Settings already has the right values.
        if not ng.login_try_port():
            return {"success": False, "error": "Could not log in to the router "
                    "(check admin user/password in Settings)."}
        info = ng.check_new_firmware()
        if not info:
            return {"success": False, "error": "Router did not return firmware info. "
                    "It may not support remote firmware checks over the API."}
        current = info.get("CurrentVersion")
        new = info.get("NewVersion") or None
        return {
            "success": True,
            "error": None,
            "current_version": current,
            "new_version": new,
            "update_available": bool(new) and new != current,
            "release_note": info.get("ReleaseNote") or "",
        }
    except Exception as exc:  # noqa: BLE001 — surface any driver/transport error verbatim
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}


def update_firmware(
    host: str,
    user: str,
    password: str,
    timeout: int = 25,
    use_ssl: bool = False,
    port: Optional[int] = None,
) -> dict:
    """
    Tell the router to install the firmware update it already reported via
    check_firmware(). The router reboots itself once the flash completes —
    expect ~2-5 minutes of downtime, same as a manual update from the admin UI.
    """
    if not password:
        return {"success": False, "error": "No router admin password configured "
                "(set it in Settings or the ROUTER_PASS env var)."}
    try:
        from pynetgear import Netgear
    except ImportError:
        return {"success": False, "error": "pynetgear is not installed. Run: pip install pynetgear"}

    try:
        ng = Netgear(password=password, host=host, user=user or "admin", ssl=use_ssl, port=port)
        if not ng.login_try_port():
            return {"success": False, "error": "Could not log in to the router "
                    "(check admin user/password in Settings)."}
        result = ng.update_new_firmware()
        return {
            "success": bool(result is not None),
            "error": None if result is not None else
                     "Router rejected the update command, or there is no update queued — "
                     "run a firmware check first.",
            "detail": "Firmware update accepted. The router will flash and reboot itself; "
                      "expect a few minutes of downtime.",
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
