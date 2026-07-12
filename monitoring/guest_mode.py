"""
monitoring/guest_mode.py — the Guest Mode safety gate.

Guest Mode is the master switch you turn ON before connecting NetMon to a
network you do NOT own (hotel, airport, cafe Wi-Fi). When it is on, every
feature that actively touches other devices or acts on the network is
suppressed, leaving only passive, self-directed monitoring of your own
connection.

This module is the single source of truth for that policy. It is deliberately
tiny, stdlib-only, and side-effect-light so that every gate — the scheduler
loops (Layer 1) and the dangerous action entry points (Layer 2) — can ask it
the same question and get the same answer:

    should_block("mitm", db)  ->  True when Guest Mode forbids this feature

Two layers use this:
  Layer 1 (scheduler): active loops skip when their feature is blocked.
  Layer 2 (actions):   run_scan / MitmEngine.start / blockers / router reboot
                       hard-refuse at entry, so even a manual button or a stray
                       API call cannot fire an active operation in Guest Mode.

The DB setting key is "guest_mode" ("true"/"false"); default OFF ("false").
"""
from __future__ import annotations

from models.tables import Setting

# Setting key that stores Guest Mode state. "true" => guest mode ON.
GUEST_MODE_KEY = "guest_mode"

# Features suppressed while Guest Mode is ON. Each name is a stable identifier
# a gate passes to should_block(). Anything NOT in this set is considered
# passive/self-directed and is allowed to keep running (health checks, DNS
# health, DoH-leak test, read-only captive-portal analysis, internal
# housekeeping, and passive analysis of already-stored data).
BLOCKED_FEATURES: frozenset[str] = frozenset({
    "mitm",              # ARP man-in-the-middle — the critical one
    "auto_scan",         # nmap ping sweep + port + vulners NSE
    "active_discovery",  # active device enumeration
    "port_refresh",      # port scanning known devices
    "ssl_cert_scan",     # connects out to hosts to grab certs
    "deep_scan_ai",      # AI-driven deep scan
    "hunt",              # active host hunting
    "capture",           # packet capture (records traffic)
    "incident_capture",  # packet capture on incident
    "autoheal",          # acts on the network to self-heal
    "blocker",           # firewall / device blocking
    "dns_blocker",       # DNS-level blocking
    "dhcp",              # DHCP actions
    "router_reboot",     # logs into and reboots the router
    "router_firmware",   # queries/acts on router firmware
})


def is_guest_mode(db) -> bool:
    """Return True when Guest Mode is currently enabled.

    Fail-safe: if the setting is missing or unreadable, Guest Mode is OFF
    (default behavior on a trusted home network is preserved).
    """
    row = db.query(Setting).filter(Setting.key == GUEST_MODE_KEY).first()
    return bool(row and (row.value or "").strip().lower() == "true")


def should_block(feature: str, db) -> bool:
    """True when Guest Mode is on AND `feature` is an active/invasive feature.

    Passive, self-directed features (not in BLOCKED_FEATURES) are never blocked.
    """
    return feature in BLOCKED_FEATURES and is_guest_mode(db)


class GuestModeBlocked(RuntimeError):
    """Raised by Layer-2 action guards when Guest Mode forbids an operation."""

    def __init__(self, feature: str):
        self.feature = feature
        super().__init__(
            f"Guest Mode is ON — the '{feature}' operation is suppressed because "
            "NetMon is connected to a network you do not own. Turn Guest Mode off "
            "to run active operations on your own network."
        )


def guard(feature: str, db) -> None:
    """Layer-2 convenience: raise GuestModeBlocked if `feature` is blocked.

    Call at the top of a dangerous action entry point:

        from monitoring.guest_mode import guard
        guard("mitm", db)  # raises before any ARP packet is sent
    """
    if should_block(feature, db):
        raise GuestModeBlocked(feature)


def is_guest_mode_now() -> bool:
    """DB-less variant: open a short-lived session and report Guest Mode state.

    For action entry points that have no `db` in scope (e.g. run_scan()).
    Fail-safe: any error reading state returns False (does not block on its own
    failure), matching is_guest_mode().
    """
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        return is_guest_mode(db)
    except Exception:
        return False
    finally:
        db.close()


def guard_now(feature: str) -> None:
    """DB-less Layer-2 guard: raise GuestModeBlocked if `feature` is blocked.

    Drop-in for dangerous entry points without a `db` session:

        from monitoring.guest_mode import guard_now
        guard_now("auto_scan")  # raises before nmap is launched
    """
    if feature in BLOCKED_FEATURES and is_guest_mode_now():
        raise GuestModeBlocked(feature)
