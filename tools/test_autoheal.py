"""
test_autoheal.py — Verifies the Uptime Guardian without touching the real router.

Run:  python tools/test_autoheal.py   (from the netmon project root)

Covers:
  1. decide() — the pure decision engine — across every branch.
  2. run_cycle() dry-run — full orchestration incl. ActivityLog writes, the
     confirm window, single-reboot-per-outage, recovery, and ISP-outage giveup.
     (Cleans up the rows it creates and restores settings afterward.)
  3. router driver safety — never raises; reports errors in the result dict.

It does NOT issue a real reboot (that needs the admin password + would drop the
network). The live reboot is exercised separately via the manual button.
"""
import sys, os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_pass = 0
_fail = 0
def check(name, cond):
    global _pass, _fail
    if cond:
        _pass += 1; print(f"  PASS  {name}")
    else:
        _fail += 1; print(f"  FAIL  {name}")


def base_cfg(**over):
    cfg = dict(confirm_checks=3, max_per_outage=1, cooldown_s=600,
               max_per_day=4, recovery_window_s=240, dry_run=True, enabled=True)
    cfg.update(over)
    return cfg


def test_decide():
    from monitoring.autoheal import decide
    now = datetime.now(timezone.utc)
    cfg = base_cfg()

    d = decide(internet_up=True, gateway_up=True, consecutive_offline=0, cfg=cfg,
               reboots_in_outage=0, reboots_today=0, last_attempt_at=None, now=now)
    check("online when internet up", d["action"] == "online")

    d = decide(internet_up=False, gateway_up=True, consecutive_offline=1, cfg=cfg,
               reboots_in_outage=0, reboots_today=0, last_attempt_at=None, now=now)
    check("confirming on brief blip", d["action"] == "confirming")

    d = decide(internet_up=False, gateway_up=True, consecutive_offline=3, cfg=cfg,
               reboots_in_outage=0, reboots_today=0, last_attempt_at=None, now=now)
    check("reboot once outage confirmed (gateway up)", d["action"] == "reboot")

    d = decide(internet_up=False, gateway_up=False, consecutive_offline=3, cfg=cfg,
               reboots_in_outage=0, reboots_today=0, last_attempt_at=None, now=now)
    check("reboot attempted even if gateway down", d["action"] == "reboot")

    d = decide(internet_up=False, gateway_up=True, consecutive_offline=9, cfg=cfg,
               reboots_in_outage=1, reboots_today=1,
               last_attempt_at=now - timedelta(seconds=60), now=now)
    check("awaiting_recovery within boot window", d["action"] == "awaiting_recovery")

    d = decide(internet_up=False, gateway_up=True, consecutive_offline=20, cfg=cfg,
               reboots_in_outage=1, reboots_today=1,
               last_attempt_at=now - timedelta(seconds=300), now=now)
    check("giveup after reboot didn't help (per-outage cap)", d["action"] == "giveup")

    d = decide(internet_up=False, gateway_up=True, consecutive_offline=5, cfg=base_cfg(max_per_day=2),
               reboots_in_outage=0, reboots_today=2,
               last_attempt_at=now - timedelta(seconds=99999), now=now)
    check("giveup at daily cap", d["action"] == "giveup")

    # cooldown branch reachable only when per-outage cap allows >1 reboot
    d = decide(internet_up=False, gateway_up=True, consecutive_offline=9,
               cfg=base_cfg(max_per_outage=2, cooldown_s=600, recovery_window_s=240),
               reboots_in_outage=1, reboots_today=1,
               last_attempt_at=now - timedelta(seconds=300), now=now)
    check("cooldown between reboots (past recovery, within cooldown)", d["action"] == "cooldown")


def test_run_cycle_dryrun():
    from app.database import Base, engine, SessionLocal
    from models.tables import Setting, ActivityLog
    import monitoring.autoheal as ah

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    saved = {}
    test_start = datetime.now(timezone.utc)
    try:
        # Force enabled + dry-run + tight thresholds for the test; remember originals.
        overrides = {"autoheal_enabled": "true", "autoheal_dry_run": "true",
                     "autoheal_confirm_checks": "3", "autoheal_max_reboots_per_outage": "1",
                     "autoheal_recovery_window_s": "240", "autoheal_cooldown_min": "10",
                     "autoheal_router_pass": "", "autoheal_router_ssl": "true",
                     "autoheal_router_port": ""}
        for k, v in overrides.items():
            row = db.query(Setting).filter(Setting.key == k).first()
            saved[k] = row.value if row else None
            if row: row.value = v
            else: db.add(Setting(key=k, value=v))
        db.commit()

        ah._reset_state()
        cfg = ah.get_config(db)
        check("SSL router mode defaults to port 443", cfg["router_ssl"] is True and cfg["router_port"] == 443)

        offline = lambda cfg: {"internet_up": False, "gateway_up": True,
                               "internet_latency_ms": None, "gateway_latency_ms": 2.0}
        online = lambda cfg: {"internet_up": True, "gateway_up": True,
                              "internet_latency_ms": 15.0, "gateway_latency_ms": 2.0}

        a1 = ah.run_cycle(probe_fn=offline)   # confirm 1
        a2 = ah.run_cycle(probe_fn=offline)   # confirm 2
        a3 = ah.run_cycle(probe_fn=offline)   # confirm 3 -> dry-run reboot
        check("cycle1 confirming", a1["action"] == "confirming")
        check("cycle3 triggers (dry-run) reboot", a3["action"] == "reboot" and a3.get("executed") == "dry_run")

        a4 = ah.run_cycle(probe_fn=offline)   # within recovery window now
        check("after reboot -> awaiting_recovery", a4["action"] == "awaiting_recovery")

        # exactly one dry-run attempt logged for this outage
        n_attempts = (db.query(ActivityLog)
                      .filter(ActivityLog.category == "autoheal",
                              ActivityLog.event == ah.EV_DRYRUN,
                              ActivityLog.created_at >= test_start).count())
        check("exactly one dry-run reboot logged (no loop)", n_attempts == 1)

        reset = ah.reset_reboot_counter(db)
        stats_after_reset = ah.attempt_stats(db)
        check("reset clears counted reboot budget", reset["cleared_reboots_today"] >= 1 and stats_after_reset["reboots_today"] == 0)

        a4b = ah.run_cycle(probe_fn=offline)
        check("after reset, outage can use budget again", a4b["action"] == "reboot" and a4b.get("executed") == "dry_run")

        a5 = ah.run_cycle(probe_fn=online)    # recovery
        check("recovery detected after reboot", a5["action"] == "online" and a5.get("recovered"))
        n_recovered = (db.query(ActivityLog)
                       .filter(ActivityLog.category == "autoheal",
                               ActivityLog.event == ah.EV_RECOVERED,
                               ActivityLog.created_at >= test_start).count())
        check("recovery event logged", n_recovered == 1)
    finally:
        # cleanup: remove rows we created, restore settings
        (db.query(ActivityLog)
           .filter(ActivityLog.category == "autoheal", ActivityLog.created_at >= test_start)
           .delete(synchronize_session=False))
        for k, v in saved.items():
            row = db.query(Setting).filter(Setting.key == k).first()
            if row is not None:
                if v is None:
                    db.delete(row)
                else:
                    row.value = v
        db.commit()
        db.close()
        ah._reset_state()


def test_driver_safety():
    from network.router_reboot import reboot_router
    r = reboot_router("192.168.1.1", "admin", "", method="netgear_soap")
    check("driver: no password -> graceful error (no raise)", r["success"] is False and r["error"])
    r = reboot_router("192.168.1.1", "admin", "x", method="bogus_method")
    check("driver: unknown method -> graceful error", r["success"] is False and "Unknown" in r["error"])


def test_smartplug_drivers():
    from network.router_reboot import reboot_router
    from unittest.mock import patch, MagicMock
    import struct

    # 1. Test Tasmota driver
    r = reboot_router("", "", "", method="tasmota")
    check("tasmota: empty host -> error", r["success"] is False and "host" in r["error"])
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"status":"ok"}'
    mock_resp.__enter__.return_value = mock_resp
    with patch("urllib.request.urlopen", return_value=mock_resp):
        r = reboot_router("192.168.1.100", "admin", "secret", method="tasmota")
        check("tasmota: success mock", r["success"] is True and "Tasmota power-cycle" in r["detail"])
        
    # 2. Test Shelly driver
    r = reboot_router("", "", "", method="shelly")
    check("shelly: empty host -> error", r["success"] is False and "host" in r["error"])
    
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b'{"ison":false}'
    mock_resp.__enter__.return_value = mock_resp
    with patch("urllib.request.urlopen", return_value=mock_resp):
        r = reboot_router("192.168.1.100", "admin", "secret", method="shelly")
        check("shelly: success mock", r["success"] is True and "Shelly Gen 1" in r["detail"])

    # 3. Test Kasa driver
    r = reboot_router("", "", "", method="kasa")
    check("kasa: empty host -> error", r["success"] is False and "host" in r["error"])
    
    def make_kasa_resp(string: str) -> bytes:
        key = 171
        result = bytearray(struct.pack('>I', len(string)))
        for c in string:
            a = key ^ ord(c)
            key = a
            result.append(a)
        return bytes(result)
        
    mock_sock_inst = MagicMock()
    mock_sock_inst.recv.side_effect = [
        make_kasa_resp('{"count_down":{"delete_all_rules":{"err_code":0}}}'),
        make_kasa_resp('{"count_down":{"add_rule":{"err_code":0}}}'),
        make_kasa_resp('{"system":{"set_relay_state":{"err_code":0}}}')
    ]
    with patch("socket.socket", return_value=mock_sock_inst), patch("time.sleep"):
        r = reboot_router("192.168.1.100", "", "", method="kasa")
        check("kasa: success mock", r["success"] is True and "successfully" in r["detail"])


if __name__ == "__main__":
    print("decide() — pure decision engine:");      test_decide()
    print("run_cycle() — dry-run orchestration:");   test_run_cycle_dryrun()
    print("router driver — safety:");                test_driver_safety()
    print("smartplug drivers — safety/mocks:");      test_smartplug_drivers()
    print(f"\n{_pass} passed, {_fail} failed")
    sys.exit(1 if _fail else 0)
