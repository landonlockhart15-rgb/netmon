"""
database.py — SQLite connection, session management, startup migrations,
              and default settings seeding.
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/netmon.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a DB session, closes it when done."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def run_migrations():
    """
    Apply column-level schema changes that create_all cannot handle.
    Safe to run on every startup — checks before altering.

    New tables (health_checks, speed_tests) are handled by create_all
    because they're brand new. Only ADD COLUMN migrations go here.
    """
    with engine.connect() as conn:

        # ── scan_devices.hostname (added Phase 3) ─────────────────────────
        result = conn.execute(text("PRAGMA table_info(scan_devices)"))
        existing = [row[1] for row in result]
        if "hostname" not in existing:
            conn.execute(text("ALTER TABLE scan_devices ADD COLUMN hostname TEXT"))
            conn.commit()
            print("[db] Migration: scan_devices.hostname added.")

        # ── capture_sessions table (added Phase 7) ────────────────────────
        # create_all handles new tables; only ADD COLUMN migrations go here.

        # ── health_checks.local_latency_ms + local_target (added Phase 7) ──
        result = conn.execute(text("PRAGMA table_info(health_checks)"))
        existing = [row[1] for row in result]
        if "local_latency_ms" not in existing:
            conn.execute(text("ALTER TABLE health_checks ADD COLUMN local_latency_ms REAL"))
            conn.commit()
            print("[db] Migration: health_checks.local_latency_ms added.")
        if "local_target" not in existing:
            conn.execute(text("ALTER TABLE health_checks ADD COLUMN local_target TEXT"))
            conn.commit()
            print("[db] Migration: health_checks.local_target added.")

        # ── traffic_summaries.top_domains (added Phase 7b) ───────────────
        result = conn.execute(text("PRAGMA table_info(traffic_summaries)"))
        existing = [row[1] for row in result]
        if "top_domains" not in existing:
            conn.execute(text("ALTER TABLE traffic_summaries ADD COLUMN top_domains TEXT DEFAULT '[]'"))
            conn.commit()
            print("[db] Migration: traffic_summaries.top_domains added.")

        # ── speed_tests.upload_mbps (added Phase 6) ───────────────────────
        result = conn.execute(text("PRAGMA table_info(speed_tests)"))
        existing = [row[1] for row in result]
        if "upload_mbps" not in existing:
            conn.execute(text("ALTER TABLE speed_tests ADD COLUMN upload_mbps REAL"))
            conn.commit()
            print("[db] Migration: speed_tests.upload_mbps added.")

        # ── activity_log.dismissed (added for Shield dismiss feature) ────────
        result = conn.execute(text("PRAGMA table_info(activity_log)"))
        existing = [row[1] for row in result]
        if "dismissed" not in existing:
            conn.execute(text("ALTER TABLE activity_log ADD COLUMN dismissed INTEGER DEFAULT 0"))
            conn.commit()
            print("[db] Migration: activity_log.dismissed added.")

        # ── activity_log: autonomous-action tracking columns ──────────────
        # Records who initiated each action and how to undo it. Pre-existing
        # rows get actor='system' and revert_json=NULL (so they're not listed
        # as reversible — the new UI only shows rows with revert_json set).
        result = conn.execute(text("PRAGMA table_info(activity_log)"))
        existing = [row[1] for row in result]
        if "actor" not in existing:
            conn.execute(text("ALTER TABLE activity_log ADD COLUMN actor TEXT DEFAULT 'system'"))
            conn.commit()
            print("[db] Migration: activity_log.actor added.")
        if "revert_json" not in existing:
            conn.execute(text("ALTER TABLE activity_log ADD COLUMN revert_json TEXT"))
            conn.commit()
            print("[db] Migration: activity_log.revert_json added.")
        if "reverted_at" not in existing:
            conn.execute(text("ALTER TABLE activity_log ADD COLUMN reverted_at DATETIME"))
            conn.commit()
            print("[db] Migration: activity_log.reverted_at added.")
        if "reverted_by" not in existing:
            conn.execute(text("ALTER TABLE activity_log ADD COLUMN reverted_by TEXT"))
            conn.commit()
            print("[db] Migration: activity_log.reverted_by added.")

        # ── devices: per-device baseline + allow-list (Phase 0/1) ────────
        result = conn.execute(text("PRAGMA table_info(devices)"))
        existing = [row[1] for row in result]
        if "known_ports_json" not in existing:
            conn.execute(text("ALTER TABLE devices ADD COLUMN known_ports_json TEXT"))
            conn.commit()
            print("[db] Migration: devices.known_ports_json added.")
        if "allow_json" not in existing:
            conn.execute(text("ALTER TABLE devices ADD COLUMN allow_json TEXT"))
            conn.commit()
            print("[db] Migration: devices.allow_json added.")
        if "baseline_set_at" not in existing:
            conn.execute(text("ALTER TABLE devices ADD COLUMN baseline_set_at DATETIME"))
            conn.commit()
            print("[db] Migration: devices.baseline_set_at added.")
        if "os_guess" not in existing:
            conn.execute(text("ALTER TABLE devices ADD COLUMN os_guess TEXT"))
            conn.commit()
            print("[db] Migration: devices.os_guess added.")
        if "os_guess_at" not in existing:
            conn.execute(text("ALTER TABLE devices ADD COLUMN os_guess_at DATETIME"))
            conn.commit()
            print("[db] Migration: devices.os_guess_at added.")

        # ── Env-backed secret migration ───────────────────────────────────
        # If NTFY_PASS or SMTP_PASS is now set in the environment but the
        # old plain-text DB value is still hanging around, blank the DB row
        # so a future operator (or a leaked DB backup) can't recover it.
        for db_key, env_key in (("ntfy_pass", "NTFY_PASS"),
                                ("smtp_pass", "SMTP_PASS")):
            if not os.getenv(env_key):
                continue
            row = conn.execute(
                text("SELECT value FROM settings WHERE key=:k"),
                {"k": db_key},
            ).first()
            if row and row[0]:
                conn.execute(
                    text("UPDATE settings SET value='' WHERE key=:k"),
                    {"k": db_key},
                )
                conn.commit()
                print(f"[db] Migration: cleared {db_key} from DB (now read from {env_key}).")

        # ── speed_test_url: keep stale defaults in sync with the test engine ──
        # Cloudflare's __down endpoint caps each request at 50 MB (anything
        # ≥100 MB returns 403). The parallel-stream test handles that cap by
        # re-opening connections within the measurement window, so 50 MB per
        # request is the correct value. Upgrade any prior NetMon default — and
        # fix the broken 100/500 MB values that were briefly defaults.
        old_urls = {
            "https://speed.cloudflare.com/__down?bytes=5000000",
            "https://speed.cloudflare.com/__down?bytes=25000000",
            "https://speed.cloudflare.com/__down?bytes=100000000",
            "https://speed.cloudflare.com/__down?bytes=500000000",
        }
        new_url = "https://speed.cloudflare.com/__down?bytes=50000000"
        row = conn.execute(
            text("SELECT value FROM settings WHERE key='speed_test_url'")
        ).first()
        if row and row[0] in old_urls:
            conn.execute(
                text("UPDATE settings SET value=:new WHERE key='speed_test_url'"),
                {"new": new_url},
            )
            conn.commit()
            print("[db] Migration: speed_test_url set to 100MB (Cloudflare per-request cap).")


def seed_default_settings():
    """
    Insert default setting rows on first startup.
    Uses INSERT OR IGNORE (via query-then-insert) so existing values are
    never overwritten — user changes persist across restarts.

    Settings reference:
      health_check_interval_s  How often the background checker runs (seconds)
      health_target            IP or hostname to ping
      latency_warn_ms          Latency above this marks the check "degraded"
      latency_crit_ms          Stored for reference / future alerting
      packet_loss_warn_pct     Loss % above this marks the check "degraded"
      health_alerts_enabled    "true" / "false"
      speed_test_url           URL for the download speed test
    """
    from models.tables import Setting

    defaults = {
        "health_check_interval_s": "300",
        "health_target":           "8.8.8.8",
        "latency_warn_ms":         "100",
        "latency_crit_ms":         "300",
        "packet_loss_warn_pct":    "10",
        "health_alerts_enabled":   "true",
        "speed_test_url":          "https://speed.cloudflare.com/__down?bytes=50000000",
        "uptime_stats_started_at": "",
        "uptime_total_checks":     "0",
        "uptime_online_checks":    "0",
        "uptime_degraded_checks":  "0",
        "uptime_offline_checks":   "0",
        "uptime_last_checked_at":  "",
        # AI settings — off by default; user must explicitly enable
        "ai_enabled":              "false",
        "ai_auto_analyze":         "false",
        # Traffic capture settings
        # capture_auto_start (Phase 4): when true and no explicit interface is
        # configured, NetMon picks the active adapter at startup and begins
        # capture automatically. Set to "false" to keep the old opt-in behavior.
        "capture_auto_start":      "false",
        "capture_enabled":         "false",
        "capture_interface":       "",
        "capture_file_size_mb":    "50",   # bumped from 10 for better incident windows
        "capture_file_count":      "10",   # bumped from 5 (~1GB ring at 100MB each)
        "capture_retention_days":  "3",
        "traffic_summary_interval_s": "20",
        # Incident pcap retention (Phase 4) — tagged snippets kept longer than ring.
        "incident_capture_enabled":   "true",
        "incident_retention_days":    "30",
        "health_local_target":        "",
        # Auto-scan settings
        "auto_scan_enabled":          "true",
        "auto_scan_interval_h":       "4",
        # Notification settings
        "ntfy_enabled":               "false",
        "ntfy_server":                "https://ntfy.sh",
        "ntfy_topic":                 "",
        "ntfy_user":                  "",
        "ntfy_pass":                  "",
        "email_enabled":              "false",
        "email_to":                   "",
        "smtp_host":                  "smtp.gmail.com",
        "smtp_port":                  "587",
        "smtp_user":                  "",
        "smtp_pass":                  "",
        # Anomaly detection
        "anomaly_detection_enabled":  "true",
        "anomaly_spike_multiplier":   "4.0",
        # Notification threshold — only push to phone when level >= this
        # "info" | "warning" | "action" | "critical"  (default: critical)
        "ntfy_min_level":             "critical",
        # Autonomous security reports (Qwen hourly analysis)
        "auto_report_enabled":        "true",
        # DNS Ad Blocker
        "dns_blocker_enabled":        "false",
        "dns_upstream":               "8.8.8.8",
        # Uptime Guardian (auto-heal) — off by default; dry-run until proven.
        # Router admin password should be set via the ROUTER_PASS env var or
        # the autoheal_router_pass setting (never committed to git).
        "autoheal_enabled":               "false",
        "autoheal_dry_run":               "true",
        "autoheal_interval_s":            "30",
        "autoheal_confirm_checks":        "3",
        "autoheal_reboot_method":         "netgear_soap",
        "autoheal_router_host":           "",          # blank → autodetected gateway
        "autoheal_router_user":           "admin",
        "autoheal_router_pass":           "",
        "autoheal_router_ssl":            "false",
        "autoheal_router_port":           "",
        "autoheal_internet_targets":      "8.8.8.8,1.1.1.1",
        "autoheal_max_reboots_per_outage": "1",
        "autoheal_cooldown_min":          "10",
        "autoheal_max_reboots_per_day":   "4",
        "autoheal_recovery_window_s":     "240",
    }

    db = SessionLocal()
    try:
        for key, value in defaults.items():
            exists = db.query(Setting).filter(Setting.key == key).first()
            if not exists:
                db.add(Setting(key=key, value=value))
        db.commit()
    finally:
        db.close()
