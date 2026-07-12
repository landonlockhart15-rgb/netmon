"""
Tests for monitoring/guest_mode.py (the Guest Mode safety-gate policy module)
and the /api/settings/guest-mode endpoints in api/routes.py.

Run from the project root:
    python -m pytest tests/test_guest_mode.py -q
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import get_db, Base
from models.tables import Setting

import monitoring.guest_mode as guest_mode


class TestGuestModePolicy(unittest.TestCase):
    """Unit tests for the pure is_guest_mode()/should_block() policy functions."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = Session()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_off_by_default(self):
        # No "guest_mode" row at all -> fail-safe OFF.
        self.assertFalse(guest_mode.is_guest_mode(self.db))

    def test_explicit_false(self):
        self.db.add(Setting(key="guest_mode", value="false"))
        self.db.commit()
        self.assertFalse(guest_mode.is_guest_mode(self.db))

    def test_explicit_true(self):
        self.db.add(Setting(key="guest_mode", value="true"))
        self.db.commit()
        self.assertTrue(guest_mode.is_guest_mode(self.db))

    def test_blocked_feature_blocked_when_on(self):
        self.db.add(Setting(key="guest_mode", value="true"))
        self.db.commit()
        for feature in ("mitm", "auto_scan", "active_discovery", "port_refresh",
                        "ssl_cert_scan", "deep_scan_ai", "hunt", "capture",
                        "incident_capture", "autoheal", "blocker", "dns_blocker",
                        "dhcp", "router_reboot", "router_firmware"):
            self.assertIn(feature, guest_mode.BLOCKED_FEATURES)
            self.assertTrue(guest_mode.should_block(feature, self.db), feature)

    def test_blocked_feature_not_blocked_when_off(self):
        self.db.add(Setting(key="guest_mode", value="false"))
        self.db.commit()
        self.assertFalse(guest_mode.should_block("auto_scan", self.db))

    def test_passive_feature_never_blocked(self):
        # health_check is passive/self-directed and must NEVER be blocked,
        # even with Guest Mode on.
        self.db.add(Setting(key="guest_mode", value="true"))
        self.db.commit()
        self.assertNotIn("health_check", guest_mode.BLOCKED_FEATURES)
        self.assertFalse(guest_mode.should_block("health_check", self.db))

    def test_unknown_feature_not_blocked(self):
        self.db.add(Setting(key="guest_mode", value="true"))
        self.db.commit()
        self.assertFalse(guest_mode.should_block("some_made_up_feature", self.db))

    def test_guard_raises_when_blocked(self):
        self.db.add(Setting(key="guest_mode", value="true"))
        self.db.commit()
        with self.assertRaises(guest_mode.GuestModeBlocked):
            guest_mode.guard("mitm", self.db)

    def test_guard_noop_when_not_blocked(self):
        self.db.add(Setting(key="guest_mode", value="false"))
        self.db.commit()
        guest_mode.guard("mitm", self.db)  # should not raise


class TestGuestModeAPI(unittest.TestCase):
    """Integration tests for GET/POST /api/settings/guest-mode."""

    def setUp(self):
        self.patch_auth = __import__("unittest.mock", fromlist=["patch"]).patch(
            "app.main.validate_session", return_value=True
        )
        self.patch_auth.start()

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.engine.dispose()
        self.patch_auth.stop()

    def test_get_default_is_false(self):
        resp = self.client.get("/api/settings/guest-mode")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["guest_mode"])
        self.assertIsInstance(data["blocked_features"], list)
        self.assertTrue(len(data["blocked_features"]) > 0)
        self.assertEqual(data["blocked_features"], sorted(data["blocked_features"]))
        self.assertEqual(data["suppressed"], data["blocked_features"])

    def test_post_true_then_get_reflects_it(self):
        resp = self.client.post("/api/settings/guest-mode", json={"enabled": True})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["guest_mode"])
        self.assertTrue(data["changed"])

        resp2 = self.client.get("/api/settings/guest-mode")
        self.assertTrue(resp2.json()["guest_mode"])

    def test_post_false_clears_it(self):
        self.client.post("/api/settings/guest-mode", json={"enabled": True})
        resp = self.client.post("/api/settings/guest-mode", json={"enabled": False})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["guest_mode"])
        self.assertTrue(data["changed"])

        resp2 = self.client.get("/api/settings/guest-mode")
        self.assertFalse(resp2.json()["guest_mode"])

    def test_post_same_value_reports_unchanged(self):
        self.client.post("/api/settings/guest-mode", json={"enabled": True})
        resp = self.client.post("/api/settings/guest-mode", json={"enabled": True})
        data = resp.json()
        self.assertTrue(data["guest_mode"])
        self.assertFalse(data["changed"])

    def test_post_bad_payload_does_not_500(self):
        # Missing "enabled" key entirely.
        resp = self.client.post("/api/settings/guest-mode", json={"foo": "bar"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["changed"])
        self.assertFalse(data["guest_mode"])

    def test_post_non_bool_enabled_does_not_500(self):
        resp = self.client.post("/api/settings/guest-mode", json={"enabled": "yes"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["changed"])

    def test_post_empty_body_does_not_500(self):
        resp = self.client.post("/api/settings/guest-mode")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["changed"])


class TestLayer2ActionGuards(unittest.TestCase):
    """The dangerous action entry points must refuse in Guest Mode even when
    reached directly (manual button / stray call), not only via the scheduler."""

    def test_run_scan_blocked_when_guest_mode_on(self):
        from unittest.mock import patch
        from scanner.runner import run_scan
        from monitoring.guest_mode import GuestModeBlocked
        with patch("monitoring.guest_mode.is_guest_mode_now", return_value=True):
            with self.assertRaises(GuestModeBlocked):
                run_scan("192.168.1.0/24", quick=True)

    def test_run_scan_passes_guard_when_guest_mode_off(self):
        # With Guest Mode off, run_scan must get PAST the guard. We force nmap
        # missing so it raises RuntimeError (not GuestModeBlocked) instead of
        # actually scanning.
        from unittest.mock import patch
        from monitoring.guest_mode import GuestModeBlocked
        import scanner.runner as runner
        with patch("monitoring.guest_mode.is_guest_mode_now", return_value=False), \
             patch("scanner.runner.find_nmap", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                runner.run_scan("192.168.1.0/24", quick=True)
            self.assertNotIsInstance(ctx.exception, GuestModeBlocked)

    def test_mitm_start_blocked_when_guest_mode_on(self):
        from unittest.mock import patch
        from traffic.mitm import MitmEngine
        with patch("monitoring.guest_mode.is_guest_mode_now", return_value=True):
            result = MitmEngine().start("eth0", ["192.168.1.50"], gateway_ip="192.168.1.1")
        self.assertEqual(result["status"], "guest_mode_blocked")

    def test_router_reboot_blocked_when_guest_mode_on(self):
        from unittest.mock import patch
        from network.router_reboot import reboot_router
        with patch("monitoring.guest_mode.is_guest_mode_now", return_value=True):
            result = reboot_router("192.168.1.1", "admin", "pw")
        self.assertFalse(result["success"])
        self.assertIn("Guest Mode", result["error"])


if __name__ == "__main__":
    unittest.main()
