"""
Focused unit tests for monitoring/scheduler.py helper functions.

Run from the project root:
    python -m unittest tests/test_monitoring_scheduler.py -v
"""
import os
import sys
import unittest
import json
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
from models.tables import Base, Setting, ActivityLog, HealthCheck
from monitoring.scheduler import (
    _get_str,
    _get_float,
    _get_int,
    _netmon_enabled,
    _run_log_cleanup,
    _run_and_save,
    _get_active_discovery_settings,
)


class TestSchedulerHelpers(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def tearDown(self):
        self.session.close()

    def test_get_str(self):
        # Default value
        self.assertEqual(_get_str(self.session, "test_key", "default_val"), "default_val")

        # Set value
        s = Setting(key="test_key", value="custom_val")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_str(self.session, "test_key", "default_val"), "custom_val")

    def test_get_float(self):
        # Default value
        self.assertEqual(_get_float(self.session, "float_key", 3.14), 3.14)

        # Valid float
        s = Setting(key="float_key", value="5.55")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_float(self.session, "float_key", 3.14), 5.55)

        # Invalid float reverts to default
        s.value = "not-a-float"
        self.session.commit()
        self.assertEqual(_get_float(self.session, "float_key", 3.14), 3.14)

    def test_get_int(self):
        # Default value
        self.assertEqual(_get_int(self.session, "int_key", 42), 42)

        # Valid int
        s = Setting(key="int_key", value="100")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_int(self.session, "int_key", 42), 100)

        # Invalid int reverts to default
        s.value = "not-an-int"
        self.session.commit()
        self.assertEqual(_get_int(self.session, "int_key", 42), 42)

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_get_active_discovery_settings(self, mock_path):
        mock_path.read_text.side_effect = Exception("Not found")
        # Test default settings
        with patch("monitoring.scheduler.SessionLocal", return_value=self.session):
            interval, enabled = _get_active_discovery_settings()
            self.assertEqual(interval, 300)
            self.assertTrue(enabled)

        # Test custom interval and disabled
        self.session.add(Setting(key="active_discovery_interval_s", value="600"))
        self.session.add(Setting(key="active_discovery_enabled", value="false"))
        self.session.commit()
        with patch("monitoring.scheduler.SessionLocal", return_value=self.session):
            interval, enabled = _get_active_discovery_settings()
            self.assertEqual(interval, 600)
            self.assertFalse(enabled)

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_setting_disabled(self, mock_path):
        # Setting netmon_enabled to false
        s = Setting(key="netmon_enabled", value="false")
        self.session.add(s)
        self.session.commit()
        self.assertFalse(_netmon_enabled(self.session))

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_setting_enabled_no_maintenance(self, mock_path):
        # Setting netmon_enabled to true
        s = Setting(key="netmon_enabled", value="true")
        self.session.add(s)
        self.session.commit()

        # Maintenance file fails to read or has no services
        mock_path.read_text.side_effect = Exception("File not found")
        self.assertTrue(_netmon_enabled(self.session))

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_maintenance_disabled(self, mock_path):
        # Setting netmon_enabled to true
        s = Setting(key="netmon_enabled", value="true")
        self.session.add(s)
        self.session.commit()

        # Maintenance file says netmon is disabled
        mock_path.read_text.return_value = json.dumps({
            "services": {
                "netmon": {
                    "disabled": True
                }
            }
        })
        self.assertFalse(_netmon_enabled(self.session))

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_maintenance_not_disabled(self, mock_path):
        # Setting netmon_enabled to true
        s = Setting(key="netmon_enabled", value="true")
        self.session.add(s)
        self.session.commit()

        # Maintenance file says netmon is NOT disabled
        mock_path.read_text.return_value = json.dumps({
            "services": {
                "netmon": {
                    "disabled": False
                }
            }
        })
        self.assertTrue(_netmon_enabled(self.session))


class TestSchedulerRuns(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_run_log_cleanup(self):
        now = datetime.now(timezone.utc)
        
        # 1. DNS entry older than 7 days (should be deleted)
        dns_old = ActivityLog(
            category="dns",
            event="query",
            summary="dns query",
            created_at=now - timedelta(days=8)
        )
        # 2. DNS entry newer than 7 days (should be kept)
        dns_new = ActivityLog(
            category="dns",
            event="query",
            summary="dns query",
            created_at=now - timedelta(days=6)
        )
        # 3. General entry older than 30 days (should be deleted)
        gen_old = ActivityLog(
            category="traffic",
            event="spike",
            summary="traffic spike",
            created_at=now - timedelta(days=31)
        )
        # 4. General entry newer than 30 days (should be kept)
        gen_new = ActivityLog(
            category="traffic",
            event="spike",
            summary="traffic spike",
            created_at=now - timedelta(days=29)
        )
        
        self.session.add_all([dns_old, dns_new, gen_old, gen_new])
        self.session.commit()

        dns_old_id = dns_old.id
        dns_new_id = dns_new.id
        gen_old_id = gen_old.id
        gen_new_id = gen_new.id
        
        with patch("monitoring.scheduler.SessionLocal", self.Session):
            _run_log_cleanup()
            
        remaining = self.session.query(ActivityLog).all()
        remaining_ids = {r.id for r in remaining}
        
        self.assertNotIn(dns_old_id, remaining_ids)
        self.assertIn(dns_new_id, remaining_ids)
        self.assertNotIn(gen_old_id, remaining_ids)
        self.assertIn(gen_new_id, remaining_ids)
        self.assertEqual(len(remaining), 2)

    def test_run_and_save_basic(self):
        with patch("monitoring.health.run_ping") as mock_ping, \
             patch("network.autodetect.get_network_info") as mock_get_info, \
             patch("monitoring.scheduler.SessionLocal", self.Session), \
             patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE") as mock_maint:
            
            mock_ping.return_value = {
                "status": "online",
                "latency_ms": 12.0,
                "packet_loss": 0.0,
                "target": "8.8.8.8",
                "error": None
            }
            mock_get_info.return_value = {"gateway": "192.168.1.1"}
            mock_maint.read_text.side_effect = Exception("Not found")
            
            _run_and_save()

        hcs = self.session.query(HealthCheck).all()
        self.assertEqual(len(hcs), 1)
        self.assertEqual(hcs[0].status, "online")
        self.assertEqual(hcs[0].latency_ms, 12.0)
        self.assertEqual(hcs[0].local_target, "192.168.1.1")

    def test_run_and_save_pruning(self):
        # Insert 6 old health checks
        for i in range(6):
            self.session.add(HealthCheck(
                status="online",
                latency_ms=10.0,
                local_latency_ms=5.0,
                packet_loss=0.0,
                target="8.8.8.8",
                local_target="192.168.1.1"
            ))
        self.session.commit()

        with patch("monitoring.health.run_ping") as mock_ping, \
             patch("network.autodetect.get_network_info") as mock_get_info, \
             patch("monitoring.scheduler.SessionLocal", self.Session), \
             patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE") as mock_maint, \
             patch("monitoring.scheduler.MAX_ROWS", 5), \
             patch("monitoring.scheduler.KEEP_ROWS", 3):
            
            mock_ping.return_value = {
                "status": "online",
                "latency_ms": 12.0,
                "packet_loss": 0.0,
                "target": "8.8.8.8",
                "error": None
            }
            mock_get_info.return_value = {"gateway": "192.168.1.1"}
            mock_maint.read_text.side_effect = Exception("Not found")
            
            _run_and_save()

        hcs = self.session.query(HealthCheck).order_by(HealthCheck.id.asc()).all()
        self.assertEqual(len(hcs), 3)


if __name__ == "__main__":
    unittest.main()
