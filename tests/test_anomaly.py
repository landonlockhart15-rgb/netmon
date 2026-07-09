"""
Focused unit tests for monitoring/anomaly.py behavioral anomaly detection checks.

Run from the project root:
    python -m unittest tests/test_anomaly.py -v
"""
import os
import sys
import json
import unittest
import warnings
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

warnings.simplefilter("ignore", category=ResourceWarning)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.tables import Base, TrafficSummary, HealthCheck, Setting, Device, Scan, ScanDevice, ActivityLog
import monitoring.anomaly as anomaly


class TestAnomalyCooldown(unittest.TestCase):
    def setUp(self):
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        anomaly._COOLDOWNS = self._orig_cooldowns

    def test_cooldown_expired(self):
        key = "test_alert:192.168.1.5"
        # Initially not in cooldown, so it should be cooled down (ready to alert)
        self.assertTrue(anomaly._is_cooled_down(key, "traffic_spike"))

        # Stamp it
        anomaly._stamp(key)
        self.assertFalse(anomaly._is_cooled_down(key, "traffic_spike"))

        # Move the stamped time 31 minutes into the past
        anomaly._COOLDOWNS[key] = datetime.now(timezone.utc) - timedelta(minutes=31)
        self.assertTrue(anomaly._is_cooled_down(key, "traffic_spike"))

    def test_cooldown_not_expired_under_limit(self):
        key = "test_alert:192.168.1.5"
        anomaly._stamp(key)
        # Move the stamped time 29 minutes into the past (traffic_spike is 30 mins)
        anomaly._COOLDOWNS[key] = datetime.now(timezone.utc) - timedelta(minutes=29)
        self.assertFalse(anomaly._is_cooled_down(key, "traffic_spike"))

    def test_cooldown_custom_limits(self):
        key = "test_alert:192.168.1.5"
        anomaly._stamp(key)
        
        # 16 minutes in the past:
        # - port_scan (15 mins limit) -> should be expired (True)
        # - traffic_spike (30 mins limit) -> should NOT be expired (False)
        # - health_outage (10 mins limit) -> should be expired (True)
        anomaly._COOLDOWNS[key] = datetime.now(timezone.utc) - timedelta(minutes=16)
        self.assertTrue(anomaly._is_cooled_down(key, "port_scan"))
        self.assertFalse(anomaly._is_cooled_down(key, "traffic_spike"))
        self.assertTrue(anomaly._is_cooled_down(key, "health_outage"))


class TestNightTimeCheck(unittest.TestCase):
    @patch("monitoring.anomaly.datetime")
    def test_is_night(self, mock_datetime):
        from zoneinfo import ZoneInfo
        
        # Test daytime (e.g. 12:00 PM Central Time)
        mock_dt_day = datetime(2026, 6, 11, 12, 0, 0, tzinfo=ZoneInfo("America/Chicago"))
        mock_datetime.now.return_value = mock_dt_day
        self.assertFalse(anomaly._is_night())

        # Test nighttime (e.g. 23:00 PM Central Time)
        mock_dt_night = datetime(2026, 6, 11, 23, 0, 0, tzinfo=ZoneInfo("America/Chicago"))
        mock_datetime.now.return_value = mock_dt_night
        self.assertTrue(anomaly._is_night())


class TestTrafficSpikes(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()
        anomaly._COOLDOWNS = self._orig_cooldowns

    def test_insufficient_history(self):
        # With less than 5 rows, it should return []
        events = anomaly.check_traffic_spikes(self.session)
        self.assertEqual(events, [])

    def test_no_spike(self):
        # Add setting for threshold (e.g., 4.0)
        self.session.add(Setting(key="anomaly_spike_multiplier", value="4.0"))
        
        # Add 6 summaries where traffic is steady (10MB each)
        top_talkers_data = json.dumps([{"ip": "192.168.1.5", "bytes": 10000000}])
        for i in range(6):
            self.session.add(TrafficSummary(top_talkers=top_talkers_data))
        self.session.commit()

        events = anomaly.check_traffic_spikes(self.session)
        self.assertEqual(events, [])

    def test_spike_detected(self):
        self.session.add(Setting(key="anomaly_spike_multiplier", value="4.0"))
        
        # Add 5 summaries with baseline of 2MB
        baseline_talkers = json.dumps([{"ip": "192.168.1.5", "bytes": 2000000}])
        for i in range(5):
            self.session.add(TrafficSummary(top_talkers=baseline_talkers))
            
        # Add a spike in the latest summary: 10MB
        spike_talkers = json.dumps([{"ip": "192.168.1.5", "bytes": 10000000}])
        self.session.add(TrafficSummary(top_talkers=spike_talkers))
        self.session.commit()

        events = anomaly.check_traffic_spikes(self.session)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "traffic_spike")
        self.assertEqual(events[0]["ip"], "192.168.1.5")


class TestHealthOutage(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()
        anomaly._COOLDOWNS = self._orig_cooldowns

    def test_insufficient_history(self):
        events = anomaly.check_health_outage(self.session)
        self.assertEqual(events, [])

    def test_healthy(self):
        for i in range(3):
            self.session.add(HealthCheck(status="online", packet_loss=0.0, latency_ms=10.0))
        self.session.commit()
        events = anomaly.check_health_outage(self.session)
        self.assertEqual(events, [])

    def test_outage_detected(self):
        for i in range(3):
            self.session.add(HealthCheck(status="offline", packet_loss=50.0, latency_ms=100.0))
        self.session.commit()
        events = anomaly.check_health_outage(self.session)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "health_outage")
        self.assertIsNone(events[0]["ip"])
        self.assertEqual(events[0]["level"], "critical")


class TestSustainedBandwidth(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()
        anomaly._COOLDOWNS = self._orig_cooldowns

    def test_sustained_detected(self):
        # N = 6 summaries with 9,000,000 bytes for 192.168.1.5 (above floor of 8MB)
        talkers = json.dumps([{"ip": "192.168.1.5", "bytes": 9000000}])
        for i in range(6):
            self.session.add(TrafficSummary(top_talkers=talkers))
        self.session.commit()
        events = anomaly.check_sustained_bandwidth(self.session)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "sustained_bandwidth")
        self.assertEqual(events[0]["ip"], "192.168.1.5")


class TestDegradedHealth(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()
        anomaly._COOLDOWNS = self._orig_cooldowns

    def test_degraded_detected(self):
        # We need recent (rows[:5]) to have the degraded checks, and baseline (rows[5:]) to have the online ones.
        # Since the query orders by ID descending, the last added rows have higher IDs and will be in rows[:5].
        for i in range(25):
            self.session.add(HealthCheck(status="online", packet_loss=1.0, latency_ms=10.0))
        for i in range(5):
            self.session.add(HealthCheck(status="degraded", packet_loss=10.0, latency_ms=150.0))
        self.session.commit()

        events = anomaly.check_degraded_health(self.session)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "degraded_health")


class TestShadowDevices(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()
        anomaly._COOLDOWNS = self._orig_cooldowns

    def _scan(self, minutes_ago):
        scan = Scan(
            started_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
            status="complete",
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def test_brief_untrusted_device_absent_from_latest_scan(self):
        first = self._scan(20)
        latest = self._scan(5)
        shadow = Device(mac="02:11:22:33:44:55", hostname="phone", is_known=False)
        stable = Device(mac="00:11:22:33:44:55", hostname="router", is_known=True)
        self.session.add_all([shadow, stable])
        self.session.flush()
        self.session.add(ScanDevice(scan_id=first.id, device_id=shadow.id, ip="192.168.1.77"))
        self.session.add(ScanDevice(scan_id=latest.id, device_id=stable.id, ip="192.168.1.1"))
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "shadow_device")
        self.assertEqual(events[0]["ip"], "192.168.1.77")
        self.assertIn("appeared briefly", events[0]["body"])

    def test_mac_rotation_on_same_ip(self):
        scans = [self._scan(minutes) for minutes in (30, 20, 10)]
        for idx, scan in enumerate(scans):
            dev = Device(mac=f"02:11:22:33:44:{idx:02x}", hostname=f"mobile-{idx}", is_known=False)
            self.session.add(dev)
            self.session.flush()
            self.session.add(ScanDevice(scan_id=scan.id, device_id=dev.id, ip="192.168.1.88"))
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)

        rotation = [ev for ev in events if "MAC rotation" in ev["title"]]
        self.assertEqual(len(rotation), 1)
        self.assertEqual(rotation[0]["ip"], "192.168.1.88")
        self.assertIn("3 different MAC", rotation[0]["body"])


class TestPortScans(unittest.TestCase):
    def setUp(self):
        self._orig_cooldowns = anomaly._COOLDOWNS.copy()
        anomaly._COOLDOWNS.clear()

    def tearDown(self):
        anomaly._COOLDOWNS = self._orig_cooldowns

    def test_vertical_scan(self):
        with patch("monitoring.anomaly._is_this_machine", return_value=False), \
             patch("monitoring.anomaly.explain_protected_target", return_value=None), \
             patch("network.protection.explain_protected_target", return_value=None), \
             patch("network.protection.protected_ips", return_value=set()), \
             patch("traffic.interfaces.find_tool", return_value="tshark"), \
             patch("traffic.analyzer.get_readable_files", return_value=["dummy.pcapng"]), \
             patch("subprocess.run") as mock_run:
            
            # VERT_THRESHOLD = 20 distinct ports
            lines = []
            for port in range(1, 22):
                lines.append(f"192.168.1.15\t192.168.1.20\t{port}")
            stdout_output = "\n".join(lines)
            
            mock_proc = MagicMock()
            mock_proc.stdout = stdout_output
            mock_run.return_value = mock_proc

            events = anomaly.check_port_scans()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["type"], "port_scan")
            self.assertEqual(events[0]["ip"], "192.168.1.15")
            self.assertIn("probed 21 ports", events[0]["body"])

    def test_horizontal_scan(self):
        with patch("monitoring.anomaly._is_this_machine", return_value=False), \
             patch("monitoring.anomaly.explain_protected_target", return_value=None), \
             patch("network.protection.explain_protected_target", return_value=None), \
             patch("network.protection.protected_ips", return_value=set()), \
             patch("traffic.interfaces.find_tool", return_value="tshark"), \
             patch("traffic.analyzer.get_readable_files", return_value=["dummy.pcapng"]), \
             patch("subprocess.run") as mock_run:

            # HORIZ_THRESHOLD = 15 distinct hosts scanned
            lines = []
            for dst_last in range(10, 27):
                lines.append(f"192.168.1.15\t192.168.1.{dst_last}\t80")
            stdout_output = "\n".join(lines)

            mock_proc = MagicMock()
            mock_proc.stdout = stdout_output
            mock_run.return_value = mock_proc

            events = anomaly.check_port_scans()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["type"], "port_scan")
            self.assertEqual(events[0]["ip"], "192.168.1.15")
            self.assertIn("probed 17 distinct hosts", events[0]["body"])


if __name__ == "__main__":
    unittest.main()
