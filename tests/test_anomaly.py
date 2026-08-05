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

from models.tables import Base, TrafficSummary, HealthCheck, Setting, Device, DHCPLeaseObservation, Scan, ScanDevice, ActivityLog
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

    def test_known_device_mac_change_triggers_identity_integrity_alert(self):
        first, latest = self._scan(20), self._scan(5)
        known = Device(mac="00:11:22:33:44:55", hostname="router", is_known=True)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", hostname="router", is_known=False)
        self.session.add_all([known, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=known.id, ip="192.168.1.1"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.1"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)

        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 1)
        self.assertIn("established device identity changed", integrity[0]["body"])
        # A known device is involved (the prior identity), so this escalates to critical.
        self.assertEqual(integrity[0]["level"], "critical")

    def test_oui_shift_on_same_ip_triggers_identity_integrity_alert(self):
        first, latest = self._scan(20), self._scan(5)
        original = Device(mac="00:11:22:33:44:55", is_known=False)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", is_known=False)
        self.session.add_all([original, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=original.id, ip="192.168.1.2"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.2"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)

        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 1)
        self.assertIn("hardware vendor prefix changed", integrity[0]["body"])
        # Neither device is known, so severity stays at warning.
        self.assertEqual(integrity[0]["level"], "warning")

    def test_identity_integrity_critical_when_latest_device_is_known(self):
        # The *latest* device (not the prior one) is the known/established identity
        # this time — severity should still escalate to critical.
        first, latest = self._scan(20), self._scan(5)
        original = Device(mac="00:11:22:33:44:55", is_known=False)
        known_now = Device(mac="aa:bb:cc:dd:ee:ff", hostname="router", is_known=True)
        self.session.add_all([original, known_now])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=original.id, ip="192.168.1.3"),
            ScanDevice(scan_id=latest.id, device_id=known_now.id, ip="192.168.1.3"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)

        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 1)
        self.assertEqual(integrity[0]["level"], "critical")

    def test_identity_integrity_body_includes_vendor_names(self):
        first, latest = self._scan(20), self._scan(5)
        known = Device(mac="00:11:22:33:44:55", hostname="router", is_known=True)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", hostname="router", is_known=False)
        self.session.add_all([known, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=known.id, ip="192.168.1.4"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.4"),
        ])
        self.session.commit()

        with patch("monitoring.anomaly.lookup_vendor") as mock_lookup:
            mock_lookup.side_effect = lambda mac: {
                "00:11:22:33:44:55": "VendorX",
                "aa:bb:cc:dd:ee:ff": "VendorY",
            }.get(mac)
            events = anomaly.check_shadow_devices(self.session)

        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 1)
        body = integrity[0]["body"]
        self.assertIn("00:11:22:33:44:55".upper(), body)
        self.assertIn("(VendorX)", body)
        self.assertIn("AA:BB:CC:DD:EE:FF", body)
        self.assertIn("(VendorY)", body)

    def test_identity_integrity_body_unknown_vendor_fallback(self):
        # When the OUI database has no match, the body should say "unknown"
        # rather than crash or show a stray None.
        first, latest = self._scan(20), self._scan(5)
        known = Device(mac="00:11:22:33:44:55", hostname="router", is_known=True)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", hostname="router", is_known=False)
        self.session.add_all([known, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=known.id, ip="192.168.1.5"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.5"),
        ])
        self.session.commit()

        with patch("monitoring.anomaly.lookup_vendor", return_value=None):
            events = anomaly.check_shadow_devices(self.session)

        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 1)
        self.assertIn("(unknown)", integrity[0]["body"])

    def test_oui_prefix_helper_directly(self):
        # Direct unit tests for _oui_prefix helper
        self.assertEqual(anomaly._oui_prefix("00:11:22:33:44:55"), "001122")
        self.assertEqual(anomaly._oui_prefix("AA-BB-CC-DD-EE-FF"), "AABBCC")
        self.assertEqual(anomaly._oui_prefix("aabbccddeeff"), "AABBCC")
        self.assertEqual(anomaly._oui_prefix("AA:bb:CC:dd:EE:ff"), "AABBCC")
        self.assertEqual(anomaly._oui_prefix(None), "")
        self.assertEqual(anomaly._oui_prefix(""), "")
        self.assertEqual(anomaly._oui_prefix("00:11"), "")
        self.assertEqual(anomaly._oui_prefix("00:11:22:33:44:55:66"), "")
        self.assertEqual(anomaly._oui_prefix("00:11:22:33:44:ZZ"), "")

    def test_identity_integrity_with_none_or_empty_mac(self):
        # Verify that None or empty MAC values do not cause crashes and do not trigger alerts
        first, latest = self._scan(20), self._scan(5)
        dev1 = Device(mac=None, is_known=True)
        dev2 = Device(mac="", is_known=False)
        self.session.add_all([dev1, dev2])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=dev1.id, ip="192.168.1.100"),
            ScanDevice(scan_id=latest.id, device_id=dev2.id, ip="192.168.1.100"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 0)

    def test_identity_integrity_mac_normalization_and_formatting(self):
        # Verify that different MAC formats and cases for the same OUI do not trigger OUI shift alerts
        # for unrecognized devices.
        first, latest = self._scan(20), self._scan(5)
        original = Device(mac="00:11:22:33:44:55", is_known=False)
        replacement = Device(mac="00-11-22-AA-BB-CC", is_known=False)
        self.session.add_all([original, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=original.id, ip="192.168.1.101"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.101"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 0)

    def test_identity_integrity_invalid_mac_prefix_boundaries(self):
        # Verify that malformed MAC addresses return empty OUI prefix and do not trigger OUI shift alerts
        first, latest = self._scan(20), self._scan(5)
        original = Device(mac="00:11:22", is_known=False)
        replacement = Device(mac="aa:bb:cc:dd:ee:fg", is_known=False)
        self.session.add_all([original, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=original.id, ip="192.168.1.102"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.102"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 0)

    def test_identity_integrity_chronological_ordering(self):
        # Verify that scans are ordered chronologically by started_at when detecting changes,
        # even if scan IDs are assigned/inserted out of chronological order.
        scan_c = Scan(started_at=datetime.now(timezone.utc) - timedelta(minutes=30), status="complete")
        scan_a = Scan(started_at=datetime.now(timezone.utc) - timedelta(minutes=20), status="complete")
        scan_b = Scan(started_at=datetime.now(timezone.utc) - timedelta(minutes=10), status="complete")
        
        self.session.add_all([scan_c, scan_a, scan_b])
        self.session.flush()
        
        known = Device(mac="00:11:22:33:44:55", is_known=True)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", is_known=False)
        self.session.add_all([known, replacement])
        self.session.flush()
        
        self.session.add_all([
            ScanDevice(scan_id=scan_c.id, device_id=known.id, ip="192.168.1.103"),
            ScanDevice(scan_id=scan_a.id, device_id=known.id, ip="192.168.1.103"),
            ScanDevice(scan_id=scan_b.id, device_id=replacement.id, ip="192.168.1.103"),
        ])
        self.session.commit()
        
        events = anomaly.check_shadow_devices(self.session)
        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity), 1)
        self.assertIn("established device identity changed", integrity[0]["body"])

    def test_delayed_import_of_older_scan_is_not_treated_as_current(self):
        # Import order is not scan order: an older result may be persisted only
        # after a newer scan has already completed.
        now = datetime.now(timezone.utc)
        current = Scan(started_at=now - timedelta(minutes=5), status="complete")
        delayed_old = Scan(started_at=now - timedelta(minutes=20), status="complete")
        known = Device(mac="00:11:22:33:44:55", is_known=True)
        prior = Device(mac="00:11:22:aa:bb:cc", is_known=False)
        self.session.add_all([current, known, delayed_old, prior])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=current.id, device_id=known.id, ip="192.168.1.105"),
            ScanDevice(scan_id=delayed_old.id, device_id=prior.id, ip="192.168.1.105"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)

        integrity = [event for event in events if "Identity integrity" in event["title"]]
        self.assertEqual(integrity, [])

    def test_identity_integrity_cooldown(self):
        # Verify that identity integrity alert respects the cooldown logic
        first, latest = self._scan(20), self._scan(5)
        known = Device(mac="00:11:22:33:44:55", is_known=True)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", is_known=False)
        self.session.add_all([known, replacement])
        self.session.flush()
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=known.id, ip="192.168.1.104"),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip="192.168.1.104"),
        ])
        self.session.commit()

        events1 = anomaly.check_shadow_devices(self.session)
        integrity1 = [event for event in events1 if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity1), 1)

        events2 = anomaly.check_shadow_devices(self.session)
        integrity2 = [event for event in events2 if "Identity integrity" in event["title"]]
        self.assertEqual(len(integrity2), 0)

    def test_untrusted_dhcp_client_absent_from_latest_scan_is_reported(self):
        now = datetime.now(timezone.utc)
        latest = Scan(status="complete", started_at=now)
        hidden = Device(mac="02:11:22:33:44:55", hostname="hidden-client", is_known=False)
        self.session.add_all([latest, hidden])
        self.session.flush()
        self.session.add(DHCPLeaseObservation(
            device_id=hidden.id, mac=hidden.mac, requested_ip="192.168.1.222",
            source_ip="0.0.0.0", message_type=3, observed_at=now,
        ))
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        lease_events = [event for event in events if "Hidden DHCP client" in event["title"]]
        self.assertEqual(len(lease_events), 1)
        self.assertEqual(lease_events[0]["ip"], "192.168.1.222")

    def test_orphaned_dhcp_lease_observation_does_not_crash(self):
        now = datetime.now(timezone.utc)
        latest = Scan(status="complete", started_at=now)
        self.session.add(latest)
        self.session.flush()
        # Add an observation with a non-existent device_id (9999)
        self.session.add(DHCPLeaseObservation(
            device_id=9999, mac="02:00:00:00:00:99", requested_ip="192.168.1.250",
            source_ip="0.0.0.0", message_type=3, observed_at=now,
        ))
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        # Should complete without raising AttributeError and return [] or valid events
        self.assertIsInstance(events, list)

    def test_orphaned_scan_device_does_not_crash(self):
        first = self._scan(20)
        latest = self._scan(5)
        stable = Device(mac="00:11:22:33:44:55", hostname="router", is_known=True)
        self.session.add(stable)
        self.session.flush()
        # ScanDevice pointing to a non-existent device_id 8888
        self.session.add(ScanDevice(scan_id=first.id, device_id=8888, ip="192.168.1.99"))
        self.session.add(ScanDevice(scan_id=latest.id, device_id=stable.id, ip="192.168.1.1"))
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        self.assertIsInstance(events, list)

    def test_mac_rotation_detection_triggers_warning_for_frequent_mac_changes(self):
        # 1 IP used by 3 different MAC addresses within 24h, 2 of which are locally administered (randomized)
        s1 = Scan(status="complete", started_at=datetime.now(timezone.utc) - timedelta(hours=3))
        s2 = Scan(status="complete", started_at=datetime.now(timezone.utc) - timedelta(hours=2))
        s3 = Scan(status="complete", started_at=datetime.now(timezone.utc) - timedelta(hours=1))
        self.session.add_all([s1, s2, s3])
        self.session.flush()

        dev1 = Device(mac="02:11:22:33:44:55", is_known=False)  # local (bit 0x02 set, OUI 021122)
        dev2 = Device(mac="02:11:22:33:44:66", is_known=False)  # local (bit 0x02 set, OUI 021122)
        dev3 = Device(mac="02:11:22:33:44:77", is_known=False)  # local (bit 0x02 set, OUI 021122)
        self.session.add_all([dev1, dev2, dev3])
        self.session.flush()

        ip = "192.168.1.180"
        self.session.add_all([
            ScanDevice(scan_id=s1.id, device_id=dev1.id, ip=ip),
            ScanDevice(scan_id=s2.id, device_id=dev2.id, ip=ip),
            ScanDevice(scan_id=s3.id, device_id=dev3.id, ip=ip),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        rot_events = [e for e in events if "MAC rotation" in e["title"]]
        self.assertEqual(len(rot_events), 1)
        self.assertEqual(rot_events[0]["ip"], ip)
        self.assertEqual(rot_events[0]["level"], "warning")
        self.assertIn("3 different MAC addresses", rot_events[0]["body"])

    def test_mac_rotation_skipped_when_identity_integrity_alert_already_fired(self):
        # When an identity integrity alert fires for an IP, MAC rotation should be suppressed for that IP
        first, latest = self._scan(20), self._scan(5)
        known = Device(mac="00:11:22:33:44:55", is_known=True)
        replacement = Device(mac="aa:bb:cc:dd:ee:ff", is_known=False)
        self.session.add_all([known, replacement])
        self.session.flush()
        ip = "192.168.1.181"
        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=known.id, ip=ip),
            ScanDevice(scan_id=latest.id, device_id=replacement.id, ip=ip),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        integrity = [e for e in events if "Identity integrity" in e["title"]]
        rotation = [e for e in events if "MAC rotation" in e["title"]]
        self.assertEqual(len(integrity), 1)
        self.assertEqual(len(rotation), 0)

    def test_mac_rotation_filtering_thresholds(self):
        # Fewer than 3 MACs for an IP should not trigger rotation alert
        s1, s2 = self._scan(20), self._scan(5)
        dev1 = Device(mac="02:11:22:33:44:55", is_known=False)
        dev2 = Device(mac="06:11:22:33:44:55", is_known=False)
        self.session.add_all([dev1, dev2])
        self.session.flush()
        ip = "192.168.1.182"
        self.session.add_all([
            ScanDevice(scan_id=s1.id, device_id=dev1.id, ip=ip),
            ScanDevice(scan_id=s2.id, device_id=dev2.id, ip=ip),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        rotation = [e for e in events if "MAC rotation" in e["title"]]
        self.assertEqual(len(rotation), 0)

    def test_dhcp_lease_message_types_filtering(self):
        # Message types 1 (DISCOVER), 3 (REQUEST), 8 (INFORM) should trigger passive detection,
        # while message types 2 (OFFER) or 5 (ACK) should be ignored.
        now = datetime.now(timezone.utc)
        latest = Scan(status="complete", started_at=now)
        dev_disc = Device(mac="02:11:22:33:44:01", is_known=False)
        dev_offer = Device(mac="02:11:22:33:44:02", is_known=False)
        dev_inform = Device(mac="02:11:22:33:44:08", is_known=False)
        self.session.add_all([latest, dev_disc, dev_offer, dev_inform])
        self.session.flush()

        self.session.add_all([
            DHCPLeaseObservation(device_id=dev_disc.id, mac=dev_disc.mac, requested_ip="192.168.1.201", message_type=1, observed_at=now),
            DHCPLeaseObservation(device_id=dev_offer.id, mac=dev_offer.mac, requested_ip="192.168.1.202", message_type=2, observed_at=now),
            DHCPLeaseObservation(device_id=dev_inform.id, mac=dev_inform.mac, requested_ip="192.168.1.208", message_type=8, observed_at=now),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        lease_ips = [e["ip"] for e in events if "Hidden DHCP client" in e["title"]]
        self.assertIn("192.168.1.201", lease_ips)
        self.assertNotIn("192.168.1.202", lease_ips)
        self.assertIn("192.168.1.208", lease_ips)

    def test_dhcp_lease_observation_with_missing_ip_falls_back_to_mac(self):
        now = datetime.now(timezone.utc)
        latest = Scan(status="complete", started_at=now)
        dev = Device(mac="02:aa:bb:cc:dd:ee", hostname=None, dhcp_hostname=None, is_known=False)
        self.session.add_all([latest, dev])
        self.session.flush()

        self.session.add(DHCPLeaseObservation(
            device_id=dev.id, mac=dev.mac, requested_ip=None,
            source_ip="0.0.0.0", message_type=3, observed_at=now,
        ))
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        lease_events = [e for e in events if "Hidden DHCP client" in e["title"]]
        self.assertEqual(len(lease_events), 1)
        self.assertIn("02:aa:bb:cc:dd:ee", lease_events[0]["title"])
        self.assertEqual(lease_events[0]["ip"], None)
        # Verify actions list contains only dismiss action when ip is None
        self.assertEqual(len(lease_events[0]["actions"]), 1)
        self.assertEqual(lease_events[0]["actions"][0]["label"], "Dismiss")

    def test_brief_shadow_device_disappeared_boundary_conditions(self):
        # Device appeared in 2 scans 25 mins ago, absent in latest scan 10 mins ago -> reported
        now = datetime.now(timezone.utc)
        s1 = Scan(status="complete", started_at=now - timedelta(minutes=35))
        s2 = Scan(status="complete", started_at=now - timedelta(minutes=10))
        latest = Scan(status="complete", started_at=now)
        shadow_dev = Device(mac="02:99:88:77:66:55", hostname="temp-phone", is_known=False)
        self.session.add_all([s1, s2, latest, shadow_dev])
        self.session.flush()

        self.session.add_all([
            ScanDevice(scan_id=s1.id, device_id=shadow_dev.id, ip="192.168.1.199"),
            ScanDevice(scan_id=s2.id, device_id=shadow_dev.id, ip="192.168.1.199"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        disappeared = [e for e in events if "Shadow device disappeared" in e["title"]]
        self.assertEqual(len(disappeared), 1)
        self.assertEqual(disappeared[0]["ip"], "192.168.1.199")

    def test_brief_shadow_device_disappeared_ignored_if_present_in_latest_scan(self):
        now = datetime.now(timezone.utc)
        s1 = Scan(status="complete", started_at=now - timedelta(minutes=10))
        latest = Scan(status="complete", started_at=now)
        active_dev = Device(mac="02:99:88:77:66:54", is_known=False)
        self.session.add_all([s1, latest, active_dev])
        self.session.flush()

        self.session.add_all([
            ScanDevice(scan_id=s1.id, device_id=active_dev.id, ip="192.168.1.198"),
            ScanDevice(scan_id=latest.id, device_id=active_dev.id, ip="192.168.1.198"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        disappeared = [e for e in events if "Shadow device disappeared" in e["title"]]
        self.assertEqual(len(disappeared), 0)

    def test_shadow_devices_empty_db_and_incomplete_scans(self):
        # When DB has no scans or only incomplete scans, check_shadow_devices returns empty list
        events_empty = anomaly.check_shadow_devices(self.session)
        self.assertEqual(events_empty, [])

        inc_scan = Scan(status="running", started_at=datetime.now(timezone.utc))
        self.session.add(inc_scan)
        self.session.commit()

        events_inc = anomaly.check_shadow_devices(self.session)
        self.assertEqual(events_inc, [])

    def test_is_locally_administered_mac_helper_comprehensive(self):
        # Test private/randomized MAC detection across formats and bit patterns
        self.assertTrue(anomaly._is_locally_administered_mac("02:00:00:00:00:00"))  # bit 1 set (2)
        self.assertTrue(anomaly._is_locally_administered_mac("06-00-00-00-00-00"))  # bit 1 set (6)
        self.assertTrue(anomaly._is_locally_administered_mac("0A:00:00:00:00:00"))  # bit 1 set (A = 10)
        self.assertTrue(anomaly._is_locally_administered_mac("0E:00:00:00:00:00"))  # bit 1 set (E = 14)
        self.assertFalse(anomaly._is_locally_administered_mac("00:11:22:33:44:55")) # OUI global (0)
        self.assertFalse(anomaly._is_locally_administered_mac("04:11:22:33:44:55")) # bit 1 not set
        self.assertFalse(anomaly._is_locally_administered_mac(None))
        self.assertFalse(anomaly._is_locally_administered_mac(""))
        self.assertFalse(anomaly._is_locally_administered_mac("invalid"))

    def test_identity_integrity_when_latest_device_is_known_and_same_oui(self):
        # Probe edge case: latest_row device is known, older_rows device is unknown, same OUI vendor.
        first, latest = self._scan(20), self._scan(5)
        unknown_older = Device(mac="00:11:22:33:44:55", is_known=False)
        known_latest = Device(mac="00:11:22:99:88:77", hostname="core-router", is_known=True)
        self.session.add_all([unknown_older, known_latest])
        self.session.flush()

        self.session.add_all([
            ScanDevice(scan_id=first.id, device_id=unknown_older.id, ip="192.168.1.25"),
            ScanDevice(scan_id=latest.id, device_id=known_latest.id, ip="192.168.1.25"),
        ])
        self.session.commit()

        events = anomaly.check_shadow_devices(self.session)
        integrity = [e for e in events if "Identity integrity" in e["title"]]
        # Note: older_macs values are all unknown, so established_identity_changed is False
        # and oui_shifted is False (same OUI prefix '001122'), meaning no integrity event is emitted.
        self.assertEqual(len(integrity), 0)




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
