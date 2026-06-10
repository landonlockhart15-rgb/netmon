"""
Focused unit tests for network/geo.py offline IPv4 GeoIP lookup and device history.

Run from the project root:
    python -m unittest tests/test_network_geo.py -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.tables import Base, Device, DeviceCountryHistory
import network.geo as geo


class TestIpConversion(unittest.TestCase):
    def test_ip_to_int(self):
        self.assertEqual(geo._ip_to_int("192.168.1.1"), 3232235777)
        self.assertEqual(geo._ip_to_int("10.0.0.1"), 167772161)
        self.assertEqual(geo._ip_to_int("8.8.8.8"), 134744072)
        self.assertIsNone(geo._ip_to_int("invalid_ip"))
        self.assertIsNone(geo._ip_to_int("256.0.0.1"))

    def test_is_private(self):
        self.assertTrue(geo._is_private(geo._ip_to_int("192.168.1.100")))
        self.assertTrue(geo._is_private(geo._ip_to_int("10.5.5.5")))
        self.assertTrue(geo._is_private(geo._ip_to_int("172.16.0.25")))
        self.assertTrue(geo._is_private(geo._ip_to_int("127.0.0.1")))
        self.assertTrue(geo._is_private(geo._ip_to_int("169.254.10.10")))
        self.assertFalse(geo._is_private(geo._ip_to_int("8.8.8.8")))
        self.assertFalse(geo._is_private(geo._ip_to_int("1.1.1.1")))


class TestGeoDatabase(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.close(self.db_fd)
        self.db_path_obj = Path(self.db_path)
        
        self.orig_cache = geo._CACHE
        self.orig_db_path = geo._GEO_DB_PATH
        geo._CACHE = None
        geo._GEO_DB_PATH = self.db_path_obj

    def tearDown(self):
        geo._CACHE = self.orig_cache
        geo._GEO_DB_PATH = self.orig_db_path
        if self.db_path_obj.exists():
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_connect_and_update_metadata(self):
        conn = geo._connect(self.db_path_obj)
        self.assertIsNotNone(conn)
        try:
            self.assertIsNone(geo._last_updated(conn))
            geo._mark_updated(conn)
            lu = geo._last_updated(conn)
            self.assertIsNotNone(lu)
            self.assertIsInstance(lu, datetime)
        finally:
            conn.close()

    @patch("urllib.request.urlopen")
    def test_init_geo_db_and_lookup(self, mock_urlopen):
        # Mock GeoIP CSV Response:
        # start_int, end_int, country_code
        csv_data = (
            "134744064,134744079,US\n"  # US range including 8.8.8.8
            "16843008,16843023,AU\n"    # AU range
        ).encode("utf-8")
        
        mock_response = MagicMock()
        mock_response.read.return_value = csv_data
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        # Initialize Geo DB
        refreshed = geo.init_geo_db(force=True)
        self.assertTrue(refreshed)

        # Query ranges
        self.assertEqual(geo.country_for_ip("8.8.8.8"), "US")
        self.assertEqual(geo.country_for_ip("1.1.1.1"), "AU")
        
        # Test private IP lookup
        self.assertIsNone(geo.country_for_ip("192.168.1.1"))
        
        # Test unknown IP lookup
        self.assertIsNone(geo.country_for_ip("200.200.200.200"))


class TestDeviceHistory(unittest.TestCase):
    @classmethod
    def setUpClassClass(cls):
        pass

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        
        # Insert a dummy device
        self.device = Device(mac="aa:bb:cc:dd:ee:ff", label="Test Device")
        self.session.add(self.device)
        self.session.commit()

    def tearDown(self):
        self.session.close()

    def test_is_unusual_destination(self):
        # No history initially
        self.assertTrue(geo.is_unusual_destination(self.device.id, "US", self.session))

        # Add history
        history = DeviceCountryHistory(
            device_id=self.device.id,
            country="US",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            total_bytes=100
        )
        self.session.add(history)
        self.session.commit()

        # Now it should not be unusual
        self.assertFalse(geo.is_unusual_destination(self.device.id, "US", self.session))
        # Another country should still be unusual
        self.assertTrue(geo.is_unusual_destination(self.device.id, "FR", self.session))

    def test_record_device_country(self):
        # 1. New country record
        geo.record_device_country(self.device.id, "DE", self.session, bytes_added=500)
        self.session.commit()

        records = self.session.query(DeviceCountryHistory).filter_by(device_id=self.device.id, country="DE").all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].total_bytes, 500)

        # 2. Update existing country record
        geo.record_device_country(self.device.id, "DE", self.session, bytes_added=250)
        self.session.commit()

        records = self.session.query(DeviceCountryHistory).filter_by(device_id=self.device.id, country="DE").all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].total_bytes, 750)


if __name__ == "__main__":
    unittest.main()
