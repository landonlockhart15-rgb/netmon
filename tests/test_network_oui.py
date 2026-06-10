"""
Focused unit tests for network/oui.py MAC-vendor offline lookup and parsing.

Run from the project root:
    python -m unittest tests/test_network_oui.py -v
"""
import csv
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import network.oui as oui


class TestNormalizePrefix(unittest.TestCase):
    def test_normalize_prefix(self):
        self.assertEqual(oui._normalize_prefix("aa:bb:cc:dd:ee:ff"), "AABBCC")
        self.assertEqual(oui._normalize_prefix("AA-BB-CC-DD-EE-FF"), "AABBCC")
        self.assertEqual(oui._normalize_prefix("AABBCCDDEEFF"), "AABBCC")
        self.assertEqual(oui._normalize_prefix("aabbcc"), "AABBCC")
        self.assertEqual(oui._normalize_prefix(""), "")
        self.assertEqual(oui._normalize_prefix(None), "")


class TestIsStale(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.close()
        self.path = Path(self.temp_file.name)

    def tearDown(self):
        if self.path.exists():
            os.remove(self.path)

    def test_missing_is_stale(self):
        non_existent = Path("non_existent_file_xyz")
        self.assertTrue(oui._is_stale(non_existent))

    def test_fresh_not_stale(self):
        # Freshly created file: modify time is now
        self.assertFalse(oui._is_stale(self.path))

    def test_old_is_stale(self):
        # Set modify time to 31 days ago
        old_time = time.time() - (31 * 86400)
        os.utime(self.path, (old_time, old_time))
        self.assertTrue(oui._is_stale(self.path))


class TestOuiDatabase(unittest.TestCase):
    def setUp(self):
        # Create a temporary file path for sqlite DB
        self.db_fd, self.db_path = tempfile.mkstemp()
        os.close(self.db_fd)
        self.db_path_obj = Path(self.db_path)
        
        # Save cache and patch db path
        self.orig_cache = oui._CACHE
        oui._CACHE = None
        self.patcher = patch("network.oui._OUI_DB_PATH", self.db_path_obj)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        oui._CACHE = self.orig_cache
        if self.db_path_obj.exists():
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_populate_and_load_cache(self):
        csv_data = (
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-L,00000A,OMRON Corporation,Kyoto\n"
            "MA-L,3CD0F6,Google LLC,Mountain View\n"
            "MA-L,invalid,Some Org,Address\n"
        )
        count = oui._populate_from_csv(csv_data, self.db_path_obj)
        self.assertEqual(count, 2)

        cache = oui._load_cache(self.db_path_obj)
        self.assertEqual(cache, {"00000A": "OMRON Corporation", "3CD0F6": "Google LLC"})

    def test_lookup_vendor(self):
        csv_data = (
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-L,3CD0F6,Google LLC,Mountain View\n"
        )
        oui._populate_from_csv(csv_data, self.db_path_obj)

        # First lookup: populates cache from file
        self.assertEqual(oui.lookup_vendor("3c:d0:f6:12:34:56"), "Google LLC")
        
        # Unknown lookup
        self.assertIsNone(oui.lookup_vendor("11:22:33:44:55:66"))
        
        # Invalid input
        self.assertIsNone(oui.lookup_vendor("123"))

    @patch("urllib.request.urlopen")
    def test_init_oui_db_success(self, mock_urlopen):
        # Mock successful network call
        mock_response = MagicMock()
        csv_data = (
            "Registry,Assignment,Organization Name\n"
            "MA-L,AABBCC,Test Vendor\n"
        ).encode("utf-8")
        mock_response.read.return_value = csv_data
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        # Force init
        refreshed = oui.init_oui_db(force=True, db_path=self.db_path_obj)
        self.assertTrue(refreshed)
        self.assertEqual(oui.lookup_vendor("AA:BB:CC:11:22:33"), "Test Vendor")

    @patch("urllib.request.urlopen")
    def test_init_oui_db_fail_silent(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Network Down")
        
        # Should not raise exception
        refreshed = oui.init_oui_db(force=True, db_path=self.db_path_obj)
        self.assertFalse(refreshed)


class TestEnrichVendor(unittest.TestCase):
    def setUp(self):
        self.orig_cache = oui._CACHE
        oui._CACHE = {"3CD0F6": "Google LLC"}

    def tearDown(self):
        oui._CACHE = self.orig_cache

    def test_enrich_vendor_keep_meaningful(self):
        self.assertEqual(oui.enrich_vendor("3c:d0:f6:12:34:56", "Google Inc"), "Google Inc")
        self.assertEqual(oui.enrich_vendor("3c:d0:f6:12:34:56", "MyCustomName"), "MyCustomName")

    def test_enrich_vendor_fallback(self):
        self.assertEqual(oui.enrich_vendor("3c:d0:f6:12:34:56", None), "Google LLC")
        self.assertEqual(oui.enrich_vendor("3c:d0:f6:12:34:56", ""), "Google LLC")
        self.assertEqual(oui.enrich_vendor("3c:d0:f6:12:34:56", "unknown"), "Google LLC")
        self.assertEqual(oui.enrich_vendor("3c:d0:f6:12:34:56", "  unknown  "), "Google LLC")


if __name__ == "__main__":
    unittest.main()
