"""
Focused unit tests for scanner/diff.py comparison and snapshot logic.

Run from the project root:
    python -m unittest tests/test_scanner_diff.py -v
"""
import os
import sys
import unittest
import json
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.diff import compute_diff, build_snapshot


class ComputeDiff(unittest.TestCase):
    def test_new_device(self):
        prev = {}
        curr = {
            1: {
                "device_id": 1,
                "ip": "192.168.1.50",
                "hostname": "new-laptop",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ports": set(),
                "name": "New Laptop",
            }
        }
        res = compute_diff(prev, curr)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["change_type"], "new_device")
        self.assertEqual(res[0]["device_id"], 1)
        self.assertEqual(res[0]["message"], "New Laptop appeared on the network")
        detail = json.loads(res[0]["detail"])
        self.assertEqual(detail["ip"], "192.168.1.50")
        self.assertEqual(detail["hostname"], "new-laptop")
        self.assertEqual(detail["mac"], "aa:bb:cc:dd:ee:ff")

    def test_device_missing(self):
        prev = {
            1: {
                "device_id": 1,
                "ip": "192.168.1.50",
                "hostname": "old-laptop",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ports": set(),
                "name": "Old Laptop",
            }
        }
        curr = {}
        res = compute_diff(prev, curr)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["change_type"], "device_missing")
        self.assertEqual(res[0]["device_id"], 1)
        self.assertEqual(res[0]["message"], "Old Laptop is no longer responding")
        detail = json.loads(res[0]["detail"])
        self.assertEqual(detail["last_ip"], "192.168.1.50")
        self.assertEqual(detail["last_hostname"], "old-laptop")
        self.assertEqual(detail["mac"], "aa:bb:cc:dd:ee:ff")

    def test_ip_changed(self):
        prev = {
            2: {
                "device_id": 2,
                "ip": "192.168.1.60",
                "hostname": "phone",
                "mac": "11:22:33:44:55:66",
                "ports": set(),
                "name": "Phone",
            }
        }
        curr = {
            2: {
                "device_id": 2,
                "ip": "192.168.1.70",
                "hostname": "phone",
                "mac": "11:22:33:44:55:66",
                "ports": set(),
                "name": "Phone",
            }
        }
        res = compute_diff(prev, curr)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["change_type"], "ip_changed")
        self.assertEqual(res[0]["message"], "Phone: IP changed 192.168.1.60 → 192.168.1.70")
        detail = json.loads(res[0]["detail"])
        self.assertEqual(detail["from"], "192.168.1.60")
        self.assertEqual(detail["to"], "192.168.1.70")

    def test_hostname_changed(self):
        prev = {
            2: {
                "device_id": 2,
                "ip": "192.168.1.60",
                "hostname": "phone-old",
                "mac": "11:22:33:44:55:66",
                "ports": set(),
                "name": "Phone",
            }
        }
        curr = {
            2: {
                "device_id": 2,
                "ip": "192.168.1.60",
                "hostname": "phone-new",
                "mac": "11:22:33:44:55:66",
                "ports": set(),
                "name": "Phone",
            }
        }
        # Both sides present -> should report
        res = compute_diff(prev, curr)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["change_type"], "hostname_changed")
        self.assertEqual(res[0]["message"], "Phone: hostname changed phone-old → phone-new")

        # One side None -> should skip
        prev[2]["hostname"] = None
        res_skipped = compute_diff(prev, curr)
        self.assertEqual(len(res_skipped), 0)

    def test_ports_changed(self):
        prev = {
            3: {
                "device_id": 3,
                "ip": "192.168.1.80",
                "hostname": "server",
                "mac": "99:88:77:66:55:44",
                "ports": {22, 80},
                "name": "Server",
            }
        }
        curr = {
            3: {
                "device_id": 3,
                "ip": "192.168.1.80",
                "hostname": "server",
                "mac": "99:88:77:66:55:44",
                "ports": {80, 443},
                "name": "Server",
            }
        }
        res = compute_diff(prev, curr)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["change_type"], "ports_changed")
        self.assertEqual(res[0]["message"], "Server: opened [443], closed [22]")
        detail = json.loads(res[0]["detail"])
        self.assertEqual(detail["opened"], [443])
        self.assertEqual(detail["closed"], [22])
        self.assertEqual(detail["prev_ports"], [22, 80])
        self.assertEqual(detail["curr_ports"], [80, 443])

        # Test both sides empty -> should skip
        prev[3]["ports"] = set()
        curr[3]["ports"] = set()
        res_skipped = compute_diff(prev, curr)
        self.assertEqual(len(res_skipped), 0)


class BuildSnapshot(unittest.TestCase):
    def test_build_snapshot_mapping(self):
        # Create a mock ScanDevice
        mock_sd = MagicMock()
        mock_sd.device_id = 42
        mock_sd.ip = "192.168.1.99"
        mock_sd.hostname = "my-host"
        mock_sd.ports_list = [22, 80, 443]

        # Create nested mock Device
        mock_dev = MagicMock()
        mock_dev.label = "Custom Label"
        mock_dev.mac = "aa:bb:cc:11:22:33"
        mock_sd.device = mock_dev

        snapshot = build_snapshot([mock_sd])

        self.assertIn(42, snapshot)
        snap = snapshot[42]
        self.assertEqual(snap["device_id"], 42)
        self.assertEqual(snap["ip"], "192.168.1.99")
        self.assertEqual(snap["hostname"], "my-host")
        self.assertEqual(snap["mac"], "aa:bb:cc:11:22:33")
        self.assertEqual(snap["ports"], {22, 80, 443})
        self.assertEqual(snap["name"], "Custom Label")


if __name__ == "__main__":
    unittest.main()
