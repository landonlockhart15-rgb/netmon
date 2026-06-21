"""
Focused unit tests for traffic/analyzer.py parsers and cleanup logic.

Run from the project root:
    python -m unittest tests/test_traffic_analyzer.py -v
"""
import os
import sys
import unittest
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic.analyzer import _is_private, _parse_conv_ip, _parse_phs, cleanup_old_captures


class PrivateIpCheck(unittest.TestCase):
    def test_rfc1918_private_ips(self):
        self.assertTrue(_is_private("192.168.1.1"))
        self.assertTrue(_is_private("10.0.0.5"))
        self.assertTrue(_is_private("172.16.4.1"))
        self.assertTrue(_is_private("172.31.255.255"))
        self.assertTrue(_is_private("127.0.0.1"))

    def test_public_and_invalid_ips(self):
        self.assertFalse(_is_private("8.8.8.8"))
        self.assertFalse(_is_private("1.1.1.1"))
        self.assertFalse(_is_private("172.15.255.255"))  # Out of RFC1918 172.16-31 range
        self.assertFalse(_is_private("172.32.0.1"))      # Out of range
        self.assertFalse(_is_private("invalid-ip"))
        self.assertFalse(_is_private(""))


class ParseConvIp(unittest.TestCase):
    def test_parse_valid_output(self):
        output = (
            "===================================================================\n"
            "IP Conversations\n"
            "Filter:<none>\n"
            "===================================================================\n"
            "192.168.1.5          <-> 8.8.8.8          10       1,000         5         500        15       1,500\n"
            "192.168.1.10         <-> 1.1.1.1           2         200         3         300         5         500\n"
        )
        res = _parse_conv_ip(output)
        self.assertEqual(len(res), 2)

        self.assertEqual(res[0]["ip_a"], "192.168.1.5")
        self.assertEqual(res[0]["ip_b"], "8.8.8.8")
        self.assertEqual(res[0]["total_packets"], 15)
        self.assertEqual(res[0]["total_bytes"], 1500)

        self.assertEqual(res[1]["ip_a"], "192.168.1.10")
        self.assertEqual(res[1]["ip_b"], "1.1.1.1")
        self.assertEqual(res[1]["total_packets"], 5)
        self.assertEqual(res[1]["total_bytes"], 500)

    def test_parse_invalid_or_empty(self):
        self.assertEqual(_parse_conv_ip(""), [])
        self.assertEqual(_parse_conv_ip("no conversations here"), [])


class ParsePhs(unittest.TestCase):
    def test_parse_valid_phs(self):
        output = (
            "===================================================================\n"
            "Protocol Hierarchy Statistics\n"
            "Filter: frames\n"
            "===================================================================\n"
            "eth    frames:1000 bytes:150000\n"
            "  ip    frames:1000 bytes:150000\n"
            "    tcp    frames:700 bytes:85000\n"
            "    udp    frames:300 bytes:65000\n"
            "      dns    frames:50 bytes:5000\n"
        )
        proto_counts, total_packets, total_bytes = _parse_phs(output)

        self.assertEqual(total_packets, 1000)
        self.assertEqual(total_bytes, 150000)
        self.assertEqual(proto_counts.get("TCP"), 700)
        self.assertEqual(proto_counts.get("UDP"), 300)
        self.assertEqual(proto_counts.get("DNS"), 50)

    def test_parse_empty(self):
        proto_counts, total_packets, total_bytes = _parse_phs("")
        self.assertEqual(proto_counts, {})
        self.assertEqual(total_packets, 0)
        self.assertEqual(total_bytes, 0)


class CleanupOldCaptures(unittest.TestCase):
    def test_cleanup_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a fresh file (mtime = now)
            fresh_file = temp_path / "ring_fresh.pcapng"
            fresh_file.write_text("dummy fresh")

            # Create an old file
            old_file = temp_path / "ring_old.pcapng"
            old_file.write_text("dummy old")

            # Set mtime of old file to 4 days ago
            four_days_ago = time.time() - (4 * 86400)
            os.utime(str(old_file), (four_days_ago, four_days_ago))

            # Run cleanup with 3 days retention
            removed_count = cleanup_old_captures(temp_path, retention_days=3)

            self.assertEqual(removed_count, 1)
            self.assertTrue(fresh_file.exists())
            self.assertFalse(old_file.exists())


class TestGetDeviceActivityValidation(unittest.TestCase):
    def test_get_device_activity_invalid_ip(self):
        from traffic.analyzer import get_device_activity
        # Invalid/malicious IPs should immediately fail validation
        expected_error = {"error": "Invalid IP address", "http_requests": [], "tls_sessions": [], "dns_queries": []}
        self.assertEqual(get_device_activity("invalid-ip"), expected_error)
        self.assertEqual(get_device_activity("192.168.1.300"), expected_error)
        self.assertEqual(get_device_activity("1.2.3.4; command_injection"), expected_error)
        self.assertEqual(get_device_activity(None), expected_error)


if __name__ == "__main__":
    unittest.main()

