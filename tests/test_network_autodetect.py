"""
Focused unit tests for network/autodetect.py active adapter detection and CIDR parsing.

Run from the project root:
    python -m unittest tests/test_network_autodetect.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import network.autodetect as autodetect


class TestHelperMethods(unittest.TestCase):
    def test_cidr_from_mask(self):
        self.assertEqual(autodetect._cidr_from_mask("255.255.255.0"), 24)
        self.assertEqual(autodetect._cidr_from_mask("255.255.0.0"), 16)
        self.assertEqual(autodetect._cidr_from_mask("255.0.0.0"), 8)
        self.assertEqual(autodetect._cidr_from_mask("255.255.255.255"), 32)
        self.assertEqual(autodetect._cidr_from_mask("255.255.254.0"), 23)

    def test_network_addr(self):
        self.assertEqual(autodetect._network_addr("192.168.1.137", "255.255.255.0"), "192.168.1.0")
        self.assertEqual(autodetect._network_addr("10.5.12.99", "255.240.0.0"), "10.0.0.0")
        self.assertEqual(autodetect._network_addr("172.16.42.12", "255.255.0.0"), "172.16.0.0")

    def test_is_usable(self):
        self.assertTrue(autodetect._is_usable("192.168.1.1"))
        self.assertTrue(autodetect._is_usable("10.0.0.1"))
        self.assertTrue(autodetect._is_usable("172.16.0.1"))
        self.assertFalse(autodetect._is_usable("127.0.0.1"))
        self.assertFalse(autodetect._is_usable("169.254.5.5"))
        # CGNAT range (100.64.0.0 to 100.127.255.255)
        self.assertFalse(autodetect._is_usable("100.64.0.1"))
        self.assertFalse(autodetect._is_usable("100.100.5.5"))
        self.assertFalse(autodetect._is_usable("100.127.255.254"))
        self.assertTrue(autodetect._is_usable("100.128.0.1"))


class TestAutodetectSystemCalls(unittest.TestCase):
    def setUp(self):
        autodetect.invalidate_cache()

    def tearDown(self):
        autodetect.invalidate_cache()

    @patch("subprocess.check_output")
    def test_default_route_iface_ip(self, mock_subprocess):
        # Mock route print output
        mock_subprocess.return_value = (
            "===========================================================================\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.64     25\n"
            "===========================================================================\n"
        )
        self.assertEqual(autodetect._default_route_iface_ip(), "192.168.1.64")

    @patch("subprocess.check_output")
    def test_default_route_iface_ip_ignores_unusable(self, mock_subprocess):
        # Mock route print with CGNAT interface IP
        mock_subprocess.return_value = (
            "          0.0.0.0          0.0.0.0      100.64.0.1    100.64.0.2     25\n"
        )
        self.assertEqual(autodetect._default_route_iface_ip(), "")

    @patch("subprocess.check_output")
    def test_connected_iface_names(self, mock_subprocess):
        mock_subprocess.return_value = (
            "Admin State    State          Type             Interface Name\n"
            "-------------------------------------------------------------------------\n"
            "Enabled        Connected      Dedicated        Wi-Fi\n"
            "Enabled        Disconnected   Dedicated        Ethernet\n"
        )
        self.assertEqual(autodetect._connected_iface_names(), {"Wi-Fi"})


class TestGetNetworkInfo(unittest.TestCase):
    def setUp(self):
        autodetect.invalidate_cache()

    def tearDown(self):
        autodetect.invalidate_cache()

    @patch("subprocess.check_output")
    def test_get_network_info_parsing(self, mock_subprocess):
        # We need to mock ipconfig /all, route print, and netsh
        def side_effect(args, **kwargs):
            cmd = args[0]
            if cmd == "route":
                return (
                    "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25\n"
                )
            elif cmd == "netsh":
                return (
                    "Enabled        Connected      Dedicated        Wi-Fi\n"
                )
            elif cmd == "ipconfig":
                return (
                    "Windows IP Configuration\n\n"
                    "Ethernet adapter Ethernet:\n"
                    "   Media State . . . . . . . . . . . : Media disconnected\n\n"
                    "Wireless LAN adapter Wi-Fi:\n"
                    "   Connection-specific DNS Suffix  . :\n"
                    "   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6E AX211\n"
                    "   Physical Address. . . . . . . . . : 00-11-22-33-44-55\n"
                    "   DHCP Enabled. . . . . . . . . . . : Yes\n"
                    "   IPv4 Address. . . . . . . . . . . : 192.168.1.100(Preferred)\n"
                    "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                    "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
                )
            raise ValueError(f"Unexpected command: {args}")

        mock_subprocess.side_effect = side_effect

        info = autodetect.get_network_info()
        self.assertEqual(info["local_ip"], "192.168.1.100")
        self.assertEqual(info["gateway"], "192.168.1.1")
        self.assertEqual(info["subnet"], "192.168.1.0/24")
        self.assertEqual(info["interface"], "Wi-Fi")

    @patch("subprocess.check_output")
    def test_get_network_info_uses_ipv4_gateway_after_ipv6_continuation(self, mock_subprocess):
        def side_effect(args, **kwargs):
            cmd = args[0]
            if cmd == "route":
                return (
                    "          0.0.0.0          0.0.0.0      10.20.30.254    10.20.30.40     25\n"
                )
            if cmd == "netsh":
                return "Enabled        Connected      Dedicated        Ethernet\n"
            if cmd == "ipconfig":
                return (
                    "Windows IP Configuration\n\n"
                    "Ethernet adapter Ethernet:\n"
                    "   IPv4 Address. . . . . . . . . . . : 10.20.30.40(Preferred)\n"
                    "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                    "   Default Gateway . . . . . . . . . : fe80::1%12\n"
                    "                                       10.20.30.254\n"
                )
            raise ValueError(f"Unexpected command: {args}")

        mock_subprocess.side_effect = side_effect

        info = autodetect.get_network_info()
        self.assertEqual(info["gateway"], "10.20.30.254")


class TestGetScanTarget(unittest.TestCase):
    def setUp(self):
        autodetect.invalidate_cache()
        self.orig_env = os.getenv("SCAN_TARGET")

    def tearDown(self):
        autodetect.invalidate_cache()
        if self.orig_env is not None:
            os.environ["SCAN_TARGET"] = self.orig_env
        elif "SCAN_TARGET" in os.environ:
            del os.environ["SCAN_TARGET"]

    @patch("network.autodetect.get_network_info")
    def test_scan_target_explicit_env(self, mock_get_info):
        os.environ["SCAN_TARGET"] = "10.10.10.0/24"
        self.assertEqual(autodetect.get_scan_target(), "10.10.10.0/24")
        mock_get_info.assert_not_called()

    @patch("network.autodetect.get_network_info")
    def test_scan_target_autodetect(self, mock_get_info):
        os.environ["SCAN_TARGET"] = "auto"
        mock_get_info.return_value = {
            "local_ip": "192.168.1.5",
            "scan_target": "192.168.1.0/24"
        }
        self.assertEqual(autodetect.get_scan_target(), "192.168.1.0/24")


if __name__ == "__main__":
    unittest.main()
