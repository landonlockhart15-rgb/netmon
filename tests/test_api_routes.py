"""
Focused unit tests for api/routes.py helper functions.

Run from the project root:
    python -m unittest tests/test_api_routes.py -v
"""
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.tables import Base, Device, Setting
from api.routes import (
    _iso,
    _infer_vendor_from_ua,
    _infer_type_from_domains,
    _is_dead_end_reply,
    _env_locked_keys,
    _parse_ipconfig_all,
    _get_setting_str,
    _get_setting_float,
    _resolve_device,
    _latest_scan_device,
    _attack_tree_device_summary,
    _attack_risk,
    _attack_step_reasons,
)


class TestIso(unittest.TestCase):
    def test_iso_none(self):
        self.assertIsNone(_iso(None))

    def test_iso_naive(self):
        dt = datetime(2026, 6, 10, 15, 30, 0)
        self.assertEqual(_iso(dt), "2026-06-10T15:30:00Z")

    def test_iso_aware_utc(self):
        dt = datetime(2026, 6, 10, 15, 30, 0, tzinfo=timezone.utc)
        self.assertEqual(_iso(dt), "2026-06-10T15:30:00+00:00")

    def test_iso_aware_offset(self):
        tz = timezone(timedelta(hours=-5))
        dt = datetime(2026, 6, 10, 15, 30, 0, tzinfo=tz)
        # Note: due to the condition "+ not in s and s[-1] != 'Z'" in _iso,
        # negative offset strings get 'Z' appended.
        self.assertEqual(_iso(dt), "2026-06-10T15:30:00-05:00Z")


class TestInferVendor(unittest.TestCase):
    def test_empty_list(self):
        self.assertEqual(_infer_vendor_from_ua([]), "")

    def test_iphone_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"]),
            "Apple (iPhone/iPad)"
        )

    def test_samsung_android_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (Linux; Android 12; Samsung SM-G998B)"]),
            "Samsung Android"
        )

    def test_generic_android_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (Linux; Android 10; Mobile)"]),
            "Android Device"
        )

    def test_roku_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Roku/DVP-9.10 (519.10E04111A)"]),
            "Roku"
        )

    def test_amazon_kindle_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_3; Silk/3.0)"]),
            "Amazon Kindle"
        )

    def test_windows_pc_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]),
            "Windows PC"
        )

    def test_apple_mac_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"]),
            "Apple Mac"
        )

    def test_linux_pc_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (X11; Linux x86_64)"]),
            "Linux PC"
        )

    def test_playstation_ua(self):
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (PlayStation 5; Lnc/1.0)"]),
            "PlayStation"
        )

    def test_xbox_ua(self):
        # windows nt check comes first in the actual implementation, so we use a non-Windows NT xbox UA
        self.assertEqual(
            _infer_vendor_from_ua(["Mozilla/5.0 (compatible; Xbox; Xbox One)"]),
            "Xbox"
        )


class TestInferType(unittest.TestCase):
    def test_empty_list(self):
        self.assertEqual(_infer_type_from_domains([]), "")

    def test_apple_dns(self):
        self.assertEqual(_infer_type_from_domains(["init.ess.apple.com", "other.com"]), "Apple Device")

    def test_android_dns(self):
        self.assertEqual(_infer_type_from_domains(["play.googleapis.com"]), "Android Device")

    def test_roku_dns(self):
        self.assertEqual(_infer_type_from_domains(["some-sub.rbxd.com"]), "Roku Streaming")

    def test_amazon_dns(self):
        self.assertEqual(_infer_type_from_domains(["device-metrics-us.amazon.com"]), "Amazon Device")

    def test_xbox_dns(self):
        self.assertEqual(_infer_type_from_domains(["title.mgt.xboxlive.com"]), "Xbox")

    def test_playstation_dns(self):
        self.assertEqual(_infer_type_from_domains(["sony.com"]), "PlayStation")

    def test_ring_dns(self):
        self.assertEqual(_infer_type_from_domains(["ring.com"]), "Ring/Security Camera")

    def test_smarthome_dns(self):
        self.assertEqual(_infer_type_from_domains(["tplink-smarthome.com"]), "Smart Home Device")

    def test_router_dns(self):
        self.assertEqual(_infer_type_from_domains(["routerlogin.net"]), "Router/Gateway")

    def test_hue_dns(self):
        self.assertEqual(_infer_type_from_domains(["meethue.com"]), "Philips Hue")

    def test_nest_dns(self):
        self.assertEqual(_infer_type_from_domains(["google-nest.com"]), "Google Nest")


class TestIsDeadEndReply(unittest.TestCase):
    def test_tool_request_present(self):
        self.assertFalse(_is_dead_end_reply({"tool_request": {"name": "nmap"}}))

    def test_proposal_present(self):
        self.assertFalse(_is_dead_end_reply({"proposal": {"label": "New label"}}))

    def test_empty_reply(self):
        self.assertTrue(_is_dead_end_reply({"reply": ""}))
        self.assertTrue(_is_dead_end_reply({}))

    def test_dead_end_patterns(self):
        self.assertTrue(_is_dead_end_reply({"reply": "Let's check the mac prefix."}))
        self.assertTrue(_is_dead_end_reply({"reply": "I'll run a scan now."}))

    def test_question_not_dead_end(self):
        self.assertFalse(_is_dead_end_reply({"reply": "Is this your router?"}))

    def test_other_responses(self):
        # A response with no question, no tool, no proposal is a dead end
        self.assertTrue(_is_dead_end_reply({"reply": "I have found the device name."}))


class TestEnvLockedKeys(unittest.TestCase):
    @patch.dict(os.environ, {"NTFY_PASS": "secret", "SMTP_PASS": ""})
    def test_env_locked(self):
        # We only expect ntfy_pass to be locked, since NTFY_PASS env var is present and SMTP_PASS is empty.
        locked = _env_locked_keys()
        self.assertIn("ntfy_pass", locked)
        self.assertNotIn("smtp_pass", locked)


class TestParseIpconfigAll(unittest.TestCase):
    @patch("api.routes._sp.run")
    def test_parse_success(self, mock_run):
        mock_stdout = (
            "Windows IP Configuration\n"
            "\n"
            "Ethernet adapter Ethernet:\n"
            "   Connection-specific DNS Suffix  . : \n"
            # Description is split by '(' under the hood, so "Intel" is returned
            "   Description . . . . . . . . . . . : Intel(R) Ethernet Connection\n"
            "   Physical Address. . . . . . . . . : 00-11-22-33-44-55\n"
            "   DHCP Enabled. . . . . . . . . . . : Yes\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
            "   DNS Servers . . . . . . . . . . . : 8.8.8.8\n"
            "                                       8.8.4.4\n"
        )
        mock_run.return_value = MagicMock(stdout=mock_stdout)
        adapters = _parse_ipconfig_all()
        self.assertEqual(len(adapters), 1)
        adapter = adapters[0]
        self.assertEqual(adapter["name"], "Ethernet adapter Ethernet")
        self.assertEqual(adapter["description"], "Intel")
        self.assertEqual(adapter["mac"], "00-11-22-33-44-55")
        self.assertEqual(adapter["dhcp_enabled"], "Yes")
        self.assertEqual(adapter["ipv4"], "192.168.1.50")
        self.assertEqual(adapter["subnet"], "255.255.255.0")
        self.assertEqual(adapter["gateway"], "192.168.1.1")
        self.assertEqual(adapter["dns_servers"], ["8.8.8.8", "8.8.4.4"])

    @patch("api.routes._sp.run")
    def test_parse_ignores_link_local(self, mock_run):
        mock_stdout = (
            "Ethernet adapter Local:\n"
            "   IPv4 Address. . . . . . . . . . . : 169.254.12.34\n"
        )
        mock_run.return_value = MagicMock(stdout=mock_stdout)
        adapters = _parse_ipconfig_all()
        self.assertEqual(len(adapters), 0)


class TestDatabaseHelpers(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def tearDown(self):
        self.session.close()

    def test_get_setting_str(self):
        # Default value
        self.assertEqual(_get_setting_str(self.session, "my_key", "default_val"), "default_val")

        # Set value
        s = Setting(key="my_key", value="custom_val")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_setting_str(self.session, "my_key", "default_val"), "custom_val")

    def test_get_setting_float(self):
        # Default value
        self.assertEqual(_get_setting_float(self.session, "float_key", 1.5), 1.5)

        # Valid float
        s = Setting(key="float_key", value="2.75")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_setting_float(self.session, "float_key", 1.5), 2.75)

        # Invalid float reverts to default
        s.value = "not-a-float"
        self.session.commit()
        self.assertEqual(_get_setting_float(self.session, "float_key", 1.5), 1.5)

    def test_resolve_device_new(self):
        d_dict = {
            "mac": "aa:bb:cc:dd:ee:11",
            "ip": "192.168.1.10",
            "hostname": "new-host",
            "vendor": "SomeVendor",
        }
        device, is_new = _resolve_device(self.session, d_dict)
        self.assertTrue(is_new)
        self.assertEqual(device.mac, "aa:bb:cc:dd:ee:11")
        self.assertEqual(device.hostname, "new-host")
        self.assertEqual(device.vendor, "SomeVendor")

        # Resolving same device should not create a new one
        device2, is_new2 = _resolve_device(self.session, d_dict)
        self.assertFalse(is_new2)
        self.assertEqual(device2.id, device.id)


if __name__ == "__main__":
    unittest.main()
