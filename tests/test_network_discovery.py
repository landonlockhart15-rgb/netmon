"""
Unit tests for network/discovery.py functions.

Run from the project root:
    python -m unittest tests/test_network_discovery.py -v
"""
import os
import sys
import unittest
import struct
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.tables import Base, Device, ScanDevice
from network.discovery import (
    parse_dns_packet,
    _sanitize_string,
    _update_device_hostname,
    _update_device_vendor,
    _resolve_upnp_details,
)


class TestNetworkDiscovery(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def tearDown(self):
        self.session.close()

    def test_parse_dns_packet_empty(self):
        self.assertEqual(parse_dns_packet(b""), [])

    def test_parse_dns_packet_short(self):
        self.assertEqual(parse_dns_packet(b"\x00\x00\x00"), [])

    def test_parse_dns_packet_valid_ptr(self):
        header = b"\x12\x34\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
        qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        qtype_class = b"\x00\x0c\x00\x01"
        ans_name = b"\xc0\x0c"
        ans_type_class_ttl = b"\x00\x0c\x00\x01\x00\x00\x00\x78"
        rdata = b"\x09my-device\x05local\x00"
        rdlen = struct.pack("!H", len(rdata))
        packet = header + qname + qtype_class + ans_name + ans_type_class_ttl + rdlen + rdata

        names = parse_dns_packet(packet)
        self.assertIn("_services._dns-sd._udp.local", names)
        self.assertIn("my-device.local", names)

    def test_sanitize_string(self):
        # Control characters removal
        self.assertEqual(_sanitize_string("hello\x00world"), "helloworld")
        # HTML tag removal
        self.assertEqual(_sanitize_string("<b>Test</b> Device"), "Test Device")
        # Angle bracket removal
        self.assertEqual(_sanitize_string("<script>alert(1)</script>"), "alert(1)")
        # Truncation and whitespace normalization
        long_str = "a " * 100
        sanitized = _sanitize_string(long_str, max_len=10)
        self.assertEqual(len(sanitized), 9)  # "a a a a a" -> 9 characters
        # None handling
        self.assertEqual(_sanitize_string(None), "")

    def test_update_device_hostname(self):
        device = Device(mac="aa:bb:cc:dd:ee:ff", vendor="Unknown", hostname="")
        self.session.add(device)
        self.session.commit()
        device_id = device.id

        sd = ScanDevice(scan_id=1, device_id=device_id, ip="192.168.1.5")
        self.session.add(sd)
        self.session.commit()

        with patch("network.discovery.SessionLocal", return_value=self.session):
            _update_device_hostname("192.168.1.5", "My-Host", source="test")

        db = self.Session()
        device_db = db.query(Device).filter(Device.id == device_id).first()
        self.assertEqual(device_db.hostname, "My-Host")
        db.close()

    def test_update_device_vendor(self):
        device = Device(mac="aa:bb:cc:dd:ee:ff", vendor="Unknown", hostname="")
        self.session.add(device)
        self.session.commit()
        device_id = device.id

        sd = ScanDevice(scan_id=1, device_id=device_id, ip="192.168.1.5")
        self.session.add(sd)
        self.session.commit()

        with patch("network.discovery.SessionLocal", return_value=self.session):
            _update_device_vendor("192.168.1.5", "My-Vendor", source="test")

        db = self.Session()
        device_db = db.query(Device).filter(Device.id == device_id).first()
        self.assertEqual(device_db.vendor, "My-Vendor")
        db.close()

    @patch("urllib.request.urlopen")
    def test_resolve_upnp_details_valid(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"<root><device><friendlyName>My Cool Router</friendlyName><manufacturer>Netgear</manufacturer><modelName>R7000</modelName></device></root>"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        device = Device(mac="11:22:33:44:55:66", vendor="Unknown", hostname="")
        self.session.add(device)
        self.session.commit()
        device_id = device.id

        sd = ScanDevice(scan_id=1, device_id=device_id, ip="192.168.1.1")
        self.session.add(sd)
        self.session.commit()

        with patch("network.discovery.SessionLocal", return_value=self.session):
            _resolve_upnp_details("192.168.1.1", "http://192.168.1.1:8080/desc.xml")

        db = self.Session()
        device_db = db.query(Device).filter(Device.id == device_id).first()
        self.assertEqual(device_db.vendor, "Netgear R7000")
        self.assertEqual(device_db.hostname, "My Cool Router")
        db.close()

    @patch("urllib.request.urlopen")
    def test_resolve_upnp_details_ssrf_rejected(self, mock_urlopen):
        device = Device(mac="11:22:33:44:55:66", vendor="Unknown", hostname="")
        self.session.add(device)
        self.session.commit()
        device_id = device.id

        sd = ScanDevice(scan_id=1, device_id=device_id, ip="192.168.1.1")
        self.session.add(sd)
        self.session.commit()

        # Target hostname does not match the responding device's IP (e.g. AWS metadata endpoint)
        with patch("network.discovery.SessionLocal", return_value=self.session):
            _resolve_upnp_details("192.168.1.1", "http://169.254.169.254/latest/meta-data/")

        mock_urlopen.assert_not_called()
        db = self.Session()
        device_db = db.query(Device).filter(Device.id == device_id).first()
        self.assertEqual(device_db.vendor, "Unknown")
        db.close()

    @patch("urllib.request.urlopen")
    def test_resolve_upnp_details_scheme_rejected(self, mock_urlopen):
        # file:// protocol SSRF/arbitrary file read attempt
        with patch("network.discovery.SessionLocal", return_value=self.session):
            _resolve_upnp_details("192.168.1.1", "file:///etc/passwd")

        mock_urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
