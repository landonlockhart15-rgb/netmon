"""
Unit tests for network/discovery.py functions.

Run from the project root:
    python -m unittest tests/test_network_discovery.py -v
"""
import os
import sys
import unittest
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network.discovery import parse_dns_packet

class TestNetworkDiscovery(unittest.TestCase):
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

if __name__ == "__main__":
    unittest.main()
