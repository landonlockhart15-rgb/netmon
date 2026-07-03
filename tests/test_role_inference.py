"""
Focused unit tests for traffic/role_inference.py.

Run from the project root:
    python -m unittest tests/test_role_inference.py -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic.role_inference import infer_device_role


class TestRoleInference(unittest.TestCase):
    def test_user_agent_inference(self):
        # 1. Smart TV User-Agent
        act = {"http_requests": [{"ua": "Mozilla/5.0 (SmartTV; AppleTV; WebOS)"}]}
        self.assertEqual(infer_device_role("192.168.1.10", act, {}), "Smart TV")

        # 2. Work Laptop User-Agent
        act = {"http_requests": [{"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}]}
        self.assertEqual(infer_device_role("192.168.1.11", act, {}), "Work Laptop")

        # 3. Mobile Phone User-Agent
        act = {"http_requests": [{"ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"}]}
        self.assertEqual(infer_device_role("192.168.1.12", act, {}), "Mobile Phone")

        # 4. IoT Camera User-Agent
        act = {"http_requests": [{"ua": "Blink/1.0.0 (Camera)"}]}
        self.assertEqual(infer_device_role("192.168.1.13", act, {}), "IoT Camera")

    def test_domain_inference(self):
        # 1. Smart TV domains
        act = {"summary": {"top_domains": [{"domain": "netflix.com"}, {"domain": "roku.com"}]}}
        self.assertEqual(infer_device_role("192.168.1.14", act, {}), "Smart TV")

        # 2. Work Laptop domains
        act = {"summary": {"top_domains": [{"domain": "github.com"}, {"domain": "slack.com"}]}}
        self.assertEqual(infer_device_role("192.168.1.15", act, {}), "Work Laptop")

        # 3. IoT Camera domains
        act = {"summary": {"top_domains": [{"domain": "ring.com"}, {"domain": "blinkap.com"}]}}
        self.assertEqual(infer_device_role("192.168.1.16", act, {}), "IoT Camera")

        # 4. Gaming Console domains
        act = {"summary": {"top_domains": [{"domain": "playstation.net"}]}}
        self.assertEqual(infer_device_role("192.168.1.17", act, {}), "Gaming Console")

        # 5. Smart Home domains
        act = {"summary": {"top_domains": [{"domain": "tuya.com"}, {"domain": "kasa.tplink.com"}]}}
        self.assertEqual(infer_device_role("192.168.1.18", act, {}), "Smart Home Device")

    def test_flow_stats_inference(self):
        # 1. Smart TV flow: High volume + High packet sizes
        flow = {
            "destination_ports": [443, 443],
            "packet_lengths": [1200, 1300, 1400, 1400, 1400, 1100] * 50,  # > 200 packets, avg size > 700
            "ttls": [64],
            "window_sizes": [14600]
        }
        self.assertEqual(infer_device_role("192.168.1.19", {}, flow), "Smart TV")

        # 2. IoT Camera flow: Low volume + MQTT / SSL ports + 'cam' domain hint
        flow = {
            "destination_ports": [8883, 8883, 123],
            "packet_lengths": [100, 150, 90, 80],  # low volume (< 200 packets)
            "ttls": [64],
            "window_sizes": [1024]
        }
        act = {"summary": {"top_domains": [{"domain": "security-cam-api.net"}]}}
        self.assertEqual(infer_device_role("192.168.1.20", act, flow), "IoT Camera")

        # 3. Work Laptop flow: Windows TTL (128) + diverse ports (> 5 ports)
        flow = {
            "destination_ports": [80, 443, 22, 3389, 8080, 1433],
            "packet_lengths": [1500, 1200, 60, 60, 60] * 50,
            "ttls": [128],
            "window_sizes": [8192]
        }
        self.assertEqual(infer_device_role("192.168.1.21", {}, flow), "Work Laptop")

    def test_browser_header_inference(self):
        # Browser-style HTTP headers should tilt the ambiguous desktop/laptop case toward Work Laptop
        act = {
            "http_requests": [{
                "accept": "*/*",
                "accept_language": "en-US,en;q=0.9",
                "accept_encoding": "gzip, deflate, br",
                "referer": "https://mail.google.com/",
                "connection": "keep-alive",
            }],
        }
        flow = {
            "destination_ports": [443, 80],
            "packet_lengths": [900, 1100, 1200, 950],
            "ttls": [64],
            "window_sizes": [65535],
        }
        self.assertEqual(infer_device_role("192.168.1.24", act, flow), "Work Laptop")

    def test_fallback_inference(self):
        # 1. Hostname/IP hints fallback
        act = {"summary": {"top_domains": [{"domain": "work-laptop-lockhart.local"}]}}
        self.assertEqual(infer_device_role("192.168.1.22", act, {}), "Work Laptop")

        # 2. No matching info
        self.assertEqual(infer_device_role("192.168.1.23", {}, {}), "")

    def test_extract_flow_stats_validation(self):
        from traffic.role_inference import extract_flow_stats
        # Invalid/malicious IPs should immediately fail validation and return {}
        self.assertEqual(extract_flow_stats("invalid-ip"), {})
        self.assertEqual(extract_flow_stats("192.168.1.300"), {})
        self.assertEqual(extract_flow_stats("1.2.3.4; command_injection"), {})
        self.assertEqual(extract_flow_stats(None), {})

    def test_extract_flow_stats_parsing(self):
        from unittest.mock import patch
        from pathlib import Path
        from traffic.role_inference import extract_flow_stats

        with patch('traffic.role_inference.find_tool') as mock_find_tool, \
             patch('traffic.role_inference.get_readable_files') as mock_get_files, \
             patch('subprocess.run') as mock_run:
            
            mock_find_tool.return_value = "tshark"
            mock_get_files.return_value = [Path("dummy.pcap")]
            
            # Fields in order:
            # ip.ttl, tcp.window_size, tcp.flags.syn, tcp.flags.ack, tcp.dstport, udp.dstport, frame.len
            mock_run.return_value.stdout = (
                "64\t14600\t1\t0\t443\t\t1200\n"
                "64\t15000\t0\t1\t443\t\t60\n"
                "128\t\t\t\t\t53\t80\n"
                "64,64\t14600\t1\t0\t443,443\t\t1200\n"
            )
            
            stats = extract_flow_stats("192.168.1.10", max_files=1)
            
            self.assertEqual(stats["ttls"], [64, 64, 128, 64])
            self.assertEqual(stats["window_sizes"], [14600, 14600])  # only TCP SYN (syn=1, ack=0)
            self.assertEqual(stats["destination_ports"], [443, 443, 53, 443])
            self.assertEqual(stats["packet_lengths"], [1200, 60, 80, 1200])


if __name__ == "__main__":
    unittest.main()
