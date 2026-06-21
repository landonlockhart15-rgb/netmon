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



if __name__ == "__main__":
    unittest.main()
