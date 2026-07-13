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

    def test_extract_flow_stats_parsing_extended(self):
        from unittest.mock import patch
        from pathlib import Path
        from traffic.role_inference import extract_flow_stats

        with patch('traffic.role_inference.find_tool') as mock_find_tool, \
             patch('traffic.role_inference.get_readable_files') as mock_get_files, \
             patch('subprocess.run') as mock_run:
            
            mock_find_tool.return_value = "tshark"
            mock_get_files.return_value = [Path("dummy.pcap")]
            
            # Fields in order:
            # ip.ttl, tcp.window_size, tcp.flags.syn, tcp.flags.ack, tcp.dstport, udp.dstport, frame.len, ip.dst, frame.time_epoch
            mock_run.return_value.stdout = (
                "64\t14600\t1\t0\t443\t\t1200\t8.8.8.8\t1719999990.0\n"
                "64\t15000\t0\t1\t443\t\t60\t8.8.8.8\t1719999992.0\n"
                "128\t\t\t\t\t53\t80\t1.1.1.1\t1719999994.0\n"
                "64,64\t14600\t1\t0\t443,443\t\t1200\t8.8.8.8,8.8.8.8\t1719999996.0\n"
            )
            
            stats = extract_flow_stats("192.168.1.10", max_files=1)
            
            self.assertEqual(stats["ttls"], [64, 64, 128, 64])
            self.assertEqual(stats["window_sizes"], [14600, 14600])  # only TCP SYN (syn=1, ack=0)
            self.assertEqual(stats["destination_ports"], [443, 443, 53, 443])
            self.assertEqual(stats["packet_lengths"], [1200, 60, 80, 1200])
            self.assertEqual(stats["destination_ips"], ["8.8.8.8", "8.8.8.8", "1.1.1.1", "8.8.8.8"])
            self.assertEqual(stats["timestamps"], [1719999990.0, 1719999992.0, 1719999994.0, 1719999996.0])
            # 4 packets over 6 seconds duration = 4 / 6 = ~0.66667
            self.assertAlmostEqual(stats["packet_frequency"], 4 / 6.0)

    def test_infer_behavior_profile_robustness(self):
        from traffic.role_inference import infer_behavior_profile, infer_device_role
        
        # Test case: None and empty values
        res = infer_behavior_profile("192.168.1.1", None, None)
        self.assertEqual(res, "")
        
        # Test case: Non-dict inputs
        res2 = infer_behavior_profile("192.168.1.1", "invalid_activity", [1, 2, 3])
        self.assertEqual(res2, "")
        
        # Test case: Metadata keys are None
        bad_act = {
            "http_requests": None,
            "tls_sessions": None,
            "dns_queries": None,
            "summary": None
        }
        bad_flow = {
            "destination_ports": None,
            "packet_lengths": None,
            "ttls": None,
            "window_sizes": None
        }
        res3 = infer_behavior_profile("192.168.1.1", bad_act, bad_flow)
        self.assertEqual(res3, "")
        
        # Test case: Metadata keys contain non-dict elements or unexpected formats
        bad_act2 = {
            "http_requests": [None, 123, "string_ua", {"ua": 456}],
            "tls_sessions": [None, 123, {"sni": 456}],
            "dns_queries": [None, 123, {"domain": 456}],
            "summary": "not_a_dict"
        }
        bad_flow2 = {
            "destination_ports": [None, "not_a_port", 443],
            "packet_lengths": [None, "not_a_len", 1200],
            "ttls": [None, "not_a_ttl", 64],
            "window_sizes": [None, "not_a_win", 14600]
        }
        res4 = infer_behavior_profile("192.168.1.1", bad_act2, bad_flow2)
        # Should not crash, and might match flow rules or user-agents if they get parsed safely
        self.assertIsInstance(res4, str)

        # Test both aliases point to/do the same thing
        res_alias = infer_device_role("192.168.1.1", bad_act2, bad_flow2)
        self.assertEqual(res_alias, res4)

    def test_iot_sensor_inference(self):
        # 1. Domain based IoT Sensor
        act = {"summary": {"top_domains": [{"domain": "sensor-telemetry.weather.org"}]}}
        self.assertEqual(infer_device_role("192.168.1.50", act, {}), "IoT Sensor")

        # 2. Port based IoT Sensor (CoAP 5683/5684) + Small average packet length
        flow = {
            "destination_ports": [5683, 5683, 123],
            "packet_lengths": [60, 70, 65, 80],
            "ttls": [64],
            "window_sizes": [1024]
        }
        self.assertEqual(infer_device_role("192.168.1.51", {}, flow), "IoT Sensor")

        # 3. Frequency based IoT Sensor: low frequency (2 packets over 10 seconds = 0.2 Hz) + small packets
        flow = {
            "destination_ports": [443, 123],
            "packet_lengths": [100, 100],
            "destination_ips": ["1.2.3.4"],
            "packet_frequency": 0.2
        }
        self.assertEqual(infer_device_role("192.168.1.52", {}, flow), "IoT Sensor")

    def test_honeypot_inference(self):
        # 1. Domain based Honeypot
        act = {"summary": {"top_domains": [{"domain": "my-cowrie-honeypot.local"}]}}
        self.assertEqual(infer_device_role("192.168.1.60", act, {}), "Honeypot")

        # 2. Destination IP based Honeypot (dshield.org)
        flow = {
            "destination_ips": ["192.168.1.100", "dshield.org"],
            "destination_ports": [443],
            "packet_lengths": [100],
        }
        self.assertEqual(infer_device_role("192.168.1.61", {}, flow), "Honeypot")

    def test_large_stream_robustness(self):
        # Ensure behavior profile tests match expected activity labels for large packet streams.
        # Check IoT Camera with a large packet stream (e.g. 300 packets) still returns IoT Camera,
        # rather than Work Laptop, Smart TV, or empty string.
        flow = {
            "destination_ports": [8883, 8883] * 150,  # 300 packets
            "packet_lengths": [120, 150, 130] * 100,
            "ttls": [64] * 300,
        }
        act = {"summary": {"top_domains": [{"domain": "security-cam-api.net"}]}}
        self.assertEqual(infer_device_role("192.168.1.70", act, flow), "IoT Camera")

        # Check IoT Sensor with a large packet stream (e.g. 300 packets) still returns IoT Sensor.
        flow_sensor = {
            "destination_ports": [5683, 5683] * 150,  # 300 packets
            "packet_lengths": [80, 90, 85] * 100,
            "ttls": [64] * 300,
        }
        self.assertEqual(infer_device_role("192.168.1.71", {}, flow_sensor), "IoT Sensor")

    def test_destination_ips_type_error(self):
        # Verify that passing non-string elements inside destination_ips does NOT raise TypeError
        # and handles them gracefully.
        flow_none = {
            "destination_ips": [None],
            "packet_lengths": [100],
            "destination_ports": [443]
        }
        res = infer_device_role("192.168.1.80", {}, flow_none)
        self.assertIsInstance(res, str)

        flow_int = {
            "destination_ips": [123],
            "packet_lengths": [100],
            "destination_ports": [443]
        }
        res2 = infer_device_role("192.168.1.81", {}, flow_int)
        self.assertIsInstance(res2, str)

    def test_packet_frequency_boundaries(self):
        # 1. Very high frequency should not match the sensor heuristic (0.01 <= freq <= 5.0)
        flow_high = {
            "destination_ports": [80],
            "packet_lengths": [100],
            "packet_frequency": 1000000.0
        }
        self.assertNotEqual(infer_device_role("192.168.1.83", {}, flow_high), "IoT Sensor")

        # 2. Negative frequency should not match the sensor heuristic
        flow_neg = {
            "destination_ports": [80],
            "packet_lengths": [100],
            "packet_frequency": -1.0
        }
        self.assertNotEqual(infer_device_role("192.168.1.84", {}, flow_neg), "IoT Sensor")

        # 3. NaN frequency should not match the sensor heuristic
        flow_nan = {
            "destination_ports": [80],
            "packet_lengths": [100],
            "packet_frequency": float('nan')
        }
        self.assertNotEqual(infer_device_role("192.168.1.85", {}, flow_nan), "IoT Sensor")

    def test_extract_flow_stats_parsing_malformed_lines(self):
        from unittest.mock import patch
        from pathlib import Path
        from traffic.role_inference import extract_flow_stats

        with patch('traffic.role_inference.find_tool') as mock_find_tool, \
             patch('traffic.role_inference.get_readable_files') as mock_get_files, \
             patch('subprocess.run') as mock_run:
            
            mock_find_tool.return_value = "tshark"
            mock_get_files.return_value = [Path("dummy.pcap")]
            
            # Fields in order:
            # ip.ttl, tcp.window_size, tcp.flags.syn, tcp.flags.ack, tcp.dstport, udp.dstport, frame.len, ip.dst, frame.time_epoch
            mock_run.return_value.stdout = (
                "\n"  # empty line
                "\t\t\t\t\t\t\n"  # tabs but no values
                "not-an-int\tnot-an-int\t\t\tnot-a-port\tnot-a-port\tnot-a-len\t\tnot-a-timestamp\n"  # invalid types
                "64\t14600\t1\t0\t443\t\t1200\t8.8.8.8\t1719999990.0\n"
            )
            
            stats = extract_flow_stats("192.168.1.10", max_files=1)
            # Should skip malformed lines and parse the only valid line
            self.assertEqual(stats["ttls"], [64])
            self.assertEqual(stats["window_sizes"], [14600])
            self.assertEqual(stats["destination_ports"], [443])
            self.assertEqual(stats["packet_lengths"], [1200])
            self.assertEqual(stats["destination_ips"], ["8.8.8.8"])
            self.assertEqual(stats["timestamps"], [1719999990.0])
            self.assertEqual(stats["packet_frequency"], 0.0)


if __name__ == "__main__":
    unittest.main()
