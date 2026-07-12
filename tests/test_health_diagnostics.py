import os
import socket
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitoring.health import check_captive_portal, test_dns_resolution as dns_resolution_check
import monitoring.health as health


class TestHealthDiagnostics(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_generate_204_http_500_is_probe_error_not_captive_portal(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://connectivitycheck.gstatic.com/generate_204",
            500,
            "Internal Server Error",
            hdrs=None,
            fp=None,
        )

        result = check_captive_portal(
            urls=("http://connectivitycheck.gstatic.com/generate_204",),
            timeout=1.0,
        )

        self.assertFalse(result["captive"])
        self.assertEqual(result["status"], "unknown")
        self.assertIn("HTTP 500", result["error"])

    @patch("socket.getaddrinfo")
    def test_dns_resolution_restores_global_socket_default_timeout(self, mock_getaddrinfo):
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(12.5)
        try:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]

            result = dns_resolution_check(timeout=1.0)

            self.assertEqual(result["status"], "online")
            self.assertEqual(socket.getdefaulttimeout(), 12.5)
        finally:
            socket.setdefaulttimeout(original_timeout)


class TestCaptivePortalCache(unittest.TestCase):
    """Read-only cache wrapper around analyze_captive_portal_page — no submit path."""

    def setUp(self):
        self._original_cache = dict(health._CAPTIVE_PORTAL_CACHE)

    def tearDown(self):
        health._CAPTIVE_PORTAL_CACHE.clear()
        health._CAPTIVE_PORTAL_CACHE.update(self._original_cache)

    def test_get_cached_status_before_any_analysis(self):
        health._CAPTIVE_PORTAL_CACHE.update({"result": None, "checked_at": None})
        status = health.get_cached_captive_portal_status()
        self.assertEqual(status["status"], "unknown")
        self.assertFalse(status["captive"])
        self.assertIsNone(status["page"])
        self.assertIsNone(status["checked_at"])

    @patch("monitoring.health.analyze_captive_portal_page")
    def test_analyze_and_cache_populates_cache(self, mock_analyze):
        mock_analyze.return_value = {
            "status": "captive",
            "captive": True,
            "url": "http://connectivitycheck.gstatic.com/generate_204",
            "final_url": "http://portal.local/login",
            "http_status": 200,
            "error": None,
            "page": {"title": "Café Wifi", "form_count": 1, "fields": []},
        }

        result = health.analyze_and_cache_captive_portal()

        self.assertTrue(result["captive"])
        self.assertIsNotNone(result["checked_at"])
        mock_analyze.assert_called_once()

        # A subsequent status read reflects the cached result without probing again.
        cached = health.get_cached_captive_portal_status()
        self.assertEqual(cached["status"], "captive")
        self.assertEqual(cached["page"]["title"], "Café Wifi")
        self.assertEqual(mock_analyze.call_count, 1)

    def test_captive_portal_cache_never_exposes_a_submit_path(self):
        # Hard security boundary: no submit function should exist on the module.
        self.assertFalse(hasattr(health, "submit_captive_portal_form"))
        self.assertFalse(hasattr(health, "submit_captive_portal"))


if __name__ == "__main__":
    unittest.main()
