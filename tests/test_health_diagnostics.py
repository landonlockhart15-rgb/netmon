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


class TestAutohealCaptiveProbe(unittest.TestCase):
    """Internet-down + gateway-up should auto-probe for a captive portal once."""

    def setUp(self):
        import monitoring.autoheal as ah
        self.ah = ah
        self._saved = dict(ah._STATE)

    def tearDown(self):
        self.ah._STATE.clear()
        self.ah._STATE.update(self._saved)

    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_runs_once_when_gateway_up(self, mock_probe):
        mock_probe.return_value = {"captive": True, "page": {"title": "Hotel WiFi"},
                                   "final_url": "http://portal", "http_status": 200}
        self.ah._STATE["captive_probe_done"] = False
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})
        self.assertEqual(mock_probe.call_count, 1)
        self.assertTrue(self.ah._STATE["captive_probe_done"])

    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_skipped_when_gateway_down(self, mock_probe):
        self.ah._STATE["captive_probe_done"] = False
        self.ah._maybe_probe_captive_portal({"gateway_up": False, "internet_up": False})
        mock_probe.assert_not_called()
        self.assertFalse(self.ah._STATE["captive_probe_done"])

    @patch("monitoring.autoheal._emit")
    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_emits_captive_event_with_title(self, mock_probe, mock_emit):
        mock_probe.return_value = {
            "captive": True,
            "page": {"title": "Hotel Guest WiFi"},
            "final_url": "http://192.168.1.1/login.html",
            "http_status": 200,
        }
        self.ah._STATE["captive_probe_done"] = False
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})

        mock_emit.assert_called_once()
        args, kwargs = mock_emit.call_args
        self.assertEqual(args[0], self.ah.EV_CAPTIVE)
        self.assertEqual(args[1], "warning")
        self.assertIn('("Hotel Guest WiFi")', args[2])
        self.assertEqual(args[3]["final_url"], "http://192.168.1.1/login.html")
        self.assertEqual(args[3]["http_status"], 200)
        self.assertEqual(kwargs.get("notify"), False)

    @patch("monitoring.autoheal._emit")
    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_emits_captive_event_without_title(self, mock_probe, mock_emit):
        mock_probe.return_value = {
            "captive": True,
            "page": None,
            "final_url": "http://10.0.0.1/portal",
            "http_status": 302,
        }
        self.ah._STATE["captive_probe_done"] = False
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})

        mock_emit.assert_called_once()
        args = mock_emit.call_args[0]
        self.assertEqual(args[0], self.ah.EV_CAPTIVE)
        self.assertEqual(args[2], "Captive portal detected — a login page is intercepting traffic.")

    @patch("monitoring.autoheal._emit")
    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_handles_non_dict_page_gracefully(self, mock_probe, mock_emit):
        mock_probe.return_value = {
            "captive": True,
            "page": "invalid page payload",
            "final_url": "http://10.0.0.1/portal",
            "http_status": 200,
        }
        self.ah._STATE["captive_probe_done"] = False
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})

        mock_emit.assert_called_once()
        args = mock_emit.call_args[0]
        self.assertEqual(args[2], "Captive portal detected — a login page is intercepting traffic.")

    @patch("monitoring.autoheal._emit")
    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_does_not_emit_when_not_captive(self, mock_probe, mock_emit):
        mock_probe.return_value = {
            "captive": False,
            "status": "online",
            "page": None,
        }
        self.ah._STATE["captive_probe_done"] = False
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})

        mock_emit.assert_not_called()
        self.assertTrue(self.ah._STATE["captive_probe_done"])

    @patch("monitoring.health.analyze_and_cache_captive_portal")
    def test_probe_resilient_to_exceptions(self, mock_probe):
        mock_probe.side_effect = RuntimeError("Socket timeout during probing")
        self.ah._STATE["captive_probe_done"] = False

        # Should not raise exception
        self.ah._maybe_probe_captive_portal({"gateway_up": True, "internet_up": False})

        self.assertTrue(self.ah._STATE["captive_probe_done"])

    def test_state_clearing_resets_captive_probe(self):
        self.ah._STATE["captive_probe_done"] = True
        self.ah._clear_internet_outage_state()
        self.assertFalse(self.ah._STATE["captive_probe_done"])

        self.ah._STATE["captive_probe_done"] = True
        self.ah._reset_state()
        self.assertFalse(self.ah._STATE["captive_probe_done"])


if __name__ == "__main__":
    unittest.main()

