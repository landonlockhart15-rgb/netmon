import os
import socket
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitoring.health import check_captive_portal, test_dns_resolution as dns_resolution_check


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


if __name__ == "__main__":
    unittest.main()
