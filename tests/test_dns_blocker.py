"""
Focused unit tests for dns_blocker/blocklist.py parser and domain matching logic.

Run from the project root:
    python -m unittest tests/test_dns_blocker.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns_blocker.blocklist as blocklist


class ParseHosts(unittest.TestCase):
    def test_parse_hosts_valid(self):
        text = (
            "127.0.0.1 localhost\n"
            "0.0.0.0 badsite.com\n"
            "127.0.0.1 anotherbad.org  \n"
            "# comment line\n"
            "0.0.0.0 broadcasthost\n"
        )
        expected = {"badsite.com", "anotherbad.org"}
        self.assertEqual(blocklist._parse_hosts(text), expected)

    def test_parse_hosts_lowercases(self):
        text = "0.0.0.0 BADsite.COM"
        self.assertEqual(blocklist._parse_hosts(text), {"badsite.com"})


class ParseAdblock(unittest.TestCase):
    def test_parse_adblock_valid(self):
        text = (
            "! This is a comment\n"
            "# Another comment\n"
            "||badadserver.com^\n"
            "||another-bad-one.net\n"
            "simpledomain.com\n"
            "invalid_domain^^\n"  # Invalid domain character
        )
        expected = {"badadserver.com", "another-bad-one.net", "simpledomain.com"}
        self.assertEqual(blocklist._parse_adblock(text), expected)


class IsBlocked(unittest.TestCase):
    def setUp(self):
        self._orig_blocked = blocklist._blocked
        self._orig_whitelist = blocklist.WHITELIST.copy()

    def tearDown(self):
        blocklist._blocked = self._orig_blocked
        blocklist.WHITELIST = self._orig_whitelist

    def test_whitelist_priority(self):
        # Even if google.com is in blocked set, whitelist must take priority
        blocklist._blocked = {"google.com", "ads.google.com"}
        blocklist.WHITELIST = {"google.com"}
        self.assertFalse(blocklist.is_blocked("google.com"))
        self.assertFalse(blocklist.is_blocked("ads.google.com"))
        self.assertFalse(blocklist.is_blocked("sub.ads.google.com"))

    def test_blocklist_matching(self):
        blocklist._blocked = {"doubleclick.net", "malware.org"}
        blocklist.WHITELIST = set()

        # Direct match
        self.assertTrue(blocklist.is_blocked("doubleclick.net"))
        # Subdomain match
        self.assertTrue(blocklist.is_blocked("ads.doubleclick.net"))
        self.assertTrue(blocklist.is_blocked("sub.ads.doubleclick.net"))
        # Unrelated domain
        self.assertFalse(blocklist.is_blocked("google.com"))
        # Partial match should not trigger false positives
        self.assertFalse(blocklist.is_blocked("notdoubleclick.net"))


class RecordQueryAndStats(unittest.TestCase):
    def setUp(self):
        self._orig_stats = blocklist._stats.copy()

    def tearDown(self):
        blocklist._stats = self._orig_stats

    def test_record_query_stats(self):
        # Reset stats
        blocklist._stats["queries_today"] = 0
        blocklist._stats["blocked_today"] = 0
        blocklist._stats["top_blocked"] = {}

        blocklist.record_query("allowed.com", blocked=False)
        blocklist.record_query("blocked1.com", blocked=True)
        blocklist.record_query("blocked1.com", blocked=True)
        blocklist.record_query("blocked2.com", blocked=True)

        stats = blocklist.get_stats()
        self.assertEqual(stats["queries_today"], 4)
        self.assertEqual(stats["blocked_today"], 3)
        self.assertEqual(
            stats["top_blocked"],
            [
                {"domain": "blocked1.com", "count": 2},
                {"domain": "blocked2.com", "count": 1},
            ],
        )


class BlockingResolverThreatIntel(unittest.TestCase):
    @patch("dns_blocker.blocklist.is_whitelisted")
    @patch("ai.threat_intel.check_domain")
    @patch("ai.threat_intel.is_confirmed_malicious")
    @patch("dns_blocker.server._log_threat_intel_block")
    def test_resolve_threat_intel_hit(self, mock_log, mock_is_confirmed, mock_check_domain, mock_is_whitelisted):
        from dnslib import DNSRecord, RCODE
        from dns_blocker.server import BlockingResolver
        from ai.threat_intel import ThreatMatch

        mock_is_whitelisted.return_value = False

        match = ThreatMatch("urlhaus_hosts", "URLhaus Malware Host", "critical")
        mock_check_domain.return_value = [match]
        mock_is_confirmed.return_value = True

        resolver = BlockingResolver()
        request = DNSRecord.question("malicious-c2.com")
        
        class MockHandler:
            client_address = ("192.168.1.50", 12345)
        
        reply = resolver.resolve(request, MockHandler())
        
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        mock_log.assert_called_once()
        args, kwargs = mock_log.call_args
        self.assertEqual(args[0], "192.168.1.50")
        self.assertEqual(args[1], "malicious-c2.com")

    @patch("dns_blocker.blocklist.is_whitelisted")
    @patch("ai.threat_intel.check_domain")
    @patch("dns_blocker.server.bl.is_blocked")
    @patch("dns_blocker.server.DNSRecord.parse")
    def test_resolve_whitelisted_bypasses_threat_intel(self, mock_parse, mock_is_blocked, mock_check_domain, mock_is_whitelisted):
        from dnslib import DNSRecord, RCODE
        from dns_blocker.server import BlockingResolver

        mock_is_whitelisted.return_value = True
        mock_is_blocked.return_value = False

        resolver = BlockingResolver()
        request = DNSRecord.question("google.com")
        
        class MockHandler:
            client_address = ("192.168.1.50", 12345)
        
        with patch.object(request, "send") as mock_send:
            mock_send.return_value = b""
            mock_reply = DNSRecord()
            mock_reply.header.rcode = RCODE.NOERROR
            mock_parse.return_value = mock_reply
            
            reply = resolver.resolve(request, MockHandler())
            
            mock_check_domain.assert_not_called()
            self.assertEqual(reply.header.rcode, RCODE.NOERROR)

    @patch("monitoring.activity.write_log")
    @patch("monitoring.notifier.alert")
    @patch("app.database.SessionLocal")
    def test_log_threat_intel_block(self, mock_session, mock_notify, mock_write_log):
        from dns_blocker.server import _log_threat_intel_block
        from ai.threat_intel import ThreatMatch
        
        mock_session.return_value.query.return_value.join.return_value.filter.return_value.order_by.return_value.first.return_value = None

        match = ThreatMatch("urlhaus_hosts", "URLhaus Malware Host", "critical")
        
        _log_threat_intel_block("192.168.1.50", "malicious-c2.com", "URLhaus Malware Host (severity: critical)", [match])
        
        mock_write_log.assert_called_once_with(
            level="critical",
            category="threat",
            event="dns_threat_blocked",
            summary="Threat blocked: malicious-c2.com (from 192.168.1.50) — URLhaus Malware Host (severity: critical)",
            detail={
                "domain": "malicious-c2.com",
                "client_ip": "192.168.1.50",
                "hits": [{"feed": "urlhaus_hosts", "severity": "critical"}],
                "action": "blocked (NXDOMAIN)"
            },
            device_ip="192.168.1.50",
            device_id=None
        )
        
        mock_notify.assert_called_once_with(
            title="Threat Blocked: Malicious DNS Query",
            body="Client: 192.168.1.50\nDomain: malicious-c2.com\nThreat: URLhaus Malware Host (severity: critical)",
            level="critical",
            force_push=True
        )


if __name__ == "__main__":
    unittest.main()
