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


if __name__ == "__main__":
    unittest.main()
