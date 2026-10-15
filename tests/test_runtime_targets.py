import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.runtime import as_target_url, normalize_target


class RuntimeTargetTests(unittest.TestCase):
    def test_normalize_target_preserves_port_from_url_and_host_port(self):
        self.assertEqual(normalize_target("http://10.55.1.21:7788"), "10.55.1.21:7788")
        self.assertEqual(normalize_target("10.55.1.21:7788"), "10.55.1.21:7788")

    def test_normalize_target_formats_ipv6(self):
        self.assertEqual(normalize_target("http://[2001:db8::1]:8443"), "[2001:db8::1]:8443")
        self.assertEqual(normalize_target("2001:db8::1"), "[2001:db8::1]")

    def test_as_target_url_uses_configured_default_port(self):
        with patch("cve_hunter.runtime.cfg", SimpleNamespace(target_port=7788)):
            self.assertEqual(as_target_url("10.55.1.21"), "http://10.55.1.21:7788")
            self.assertEqual(as_target_url("10.55.1.21:8080"), "http://10.55.1.21:8080")

    def test_normalize_target_can_fill_default_port_without_overriding_explicit(self):
        self.assertEqual(normalize_target("10.55.1.21", default_port=7788), "10.55.1.21:7788")
        self.assertEqual(normalize_target("10.55.1.21:80", default_port=7788), "10.55.1.21:80")

    def test_normalize_target_rejects_invalid_port_or_host(self):
        with self.assertRaises(ValueError):
            normalize_target("10.55.1.21:70000")
        with self.assertRaises(ValueError):
            normalize_target("example.test:7788")
