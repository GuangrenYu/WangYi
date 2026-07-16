import unittest
from datetime import datetime
from pathlib import Path

from tools.local_http2pcap_service import _dated_output_path, _safe_capture_name, _target_host


class LocalHttp2PcapServiceTests(unittest.TestCase):
    def test_target_host_comes_from_raw_host_header(self):
        raw = "GET /poc HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
        self.assertEqual(_target_host(raw), "127.0.0.1")

    def test_target_url_is_used_when_host_header_is_missing(self):
        self.assertEqual(_target_host("GET / HTTP/1.1\r\n\r\n", "http://10.0.0.8:8080"), "10.0.0.8")

    def test_capture_name_sanitizes_untrusted_labels(self):
        name = _safe_capture_name("../../bad", "127.0.0.1:80")
        self.assertEqual(name, "capture.pcap")
        self.assertNotIn("..", name)
        self.assertTrue(name.endswith(".pcap"))

    def test_capture_name_only_contains_cve_id(self):
        self.assertEqual(_safe_capture_name("cve-2024-23334", "127.0.0.1"), "CVE-2024-23334.pcap")

    def test_capture_path_is_grouped_by_test_date(self):
        path = _dated_output_path(Path("data/cve/pcaps"), "capture.pcap", datetime(2026, 7, 15, 9, 30))
        self.assertEqual(path, Path("data/cve/pcaps/2026-07-15/capture.pcap"))


if __name__ == "__main__":
    unittest.main()
