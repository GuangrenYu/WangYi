import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.local_http2pcap_service import (
    _dated_output_path,
    _nuclei_findings,
    _pending_output_path,
    _run_nuclei_poc,
    _safe_capture_name,
    _target_host,
)


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

    def test_pending_capture_path_does_not_overwrite_successful_capture(self):
        path = _pending_output_path(
            Path("data/cve/pcaps"),
            "CVE-2024-23334.pcap",
            datetime(2026, 7, 15, 9, 30),
        )
        self.assertEqual(path, Path("data/cve/pcaps/.pending/2026-07-15/CVE-2024-23334.pcap"))

    def test_nuclei_findings_only_returns_json_objects(self):
        output = 'warning\n{"template-id":"CVE-2024-23334"}\n[]\n{"matched-at":"http://127.0.0.1"}'
        self.assertEqual(len(_nuclei_findings(output)), 2)

    def test_nuclei_poc_reports_local_match(self):
        template = """id: CVE-2024-23334
info:
  name: local test
  severity: high
http:
  - method: GET
    path:
      - '{{BaseURL}}/poc'
"""
        completed = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout='{"template-id":"CVE-2024-23334","status-code":200,"response":"HTTP/1.1 200 OK\\r\\n\\r\\nhit"}\n',
        )
        with (
            patch("tools.local_http2pcap_service._find_tool", return_value="nuclei") as find_tool,
            patch("tools.local_http2pcap_service.subprocess.run", return_value=completed) as run,
        ):
            result = _run_nuclei_poc(template, "http://127.0.0.1:8080")

        self.assertTrue(result["success"])
        self.assertTrue(result["matched"])
        self.assertEqual(result["status_code"], 200)
        self.assertIn("hit", result["body"])
        find_tool.assert_called_once_with("nuclei", "")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-u") + 1], "http://127.0.0.1:8080")
        self.assertIn("-no-interactsh", command)
        self.assertEqual(command[command.index("-pt") + 1], "http")

    def test_nuclei_poc_rejects_non_http_template(self):
        with self.assertRaisesRegex(ValueError, "仅执行包含 http 请求"):
            _run_nuclei_poc("id: local-test\ndns: []\n", "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
