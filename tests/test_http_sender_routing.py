import unittest
import tempfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.tools import http_sender


class HttpSenderRoutingTests(unittest.TestCase):
    def test_capture_output_path_uses_test_date(self):
        fake_cfg = SimpleNamespace(pcap_output_dir="data/cve/pcaps")
        with patch.object(http_sender, "cfg", fake_cfg):
            path = http_sender._capture_output_path("127.0.0.1", "CVE-2024-23334", datetime(2026, 7, 15, 9, 30))
        self.assertEqual(path, Path("data/cve/pcaps/.pending/2026-07-15/CVE-2024-23334.pcap"))

    def test_failed_capture_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pending = Path(tmp) / ".pending" / "2026-07-15" / "CVE-2024-23334.pcap"
            pending.parent.mkdir(parents=True)
            pending.write_bytes(b"pcap")
            fake_cfg = SimpleNamespace(pcap_output_dir=tmp)
            with patch.object(http_sender, "cfg", fake_cfg):
                result = http_sender.finalize_capture(str(pending), keep=False)
            self.assertEqual(result, "")
            self.assertFalse(pending.exists())

    def test_failed_retry_does_not_overwrite_existing_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            final = Path(tmp) / "2026-07-15" / "CVE-2024-23334.pcap"
            final.parent.mkdir(parents=True)
            final.write_bytes(b"successful capture")
            pending = Path(tmp) / ".pending" / "2026-07-15" / "CVE-2024-23334.pcap"
            pending.parent.mkdir(parents=True)
            pending.write_bytes(b"failed retry")
            fake_cfg = SimpleNamespace(pcap_output_dir=tmp)

            with patch.object(http_sender, "cfg", fake_cfg):
                result = http_sender.finalize_capture(str(pending), keep=False)

            self.assertEqual(result, "")
            self.assertFalse(pending.exists())
            self.assertEqual(final.read_bytes(), b"successful capture")

    def test_successful_capture_is_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            pending = Path(tmp) / ".pending" / "2026-07-15" / "CVE-2024-23334.pcap"
            pending.parent.mkdir(parents=True)
            pending.write_bytes(b"pcap")
            fake_cfg = SimpleNamespace(pcap_output_dir=tmp)
            with patch.object(http_sender, "cfg", fake_cfg):
                result = http_sender.finalize_capture(str(pending), keep=True)
            final = Path(tmp) / "2026-07-15" / "CVE-2024-23334.pcap"
            self.assertEqual(Path(result), final)
            self.assertTrue(final.is_file())

    def test_db_long_name_normalised_to_cve_pcap(self):
        """DB-path pending names like CVE-2012-2122_database_p3306_133439_if1.pcap
        must be promoted as CVE-2012-2122.pcap."""
        with tempfile.TemporaryDirectory() as tmp:
            pending = Path(tmp) / ".pending" / "2026-07-20" / "CVE-2012-2122_database_p3306_133439_if1.pcap"
            pending.parent.mkdir(parents=True)
            pending.write_bytes(b"x" * 1024)
            fake_cfg = SimpleNamespace(pcap_output_dir=tmp)
            with patch.object(http_sender, "cfg", fake_cfg):
                result = http_sender.finalize_capture(str(pending), keep=True)
            final = Path(tmp) / "2026-07-20" / "CVE-2012-2122.pcap"
            self.assertEqual(Path(result), final)
            self.assertTrue(final.is_file())
            self.assertFalse(pending.exists())

    def test_finalize_keeps_larger_on_collision(self):
        """If CVE.pcap already exists, the larger file wins."""
        with tempfile.TemporaryDirectory() as tmp:
            # Existing larger file
            final = Path(tmp) / "2026-07-20" / "CVE-2012-2122.pcap"
            final.parent.mkdir(parents=True)
            final.write_bytes(b"x" * 2048)
            # Smaller incoming pending
            pending = Path(tmp) / ".pending" / "2026-07-20" / "CVE-2012-2122_database_p3306_999999.pcap"
            pending.parent.mkdir(parents=True)
            pending.write_bytes(b"x" * 512)
            fake_cfg = SimpleNamespace(pcap_output_dir=tmp)
            with patch.object(http_sender, "cfg", fake_cfg):
                result = http_sender.finalize_capture(str(pending), keep=True)
            # Returns the existing (larger) path, incoming deleted
            self.assertEqual(Path(result), final)
            self.assertEqual(final.stat().st_size, 2048)
            self.assertFalse(pending.exists())

    def test_finalize_replaces_smaller_existing_on_collision(self):
        """If incoming pending is larger than existing CVE.pcap, incoming wins."""
        with tempfile.TemporaryDirectory() as tmp:
            # Existing smaller file
            final = Path(tmp) / "2026-07-20" / "CVE-2012-2122.pcap"
            final.parent.mkdir(parents=True)
            final.write_bytes(b"x" * 512)
            # Larger incoming pending
            pending = Path(tmp) / ".pending" / "2026-07-20" / "CVE-2012-2122_database_p3306_999999.pcap"
            pending.parent.mkdir(parents=True)
            pending.write_bytes(b"x" * 4096)
            fake_cfg = SimpleNamespace(pcap_output_dir=tmp)
            with patch.object(http_sender, "cfg", fake_cfg):
                result = http_sender.finalize_capture(str(pending), keep=True)
            self.assertEqual(Path(result), final)
            self.assertEqual(final.stat().st_size, 4096)
            self.assertFalse(pending.exists())

    def test_configured_service_handles_local_raw_target(self):
        raw = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
        fake_cfg = SimpleNamespace(http2pcap_url="http://127.0.0.1:3012")
        with (
            patch.object(http_sender, "cfg", fake_cfg),
            patch.object(http_sender, "_send_via_http2pcap", return_value={"success": True}) as remote,
            patch.object(http_sender, "_send_builtin") as builtin,
        ):
            result = http_sender.send_poc_and_capture(raw_http=raw)

        self.assertTrue(result["success"])
        remote.assert_called_once_with(raw, "")
        builtin.assert_not_called()

    def test_http2pcap_unreachable_falls_back_to_builtin(self):
        raw = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
        fake_cfg = SimpleNamespace(http2pcap_url="http://127.0.0.1:3012")
        with (
            patch.object(http_sender, "cfg", fake_cfg),
            patch.object(
                http_sender,
                "_send_via_http2pcap",
                return_value={"success": False, "error": "[WinError 10061] connection refused"},
            ) as remote,
            patch.object(
                http_sender,
                "_send_builtin",
                return_value={"success": True, "status_code": 200, "body": "ok"},
            ) as builtin,
        ):
            result = http_sender.send_poc_and_capture(raw_http=raw, target_url="http://127.0.0.1:8080")

        self.assertTrue(result["success"])
        self.assertTrue(result.get("http2pcap_fallback"))
        remote.assert_called_once()
        builtin.assert_called_once()

    def test_http2pcap_application_error_does_not_fallback(self):
        raw = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"
        fake_cfg = SimpleNamespace(http2pcap_url="http://127.0.0.1:3012")
        with (
            patch.object(http_sender, "cfg", fake_cfg),
            patch.object(
                http_sender,
                "_send_via_http2pcap",
                return_value={"success": False, "error": "target rejected payload", "status_code": 400},
            ) as remote,
            patch.object(http_sender, "_send_builtin") as builtin,
        ):
            result = http_sender.send_poc_and_capture(raw_http=raw)

        self.assertFalse(result["success"])
        remote.assert_called_once()
        builtin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
