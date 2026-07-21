import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cve_hunter.executors.base import PROTOCOL_DATABASE, build_execution_spec
from cve_hunter.executors.database import execute_database_spec
from cve_hunter.status_codes import DB_ORACLE_SUCCESS
from cve_hunter.tools.tcp_capture import TcpCaptureSession, db_tcp_capture_enabled, start_tcp_capture


class TcpCaptureTests(unittest.TestCase):
    def test_db_tcp_capture_enabled_default_local_lab(self):
        with patch("cve_hunter.tools.tcp_capture.cfg", SimpleNamespace(run_mode="local_lab")):
            with patch.dict("os.environ", {}, clear=False):
                # ensure env var not forcing off
                import os

                os.environ.pop("DB_TCP_CAPTURE_ENABLED", None)
                self.assertTrue(db_tcp_capture_enabled())
        with patch("cve_hunter.tools.tcp_capture.cfg", SimpleNamespace(run_mode="plan_only")):
            import os

            os.environ.pop("DB_TCP_CAPTURE_ENABLED", None)
            self.assertFalse(db_tcp_capture_enabled())

    def test_start_tcp_capture_disabled(self):
        with patch("cve_hunter.tools.tcp_capture.db_tcp_capture_enabled", return_value=False):
            session = start_tcp_capture(host="127.0.0.1", port=5432, cve_id="CVE-2019-9193")
        self.assertFalse(session.enabled)
        self.assertEqual(session.pcap_path, "")

    def test_database_executor_attaches_pcap_fields(self):
        spec = build_execution_spec(
            protocol=PROTOCOL_DATABASE,
            engine="postgres",
            target="postgres://postgres:postgres@127.0.0.1:5432/postgres",
            trigger_sql=["SELECT 1;"],
            oracle={"type": "row_count", "min_rows": 1},
        )
        fake_session = TcpCaptureSession(
            pcap_path="data/cve/pcaps/.pending/2099-01-01/CVE-TEST_database_p5432.pcap",
            process=MagicMock(),
            interface=r"\Device\NPF_Loopback",
            bpf_filter="tcp port 5432",
            enabled=True,
        )
        fake_session.process.poll.return_value = None

        def fake_stop():
            fake_session.process = None
            return {
                "pcap_file_path": fake_session.pcap_path,
                "packet_count": 12,
                "capture_interface": fake_session.interface,
                "capture_filter": fake_session.bpf_filter,
                "capture_enabled": True,
                "capture_error": "",
            }

        fake_session.stop = fake_stop  # type: ignore

        cursor = MagicMock()
        cursor.description = (("?column?",),)
        cursor.fetchmany.return_value = [(1,)]
        cursor.rowcount = 1
        conn = MagicMock()

        with patch(
            "cve_hunter.executors.database.cfg",
            SimpleNamespace(run_mode="local_lab", target_allowlist=[], request_timeout=5),
        ):
            with patch("cve_hunter.tools.tcp_capture.start_tcp_capture", return_value=fake_session):
                with patch(
                    "cve_hunter.executors.database._connect",
                    return_value={"success": True, "connection": conn, "cursor": cursor},
                ):
                    with patch("cve_hunter.executors.database.time.sleep", return_value=None):
                        result = execute_database_spec(spec, {}, cve_id="CVE-2019-9193")

        self.assertEqual(result.get("pcap_file_path"), fake_session.pcap_path)
        self.assertEqual(result.get("packet_count"), 12)
        self.assertEqual(result.get("capture_filter"), "tcp port 5432")
        self.assertTrue(result.get("capture_enabled"))


if __name__ == "__main__":
    unittest.main()
