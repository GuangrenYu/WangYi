import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cve_hunter.executors.base import (
    PROTOCOL_DATABASE,
    PROTOCOL_KERNEL,
    build_execution_spec,
    execute_spec,
    infer_protocol,
)
from cve_hunter.executors.database import _evaluate_db_oracle, execute_database_spec
from cve_hunter.status_codes import (
    DB_ORACLE_SUCCESS,
    EXECUTION_POLICY_BLOCKED,
    PROTOCOL_UNSUPPORTED,
)
from cve_hunter.state import CVEState
from cve_hunter.verification import RequestExecutor, SuccessOracle


class DatabaseExecutorTests(unittest.TestCase):
    def test_infer_protocol_database_from_description(self):
        protocol = infer_protocol(
            is_http_vuln=False,
            vuln_type="SQL注入",
            description="MySQL privilege escalation via crafted query",
        )
        self.assertEqual(protocol, PROTOCOL_DATABASE)

    def test_infer_protocol_kernel_stays_interface_only(self):
        protocol = infer_protocol(is_http_vuln=False, vuln_type="本地提权", description="Linux kernel privilege escalation")
        self.assertEqual(protocol, PROTOCOL_KERNEL)

    def test_unsupported_protocol_execute_spec(self):
        result = execute_spec({"protocol": "kernel", "cve_id": "CVE-1"}, {})
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], PROTOCOL_UNSUPPORTED)

    def test_database_oracle_error_pattern(self):
        logs = [{"phase": "trigger_sql", "success": False, "error": "XPATH syntax error: '~root@localhost'", "rows": []}]
        oracle = _evaluate_db_oracle({"type": "error_pattern", "expect": "XPATH syntax error"}, logs)
        self.assertTrue(oracle["success"])
        self.assertEqual(oracle["status_code"], DB_ORACLE_SUCCESS)

    def test_database_plan_only_is_blocked(self):
        spec = build_execution_spec(
            protocol=PROTOCOL_DATABASE,
            engine="mysql",
            target="127.0.0.1:3306/test",
            trigger_sql=["SELECT 1"],
            oracle={"type": "error_pattern", "expect": "x"},
        )
        with patch("cve_hunter.executors.database.cfg", SimpleNamespace(run_mode="plan_only", target_allowlist=[], request_timeout=5)):
            result = execute_database_spec(spec, {}, cve_id="CVE-2024-1")
        self.assertTrue(result["policy_blocked"])
        self.assertEqual(result["status_code"], EXECUTION_POLICY_BLOCKED)

    def test_request_executor_routes_database_spec(self):
        candidate = {
            "execution_spec": {
                "protocol": "database",
                "engine": "mysql",
                "trigger_sql": ["SELECT 1"],
                "oracle": {"type": "error_pattern", "expect": "boom"},
            }
        }
        fake = {
            "success": True,
            "protocol": "database",
            "status_code": DB_ORACLE_SUCCESS,
            "oracle": {"success": True, "type": "error_pattern", "evidence": "boom"},
            "body": "boom",
            "logs": [{"phase": "trigger_sql", "success": False, "error": "boom"}],
            "request_success": True,
        }
        with patch("cve_hunter.verification.execute_spec", return_value=fake):
            with patch(
                "cve_hunter.verification.evaluate_execution_policy",
                return_value=SimpleNamespace(allowed=True, reason="", to_dict=lambda: {}),
            ):
                result = RequestExecutor().execute(
                    candidate,
                    {"target_url": "mysql://127.0.0.1:3306/test", "target_host": "127.0.0.1:3306"},
                    cve_id="CVE-2024-1",
                )
        self.assertTrue(result["success"])
        oracle = SuccessOracle().evaluate(
            state=CVEState(cve_id="CVE-2024-1"),
            candidate=candidate,
            result=result,
        )
        self.assertEqual(oracle["status"], "SUCCESS")
        self.assertEqual(oracle["status_code"], DB_ORACLE_SUCCESS)
        self.assertEqual(oracle["success_level"], "database_oracle")

    def test_auth_bypass_succeeds_on_nth_attempt(self):
        spec = build_execution_spec(
            protocol=PROTOCOL_DATABASE,
            engine="mysql",
            target="mysql://root:wrong@127.0.0.1:3306/",
            action="auth_bypass",
            auth_bypass={"username": "root", "password": "wrong", "max_attempts": 5},
            trigger_sql=["SELECT USER();"],
            oracle={"type": "auth_success"},
        )
        calls = {"n": 0}

        def fake_connect(engine, host, port, database, user, password):
            calls["n"] += 1
            # 前两次探测/失败，第三次成功
            if calls["n"] < 3:
                return {"success": False, "error": "Access denied for user 'root'@'%'"}
            cursor = MagicMock()
            cursor.description = (("USER()",),)
            cursor.fetchmany.return_value = [("root@%",)]
            cursor.rowcount = 1
            conn = MagicMock()
            return {"success": True, "connection": conn, "cursor": cursor}

        with patch("cve_hunter.executors.database.cfg", SimpleNamespace(run_mode="local_lab", target_allowlist=[], request_timeout=5)):
            with patch("cve_hunter.executors.database._connect", side_effect=fake_connect):
                result = execute_database_spec(spec, {}, cve_id="CVE-2012-2122")
        self.assertTrue(result["success"])
        self.assertEqual(result["status_code"], DB_ORACLE_SUCCESS)
        self.assertEqual(result["action"], "auth_bypass")
        self.assertIn("auth_bypass_success", result.get("body", ""))

    def test_auth_bypass_target_down(self):
        spec = build_execution_spec(
            protocol=PROTOCOL_DATABASE,
            engine="mysql",
            target="mysql://root:wrong@127.0.0.1:3306/",
            action="auth_bypass",
            auth_bypass={"username": "root", "password": "wrong", "max_attempts": 3},
            oracle={"type": "auth_success"},
        )
        with patch("cve_hunter.executors.database.cfg", SimpleNamespace(run_mode="local_lab", target_allowlist=[], request_timeout=5)):
            with patch(
                "cve_hunter.executors.database._connect",
                return_value={"success": False, "error": "Can't connect to MySQL server (10061)"},
            ):
                with patch("cve_hunter.executors.database.time.sleep", return_value=None):
                    result = execute_database_spec(spec, {}, cve_id="CVE-2012-2122")
        self.assertFalse(result["success"])
        self.assertEqual(result["status_code"], "目标不可达")

    def test_multi_session_oracle_result_contains(self):
        spec = build_execution_spec(
            protocol=PROTOCOL_DATABASE,
            engine="postgres",
            target="postgres://postgres:secret@127.0.0.1:5432/vulhub",
            action="multi_session",
            sessions=[
                {
                    "name": "attacker",
                    "user": "vulhub",
                    "password": "vulhub",
                    "database": "vulhub",
                    "schema_sql": ["CREATE TABLE marker(id int, note text);"],
                    "trigger_sql": [],
                },
                {
                    "name": "superuser",
                    "user": "postgres",
                    "password": "secret",
                    "database": "vulhub",
                    "trigger_sql": ["SELECT note FROM marker;"],
                },
            ],
            oracle={"type": "result_contains", "expect": "cve-2018-1058-triggered", "session": "superuser"},
        )

        def fake_connect(engine, host, port, database, user, password):
            cursor = MagicMock()
            if user == "postgres":
                cursor.description = (("note",),)
                cursor.fetchmany.return_value = [("cve-2018-1058-triggered",)]
                cursor.rowcount = 1
            else:
                cursor.description = None
                cursor.fetchmany.return_value = []
                cursor.rowcount = 0
            return {"success": True, "connection": MagicMock(), "cursor": cursor}

        with patch("cve_hunter.executors.database.cfg", SimpleNamespace(run_mode="local_lab", target_allowlist=[], request_timeout=5)):
            with patch("cve_hunter.executors.database._connect", side_effect=fake_connect):
                with patch("cve_hunter.executors.database.time.sleep", return_value=None):
                    result = execute_database_spec(spec, {}, cve_id="CVE-2018-1058")
        self.assertTrue(result["success"])
        self.assertEqual(result["status_code"], DB_ORACLE_SUCCESS)
        self.assertEqual(result["action"], "multi_session")


if __name__ == "__main__":
    unittest.main()
