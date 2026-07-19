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


if __name__ == "__main__":
    unittest.main()
