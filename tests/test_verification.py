import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.state import CVEState
from cve_hunter.status_codes import CAPTURE_SUCCESS, EXECUTION_POLICY_BLOCKED, TARGET_ORACLE_SUCCESS
from cve_hunter.verification import RequestExecutor, SuccessOracle, evaluate_success, evaluate_target_oracle


class VerificationTests(unittest.TestCase):
    def test_response_contains_oracle_success(self):
        result = evaluate_target_oracle(
            {"type": "response_contains", "markers": ["root:"], "case_sensitive": False},
            {"success": True, "status_code": 200, "body": "root:x:0:0"},
        )

        self.assertTrue(result["evaluated"])
        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "response_contains")

    def test_success_oracle_prefers_ips_cve_match(self):
        state = CVEState(cve_id="CVE-2024-0001")
        candidate = {"validation_hint": {"type": "response_contains", "markers": ["root:"]}}
        result = {
            "success": True,
            "status_code": 200,
            "body": "root:x:0:0",
            "ips_matches": [{"cve": "CVE-2024-0001", "name": "matched"}],
        }

        oracle = SuccessOracle().evaluate(state=state, candidate=candidate, result=result)

        self.assertEqual(oracle["status"], "SUCCESS")
        self.assertEqual(oracle["status_code"], CAPTURE_SUCCESS)
        self.assertEqual(oracle["success_level"], "ips_cve_match")
        self.assertTrue(oracle["target_oracle"]["success"])

    def test_success_oracle_allows_target_oracle_success_without_ips(self):
        state = CVEState(cve_id="CVE-2024-0002")
        candidate = {"validation_hint": {"type": "response_contains", "markers": ["root:"]}}
        result = {
            "success": True,
            "status_code": 200,
            "body": "root:x:0:0",
            "ips_matches": [],
        }

        oracle = SuccessOracle().evaluate(state=state, candidate=candidate, result=result)

        self.assertEqual(oracle["status"], "SUCCESS")
        self.assertEqual(oracle["status_code"], TARGET_ORACLE_SUCCESS)
        self.assertEqual(oracle["success_level"], "target_oracle")
        self.assertTrue(oracle["target_oracle"]["success"])

    def test_request_executor_plan_only_blocks_network_execution(self):
        candidate = {"raw_http": "GET / HTTP/1.1\nHost: {{TARGET_HOST}}\n\n"}
        environment = {"target_url": "http://127.0.0.1:8080", "target_host": "127.0.0.1:8080"}

        with patch("cve_hunter.verification.cfg", SimpleNamespace(run_mode="plan_only", target_allowlist=[])):
            result = RequestExecutor().execute(candidate, environment)

        self.assertFalse(result["success"])
        self.assertTrue(result["policy_blocked"])
        self.assertEqual(result["error_type"], "policy")

        oracle = evaluate_success(state=CVEState(cve_id="CVE-2024-0003"), candidate=candidate, result=result, environment=environment)
        self.assertEqual(oracle["status_code"], EXECUTION_POLICY_BLOCKED)
        self.assertEqual(oracle["success_level"], "not_executed")


if __name__ == "__main__":
    unittest.main()
