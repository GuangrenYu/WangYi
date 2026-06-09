import unittest

from cve_hunter.state import CVEState
from cve_hunter.status_codes import CAPTURE_SUCCESS, TARGET_ORACLE_SUCCESS
from cve_hunter.verification import SuccessOracle, evaluate_target_oracle


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


if __name__ == "__main__":
    unittest.main()
