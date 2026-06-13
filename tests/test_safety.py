import unittest

from cve_hunter.safety import evaluate_execution_policy, is_local_lab_host


class SafetyPolicyTests(unittest.TestCase):
    def test_plan_only_blocks_execution(self):
        decision = evaluate_execution_policy(
            "http://127.0.0.1:8080",
            "127.0.0.1:8080",
            run_mode="plan_only",
            allowlist=["127.0.0.1"],
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.run_mode, "plan_only")

    def test_local_lab_allows_private_targets(self):
        decision = evaluate_execution_policy(
            "http://192.168.1.20",
            "192.168.1.20",
            run_mode="local_lab",
            allowlist=[],
        )

        self.assertTrue(decision.allowed)
        self.assertTrue(is_local_lab_host("192.168.1.20"))

    def test_authorized_target_requires_allowlist(self):
        denied = evaluate_execution_policy(
            "https://example.com",
            "example.com",
            run_mode="authorized_target",
            allowlist=["allowed.example.com"],
        )
        allowed = evaluate_execution_policy(
            "https://example.com",
            "example.com",
            run_mode="authorized_target",
            allowlist=["example.com"],
        )

        self.assertFalse(denied.allowed)
        self.assertTrue(allowed.allowed)


if __name__ == "__main__":
    unittest.main()
