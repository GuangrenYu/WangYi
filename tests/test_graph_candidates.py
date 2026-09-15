import json
from dataclasses import replace
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.graph import (
    _append_attempt_history,
    _candidate_update,
    _llm_poc_candidates,
    _next_attempt_or_phase_update,
    _raw_http_candidates,
    node_generate_report,
    node_poc_from_refs,
    node_verify_poc,
    node_poc_from_nvd,
    route_after_phase,
    _next_phase_after_verify,
)
from cve_hunter.state import CVEState
from cve_hunter.status_codes import EXECUTION_POLICY_BLOCKED, POC_SOURCE_ACCESS_FAILED


def _raw(path: str) -> str:
    return f"GET {path} HTTP/1.1\nHost: {{{{TARGET_HOST}}}}\n\n"


class GraphCandidateTests(unittest.TestCase):
    def test_local_reference_failure_stops_without_remote_search(self):
        state = CVEState(local_only=True, allow_reference_links=True,
                         phases_tried=["poc_from_nvd", "reference_analysis"],
                         nvd_references=["https://example.test/advisory"])
        update = node_poc_from_refs(state)
        state = replace(state, **update)
        self.assertEqual(route_after_phase(state), "generate_report")
        self.assertEqual(_next_phase_after_verify(state), "generate_report")
        for phase in ["nuclei_search", "exploitdb_search", "imfht_search", "web_search"]:
            self.assertEqual(route_after_phase(replace(state, current_phase=phase)), "generate_report")

    def test_local_reference_verification_does_not_loop(self):
        state = CVEState(local_only=True, allow_reference_links=True,
                         phases_tried=["poc_from_nvd"], nvd_references=["https://example.test/advisory"])
        self.assertEqual(_next_phase_after_verify(state), "reference_analysis")
        state.phases_tried.append("reference_analysis")
        self.assertEqual(_next_phase_after_verify(state), "generate_report")

    @patch("cve_hunter.graph.invoke_llm", return_value='```http\nGET /from-local HTTP/1.1\nHost: {{TARGET_HOST}}\n\n```')
    def test_local_context_generation_creates_candidate(self, invoke):
        state = CVEState(cve_id="CVE-2001-0075", local_only=True, nvd_description="local reproduction path /from-local")
        result = node_poc_from_nvd(state)
        self.assertEqual(result["poc_candidates"][0]["source"], "local_nvd")
        invoke.assert_called_once()
    def test_candidate_update_selects_first_and_keeps_all_candidates(self):
        state = CVEState()
        candidates = _raw_http_candidates([_raw("/first"), _raw("/second")], source="reference")

        update = _candidate_update(state, candidates)

        self.assertEqual(len(update["poc_candidates"]), 2)
        self.assertEqual(update["current_candidate_index"], 0)
        self.assertIn("/first", update["poc_raw_http"])
        self.assertEqual(len(update["poc_payloads"]), 2)
        self.assertEqual(update["current_phase"], "verify_poc")
        self.assertEqual(update["milestones"]["candidate_collected"]["status"], "passed")
        self.assertEqual(update["milestones"]["candidate_collected"]["data"]["added_count"], 2)

    def test_duplicate_candidate_uses_fallback_phase(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference")
        state = CVEState(poc_candidates=candidates)

        update = _candidate_update(state, candidates, fallback_phase="nuclei_search")

        self.assertEqual(update["current_phase"], "nuclei_search")
        self.assertNotIn("poc_raw_http", update)

    def test_llm_json_candidates_are_rendered(self):
        output = """{
          "candidates": [
            {
              "method": "GET",
              "path": "/json-poc",
              "headers": {"Host": "{{TARGET_HOST}}"},
              "evidence_url": "https://example.com/ref",
              "confidence": 0.8,
              "reason": "json path"
            }
          ]
        }"""

        candidates = _llm_poc_candidates(output, source="reference", confidence=0.3, reason="fallback")

        self.assertEqual(len(candidates), 1)
        self.assertIn("GET /json-poc HTTP/1.1", candidates[0]["raw_http"])
        self.assertEqual(candidates[0]["evidence_url"], "https://example.com/ref")
        self.assertEqual(candidates[0]["confidence"], 0.8)
        self.assertEqual(candidates[0]["reason"], "json path")

    def test_next_attempt_prefers_untried_candidate(self):
        candidates = _raw_http_candidates([_raw("/first"), _raw("/second")], source="reference")
        state = CVEState(
            poc_candidates=candidates,
            current_candidate_index=0,
            phases_tried=["poc_from_refs"],
        )

        with patch("cve_hunter.graph.console.quiet", True):
            update = _next_attempt_or_phase_update(state)

        self.assertEqual(update["current_phase"], "verify_poc")
        self.assertEqual(update["current_candidate_index"], 1)
        self.assertIn("/second", update["poc_raw_http"])

    def test_local_kb_candidate_failure_routes_to_reference_analysis(self):
        candidates = _raw_http_candidates([_raw("/first")], source="local_kb_vulhub")
        state = CVEState(
            poc_candidates=candidates,
            current_candidate_index=0,
            phases_tried=["local_kb_search"],
        )

        update = _next_attempt_or_phase_update(state)

        self.assertEqual(update["current_phase"], "reference_analysis")

    def test_next_phase_after_candidates_are_exhausted(self):
        candidates = _raw_http_candidates([_raw("/first"), _raw("/second")], source="reference")
        state = CVEState(
            poc_candidates=candidates,
            current_candidate_index=1,
            phases_tried=["local_kb_search", "reference_analysis", "poc_from_refs"],
        )

        update = _next_attempt_or_phase_update(state)

        self.assertEqual(update["current_phase"], "nuclei_search")

    def test_attempt_history_records_candidate_result(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference", reason="test")
        state = CVEState(
            cve_id="CVE-2024-0001",
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_source="reference",
            poc_raw_http=candidates[0]["raw_http"],
        )

        history = _append_attempt_history(
            state,
            {"success": True, "status_code": 404, "pcap_file_path": "a.pcap"},
            {"total_count": 0},
            False,
            False,
            "http_success_no_ips",
        )

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["candidate_index"], 0)
        self.assertEqual(history[0]["outcome"], "http_success_no_ips")
        self.assertEqual(history[0]["http_status_code"], 404)
        self.assertIn("/first", history[0]["candidate"]["raw_http"])

    def test_verify_failure_records_attempt_and_selects_next_candidate(self):
        candidates = _raw_http_candidates([_raw("/first"), _raw("/second")], source="reference")
        state = CVEState(
            cve_id="CVE-2024-0001",
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_source="reference",
            poc_raw_http=candidates[0]["raw_http"],
            phases_tried=["local_kb_search", "reference_analysis", "poc_from_refs"],
        )

        with (
            patch("cve_hunter.graph.console.quiet", True),
            patch("cve_hunter.agents.cfg", SimpleNamespace(agent_llm_enabled=False)),
            patch(
                "cve_hunter.graph.execute_candidate",
                return_value={
                    "success": True,
                    "status_code": 404,
                    "body": "not found",
                    "pcap_file_path": "first.pcap",
                    "ips_matches": [],
                },
            ),
        ):
            update = node_verify_poc(state)

        self.assertEqual(update["current_phase"], "verify_poc")
        self.assertEqual(update["current_candidate_index"], 1)
        self.assertIn("/second", update["poc_raw_http"])
        self.assertEqual(len(update["attempt_history"]), 1)
        self.assertEqual(update["attempt_history"][0]["outcome"], "http_success_no_ips")

    def test_verify_request_failure_does_not_reflect(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference")
        state = CVEState(
            cve_id="CVE-2024-0001",
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_source="reference",
            poc_raw_http=candidates[0]["raw_http"],
            phases_tried=["local_kb_search", "reference_analysis", "poc_from_refs"],
        )

        with (
            patch("cve_hunter.graph.console.quiet", True),
            patch("cve_hunter.agents.cfg", SimpleNamespace(agent_llm_enabled=False)),
            patch(
                "cve_hunter.graph.execute_candidate",
                return_value={
                    "success": False,
                    "error": "connection refused",
                    "error_type": "connect",
                    "ips_matches": [],
                },
            ),
        ):
            update = node_verify_poc(state)

        self.assertEqual(update["current_phase"], "nuclei_search")
        self.assertEqual(update["attempt_history"][0]["outcome"], "request_failed")

    def test_poc_from_refs_defensively_runs_reference_analysis_first(self):
        state = CVEState(
            cve_id="CVE-2024-0001",
            nvd_references=["https://example.com/advisory"],
            reference_contents=[],
            phases_tried=["local_kb_search"],
        )

        with patch("cve_hunter.graph.console.quiet", True):
            update = node_poc_from_refs(state)

        self.assertEqual(update["current_phase"], "reference_analysis")
        self.assertNotIn("phases_tried", update)

    def test_generate_report_prefers_execution_policy_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = CVEState(
                cve_id="CVE-2024-0001",
                is_http_vuln=True,
                status_code=POC_SOURCE_ACCESS_FAILED,
                message="PoC source failed",
                poc_candidates=_raw_http_candidates([_raw("/first")], source="reference"),
                poc_raw_http=_raw("/first"),
                oracle_result={
                    "status_code": EXECUTION_POLICY_BLOCKED,
                    "message": "RUN_MODE=plan_only blocks network execution",
                },
                executor_result={"policy_blocked": True, "error": "RUN_MODE=plan_only blocks network execution"},
                attempt_history=[{"outcome": "execution_policy_blocked"}],
                generate_report=False,
            )

            with patch("cve_hunter.graph.cfg", SimpleNamespace(output_dir=tmp, run_mode="plan_only", target_allowlist=[])):
                update = node_generate_report(state)

        self.assertEqual(update["status_code"], EXECUTION_POLICY_BLOCKED)
        self.assertIn("plan_only", update["message"])

    def test_generate_report_archives_environment_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = CVEState(
                cve_id="CVE-2024-0002",
                generate_report=False,
                attack_environment={"launcher": "docker_compose"},
                environment_spec={"cve_id": "CVE-2024-0002"},
                environment_manifest_path=str(Path(tmp) / "CVE-2024-0002" / "environment_manifest.json"),
            )
            teardown_result = {
                "success": True,
                "skipped": False,
                "launcher": "docker_compose",
            }
            with (
                patch("cve_hunter.graph.cfg", SimpleNamespace(output_dir=tmp, run_mode="plan_only", target_allowlist=[])),
                patch("cve_hunter.graph.teardown_environment", return_value=teardown_result),
            ):
                update = node_generate_report(state)

            output_dir = Path(tmp) / "CVE-2024-0002"
            result_data = json.loads((output_dir / "result.json").read_text(encoding="utf-8"))
            manifest_data = json.loads((output_dir / "environment_manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(update["environment_teardown_result"], teardown_result)
        self.assertEqual(result_data["environment_teardown_result"], teardown_result)
        self.assertEqual(manifest_data["teardown_result"], teardown_result)
        self.assertEqual(result_data["milestones"]["environment_cleanup"]["status"], "passed")


if __name__ == "__main__":
    unittest.main()
