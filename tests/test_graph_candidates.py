import unittest
from unittest.mock import patch

from cve_hunter.graph import (
    _append_attempt_history,
    _candidate_update,
    _llm_poc_candidates,
    _next_attempt_or_phase_update,
    _raw_http_candidates,
    node_reflect_after_verify,
    node_verify_poc,
)
from cve_hunter.state import CVEState


def _raw(path: str) -> str:
    return f"GET {path} HTTP/1.1\nHost: {{{{TARGET_HOST}}}}\n\n"


class GraphCandidateTests(unittest.TestCase):
    def test_candidate_update_selects_first_and_keeps_all_candidates(self):
        state = CVEState()
        candidates = _raw_http_candidates([_raw("/first"), _raw("/second")], source="reference")

        update = _candidate_update(state, candidates)

        self.assertEqual(len(update["poc_candidates"]), 2)
        self.assertEqual(update["current_candidate_index"], 0)
        self.assertIn("/first", update["poc_raw_http"])
        self.assertEqual(len(update["poc_payloads"]), 2)
        self.assertEqual(update["current_phase"], "verify_poc")

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

    def test_next_phase_after_candidates_are_exhausted(self):
        candidates = _raw_http_candidates([_raw("/first"), _raw("/second")], source="reference")
        state = CVEState(
            poc_candidates=candidates,
            current_candidate_index=1,
            phases_tried=["local_kb_search", "poc_from_refs"],
        )

        update = _next_attempt_or_phase_update(state)

        self.assertEqual(update["current_phase"], "nuclei_search")

    def test_exhausted_candidates_can_route_to_reflection(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference")
        state = CVEState(
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_raw_http=candidates[0]["raw_http"],
            phases_tried=["local_kb_search", "poc_from_refs"],
        )

        update = _next_attempt_or_phase_update(state, allow_reflection=True)

        self.assertEqual(update["current_phase"], "reflect_after_verify")

    def test_reflection_round_limit_routes_to_next_phase(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference")
        state = CVEState(
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_raw_http=candidates[0]["raw_http"],
            reflection_rounds=2,
            max_reflection_rounds=2,
            phases_tried=["local_kb_search", "poc_from_refs"],
        )

        update = _next_attempt_or_phase_update(state, allow_reflection=True)

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
            phases_tried=["local_kb_search", "poc_from_refs"],
        )

        with (
            patch("cve_hunter.graph.console.quiet", True),
            patch(
                "cve_hunter.graph.send_poc_and_capture",
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
            phases_tried=["local_kb_search", "poc_from_refs"],
        )

        with (
            patch("cve_hunter.graph.console.quiet", True),
            patch(
                "cve_hunter.graph.send_poc_and_capture",
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

    def test_reflection_node_appends_variant_candidate(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference", confidence=0.7)
        state = CVEState(
            cve_id="CVE-2024-0001",
            nvd_description="test vuln",
            affected_products=["product"],
            vuln_type="rce",
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_source="reference",
            poc_raw_http=candidates[0]["raw_http"],
            http_status_code=404,
            http_response_body="not found",
            attempt_history=[{"outcome": "http_success_no_ips"}],
            phases_tried=["local_kb_search", "poc_from_refs"],
        )
        llm_output = """{
          "candidates": [
            {
              "method": "GET",
              "path": "/variant",
              "headers": {"Host": "{{TARGET_HOST}}"},
              "confidence": 0.6,
              "reason": "try alternate path"
            }
          ]
        }"""

        with (
            patch("cve_hunter.graph.console.quiet", True),
            patch("cve_hunter.graph.invoke_llm", return_value=llm_output),
        ):
            update = node_reflect_after_verify(state)

        self.assertEqual(update["current_phase"], "verify_poc")
        self.assertEqual(update["reflection_rounds"], 1)
        self.assertEqual(update["current_candidate_index"], 1)
        self.assertIn("/variant", update["poc_raw_http"])
        self.assertIn("reflect_after_verify", update["phases_tried"])

    def test_reflection_duplicate_candidate_falls_back_to_next_phase(self):
        candidates = _raw_http_candidates([_raw("/first")], source="reference")
        state = CVEState(
            cve_id="CVE-2024-0001",
            poc_candidates=candidates,
            current_candidate_index=0,
            poc_source="reference",
            poc_raw_http=candidates[0]["raw_http"],
            attempt_history=[{"outcome": "http_success_no_ips"}],
            phases_tried=["local_kb_search", "poc_from_refs"],
        )
        llm_output = """{"candidates":[{"raw_http":"GET /first HTTP/1.1\\nHost: {{TARGET_HOST}}\\n\\n"}]}"""

        with (
            patch("cve_hunter.graph.console.quiet", True),
            patch("cve_hunter.graph.invoke_llm", return_value=llm_output),
        ):
            update = node_reflect_after_verify(state)

        self.assertEqual(update["current_phase"], "nuclei_search")
        self.assertEqual(update["reflection_rounds"], 1)


if __name__ == "__main__":
    unittest.main()
