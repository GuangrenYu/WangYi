"""Nuclei YAML generation parse/validate and phase ordering."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from cve_hunter.graph import (
    _llm_nuclei_yaml_candidates,
    _next_phase_after_verify,
    node_poc_from_refs_yaml,
)
from cve_hunter.poc_parser import (
    nuclei_yaml_to_raw_http,
    parse_nuclei_yaml_candidates_json,
    validate_nuclei_yaml,
)
from cve_hunter.state import CVEState


MIN_YAML = """
id: CVE-2020-0001
info:
  name: test
  author: cve-hunter
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/vuln"
""".strip()

RAW_YAML = """
id: CVE-2020-0002
info:
  name: raw-test
  author: cve-hunter
  severity: info
http:
  - raw:
      - |
        POST /exploit HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        a=1
""".strip()


class NucleiYamlGenerationTests(unittest.TestCase):
    def test_validate_accepts_minimal_template(self):
        text, err = validate_nuclei_yaml(MIN_YAML)
        self.assertEqual(err, "")
        self.assertIn("http:", text)

    def test_validate_rejects_missing_http(self):
        text, err = validate_nuclei_yaml("id: x\ninfo:\n  name: y\n")
        self.assertEqual(text, "")
        self.assertIn("missing http", err)

    def test_parse_json_candidates(self):
        payload = {
            "candidates": [
                {
                    "nuclei_yaml": MIN_YAML,
                    "evidence_url": "http://example",
                    "confidence": 0.8,
                    "reason": "ok",
                },
                {
                    "nuclei_yaml": "not-yaml",
                    "confidence": 0.9,
                },
            ]
        }
        import json

        parsed = parse_nuclei_yaml_candidates_json(json.dumps(payload))
        self.assertEqual(len(parsed), 1)
        self.assertIn("http:", parsed[0]["nuclei_yaml"])

    def test_llm_nuclei_helper_builds_candidates(self):
        import json

        text = json.dumps({"candidates": [{"nuclei_yaml": MIN_YAML, "confidence": 0.7}]})
        cands = _llm_nuclei_yaml_candidates(text, source="reference", confidence=0.6)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["kind"], "nuclei_yaml")
        self.assertEqual(cands[0]["source"], "reference")
        self.assertTrue(cands[0]["nuclei_yaml"])

    def test_phase_order_yaml_before_raw(self):
        state = CVEState(
            phases_tried=["local_kb_search", "reference_analysis"],
            local_only=False,
        )
        self.assertEqual(_next_phase_after_verify(state), "poc_from_refs_yaml")
        state.phases_tried = state.phases_tried + ["poc_from_refs_yaml"]
        self.assertEqual(_next_phase_after_verify(state), "poc_from_refs")

    def test_poc_from_refs_yaml_falls_back_to_raw_phase_when_empty(self):
        state = CVEState(
            cve_id="CVE-2020-0001",
            reference_contents=[{"url": "http://e", "title": "t", "content": "x" * 100}],
            nvd_description="test",
        )
        with (
            patch("cve_hunter.graph.invoke_llm", return_value='{"candidates":[]}'),
            patch("cve_hunter.graph.console.print"),
        ):
            update = node_poc_from_refs_yaml(state)
        self.assertEqual(update["current_phase"], "poc_from_refs")
        self.assertIn("poc_from_refs_yaml", update["phases_tried"])

    def test_reference_evidence_reaches_generation_and_conditions_are_preserved(self):
        import json

        quote = "Authentication is not required."
        request = "GET /fixture HTTP/1.1\nHost: example.org\n"
        state = CVEState(
            cve_id="CVE-2020-0001", stop_after="poc",
            reference_contents=[{
                "url": "https://example.org/advisory", "title": "fixture",
                "content": "Introduction. " * 400 + "\n" + quote + "\n```http\n" + request + "```",
            }],
        )
        response = json.dumps({"candidates": [{
            "nuclei_yaml": MIN_YAML.replace("/vuln", "/fixture"),
            "evidence_url": "https://example.org/advisory",
            "evidence_quote": request, "preconditions": [quote],
        }]})
        with patch("cve_hunter.graph.invoke_llm", return_value=response) as llm, \
                patch("cve_hunter.graph.execute_candidate") as execute, \
                patch("cve_hunter.graph.console.print"):
            update = node_poc_from_refs_yaml(state)
        prompt = llm.call_args.args[0]
        self.assertIn(request, prompt)
        self.assertIn(quote, prompt)
        self.assertEqual(update["poc_candidates"][0]["preconditions"], [quote])
        self.assertEqual(update["poc_candidates"][0]["evidence_quote"], request)
        execute.assert_not_called()

    def test_nuclei_yaml_to_raw_from_method_path(self):
        raw = nuclei_yaml_to_raw_http(MIN_YAML)
        self.assertIn("GET /vuln HTTP/1.1", raw)
        self.assertIn("Host: {{TARGET_HOST}}", raw)

    def test_nuclei_yaml_to_raw_from_raw_block(self):
        raw = nuclei_yaml_to_raw_http(RAW_YAML)
        self.assertIn("POST /exploit HTTP/1.1", raw)
        self.assertIn("Host: {{TARGET_HOST}}", raw)
        self.assertIn("a=1", raw)


if __name__ == "__main__":
    unittest.main()
