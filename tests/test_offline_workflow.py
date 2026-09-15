import gzip
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cve_hunter.config import cfg
from cve_hunter.graph import node_poc_from_nvd
from cve_hunter.runtime import run_options, effective_target_ip
from cve_hunter.state import CVEState
from cve_hunter.tools.nvd import query_nvd
from cve_hunter.tools import nvd_local
from cve_hunter.agents import run_environment_agent


class OfflineTests(unittest.TestCase):
    def test_relative_windows_path_is_anchored_to_project(self):
        with patch("cve_hunter.tools.nvd_local.cfg", replace(cfg, nvd_local_dir="poc_kb\\nvd")):
            self.assertEqual(nvd_local._nvd_local_dir(), Path(nvd_local.__file__).resolve().parents[2] / "poc_kb" / "nvd")

    def test_missing_year_and_corrupt_feed_are_not_reported_as_absent_cve(self):
        with tempfile.TemporaryDirectory() as tmp, patch("cve_hunter.tools.nvd_local.cfg", replace(cfg, nvd_local_dir=tmp)):
            missing = query_nvd("CVE-2021-44228", local_only=True)
            self.assertEqual(missing["nvd_source"], "local_error")
            self.assertIn("2021", missing["error"])
            path = Path(tmp) / "nvdcve-2.0-2021.json"
            path.write_text('{"CVE_Items": []}', encoding="utf-8")
            invalid = query_nvd("CVE-2021-44228", local_only=True)
            self.assertEqual(invalid["nvd_source"], "local_error")
            self.assertIn("vulnerabilities", invalid["error"])
            path.write_text('{"vulnerabilities": []}', encoding="utf-8")
            self.assertEqual(query_nvd("CVE-2021-44228", local_only=True)["nvd_source"], "local_not_found")
            path.write_text(json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}), encoding="utf-8")
            self.assertEqual(query_nvd("CVE-2021-44228", local_only=True)["nvd_source"], "local")
            self.assertIn(2021, nvd_local.get_nvd_local_status()["years_available"])

    def test_local_nvd_preserves_version_cvss_and_weakness_without_api(self):
        item = {"id": "CVE-2025-12345", "descriptions": [{"lang": "en", "value": "Example vulnerable parser"}],
                "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/AV:N"}}]},
                "weaknesses": [{"description": [{"value": "CWE-20"}]}],
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:example:parser:*", "versionEndExcluding": "2.0"}]}]}]}
        with tempfile.TemporaryDirectory() as tmp, patch("cve_hunter.tools.nvd_local.cfg", replace(cfg, nvd_local_dir=tmp)), patch("cve_hunter.tools.nvd._query_nvd_api", side_effect=AssertionError("network forbidden")):
            with gzip.open(Path(tmp) / "nvdcve-2.0-2025.json.gz", "wt", encoding="utf-8") as f:
                json.dump({"vulnerabilities": [{"cve": item}]}, f)
            result = query_nvd(item["id"], local_only=True)
            self.assertEqual(result["cvss_score"], 8.7)
            self.assertEqual(result["metadata"]["configurations"], item["configurations"])
            self.assertEqual(result["metadata"]["weaknesses"], item["weaknesses"])
            self.assertEqual(result["metadata"]["cvss_vector"], "CVSS:4.0/AV:N")
            self.assertEqual(result["nvd_source"], "local")
            self.assertIn("error", query_nvd("CVE-2025-99999", local_only=True))

    def test_description_without_explicit_request_abstains(self):
        result = node_poc_from_nvd(CVEState(local_only=True, nvd_description="SQL injection in Example 1.0", cvss_score=9.8))
        self.assertEqual(result["current_phase"], "generate_report")
        self.assertFalse(result.get("poc_candidates"))

    def test_explicit_request_is_extracted_as_unverified_candidate(self):
        result = node_poc_from_nvd(CVEState(cve_id="CVE-2025-12345", local_only=True,
            nvd_description="Example request:\n```http\nGET /example HTTP/1.1\nHost: example.test\n\n```"))
        self.assertEqual(result["current_phase"], "verify_poc")
        self.assertEqual(result["poc_candidates"][0]["source"], "local_nvd")

    def test_environment_discovery_default_off_and_local_mode_overrides_opt_in(self):
        with run_options(target_ip="192.0.2.20"), patch("cve_hunter.agents._discover_environment_candidates", side_effect=AssertionError("discovery forbidden")):
            for state in [CVEState(), CVEState(local_only=True, environment_discovery=True, docker_enabled=True)]:
                result = run_environment_agent(state)
                self.assertEqual(result["environment_candidates"], [])
                self.assertEqual(result["attack_environment"]["target_url"], "http://192.0.2.20")

    def test_explicit_environment_discovery_opt_in(self):
        with patch("cve_hunter.agents._discover_environment_candidates", return_value=[]) as discover, patch("cve_hunter.agents.cfg", replace(cfg, agent_llm_enabled=False)):
            run_environment_agent(CVEState(environment_discovery=True, docker_enabled=False))
            discover.assert_called_once()

    def test_full_offline_graph_uses_feed_without_search_or_execution_in_poc_mode(self):
        from main import run_cve
        item = {"cvss_score": 5.0, "cvss_severity": "MEDIUM", "references": ["https://example.test/reference"],
                "affected_products": [], "description": "```http\nGET /example HTTP/1.1\nHost: example.test\n\n```"}
        with tempfile.TemporaryDirectory() as tmp, \
             patch("cve_hunter.tools.nvd_local.query_nvd_local", return_value=item), \
             patch("cve_hunter.graph.search_local_kb", return_value={"found": False}), \
             patch("httpx.Client.send", side_effect=AssertionError("network forbidden")), \
             patch("cve_hunter.graph.query_nvd", wraps=query_nvd), \
             patch("cve_hunter.graph.run_environment_agent", wraps=run_environment_agent), \
             patch("cve_hunter.graph.invoke_llm", side_effect=AssertionError("LLM forbidden")), \
             patch("cve_hunter.graph.execute_candidate", side_effect=AssertionError("execution forbidden")):
            result = run_cve("CVE-2025-12345", local_only=True, target_ip="192.0.2.20", stop_after="poc", output_dir=tmp, show_details=False)
        self.assertEqual(result["poc_source"], "local_nvd")
        self.assertIn("poc_from_nvd", result["phases_tried"])
        self.assertNotIn("reference_analysis", result["phases_tried"])

    def test_runtime_options_restore(self):
        original = effective_target_ip()
        with run_options(target_ip="2001:db8::1", local_only=True):
            from cve_hunter.llm import get_llm
            from cve_hunter.verification import _default_target_url
            self.assertIsNone(get_llm())
            self.assertEqual(_default_target_url(), "http://[2001:db8::1]")
        self.assertEqual(effective_target_ip(), original)
