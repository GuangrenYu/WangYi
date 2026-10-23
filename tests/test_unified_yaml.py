"""Model output is YAML; existing HTTP artifacts stay usable. No paid calls."""
import asyncio
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from cve_hunter import graph, web_app
from cve_hunter.state import CVEState

REQUEST = "GET /fixture HTTP/1.1\nHost: example.test\n\n"
TEMPLATE = """id: fixture
info:
  name: fixture
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/fixture'
"""


@pytest.mark.parametrize("node,expected", [
    (graph.node_poc_from_refs_yaml, "nuclei_search"),
    (graph.node_web_search_yaml, "generate_report"),
])
@pytest.mark.parametrize("output", ['{"candidates":[]}', 'invalid', TimeoutError()])
def test_failed_yaml_generation_never_requests_raw_http(node, expected, output):
    state = CVEState(cve_id="CVE-2025-0001", reference_contents=[{"content": REQUEST}],
                     web_search_context=REQUEST)
    options = {"side_effect": output} if isinstance(output, Exception) else {"return_value": output}
    with patch.object(graph, "invoke_llm", **options) as model:
        result = node(state)
    assert result["current_phase"] == expected
    assert model.call_count == 1
    assert model.call_args.kwargs["purpose"] in {"poc_from_refs_yaml", "web_search_yaml"}


def test_local_model_generates_yaml_and_rejects_raw_output():
    state = CVEState(cve_id="CVE-2025-0001", local_only=True,
                     nvd_description='requests.get("https://example.test/fixture")')
    with patch.object(graph, "invoke_llm", return_value=json.dumps({"candidates": [{"nuclei_yaml": TEMPLATE}]})) as model:
        result = graph.node_poc_from_nvd(state)
    assert result["poc_candidates"][0]["kind"] == "nuclei_yaml"
    assert result["poc_candidates"][0]["raw_http"] == ""
    assert "nuclei_yaml" in model.call_args.args[0]
    with patch.object(graph, "invoke_llm", return_value=json.dumps({"candidates": [{"raw_http": REQUEST}]})) as model:
        result = graph.node_poc_from_nvd(state)
    assert result["current_phase"] == "generate_report"
    assert not result.get("poc_candidates")
    assert model.call_count == 1


def test_existing_verbatim_http_is_preserved_without_model():
    state = CVEState(cve_id="CVE-2025-0001", local_only=True,
                     nvd_description="```http\n" + REQUEST + "```", stop_after="poc")
    with patch.object(graph, "invoke_llm", side_effect=AssertionError("model forbidden")):
        result = graph.node_poc_from_nvd(state)
    assert result["poc_candidates"][0]["kind"] == "raw_http"
    assert "/fixture" in result["poc_raw_http"]


def test_existing_raw_local_candidate_is_still_dispatched():
    candidate = graph._raw_http_candidates([REQUEST], source="local_kb_pcap")[0]
    state = CVEState(cve_id="CVE-2025-0001", current_phase="verify_poc", poc_candidates=[candidate])
    assert graph.route_after_local_kb(state) == "verify_poc"
    deferred = {**candidate, "reference_only": True}
    state = replace(state, poc_candidates=[deferred], current_candidate_index=-1, web_search_context=REQUEST)
    with patch.object(graph, "invoke_llm", return_value='{"candidates":[]}') as model:
        result = graph.node_web_search_yaml(state)
    assert result["current_phase"] == "verify_poc"
    assert result["poc_raw_http"] == candidate["raw_http"]
    assert model.call_count == 1


@pytest.mark.parametrize("mode", ["yaml", "yaml_only", "yamlonly"])
def test_removed_mode_is_rejected_before_task_creation(mode):
    with pytest.raises(HTTPException) as error:
        asyncio.run(web_app.create_task(mode=mode))
    assert error.value.status_code == 400
