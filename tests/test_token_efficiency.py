"""Token-saving behavior, with simulated models and HTTP transports only."""
import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from cve_hunter import graph, llm
from cve_hunter.state import CVEState
from cve_hunter.tools import reference_crawl
from cve_hunter.tools.reference_evidence import has_http_evidence


@pytest.mark.parametrize("text,expected", [
    ("Product is vulnerable. PoC: https://github.com/org/poc", False),
    ("requests.post(url, data=payload)", False),
    ("requests.post(url, data=payload)\nPoC: https://github.com/org/poc", False),
    ('requests.post("https://example.test", data=payload)', False),
    ("http:\n", False),
    ("GET /login HTTP/1.1\nHost: example.test", True),
    ('curl https://example.test/login', True),
    ('requests.post("http://example.test/login", data=payload)', True),
    ('http:\n  - method: GET\n    path:\n      - "{{BaseURL}}/login"', True),
])
def test_only_concrete_requests_qualify(text, expected):
    assert has_http_evidence({"content": text}) is expected


def test_unrelated_reference_link_cannot_complete_generic_request_code():
    page = {
        "poc_evidence": {"code_blocks": [{"text": "requests.post(url, data=payload)"}]},
        "content": "PoC repository: https://github.com/example/project",
    }
    assert not has_http_evidence(page)


@pytest.mark.parametrize("node", [graph.node_poc_from_refs_yaml])
def test_description_only_references_never_call_model(node):
    state = CVEState(cve_id="CVE-2020-0001", reference_contents=[
        {"url": "https://example.test/advisory", "content": "Upgrade product. PoC link only."}])
    with patch.object(graph, "invoke_llm", side_effect=AssertionError("paid call forbidden")):
        result = node(state)
    assert result["current_phase"] == "nuclei_search"
    assert result["agent_trace"][-1]["data"]["reason"] == "insufficient_request_evidence"


@pytest.mark.parametrize("node", [graph.node_poc_from_refs_yaml])
def test_incomplete_link_check_blocks_generation_even_if_one_page_has_evidence(node):
    state = CVEState(cve_id="CVE-2020-0001", reference_contents=[
        {"url": "https://example.test/advisory", "content": "GET /fixture HTTP/1.1\nHost: fixture"}],
        agent_trace=[{"action": "fetch_reference_contents", "data": {"reference_check_complete": False}}])
    with patch.object(graph, "invoke_llm", return_value='{"candidates":[]}'):
        result = node(state)
    assert result["current_phase"] == "nuclei_search"


def test_evidence_calls_yaml_once_then_searches_other_sources():
    state = CVEState(cve_id="CVE-2020-0001", reference_contents=[
        {"content": "GET /fixture HTTP/1.1\nHost: example.test"}])
    with patch.object(graph, "invoke_llm", return_value='{"candidates":[]}') as model:
        result = graph.node_poc_from_refs_yaml(state)
        assert result["current_phase"] == "nuclei_search"
    assert model.call_count == 1
    assert model.call_args.kwargs["purpose"] == "poc_from_refs_yaml"


@pytest.mark.parametrize("node", [graph.node_web_search_yaml])
def test_search_descriptions_do_not_call_model(node):
    with patch.object(graph, "_collect_web_search_text", return_value=("Upgrade product.", [], {})), \
         patch.object(graph, "invoke_llm", side_effect=AssertionError("paid call forbidden")):
        result = node(CVEState(cve_id="CVE-2020-0001"))
    assert result["current_phase"] == "generate_report"


def test_nvd_without_requests_does_not_call_model():
    with patch.object(graph, "invoke_llm", side_effect=AssertionError("paid call forbidden")):
        result = graph.node_poc_from_nvd(CVEState(nvd_description="An authentication bypass in product X."))
    assert result["current_phase"] == "generate_report"


def test_nvd_generation_waits_until_reference_links_are_checked():
    state = CVEState(cve_id="CVE-2020-0001", nvd_references=["https://example.test/advisory"],
                     nvd_description='requests.get("https://example.test/exploit")')
    with patch.object(graph, "invoke_llm", side_effect=AssertionError("paid call forbidden")) as model:
        result = graph.node_poc_from_nvd(state)
    assert result["current_phase"] == "reference_analysis"
    model.assert_not_called()


def test_fast_nvd_skips_generation_when_references_were_not_checked():
    state = CVEState(cve_id="CVE-2020-0001", fast_mode=True,
                     nvd_references=["https://example.test/advisory"],
                     nvd_description='requests.get("https://example.test/exploit")')
    with patch.object(graph, "invoke_llm", side_effect=AssertionError("paid call forbidden")):
        result = graph.node_poc_from_nvd(state)
    assert result["current_phase"] == "nuclei_search"


@pytest.mark.parametrize("state", [
    CVEState(poc_candidates=[{"kind": "raw_http"}]),
    CVEState(poc_candidates=[{"kind": "raw_http", "raw_http": "GET / HTTP/1.1"}],
             attempt_history=[{"candidate_index": 7}]),
])
def test_ineligible_candidates_skip_critic_and_execution(state):
    with patch.object(graph, "cfg", SimpleNamespace(max_requests_per_cve=1)), \
         patch.object(graph, "run_critic_agent", side_effect=AssertionError("critic forbidden")), \
         patch.object(graph, "execute_candidate", side_effect=AssertionError("execution forbidden")):
        graph.node_verify_poc(state)


def test_usage_cache_budget_and_isolation():
    model = Mock()
    model.invoke.return_value = SimpleNamespace(content="fixture", usage_metadata={
        "input_tokens": 10, "output_tokens": 2, "total_tokens": 12})
    with TemporaryDirectory() as tmp, patch.object(llm, "get_llm", return_value=model), \
         patch.object(llm, "cfg", SimpleNamespace(llm_model="fixture", llm_max_calls_per_cve=1)):
        directory = Path(tmp)
        with llm.llm_run_scope(directory):
            assert llm.invoke_llm("private prompt", purpose="yaml") == "fixture"
            assert llm.invoke_llm("private prompt", purpose="yaml") == "fixture"
            with pytest.raises(RuntimeError, match="budget"):
                llm.invoke_llm("different prompt", purpose="raw")
            summary = llm.llm_usage_summary()
        events = [json.loads(line) for line in (directory / "llm_usage.jsonl").read_text().splitlines()]
        assert [event["status"] for event in events] == ["success", "cache_hit", "budget_exhausted"]
        assert sum(event["total_tokens"] for event in events) == 12
        assert "private prompt" not in (directory / "llm_usage.jsonl").read_text()
        assert summary["by_purpose"]["yaml"]["cache_hits"] == 1
        with llm.llm_run_scope(directory / "second"):
            llm.invoke_llm("private prompt")
    assert model.invoke.call_count == 2


def test_skipped_candidates_do_not_consume_execution_request_budget():
    state = CVEState(
        poc_candidates=[{"kind": "raw_http"}, {"kind": "raw_http", "raw_http": "GET / HTTP/1.1"}],
        current_candidate_index=0,
        attempt_history=[{"candidate_index": 3, "skipped": True}],
    )
    with patch.object(graph, "cfg", SimpleNamespace(max_requests_per_cve=1)), \
         patch.object(graph, "run_critic_agent", return_value={
             "candidate": state.poc_candidates[1], "review": {"accepted": True},
             "trace": {"agent": "CriticAgent", "action": "review", "status": "passed", "summary": "fixture"}}):
        result = graph.node_verify_poc(state)
    assert result["current_phase"] != "generate_report"


def test_all_roots_share_a_capped_budget():
    roots = [f"https://example.test/advisory/{i}" for i in range(20)]
    with patch.object(reference_crawl, "cfg", SimpleNamespace(reference_crawl_budget=60,
            reference_discovery_enabled=False)), \
         patch.object(reference_crawl.subprocess, "run", return_value=SimpleNamespace(stdout="", returncode=0)) as reader:
        result = reference_crawl.enrich_references("CVE-2020-0001", [], [], reference_urls=roots)
    payload = json.loads(reader.call_args.kwargs["input"])
    assert {target["url"] for target in payload["targets"]} == set(roots)
    assert reader.call_args.kwargs["timeout"] <= 60
    assert result["budget_sec"] == 60


def test_reader_visits_more_than_four_root_links():
    visited = []
    def handler(request):
        visited.append(str(request.url))
        return httpx.Response(200, text="GET /fixture HTTP/1.1\nHost: fixture")
    real_client = httpx.AsyncClient
    roots = [f"https://example.test/advisory/{i}" for i in range(20)]
    with patch.object(reference_crawl, "_public_destination", AsyncMock(return_value=True)), \
         patch.object(reference_crawl.httpx, "AsyncClient", side_effect=lambda **kw: real_client(
             transport=httpx.MockTransport(handler), **kw)):
        result = asyncio.run(reference_crawl._crawl({"targets": [{"url": url} for url in roots], "budget": 1}))
    assert set(visited) == set(roots)
    assert len(result["pages"]) == 20
