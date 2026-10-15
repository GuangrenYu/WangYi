"""Accounting regressions with local fake responses; no model/network calls."""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cve_hunter import llm, web_app


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(web_app, "TASK_DIR", tmp_path / "tasks")
    monkeypatch.setattr(web_app, "USAGE_DIR", tmp_path / "usage")
    result = web_app.TaskManager()
    yield result
    for timer in result._save_timers.values():
        timer.cancel()
    result.executor.shutdown(wait=True)


def create(manager, cves):
    with patch.object(manager.executor, "submit"):
        return manager.create(cves, mode="yaml", concurrency=16, docker_enabled=False)


def fake_response():
    # Actual observed relay schema: total includes reasoning outside output.
    return SimpleNamespace(content="fixture", usage_metadata={
        "input_tokens": 498, "output_tokens": 1, "total_tokens": 517,
        "input_token_details": {"cache_read": 384}, "output_token_details": {"reasoning": 18},
    })


def test_live_start_finish_and_relay_details(tmp_path):
    snapshots = []
    with patch.object(llm, "get_llm", return_value=SimpleNamespace(invoke=lambda _: fake_response())):
        with llm.llm_run_scope(tmp_path, on_usage=snapshots.append, task_id="batch", cve_id="CVE-2025-0001"):
            llm.invoke_llm("secret input", purpose="yaml")
    assert snapshots[0]["pending_calls"] == 1
    assert snapshots[0]["reported_tokens"] == 0
    assert snapshots[-1]["reported_tokens"] == 517
    assert snapshots[-1]["input_tokens"] == 498
    assert snapshots[-1]["reasoning_tokens"] == 18
    assert snapshots[-1]["cached_input_tokens"] == 384
    event = json.loads((tmp_path / "llm_usage.jsonl").read_text())
    assert event["task_id"] == "batch" and event["call_id"] and event["run_id"]
    assert event["at"].endswith("+08:00")
    assert "secret input" not in (tmp_path / "llm_usage.jsonl").read_text()


@pytest.mark.parametrize("outcome", ["missing", "error", "cancelled"])
def test_unknown_and_cancelled_are_never_known_zero(tmp_path, outcome):
    def invoke(_):
        if outcome == "error":
            raise TimeoutError()
        if outcome == "cancelled":
            raise KeyboardInterrupt()
        return SimpleNamespace(content="fixture", usage_metadata={})
    with patch.object(llm, "get_llm", return_value=SimpleNamespace(invoke=invoke)):
        with llm.llm_run_scope(tmp_path):
            if outcome == "missing":
                llm.invoke_llm("fixture")
            else:
                with pytest.raises(TimeoutError if outcome == "error" else KeyboardInterrupt):
                    llm.invoke_llm("fixture")
            summary = llm.llm_usage_summary()
    assert summary["calls"] == summary["unknown_calls"] == 1
    assert summary["pending_calls"] == 0
    assert summary["usage_incomplete"]


def test_concurrent_batches_same_cves_are_isolated_and_exported(manager):
    cves = [f"CVE-2025-{i:04d}" for i in range(32)]
    batches = [create(manager, cves) for _ in range(2)]
    assert batches[0]["usage_directory"] != batches[1]["usage_directory"]
    def run(args):
        task, cve = args
        with llm.llm_run_scope(Path(task["usage_directory"]) / cve,
                               on_usage=lambda usage: manager._update_item(task["id"], cve, llm_usage=usage),
                               task_id=task["id"], cve_id=cve):
            llm.invoke_llm("fixture", purpose="yaml")
            llm.invoke_llm("fixture", purpose="yaml")
        manager._update_item(task["id"], cve, status="success")
    with patch.object(llm, "get_llm", return_value=SimpleNamespace(invoke=lambda _: fake_response())):
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(run, [(task, cve) for task in batches for cve in cves]))
    for task in batches:
        assert task["llm_usage"]["calls"] == 32
        assert task["llm_usage"]["cache_hits"] == 32
        assert task["llm_usage"]["reported_tokens"] == 32 * 517
        task["status"] = "completed"
        manager._save(task["id"])
        report = json.loads((Path(task["usage_directory"]) / "summary.json").read_text())
        assert report["created_at"].endswith("+08:00")
        assert report["usage"]["by_purpose"]["yaml"]["reported_tokens"] == 32 * 517
        assert len(report["cves"]) == 32
        assert (Path(task["usage_directory"]) / "summary.csv").read_bytes().startswith(b"\xef\xbb\xbf")
        async def events():
            return [event async for event in manager.events(task["id"], since=1)]
        deltas = asyncio.run(events())
        assert deltas[-1]["batch_llm_usage"]["reported_tokens"] == 32 * 517


def test_stop_and_restart_preserve_unknown_usage(manager):
    task = create(manager, ["CVE-2025-0001"])
    pending = {"calls": 1, "pending_calls": 1, "usage_incomplete": True,
               "by_purpose": {"yaml": {"calls": 1, "pending_calls": 1}}}
    manager._update_item(task["id"], "CVE-2025-0001", status="running", llm_usage=pending)
    task["status"] = "running"
    manager._save(task["id"])
    manager._load_history()
    restored = manager.get(task["id"])
    assert restored["status"] == "interrupted"
    assert restored["llm_usage"]["unknown_calls"] == 1
    assert restored["llm_usage"]["pending_calls"] == 0
    report = json.loads((Path(task["usage_directory"]) / "summary.json").read_text())
    assert report["usage"]["unknown_calls"] == 1


def test_usage_download(manager):
    task = create(manager, ["CVE-2025-0001"])
    task["status"] = "completed"
    manager._save(task["id"])
    with patch.object(web_app, "manager", manager):
        response = asyncio.run(web_app.get_task_usage(task["id"], format="csv"))
    assert Path(response.path).name == "summary.csv"


def test_workflow_context_reaches_real_graph_node(tmp_path):
    from langgraph.graph import StateGraph, START, END
    from main import run_cve
    from cve_hunter import graph, agents
    updates = []
    def node(state):
        llm.invoke_llm("fixture", purpose="yaml")
        return {"status": "FAILED", "current_phase": "done"}
    builder = StateGraph(dict)
    builder.add_node("fixture", node)
    builder.add_edge(START, "fixture")
    builder.add_edge("fixture", END)
    with patch.object(graph, "build_graph", return_value=builder.compile()), \
         patch.object(agents, "reclaim_owned_compose_projects", return_value=[]), \
         patch.object(llm, "get_llm", return_value=SimpleNamespace(invoke=lambda _: fake_response())):
        result = run_cve("CVE-2025-0001", show_details=False, on_progress=updates.append,
                         usage_task_id="batch", usage_directory=str(tmp_path))
    assert result["llm_usage"]["reported_tokens"] == 517
    usage_updates = [event["llm_usage"] for event in updates if event["event"] == "llm_usage"]
    assert usage_updates[0]["pending_calls"] == 1
    assert usage_updates[-1]["reported_tokens"] == 517
    assert (tmp_path / "CVE-2025-0001" / "llm_usage.jsonl").is_file()
