"""Focused regression tests for the bounded web-task paths.

These tests intentionally avoid Starlette's TestClient so they can exercise the
state/event machinery in environments where the AnyIO test transport is absent.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from cve_hunter import graph, web_app
from cve_hunter.state import CVEState


class TaskEventTests(TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.old_task_dir = web_app.TASK_DIR
        self.old_usage_dir = web_app.USAGE_DIR
        web_app.TASK_DIR = Path(self.tmp.name) / "tasks"
        web_app.USAGE_DIR = Path(self.tmp.name) / "usage"
        self.manager = web_app.TaskManager()

    def tearDown(self) -> None:
        with self.manager._save_timer_lock:
            for timer in self.manager._save_timers.values():
                timer.cancel()
            self.manager._save_timers.clear()
        self.manager.executor.shutdown(wait=True)
        web_app.TASK_DIR = self.old_task_dir
        web_app.USAGE_DIR = self.old_usage_dir
        self.tmp.cleanup()

    def _create(self, cves=None):
        with patch.object(self.manager.executor, "submit"):
            return self.manager.create(
                cves or ["CVE-2025-0001"],
                mode="poc",
                concurrency=1,
                docker_enabled=False,
                target_ip="127.0.0.1",
            )

    @staticmethod
    def _collect(manager, task_id, since=0):
        async def collect():
            return [event async for event in manager.events(task_id, since=since)]

        return asyncio.run(collect())

    def test_incremental_cursor_and_bounded_overflow_snapshot(self):
        task = self._create()
        with self.manager.lock:
            self.manager.tasks[task["id"]]["status"] = "completed"

        initial = self._collect(self.manager, task["id"])
        self.assertEqual(initial[0]["event"], "task")
        self.assertEqual(initial[0]["seq"], 1)

        self.manager._update_item(task["id"], "CVE-2025-0001", status="success")
        delta = self._collect(self.manager, task["id"], since=1)
        self.assertEqual(delta[0]["event"], "item")
        self.assertEqual(delta[0]["cve_id"], "CVE-2025-0001")

        self.manager.event_buffer_size = 2
        self.manager.event_logs[task["id"]] = deque(maxlen=2)
        for _ in range(4):
            self.manager._emit(task["id"], {"event": "status", "status": "completed"})
        resynced = self._collect(self.manager, task["id"], since=1)
        self.assertEqual(resynced[0]["event"], "task")
        self.assertEqual(resynced[0]["task"]["id"], task["id"])

        ahead = self._collect(self.manager, task["id"], since=9999)
        self.assertEqual(ahead[0]["event"], "task")
        self.assertEqual(ahead[0]["seq"], self.manager.tasks[task["id"]]["revision"])

    def test_concurrent_immediate_saves_leave_valid_snapshot(self):
        task = self._create()
        with self.manager.lock:
            self.manager.tasks[task["id"]]["status"] = "completed"
        threads = [
            threading.Thread(target=self.manager._save, args=(task["id"],))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        snapshot = Path(web_app.TASK_DIR) / f"{task['id']}.json"
        self.assertEqual(json.loads(snapshot.read_text(encoding="utf-8"))["id"], task["id"])

    def test_cancelled_waiting_item_does_not_leak_global_slot(self):
        self.manager.cve_slots = threading.BoundedSemaphore(1)
        task = self._create(["CVE-2025-0001", "CVE-2025-0002"])
        started = threading.Event()

        def fake_execute(task_id, cve, _options):
            self.manager._update_item(task_id, cve, status="running", phase="running")
            started.set()
            time.sleep(0.1)
            self.manager._update_item(task_id, cve, status="success", phase="done")

        with patch.object(self.manager, "_execute_one", side_effect=fake_execute):
            runner = threading.Thread(target=self.manager._run_task, args=(task["id"],))
            runner.start()
            self.assertTrue(started.wait(2))
            with self.manager.lock:
                waiting = next(
                    cve for cve, item in task["items"].items() if item["status"] == "queued"
                )
            self.manager.cancel(task["id"], waiting)
            runner.join(3)
        self.assertFalse(runner.is_alive())
        self.assertEqual(task["items"][waiting]["status"], "cancelled")
        self.assertTrue(self.manager.cve_slots.acquire(timeout=0))
        self.manager.cve_slots.release()


class FastPathTests(TestCase):
    def test_fast_mode_queries_local_nvd_only(self):
        state = CVEState(cve_id="CVE-2025-0001", fast_mode=True)
        local_info = {
            "description": "",
            "references": [],
            "affected_products": [],
            "cvss_score": 0.0,
            "cvss_severity": "",
        }
        with patch.object(graph, "query_nvd", return_value=local_info) as query:
            graph.node_query_nvd(state)
        query.assert_called_once_with("CVE-2025-0001", local_only=True)

    def test_fast_mode_respects_local_only_when_nvd_has_no_candidate(self):
        state = CVEState(
            cve_id="CVE-2025-0001",
            fast_mode=True,
            local_only=True,
            nvd_description="no executable request",
        )
        with patch.object(graph, "invoke_llm", return_value='{"candidates":[]}'):
            update = graph.node_poc_from_nvd(state)
        self.assertEqual(update["current_phase"], "generate_report")

    def test_fast_mode_routes_local_miss_to_nvd_then_stops_after_nuclei(self):
        state = CVEState(cve_id="CVE-2025-0001", fast_mode=True, current_phase="local_kb_search")
        self.assertEqual(graph.route_after_local_kb(state), "poc_from_nvd")
        state.current_phase = "poc_in_github"
        self.assertEqual(graph.route_after_phase(state), "generate_report")
        state.current_phase = "verify_poc"
        state.phases_tried = ["local_kb_search", "poc_from_nvd", "nuclei_search"]
        self.assertEqual(graph._next_phase_after_verify(state), "generate_report")

    def test_github_repositories_are_fetched_in_parallel_and_input_order(self):
        repos = [
            {"full_name": f"org/repo-{index}", "html_url": f"https://github.com/org/repo-{index}"}
            for index in range(3)
        ]
        barrier = threading.Barrier(3)

        def fetch(name):
            barrier.wait(timeout=2)
            return f"GET /{name.rsplit('/', 1)[-1]} HTTP/1.1\nHost: example.test\n"

        state = CVEState(cve_id="CVE-2025-0001")
        with (
            patch.object(graph, "search_poc_in_github", return_value={"found": True, "repos": repos}),
            patch.object(graph, "fetch_github_repo_poc", side_effect=fetch),
            patch.object(graph, "_extract_http_requests", side_effect=lambda text, _cve: [text]),
        ):
            update = graph.node_poc_in_github(state)

        self.assertEqual(
            [candidate["raw_http"] for candidate in update["poc_candidates"]],
            [f"GET /repo-{index} HTTP/1.1\nHost: example.test" for index in range(3)],
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
