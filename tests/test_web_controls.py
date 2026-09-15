import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from cve_hunter import web_app


def simulated_worker(connection, cancelled, cve, options):
    """Exercise real process lifecycle without executing a PoC."""
    if cve.endswith("0001"):
        cancelled.wait(15)
        connection.send({"event": "cancelled"})
    else:
        connection.send({"event": "result", "data": {"status": "SUCCESS", "message": "fixture"}})
    connection.close()


class WebControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [patch.object(web_app, "TASK_DIR", root / "tasks"), patch.object(web_app, "UPLOAD_DIR", root / "uploads")]
        for p in self.patches:
            p.start()
        self.manager = web_app.TaskManager()
        self.submit = patch.object(self.manager.executor, "submit")
        self.submit.start()

    def tearDown(self):
        self.submit.stop()
        self.manager.executor.shutdown(wait=True)
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def create(self, cves=None, **options):
        return self.manager.create(cves or ["CVE-2025-0001", "CVE-2025-0002"], mode="poc", concurrency=2,
                                   docker_enabled=False, output_dir=self.tmp.name, **options)

    def test_api_options_range_clamping_and_cancel(self):
        with patch.object(web_app, "manager", self.manager), TestClient(web_app.app) as client:
            response = client.post("/api/tasks", files={"files": ("cves.txt", b"CVE-2025-0001 CVE-2025-0002 CVE-2025-0001")},
                data={"target_ip": "192.0.2.1", "local_only": "true", "environment_discovery": "true", "docker_enabled": "true",
                      "range_mode": "slice", "range_start": "2", "range_end": "999", "output_dir": self.tmp.name})
            self.assertEqual(response.status_code, 200)
            task = response.json()
            self.assertEqual(task["target_ip"], "192.0.2.1")
            self.assertTrue(task["local_only"])
            self.assertFalse(task["environment_discovery"])
            self.assertFalse(task["docker_enabled"])
            self.assertEqual(task["selection"]["end"], 2)
            self.assertEqual(task["total"], 1)
            response = client.post(f'/api/tasks/{task["id"]}/cancel')
            self.assertEqual(response.json()["completed"], 1)
            self.assertEqual(client.post("/api/tasks/missing/cancel").status_code, 404)
            self.assertEqual(client.post("/api/tasks", files={"files": ("cves.txt", b"CVE-2025-0001")}, data={"target_ip": "not-an-ip"}).status_code, 400)

    def test_cancel_queued_item_does_not_cancel_other_item(self):
        task = self.create()
        self.manager.cancel(task["id"], "CVE-2025-0001")
        self.assertEqual(task["items"]["CVE-2025-0001"]["status"], "cancelled")
        self.assertEqual(task["items"]["CVE-2025-0002"]["status"], "queued")
        self.manager.cancel(task["id"], "CVE-2025-0001")
        self.assertEqual(task["completed"], 1)

    def test_cancel_running_process_other_cve_finishes(self):
        task = self.create()
        with patch("cve_hunter.web_worker.execute", simulated_worker):
            thread = threading.Thread(target=self.manager._run_task, args=(task["id"],))
            thread.start()
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                with self.manager.lock:
                    ready = (task["id"], "CVE-2025-0001") in self.manager.workers
                if ready:
                    break
                time.sleep(0.05)
            self.manager.cancel(task["id"], "CVE-2025-0001")
            thread.join(15)
            self.assertFalse(thread.is_alive())
        self.assertEqual(task["items"]["CVE-2025-0001"]["status"], "cancelled")
        self.assertEqual(task["items"]["CVE-2025-0002"]["status"], "success", task["items"]["CVE-2025-0002"])
        self.assertEqual(task["completed"], 2)
        self.assertFalse(self.manager.workers)

    def test_cancel_whole_queued_task_never_starts_workers(self):
        task = self.create()
        self.manager.cancel(task["id"])
        with patch("cve_hunter.web_worker.execute", side_effect=AssertionError("must not run")):
            self.manager._run_task(task["id"])
        self.assertEqual(task["status"], "cancelled")
        self.assertEqual(task["completed"], 2)

    def test_two_sse_clients_each_receive_completed_snapshot(self):
        task = self.create()
        task["status"] = "completed"
        async def read():
            a = [event async for event in self.manager.events(task["id"])]
            b = [event async for event in self.manager.events(task["id"])]
            return a, b
        a, b = asyncio.run(read())
        self.assertEqual(a[0]["task"]["id"], b[0]["task"]["id"])
