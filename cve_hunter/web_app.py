"""Browser workbench for CVE Hunter.

The API intentionally stays small: uploaded files become a task, a bounded
thread pool runs the existing ``main.run_cve`` workflow, and Server-Sent
Events expose each LangGraph node boundary to the browser.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import re
import threading
import uuid
import multiprocessing
import signal
import subprocess
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cve_hunter.config import cfg
from dotenv import dotenv_values


ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = ROOT / "cve_hunter" / "static"
UPLOAD_DIR = Path(cfg.output_dir) / "web_uploads"
TASK_DIR = Path(cfg.output_dir) / "web_tasks"
PCAP_DIR = Path(cfg.local_kb_pcap_dir)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
PHASE_LABELS = {
    "validate_input": "输入校验", "query_nvd": "NVD 查询", "vuln_type_check": "漏洞分类",
    "environment_agent": "环境规划", "local_kb_search": "本地知识库", "reference_analysis": "参考分析",
    "trigger_agent": "触发逻辑", "poc_from_refs": "参考 PoC", "nuclei_search": "Nuclei PoC",
    "exploitdb_search": "Exploit-DB", "imfht_search": "IMFHT", "web_search": "Web 搜索",
    "verify_poc": "验证 PoC", "archive": "归档", "save_to_local_kb": "写入知识库",
    "generate_report": "生成报告", "done": "完成",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _live_target_ip() -> str:
    """Read TARGET_IP from .env for each web request; existing processes need no restart."""
    values = dotenv_values(ROOT / ".env")
    return str(values.get("TARGET_IP") or os.getenv("TARGET_IP") or cfg.target_ip).strip()


def _json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


class TaskManager:
    def __init__(self) -> None:
        self.tasks: dict[str, dict[str, Any]] = {}
        self.streams: dict[str, queue.Queue] = {}
        self.lock = threading.RLock()
        self.context = multiprocessing.get_context("spawn")
        self.workers = {}
        self.executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="cve-web")
        TASK_DIR.mkdir(parents=True, exist_ok=True)
        self._load_history()

    def _load_history(self) -> None:
        """Restore recent task snapshots so a browser refresh keeps history."""
        snapshots = sorted(TASK_DIR.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in snapshots[:100]:
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(task, dict) or not task.get("id"):
                continue
            if task.get("status") in {"queued", "running", "stopping"}:
                task["status"] = "interrupted"
                for item in (task.get("items") or {}).values():
                    if item.get("status") in {"queued", "running", "stopping"}:
                        item["status"] = "interrupted"
                        item["phase"] = "interrupted"
                        item["message"] = "服务重启时任务未完成"
            self.tasks[str(task["id"])] = task

    def create(self, cves: list[str], *, mode: str, concurrency: int, docker_enabled: bool,
               uploaded_files: list[str] | None = None, output_dir: str = "",
               selection: dict[str, Any] | None = None, task_id: str | None = None,
               target_ip: str = "", local_only: bool = False, environment_discovery: bool = False) -> dict[str, Any]:
        task_id = task_id or uuid.uuid4().hex[:12]
        items = {
            cve: {"cve_id": cve, "status": "queued", "phase": "queued", "phases_tried": [], "message": "排队中"}
            for cve in cves
        }
        task = {
            "id": task_id, "status": "queued", "mode": mode, "docker_enabled": docker_enabled,
            "concurrency": max(1, min(int(concurrency), 16)), "created_at": _now(),
            "updated_at": _now(), "total": len(cves), "completed": 0, "items": items,
            "uploaded_files": list(uploaded_files or []),
            "output_dir": output_dir,
            "selection": dict(selection or {}),
            "target_ip": target_ip or _live_target_ip(), "local_only": local_only,
            "environment_discovery": environment_discovery and not local_only,
        }
        with self.lock:
            self.tasks[task_id] = task
            self.streams[task_id] = queue.Queue()
        self._emit(task_id, {"event": "task", "task": task})
        self.executor.submit(self._run_task, task_id)
        return task

    def get(self, task_id: str) -> dict[str, Any]:
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                raise KeyError(task_id)
            return _json_safe(task)

    def _save(self, task_id: str) -> None:
        with self.lock:
            task = self.get(task_id)
            TASK_DIR.mkdir(parents=True, exist_ok=True)
            temporary = TASK_DIR / f"{task_id}.json.tmp"
            temporary.write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(TASK_DIR / f"{task_id}.json")

    def cancel(self, task_id: str, cve: str | None = None) -> dict:
        with self.lock:
            task = self.tasks[task_id]
            if cve is not None and cve not in task["items"]:
                raise KeyError(cve)
            if cve is None and task["status"] in {"queued", "running", "stopping"}:
                task["status"] = "stopping"
            for key in ([cve] if cve else list(task["items"])):
                item = task["items"][key]
                if item["status"] == "queued":
                    item.update(status="cancelled", phase="cancelled", message="已终止，未开始执行")
                elif item["status"] in {"running", "stopping"}:
                    item.update(status="stopping", message="正在终止并清理进程")
                    worker = self.workers.get((task_id, key))
                    if worker:
                        worker[1].set()
            task["completed"] = sum(i["status"] in {"success", "failed", "cancelled"} for i in task["items"].values())
            self._save(task_id)
            return self.get(task_id)

    def _execute_one(self, task_id: str, cve: str, options: dict) -> None:
        from cve_hunter.web_worker import execute
        receive, send = self.context.Pipe(duplex=False)
        cancelled = self.context.Event()
        process = self.context.Process(target=execute, args=(send, cancelled, cve, options))
        result = None
        error = "执行进程退出但未返回结果"
        with self.lock:
            if self.tasks[task_id]["items"][cve]["status"] == "cancelled":
                receive.close()
                send.close()
                return
            self._update_item(task_id, cve, status="running", message="开始处理")
            process.start()
            self.workers[(task_id, cve)] = (process, cancelled)
        send.close()
        stop_started = None
        try:
            while True:
                if cancelled.is_set():
                    if stop_started is None:
                        stop_started = time.monotonic()
                        if os.name != "nt":
                            process.terminate()
                    if time.monotonic() - stop_started > 5 and process.is_alive():
                        self._kill_worker(process)
                try:
                    available = receive.poll(0.1)
                    event = receive.recv() if available else None
                except (EOFError, OSError):
                    break
                if not available and not process.is_alive():
                    break
                if event is not None:
                    if event["event"] == "result":
                        result = event["data"]
                    elif event["event"] == "error":
                        error = event["data"]
                    elif event["event"] == "progress" and not cancelled.is_set():
                        data = event["data"]
                        phase = data.get("phase", "running")
                        self._update_item(task_id, cve, phase=phase, phase_label=PHASE_LABELS.get(phase, phase),
                                          message=data.get("message", ""), phases_tried=data.get("phases_tried", []))
            process.join(timeout=5)
            if process.is_alive():
                self._kill_worker(process)
                process.join(timeout=5)
            with self.lock:
                if cancelled.is_set():
                    self._update_item(task_id, cve, status="cancelled", phase="cancelled", phase_label="已终止",
                                      message="进程已终止，已有文件保留；强制停止时请检查环境清理")
                elif result is not None:
                    self._update_item(task_id, cve, status="success" if result.get("status") == "SUCCESS" else "failed",
                                      phase="done", phase_label="完成", result=result, message=result.get("message", ""))
                else:
                    self._update_item(task_id, cve, status="failed", phase="done", message=error)
        finally:
            if process.is_alive():
                self._kill_worker(process)
                process.join(timeout=5)
            receive.close()
            with self.lock:
                self.workers.pop((task_id, cve), None)

    @staticmethod
    def _kill_worker(process) -> None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.is_alive():
            process.kill()

    def _emit(self, task_id: str, event: dict[str, Any]) -> None:
        event = {"at": _now(), **event}
        with self.lock:
            task = self.tasks.get(task_id)
            if task:
                task["updated_at"] = event["at"]

    def _update_item(self, task_id: str, cve: str, **updates: Any) -> None:
        with self.lock:
            task = self.tasks[task_id]
            task["items"][cve].update(_json_safe(updates))
            task["updated_at"] = _now()
        self._emit(task_id, {"event": "item", "cve_id": cve, **updates})

    def _run_task(self, task_id: str) -> None:
        with self.lock:
            task = self.tasks[task_id]
            if task["status"] != "stopping":
                task["status"] = "running"
            mode = task["mode"]
            concurrency = task["concurrency"]
            docker_enabled = task["docker_enabled"]
            cves = list(task["items"])
            uploaded_files = list(task.get("uploaded_files") or [])
            output_dir = str(task.get("output_dir") or "")
        self._emit(task_id, {"event": "status", "status": "running", "message": "任务开始执行"})

        def run_one(cve: str) -> None:
            try:
                self._execute_one(task_id, cve, {
                    "stop_after": {"analysis": "analysis", "environment": "environment", "poc": "poc"}.get(mode, ""),
                    "docker_enabled": docker_enabled, "uploaded_files": uploaded_files,
                    "output_dir": output_dir, "target_ip": task["target_ip"],
                    "local_only": task["local_only"], "environment_discovery": task["environment_discovery"],
                })
            except Exception as exc:
                with self.lock:
                    item = task["items"][cve]
                    status = "cancelled" if item["status"] in {"cancelled", "stopping"} else "failed"
                    self._update_item(task_id, cve, status=status, message=str(exc))
            finally:
                with self.lock:
                    task["completed"] = sum(i["status"] in {"success", "failed", "cancelled"} for i in task["items"].values())
                    self._save(task_id)

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix=f"cve-task-{task_id}") as pool:
            futures = [pool.submit(run_one, cve) for cve in cves]
            for future in futures:
                future.result()
        with self.lock:
            self.tasks[task_id]["status"] = "cancelled" if task["status"] == "stopping" else "completed"
            self.tasks[task_id]["completed"] = len(cves)
        self._save(task_id)
        self._emit(task_id, {"event": "status", "status": "completed", "message": "任务完成"})

    async def events(self, task_id: str):
        # Each client receives its own snapshot; clients cannot steal queue events.
        while True:
            task = self.get(task_id)
            yield {"event": "task", "task": task}
            if task["status"] not in {"queued", "running", "stopping"}:
                return
            await asyncio.sleep(0.5)


manager = TaskManager()
knowledge_jobs: dict[str, dict[str, Any]] = {}
knowledge_lock = threading.RLock()
app = FastAPI(title="CVE Hunter Workbench", version="1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "docker_default": False,
        "target_ip": _live_target_ip(),
        "cli_docker_default": bool(cfg.auto_env_enabled),
        "tasks": len(manager.tasks),
    }


def _iter_files(path: Path, *, max_files: int = 50000):
    if not path.exists():
        return
    seen = 0
    for root, dirs, names in os.walk(path):
        dirs[:] = [name for name in dirs if name not in {".git", "__pycache__", "nvd"}]
        for name in names:
            item = Path(root) / name
            if not item.is_file():
                continue
            yield item
            seen += 1
            if seen >= max_files:
                return


def _directory_stats(path: Path, *, pattern: str = "*", max_files: int = 10000) -> dict[str, Any]:
    files = [item for item in (_iter_files(path, max_files=max_files) or []) if item.match(pattern)]
    total_bytes = sum(item.stat().st_size for item in files)
    return {
        "exists": path.exists(),
        "path": str(path),
        "files": len(files),
        "size_mb": round(total_bytes / 1024 / 1024, 1),
        "truncated": len(files) >= max_files,
    }


def _knowledge_snapshot(query: str = "") -> dict[str, Any]:
    from cve_hunter.tools.nvd_local import get_nvd_local_status

    poc_root = Path(cfg.poc_kb_dir)
    custom_root = poc_root / "custom"
    pcap = _directory_stats(PCAP_DIR, pattern="*.pcap")
    if query.strip():
        needle = query.strip().lower()
        matches = []
        cve_match = re.search(r"CVE-(\d{4})(?:-(\d+))?", needle, re.IGNORECASE)
        candidates = []
        if cve_match:
            year, number = cve_match.group(1), cve_match.group(2)
            for source in (custom_root, poc_root / "trickest-cve"):
                year_root = source / year
                if year_root.exists():
                    candidates.extend(year_root.glob(f"CVE-{year}-{number}.*" if number else f"CVE-{year}-*"))
        else:
            candidates = list(_iter_files(poc_root, max_files=3000) or [])
        for item in candidates:
            if needle in item.name.lower():
                matches.append({"name": item.name, "path": str(item), "size": item.stat().st_size})
        matches = matches[:100]
    else:
        matches = []
    return {
        "poc": _directory_stats(poc_root, max_files=3000),
        "custom_poc": _directory_stats(custom_root),
        "nvd": get_nvd_local_status(),
        "cvelist": _directory_stats(ROOT / Path(str(getattr(cfg, "cvelist_dir", "third_party/cvelistV5/cves")).replace("\\", "/")), pattern="*.json", max_files=200000),
        "pcap": pcap,
        "search": {"query": query, "matches": matches},
    }


@app.get("/api/knowledge-bases")
async def knowledge_bases(query: str = "") -> dict[str, Any]:
    return {"status": "ok", "snapshot": _knowledge_snapshot(query)}


@app.get("/api/input-history")
async def input_history() -> dict[str, Any]:
    with manager.lock:
        values = []
        for task in manager.tasks.values():
            values.extend(task.get("items", {}).keys())
        return {"cves": list(dict.fromkeys(values))[-500:]}


def _run_nvd_update(job_id: str, years: list[int], include_modified: bool, force: bool) -> None:
    from cve_hunter.tools.nvd_local import download_nvd_feeds

    def progress(label: str, status: str, message: str) -> None:
        with knowledge_lock:
            job = knowledge_jobs.get(job_id)
            if job:
                job["current"] = {"label": label, "status": status, "message": message}
                job.setdefault("year_status", {})[label] = {"status": status, "message": message}
                job["updated_at"] = _now()

    with knowledge_lock:
        knowledge_jobs[job_id]["status"] = "running"
        knowledge_jobs[job_id]["updated_at"] = _now()
    try:
        result = download_nvd_feeds(
            years=years, include_modified=include_modified, force=force, progress_callback=progress,
        )
        with knowledge_lock:
            knowledge_jobs[job_id].update({"status": "completed", "result": result, "snapshot": _knowledge_snapshot()})
    except Exception as exc:
        with knowledge_lock:
            knowledge_jobs[job_id].update({"status": "failed", "error": str(exc)})
    finally:
        with knowledge_lock:
            knowledge_jobs[job_id]["updated_at"] = _now()


@app.post("/api/knowledge-bases/nvd/update")
async def update_nvd(
    years: str = Form(""),
    include_modified: bool = Form(True),
    force: bool = Form(False),
) -> JSONResponse:
    from cve_hunter.tools.nvd_local import parse_nvd_years

    try:
        selected_years = parse_nvd_years(years)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    with knowledge_lock:
        if any(job.get("status") in {"queued", "running"} for job in knowledge_jobs.values()):
            raise HTTPException(409, "已有 NVD 更新任务正在运行")
        job_id = uuid.uuid4().hex[:12]
        knowledge_jobs[job_id] = {
            "id": job_id, "status": "queued", "years": selected_years,
            "include_modified": include_modified, "force": force, "created_at": _now(),
        }
    manager.executor.submit(_run_nvd_update, job_id, selected_years, include_modified, force)
    return JSONResponse(knowledge_jobs[job_id])


@app.get("/api/knowledge-bases/nvd/jobs/{job_id}")
async def nvd_job(job_id: str) -> dict[str, Any]:
    with knowledge_lock:
        job = knowledge_jobs.get(job_id)
        if not job:
            raise HTTPException(404, "NVD 更新任务不存在")
        return _json_safe(job)


@app.post("/api/tasks")
async def create_task(
    files: list[UploadFile] | None = File(None),
    cve_text: str = Form(""),
    mode: str = Form("full"),
    concurrency: int = Form(2),
    docker_enabled: bool = Form(False),
    target_ip: str = Form(""),
    local_only: bool = Form(False),
    environment_discovery: bool = Form(False),
    output_dir: str = Form(""),
    range_mode: str = Form("all"),
    range_count: int = Form(0),
    range_start: int = Form(1),
    range_end: int = Form(0),
) -> JSONResponse:
    mode = mode.strip().lower()
    if mode not in {"full", "analysis", "environment", "poc"}:
        raise HTTPException(400, "mode 必须是 full、analysis、environment 或 poc")
    files = files or []
    target_ip = target_ip.strip() or _live_target_ip()
    if target_ip.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        target_ip = urlparse(target_ip).hostname or target_ip
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise HTTPException(400, "目标 IP 必须是有效的 IPv4 或 IPv6 地址")
    environment_discovery = (environment_discovery or mode == "environment") and not local_only
    docker_enabled = docker_enabled and environment_discovery and not local_only
    task_id = uuid.uuid4().hex[:12]
    upload_root = UPLOAD_DIR / task_id
    upload_root.mkdir(parents=True, exist_ok=True)
    cves: list[str] = []
    seen: set[str] = set()
    for upload in files:
        raw = await upload.read()
        # Browsers submit relative folder paths, but a crafted client can send
        # absolute paths or traversal segments. Normalize separators and keep
        # every upload beneath this task's directory.
        relative = PurePosixPath(str(upload.filename or "upload.txt").replace("\\", "/"))
        safe_parts = [part for part in relative.parts if part not in {"", ".", ".."} and ":" not in part]
        destination = upload_root.joinpath(*safe_parts) if safe_parts else upload_root / "upload.txt"
        try:
            destination.resolve().relative_to(upload_root.resolve())
        except ValueError:
            destination = upload_root / (safe_parts[-1] if safe_parts else "upload.txt")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        text = raw.decode("utf-8", errors="ignore")
        for match in CVE_PATTERN.findall(f"{upload.filename or ''}\n{text}"):
            cve = match.upper()
            if cve not in seen:
                seen.add(cve)
                cves.append(cve)
    for match in CVE_PATTERN.findall(cve_text):
        cve = match.upper()
        if cve not in seen:
            seen.add(cve)
            cves.append(cve)
    if not cves:
        raise HTTPException(400, "上传内容中没有识别到 CVE 编号")
    original_total = len(cves)
    range_mode = range_mode.strip().lower()
    if range_mode == "head":
        count = max(1, min(int(range_count or 1), original_total))
        cves = cves[:count]
    elif range_mode == "tail":
        count = max(1, min(int(range_count or 1), original_total))
        cves = cves[-count:]
    elif range_mode == "slice":
        start = max(1, min(int(range_start or 1), original_total))
        end = max(start, min(int(range_end or start), original_total))
        cves = cves[start - 1:end]
        if not cves:
            raise HTTPException(400, f"范围超出输入文件，共 {original_total} 条 CVE")
    else:
        range_mode = "all"
    if not cves:
        raise HTTPException(400, "选择范围没有可执行的 CVE")

    requested_output = str(output_dir or "").strip()
    base_output = Path(requested_output).expanduser() if requested_output else Path(cfg.output_dir) / "web_runs"
    if not base_output.is_absolute():
        base_output = ROOT / base_output
    actual_output = base_output / task_id
    actual_output.mkdir(parents=True, exist_ok=True)
    selection = {
        "mode": range_mode,
        "count": len(cves),
        "start": start if range_mode == "slice" else (original_total - len(cves) + 1 if range_mode == "tail" else 1),
        "end": end if range_mode == "slice" else (original_total if range_mode in {"all", "tail"} else len(cves)),
        "input_total": original_total,
        "selected_total": len(cves),
    }
    task = manager.create(cves, mode=mode, concurrency=concurrency, docker_enabled=docker_enabled,
                          target_ip=target_ip, local_only=local_only, environment_discovery=environment_discovery,
                          uploaded_files=[str(path) for path in upload_root.rglob("*") if path.is_file()],
                          output_dir=str(actual_output), selection=selection, task_id=task_id)
    task["upload_dir"] = str(upload_root)
    task["output_base"] = str(base_output)
    manager._save(task["id"])
    return JSONResponse(task)


@app.get("/api/tasks")
async def list_tasks() -> list[dict[str, Any]]:
    with manager.lock:
        return [_json_safe(task) for task in sorted(manager.tasks.values(), key=lambda item: item["created_at"], reverse=True)]


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: str) -> dict[str, Any]:
    try:
        return manager.get(task_id)
    except KeyError:
        raise HTTPException(404, "任务不存在")


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str) -> dict:
    try:
        return manager.cancel(task_id)
    except KeyError:
        raise HTTPException(404, "任务不存在")


@app.post("/api/tasks/{task_id}/items/{cve_id}/cancel")
async def cancel_item(task_id: str, cve_id: str) -> dict:
    try:
        return manager.cancel(task_id, cve_id.upper())
    except KeyError:
        raise HTTPException(404, "任务或 CVE 不存在")


@app.get("/api/tasks/{task_id}/events")
async def task_events(task_id: str) -> StreamingResponse:
    with manager.lock:
        if task_id not in manager.tasks:
            raise HTTPException(404, "任务不存在")

    async def stream():
        async for event in manager.events(task_id):
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def create_app() -> FastAPI:
    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("cve_hunter.web_app:app", host="0.0.0.0", port=8000, reload=False)
