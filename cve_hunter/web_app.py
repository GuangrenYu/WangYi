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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cve_hunter.config import cfg


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
            if task.get("status") in {"queued", "running"}:
                task["status"] = "interrupted"
                for item in (task.get("items") or {}).values():
                    if item.get("status") in {"queued", "running"}:
                        item["status"] = "interrupted"
                        item["phase"] = "interrupted"
                        item["message"] = "服务重启时任务未完成"
            self.tasks[str(task["id"])] = task

    def create(self, cves: list[str], *, mode: str, concurrency: int, docker_enabled: bool,
               uploaded_files: list[str] | None = None, output_dir: str = "",
               selection: dict[str, Any] | None = None, task_id: str | None = None) -> dict[str, Any]:
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
        task = self.get(task_id)
        (TASK_DIR / f"{task_id}.json").write_text(json.dumps(task, ensure_ascii=False, indent=2), encoding="utf-8")

    def _emit(self, task_id: str, event: dict[str, Any]) -> None:
        event = {"at": _now(), **event}
        with self.lock:
            task = self.tasks.get(task_id)
            if task:
                task["updated_at"] = event["at"]
            stream = self.streams.get(task_id)
        if stream:
            stream.put(event)

    def _update_item(self, task_id: str, cve: str, **updates: Any) -> None:
        with self.lock:
            task = self.tasks[task_id]
            task["items"][cve].update(_json_safe(updates))
            task["updated_at"] = _now()
        self._emit(task_id, {"event": "item", "cve_id": cve, **updates})

    def _run_task(self, task_id: str) -> None:
        with self.lock:
            task = self.tasks[task_id]
            task["status"] = "running"
            mode = task["mode"]
            concurrency = task["concurrency"]
            docker_enabled = task["docker_enabled"]
            cves = list(task["items"])
            uploaded_files = list(task.get("uploaded_files") or [])
            output_dir = str(task.get("output_dir") or "")
        self._emit(task_id, {"event": "status", "status": "running", "message": "任务开始执行"})

        def run_one(cve: str) -> None:
            from main import quiet_workflow_output, run_cve

            stop_after = {"analysis": "analysis", "environment": "environment", "poc": "poc"}.get(mode, "")
            self._update_item(task_id, cve, status="running", phase="validate_input", message="开始处理")

            def progress(event: dict[str, Any]) -> None:
                phase = str(event.get("phase") or event.get("node") or "running")
                self._update_item(
                    task_id, cve, phase=phase, phase_label=PHASE_LABELS.get(phase, phase),
                    phases_tried=event.get("phases_tried") or [], message=event.get("message", ""),
                )

            try:
                with quiet_workflow_output():
                    result = run_cve(
                        cve, show_details=False, generate_report=True, on_progress=progress,
                        stop_after=stop_after, docker_enabled=docker_enabled, uploaded_files=uploaded_files,
                        output_dir=output_dir,
                    )
                result = _json_safe(result)
                status = str(result.get("status") or "FAILURE")
                self._update_item(
                    task_id, cve, status="success" if status == "SUCCESS" else "failed",
                    phase="done", phase_label="完成", message=result.get("message", ""), result=result,
                )
            except Exception as exc:  # keep one bad CVE from cancelling a batch
                self._update_item(task_id, cve, status="failed", phase="done", phase_label="完成", message=str(exc), error=str(exc))
            finally:
                with self.lock:
                    self.tasks[task_id]["completed"] = sum(
                        item.get("status") in {"success", "failed"} for item in self.tasks[task_id]["items"].values()
                    )
                self._save(task_id)
                self._emit(task_id, {"event": "progress", "completed": self.tasks[task_id]["completed"], "total": len(cves)})

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix=f"cve-task-{task_id}") as pool:
            futures = [pool.submit(run_one, cve) for cve in cves]
            for future in futures:
                future.result()
        with self.lock:
            self.tasks[task_id]["status"] = "completed"
            self.tasks[task_id]["completed"] = len(cves)
        self._save(task_id)
        self._emit(task_id, {"event": "status", "status": "completed", "message": "任务完成"})

    async def events(self, task_id: str):
        with self.lock:
            stream = self.streams.get(task_id)
            exists = task_id in self.tasks
        if not exists or stream is None:
            return
        yield {"event": "task", "task": self.get(task_id)}
        while True:
            try:
                event = await asyncio.to_thread(stream.get, True, 15)
            except queue.Empty:
                yield {"event": "ping"}
                continue
            yield event
            if event.get("event") == "status" and event.get("status") == "completed":
                break


manager = TaskManager()
knowledge_jobs: dict[str, dict[str, Any]] = {}
knowledge_lock = threading.RLock()
app = FastAPI(title="CVE Hunter Workbench", version="1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "docker_default": False,
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
        "pcap": pcap,
        "search": {"query": query, "matches": matches},
    }


@app.get("/api/knowledge-bases")
async def knowledge_bases(query: str = "") -> dict[str, Any]:
    return {"status": "ok", "snapshot": _knowledge_snapshot(query)}


def _run_nvd_update(job_id: str, years: list[int], include_modified: bool, force: bool) -> None:
    from cve_hunter.tools.nvd_local import download_nvd_feeds

    def progress(label: str, status: str, message: str) -> None:
        with knowledge_lock:
            job = knowledge_jobs.get(job_id)
            if job:
                job["current"] = {"label": label, "status": status, "message": message}
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
    from datetime import datetime

    current_year = datetime.now().year
    if years.strip():
        try:
            selected_years = sorted({int(value.strip()) for value in years.split(",") if value.strip()})
        except ValueError:
            raise HTTPException(400, "年份必须是逗号分隔的数字")
    else:
        selected_years = list(range(max(2002, current_year - 2), current_year + 1))
    if not selected_years or any(year < 2002 or year > current_year for year in selected_years):
        raise HTTPException(400, f"年份范围必须是 2002-{current_year}")
    with knowledge_lock:
        if any(job.get("status") == "running" for job in knowledge_jobs.values()):
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
    files: list[UploadFile] = File(...),
    mode: str = Form("full"),
    concurrency: int = Form(2),
    docker_enabled: bool = Form(False),
    output_dir: str = Form(""),
    range_mode: str = Form("all"),
    range_count: int = Form(0),
    range_start: int = Form(1),
    range_end: int = Form(0),
) -> JSONResponse:
    mode = mode.strip().lower()
    if mode not in {"full", "analysis", "environment", "poc"}:
        raise HTTPException(400, "mode 必须是 full、analysis、environment 或 poc")
    if not files:
        raise HTTPException(400, "请上传至少一个文件")
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
        start = max(1, int(range_start or 1))
        end = max(start, int(range_end or start))
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
        "count": int(range_count or 0),
        "start": int(range_start or 1),
        "end": int(range_end or 0),
        "input_total": original_total,
        "selected_total": len(cves),
    }
    task = manager.create(cves, mode=mode, concurrency=concurrency, docker_enabled=docker_enabled,
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
