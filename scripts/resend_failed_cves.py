#!/usr/bin/env python3
"""纯发包重测：不调用 LLM、不访问公网。

范围：`工作流迪普IPS结果统计new.xlsx` 的「迪普IPS待补充CVE运行结果」sheet 里，
「命中h3c」与「命中dptech」**不同时为是**的全部行。

链路（全内网）：
    本地 PoC（poc.http / poc0911 的 poc_raw_http / custom md 的 HTTP PoC）
      → http://10.20.1.240:3012/api/http2pcap 发包（check_ips=true，目标 10.55.1.21）
      → http://10.20.1.240:3013/api/logs 查告警
      → 按 cve_list / fields.CVE / attack_name 点名当前 CVE 归因 source=dptech/h3c

只做发包与归因，不生成新 PoC：nuclei、PoC-in-GitHub、Tavily、web_search 一律不碰，
httpx 全部 trust_env=False，避免 .env 里给外部情报源配的 HTTP_PROXY 把内网请求带偏。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
import openpyxl

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "resend_20260917"
RESULTS_JSONL = OUT_DIR / "results.jsonl"
# 两条通道分开落盘：原始 HTTP 一次，nuclei 模板补跑一次，汇总时取并集。
RESULTS_NUCLEI_JSONL = OUT_DIR / "results_nuclei.jsonl"
XLSX_IN = ROOT / "工作流迪普IPS结果统计new.xlsx"
XLSX_OUT = ROOT / "工作流迪普IPS结果统计new_重发结果.xlsx"
SHEET_DETAIL = "迪普IPS待补充CVE运行结果"

HTTP2PCAP_URL = "http://10.20.1.240:3012"
IPS_BASE_URL = "http://10.20.1.240:3013"
IPS_API_URL = "http://10.20.1.240:3013/api/cve-match"

DEFAULT_TARGET_HOST = "10.55.1.21"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
REQUEST_LINE_RE = re.compile(r"^([A-Z]{3,8})\s+(\S+)")

# 监视线程轮询 IPS 日志的节奏与窗口
POLL_INTERVAL = 3.0
POLL_WINDOW = 180.0
POLL_PAGE_SIZE = 1000
MAX_POLL_PAGES = 5
TAIL_SECONDS = 45.0
# 告警入库时间允许比发包时刻早一点点（设备与采集端时钟抖动）
RECEIVED_SLACK = 20.0

_log_lock = threading.Lock()


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    with _log_lock:
        print(line, flush=True)
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        with (OUT_DIR / "resend.log").open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def load_env_target() -> str:
    """从 .env 读目标地址；不联网、不加载 cve_hunter 配置。"""
    env_path = ROOT / ".env"
    values: dict[str, str] = {}
    if env_path.exists():
        for raw in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    for key in ("ATTACK_ENV_TARGET_URL", "TARGET_IP"):
        v = values.get(key, "")
        if not v:
            continue
        netloc = urlparse(v if "://" in v else f"http://{v}").netloc
        if netloc:
            return netloc
    return DEFAULT_TARGET_HOST


TARGET_HOST = load_env_target()


# --------------------------------------------------------------------------
# 范围与 PoC
# --------------------------------------------------------------------------

def split_cves(value: object) -> list[str]:
    return [m.group(0).upper() for m in CVE_RE.finditer(str(value or ""))]


def build_scope() -> tuple[list[dict], list[dict]]:
    """返回 (待重发任务列表, 无有效 CVE 的跳过行)。"""
    wb = openpyxl.load_workbook(XLSX_IN, read_only=True, data_only=True)
    ws = wb[SHEET_DETAIL]
    tasks: dict[str, dict] = {}
    skipped: list[dict] = []
    for row_no, row in enumerate(ws.iter_rows(values_only=True), start=1):
        if row_no == 1:
            continue
        row = list(row) + [None] * (11 - len(row))
        cve_cell, h3c, dptech = str(row[2] or ""), row[9], row[10]
        if h3c == "是" and dptech == "是":
            continue  # 两台设备都命中过，不在重发范围
        cves = split_cves(cve_cell)
        if not cves:
            skipped.append({"row": row_no, "id": row[0], "cve": cve_cell, "reason": "CVE 编号非法"})
            continue
        for cve in cves:
            task = tasks.setdefault(
                cve,
                {"cve": cve, "rows": [], "names": [], "old_h3c": False, "old_dptech": False},
            )
            task["rows"].append(row_no)
            task["names"].append(str(row[1] or ""))
            task["old_h3c"] = task["old_h3c"] or h3c == "是"
            task["old_dptech"] = task["old_dptech"] or dptech == "是"
    wb.close()
    return [tasks[c] for c in sorted(tasks)], skipped


def _read_http_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore").strip()


def _md_http_pocs(path: Path) -> list[str]:
    """从 custom md 里取所有 `## HTTP PoC*` 段落（跳过围栏行）。"""
    text = path.read_text(encoding="utf-8", errors="ignore")
    blocks: list[str] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("## "):
            if current:
                blocks.append("\n".join(current).strip())
            current = [] if re.fullmatch(r"HTTP PoC( \d+)?", line[3:].strip()) else None
            continue
        if current is None or line.strip() == "```":
            continue
        current.append(line)
    if current:
        blocks.append("\n".join(current).strip())
    return [b for b in blocks if b and "HTTP/" in b.splitlines()[0]]


def _md_nuclei_yaml(path: Path) -> str:
    """从 custom md 里取 `## Nuclei YAML` 段落（跳过围栏行）。"""
    text = path.read_text(encoding="utf-8", errors="ignore")
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("## "):
            if current is not None:
                break
            current = [] if line[3:].strip().lower() == "nuclei yaml" else None
            continue
        if current is None or line.strip() == "```":
            continue
        current.append(line)
    block = "\n".join(current or []).strip()
    return block if block.startswith("id:") or "\nid:" in block else ""


def build_nuclei_index() -> dict[str, list[tuple[int, float, str, str]]]:
    """cve -> nuclei 模板，优先级越小越优先。

    库里同一 CVE 常有两份模板（web_runs 的 poc.yaml 与 custom md 里的 YAML），
    取最先命中的一份即可——payload 差异才是复现关键，换模板成本很低。
    """
    index: dict[str, list[tuple[int, float, str, str]]] = {}

    def add(cve: str, priority: int, mtime: float, kind: str, payload: str) -> None:
        index.setdefault(cve.upper(), []).append((priority, mtime, kind, payload))

    for p in sorted((ROOT / "output" / "web_runs").glob("*/*/poc.yaml")):
        cve = p.parent.name
        if cve.upper().startswith("CVE-"):
            add(cve, 0, p.stat().st_mtime, "yaml_file", str(p))

    for p in sorted(ROOT.glob("poc_kb/custom/*/*.md")):
        cve = p.stem
        if cve.upper().startswith("CVE-"):
            add(cve, 1, p.stat().st_mtime, "md_yaml", str(p))

    for cve in index:
        index[cve].sort(key=lambda item: (item[0], -item[1]))
    return index


def build_poc_index() -> dict[str, list[tuple[int, float, str, str]]]:
    """cve -> [(优先级, mtime, 来源类型, 路径/取值)]，优先级越小越优先。"""
    index: dict[str, list[tuple[int, float, str, str]]] = {}

    def add(cve: str, priority: int, mtime: float, kind: str, payload: str) -> None:
        index.setdefault(cve.upper(), []).append((priority, mtime, kind, payload))

    for p in sorted((ROOT / "archives").glob("**/poc.http")):
        cve = p.parent.name
        if cve.upper().startswith("CVE-"):
            add(cve, 0, p.stat().st_mtime, "http_file", str(p))

    for p in sorted((ROOT / "output" / "web_runs").glob("*/*/poc.http")):
        cve = p.parent.name
        if cve.upper().startswith("CVE-"):
            add(cve, 1, p.stat().st_mtime, "http_file", str(p))

    for p in sorted(ROOT.glob("poc_kb/poc0911/*/poc.http")):
        cve = p.parent.name
        if cve.upper().startswith("CVE-"):
            add(cve, 2, p.stat().st_mtime, "http_file", str(p))

    for p in sorted(ROOT.glob("poc_kb/poc0911/*/result.json")):
        cve = p.parent.name
        if not cve.upper().startswith("CVE-"):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        raw = str(data.get("poc_raw_http") or "").strip()
        if raw:
            add(cve, 3, p.stat().st_mtime, "raw", raw)

    for p in sorted(ROOT.glob("poc_kb/custom/*/*.md")):
        cve = p.stem
        if cve.upper().startswith("CVE-"):
            add(cve, 4, p.stat().st_mtime, "md", str(p))

    for cve in index:
        index[cve].sort(key=lambda item: (item[0], -item[1]))
    return index


def normalize_raw_http(raw: str, target_host: str) -> str:
    """补 Host 占位符并统一成 CRLF；镜像 verification._prepare_raw_http 的规则。"""
    text = str(raw or "").replace("\r\n", "\n").strip()
    if not text:
        return ""
    text = text.replace("{{TARGET_HOST}}", target_host).replace("{{target_host}}", target_host)
    text = text.replace("{{TARGET_IP}}", target_host)
    lines = text.split("\n")
    has_host = any(l.lower().startswith("host:") and "{{" not in l for l in lines)
    if not has_host and lines:
        lines.insert(1, f"Host: {target_host}")
    return "\n".join(lines).replace("\n", "\r\n") + "\r\n\r\n"


def resolve_poc(task: dict, index: dict) -> tuple[str, str, str]:
    """返回 (raw_http, 来源描述, 路径)。找不到返回空串。"""
    labels = {0: "archive", 1: "web_runs", 2: "poc0911_poc_http"}
    for priority, _mtime, kind, payload in index.get(task["cve"], []):
        if kind == "http_file":
            raw = _read_http_file(Path(payload))
            if raw:
                return raw, labels.get(priority, "web_runs"), payload
        elif kind == "raw":
            if payload:
                return payload, "poc0911", payload_path_for_raw(payload)
        elif kind == "md":
            blocks = _md_http_pocs(Path(payload))
            if blocks:
                return blocks[0], "custom_md", payload
    return "", "", ""


def resolve_nuclei(task: dict, index: dict) -> tuple[str, str, str]:
    """返回 (yaml 文本, 来源描述, 路径)。找不到返回空串。"""
    for priority, _mtime, kind, payload in index.get(task["cve"], []):
        if kind == "yaml_file":
            text = Path(payload).read_text(encoding="utf-8", errors="ignore").strip()
            if text:
                return text, "web_runs_yaml", payload
        elif kind == "md_yaml":
            text = _md_nuclei_yaml(Path(payload))
            if text:
                return text, "custom_md_yaml", payload
    return "", "", ""


def payload_path_for_raw(raw: str) -> str:
    return f"inline:{hashlib.sha1(raw.encode('utf-8', 'ignore')).hexdigest()[:12]}"


def request_target(raw_http: str) -> str:
    first = raw_http.replace("\r\n", "\n").split("\n", 1)[0].strip()
    m = REQUEST_LINE_RE.match(first)
    return m.group(2) if m else ""


def normalize_first_line(line: str) -> str:
    """迪普的 HttpFirstLine 带方法，华三的不带；统一成 request-target 再比。"""
    s = str(line or "").strip()
    m = REQUEST_LINE_RE.match(s)
    if m:
        s = m.group(2)
    return s


# --------------------------------------------------------------------------
# IPS 日志监视线程
# --------------------------------------------------------------------------

class IpsLogMonitor:
    """后台轮询 /api/logs，按告警 id 去重累积，供发包结束后统一归因。"""

    def __init__(self, since: float | None = None) -> None:
        self.alarms: dict[object, dict] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.polls = 0
        self._since = since

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="ips-log-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=POLL_INTERVAL + 5)

    def _run(self) -> None:
        client = httpx.Client(trust_env=False, timeout=30.0)
        while not self._stop.is_set():
            try:
                self._poll_once(client)
            except Exception as exc:  # noqa: BLE001
                log(f"IPS 日志轮询失败: {exc}")
            self._stop.wait(POLL_INTERVAL)
        client.close()

    def _poll_once(self, client: httpx.Client) -> None:
        end = time.time()
        start = max(end - POLL_WINDOW, self._since) if self._since else end - POLL_WINDOW
        # 注意：接口认的是 start_time/end_time；写成 startTime/endTime 会被忽略并返回全天日志。
        base = {
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start)),
            "end_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end)),
            "page_size": POLL_PAGE_SIZE,
        }
        for page in range(1, MAX_POLL_PAGES + 1):
            params = {**base, "page": page}
            resp = client.get(f"{IPS_BASE_URL}/api/logs", params=params)
            if resp.status_code != 200:
                return
            records = resp.json().get("data") or []
            with self._lock:
                self.polls += 1
                for rec in records:
                    if isinstance(rec, dict) and rec.get("id") is not None:
                        self.alarms[rec["id"]] = rec
            if len(records) < POLL_PAGE_SIZE:
                return

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self.alarms.values())


def alarm_cves(rec: dict) -> set[str]:
    fields = rec.get("fields") if isinstance(rec.get("fields"), dict) else {}
    text = " ".join(
        [
            str(rec.get("cve_list") or ""),
            str(fields.get("CVE") or ""),
            str(rec.get("attack_name") or ""),
        ]
    )
    return {m.group(0).upper() for m in CVE_RE.finditer(text)}


def index_alarms_by_cve(alarms: list[dict]) -> dict[str, list[dict]]:
    """按告警点名的 CVE 建一次索引，避免逐 CVE 全表扫描。"""
    index: dict[str, list[dict]] = {}
    for rec in alarms:
        for cve in alarm_cves(rec):
            index.setdefault(cve, []).append(rec)
    return index


def attribute(task: dict, record: dict, alarms_by_cve: dict[str, list[dict]]) -> dict:
    """在告警里找点名当前 CVE 的记录，按 source 归因，并做首行严格比对。

    只认 `received_at` 落在本次发包时刻之后的告警：华三设备的 `timestamp` 是 UTC
    （比本地早 8 小时），且日志接口的时间过滤走的也是入库时间，用 timestamp 会串到旧记录。
    """
    cve = task["cve"]
    target = task["request_target"]
    min_received = float(record.get("sent_epoch") or 0) - RECEIVED_SLACK
    hits = {"h3c": 0, "dptech": 0, "other": 0}
    strict = {"h3c": 0, "dptech": 0}
    first_lines: list[str] = []
    for rec in alarms_by_cve.get(cve, []):
        if _received_epoch(rec) < min_received:
            continue
        source = str(rec.get("source") or "").lower()
        key = source if source in ("h3c", "dptech") else "other"
        hits[key] += 1
        line = normalize_first_line((rec.get("fields") or {}).get("HttpFirstLine", ""))
        if line:
            first_lines.append(line)
        if target and line and _first_line_match(target, line):
            if key in strict:
                strict[key] += 1
    # nuclei 通道没有确定的请求行（占位符由 nuclei 渲染），严格口径记 None，
    # 汇总时按“不参与”处理，而不是当成“发了但没匹配上”。
    strict_h3c = None if record.get("modality") == "nuclei" else strict["h3c"] > 0
    strict_dptech = None if record.get("modality") == "nuclei" else strict["dptech"] > 0
    return {
        "hit_h3c": hits["h3c"] > 0,
        "hit_dptech": hits["dptech"] > 0,
        "alarm_counts": hits,
        "strict_h3c": strict_h3c,
        "strict_dptech": strict_dptech,
        "first_lines": first_lines[:5],
    }


def _received_epoch(rec: dict) -> float:
    stamp = str(rec.get("received_at") or "").strip()
    try:
        return time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, TypeError):
        return float("inf")  # 解析不了就当成最新，宁可多算也不算漏


def _first_line_match(sent: str, logged: str) -> bool:
    if sent == logged:
        return True
    short, long_ = sorted((sent, logged), key=len)
    return len(short) >= 16 and long_.startswith(short)


# --------------------------------------------------------------------------
# 发包
# --------------------------------------------------------------------------

def send_one(task: dict, client: httpx.Client) -> dict:
    raw = task["raw_http"]
    t0 = time.time()
    record = {
        "cve": task["cve"],
        "rows": task["rows"],
        "poc_source": task["poc_source"],
        "poc_path": task["poc_path"],
        "request_target": task["request_target"],
        "raw_sha1": hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest(),
        "sent_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sent_epoch": t0,
        "success": False,
        "status_code": 0,
        "packet_count": 0,
        "http2pcap_ips_matches": 0,
        "pcap_url": "",
        "error": "",
    }
    try:
        resp = client.post(
            f"{HTTP2PCAP_URL}/api/http2pcap",
            json={"raw_http": raw, "check_ips": True, "cve_id": task["cve"]},
            timeout=httpx.Timeout(90.0, connect=5.0),
        )
        data = resp.json()
        record["success"] = bool(data.get("success"))
        record["status_code"] = data.get("status_code") or 0
        record["packet_count"] = data.get("packet_count") or 0
        record["http2pcap_ips_matches"] = len(data.get("ips_matches") or [])
        record["pcap_url"] = data.get("pcap_download_url") or ""
        record["error"] = str(data.get("error") or "")
    except Exception as exc:  # noqa: BLE001
        record["error"] = f"{type(exc).__name__}: {exc}"
    record["elapsed_seconds"] = round(time.time() - t0, 2)
    return record


def send_one_nuclei(task: dict, client: httpx.Client) -> dict:
    """走 /api/nuclei-poc，由内网服务执行本地 nuclei 模板。

    与原始 HTTP 通道的差别：占位符（{{Hostname}}/{{randstr}}…）由 nuclei 自己
    渲染，我们拿不到最终请求行，所以 strict_* 记 None —— 汇总时不计入严格口径。
    """
    yaml_text = task["yaml_content"]
    t0 = time.time()
    record = {
        "cve": task["cve"],
        "rows": task["rows"],
        "modality": "nuclei",
        "poc_source": task["poc_source"],
        "poc_path": task["poc_path"],
        "request_target": "",
        "raw_sha1": hashlib.sha1(yaml_text.encode("utf-8", "ignore")).hexdigest(),
        "sent_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sent_epoch": t0,
        "success": False,
        "matched": None,
        "packet_count": 0,
        "http2pcap_ips_matches": 0,
        "pcap_url": "",
        "result_info": "",
        "error": "",
    }
    try:
        resp = client.post(
            f"{HTTP2PCAP_URL}/api/nuclei-poc",
            json={
                "yaml_content": yaml_text,
                "target_url": f"http://{TARGET_HOST}",
                "check_ips": True,
                "cve_id": task["cve"],
            },
            timeout=httpx.Timeout(180.0, connect=5.0),
        )
        data = resp.json()
        record["success"] = bool(data.get("success"))
        record["matched"] = data.get("matched")
        record["packet_count"] = data.get("packet_count") or 0
        record["http2pcap_ips_matches"] = len(data.get("ips_matches") or [])
        record["pcap_url"] = data.get("pcap_download_url") or ""
        record["result_info"] = str(data.get("result_info") or "")[:300]
        record["error"] = str(data.get("error") or "")
    except Exception as exc:  # noqa: BLE001
        record["error"] = f"{type(exc).__name__}: {exc}"
    record["elapsed_seconds"] = round(time.time() - t0, 2)
    return record


def run_send_pass(tasks: list[dict], results_path: Path, send_fn, workers: int) -> None:
    """跑一轮发包 + 归因，原始记录与归因记录都追加进 results_path。"""
    monitor = IpsLogMonitor(since=time.time())
    monitor.start()
    client = httpx.Client(trust_env=False)
    results: list[dict] = []
    lock = threading.Lock()
    t_start = time.time()
    progress = {"n": 0}

    def worker(task: dict) -> None:
        rec = send_fn(task, client)
        with lock:
            results.append(rec)
            progress["n"] += 1
            n = progress["n"]
            with results_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if n % 25 == 0 or n == len(tasks):
                rate = n / max(time.time() - t_start, 1e-6)
                eta = (len(tasks) - n) / rate if rate else 0
                log(f"[{n}/{len(tasks)}] 成功 {sum(1 for r in results if r['success'])} | "
                    f"{rate:.2f} 个/s | 预计剩余 {eta/60:.1f} 分钟")

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(worker, tasks))
    except KeyboardInterrupt:
        log("收到中断，回收监视线程后汇总已完成部分")
    finally:
        client.close()
        log(f"发包结束，等待 {TAIL_SECONDS:.0f}s 收尾告警...")
        time.sleep(TAIL_SECONDS)
        monitor.stop()
        alarms = monitor.snapshot()
        log(f"IPS 日志累计 {len(alarms)} 条告警（轮询 {monitor.polls} 次）")

    by_cve = index_alarms_by_cve(alarms)
    task_by_cve = {t["cve"]: t for t in tasks}
    # 只补写归因结果：JSONL 保持追加语义，resume 时按最后一条去重。
    with results_path.open("a", encoding="utf-8") as f:
        for rec in results:
            rec.update(attribute(task_by_cve[rec["cve"]], rec, by_cve))
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    log(f"已写回归因结果 → {results_path}")


def filter_tasks(tasks: list[dict], args) -> list[dict]:
    if args.only:
        wanted = {c.strip().upper() for c in args.only.split(",") if c.strip()}
        tasks = [t for t in tasks if t["cve"] in wanted]
    if args.limit:
        tasks = tasks[: args.limit]
    return tasks


def load_done(results_path: Path) -> set[str]:
    done: set[str] = set()
    if not results_path.exists():
        return done
    for line in results_path.read_text(encoding="utf-8").splitlines():
        try:
            done.add(json.loads(line)["cve"])
        except Exception:
            continue
    return done


def main() -> int:
    parser = argparse.ArgumentParser(description="纯发包重测（不调 LLM、不联网）")
    parser.add_argument("--workers", type=int, default=12, help="并发发包数，默认 12")
    parser.add_argument("--limit", type=int, default=0, help="只发前 N 个 CVE（冒烟测试用）")
    parser.add_argument("--only", default="", help="只发指定 CVE（逗号分隔）")
    parser.add_argument("--dry-run", action="store_true", help="只解析 PoC，不发包")
    parser.add_argument("--resume", action="store_true", help="跳过 results.jsonl 里已完成的 CVE")
    parser.add_argument("--summarize-only", action="store_true", help="不发包，只按已有 results.jsonl 重新汇总")
    parser.add_argument("--nuclei", action="store_true",
                        help="nuclei 补跑通道：对本地有 nuclei 模板的 CVE 走 /api/nuclei-poc")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tasks, skipped_rows = build_scope()
    index = build_poc_index()
    log(f"目标地址 {TARGET_HOST}；http2pcap {HTTP2PCAP_URL}；IPS {IPS_BASE_URL}")

    if args.nuclei:
        send_fn = send_one_nuclei
        results_path = RESULTS_NUCLEI_JSONL
        n_index = build_nuclei_index()
        resolved, no_poc = [], []
        for task in tasks:
            yaml_text, label, path = resolve_nuclei(task, n_index)
            if not yaml_text:
                continue  # 无模板的 CVE 由原始 HTTP 通道负责，这里不列清单
            task.update(yaml_content=yaml_text, poc_source=label, poc_path=path, request_target="")
            resolved.append(task)
        log(f"nuclei 通道：范围 {len(tasks)} 个 CVE，命中本地模板 {len(resolved)} 个")
        # 「无本地 PoC 清单」由原始 HTTP 通道产出，这里沿用，别把那张表清空。
        if (OUT_DIR / "no_poc_cves.json").exists():
            no_poc = json.loads((OUT_DIR / "no_poc_cves.json").read_text(encoding="utf-8"))
    else:
        send_fn = send_one
        results_path = RESULTS_JSONL
        resolved, no_poc = [], []
        for task in tasks:
            raw, label, path = resolve_poc(task, index)
            if not raw:
                no_poc.append({"cve": task["cve"], "rows": task["rows"], "names": task["names"]})
                continue
            raw = normalize_raw_http(raw, TARGET_HOST)
            task.update(
                raw_http=raw,
                poc_source=label,
                poc_path=path,
                request_target=request_target(raw),
            )
            resolved.append(task)

    only_label = "（--nuclei）" if args.nuclei else ""
    log(
        f"范围{only_label}：xlsx 命中双是以外 {sum(len(t['rows']) for t in tasks)} 行 / "
        f"{len(tasks)} 个 CVE；待发 {len(resolved)} 个，无本地 PoC {len(no_poc)} 个，"
        f"跳过非法行 {len(skipped_rows)} 行"
    )
    if not args.nuclei:
        (OUT_DIR / "no_poc_cves.json").write_text(
            json.dumps(no_poc, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    resolved = filter_tasks(resolved, args)
    if args.dry_run:
        for t in resolved[:20]:
            log(f"  {t['cve']} ← {t['poc_source']} {t['poc_path']} | {t['request_target']}")
        log(f"dry-run 结束，共 {len(resolved)} 个待发 CVE")
        return 0

    if args.resume:
        done = load_done(results_path)
        if done:
            resolved = [t for t in resolved if t["cve"] not in done]
            log(f"resume：跳过已完成 {len(done)} 个，剩 {len(resolved)} 个")

    if args.summarize_only:
        log(f"--summarize-only：跳过发包，直接按 {results_path.name} 汇总")
    elif not resolved:
        log("没有待发包的 CVE，直接汇总")
    else:
        run_send_pass(resolved, results_path, send_fn, args.workers)

    write_outputs(tasks, no_poc, skipped_rows)
    return 0


# --------------------------------------------------------------------------
# 汇总与写回
# --------------------------------------------------------------------------

def _read_jsonl_last(results_path: Path) -> dict[str, dict]:
    """同一 CVE 可能有多条记录（发包一条、归因一条、resume 重发），取最后一条。"""
    out: dict[str, dict] = {}
    if not results_path.exists():
        return out
    for line in results_path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("cve"):
            out[rec["cve"]] = rec
    return out


def load_results(results_path: Path) -> dict[str, dict]:
    """两个通道分开取最后一条；同一 CVE 两边都发过时按通道合并成一个视图。"""
    return _read_jsonl_last(results_path)


def merge_passes(per_pass: dict[str, dict[str, dict]]) -> dict[str, dict]:
    """把多条通道的归因结果合成一行：任一通道命中即算命中。"""
    merged: dict[str, dict] = {}
    for name, records in per_pass.items():
        for cve, rec in records.items():
            cur = merged.get(cve)
            if cur is None:
                merged[cve] = dict(rec, modality=name, passes=[name])
                continue
            cur["passes"].append(name)
            cur["modality"] = "+".join(cur["passes"])
            cur["success"] = bool(cur.get("success")) or bool(rec.get("success"))
            cur["hit_h3c"] = bool(cur.get("hit_h3c")) or bool(rec.get("hit_h3c"))
            cur["hit_dptech"] = bool(cur.get("hit_dptech")) or bool(rec.get("hit_dptech"))
            cur["http2pcap_ips_matches"] = max(
                cur.get("http2pcap_ips_matches") or 0, rec.get("http2pcap_ips_matches") or 0
            )
            # strict_* 为 None 表示该通道不参与严格口径，用 or 时要跳过 None
            for key in ("strict_h3c", "strict_dptech"):
                cur[key] = _or_none(cur.get(key), rec.get(key))
            if not cur.get("error"):
                cur["error"] = rec.get("error", "")
            cur["poc_source"] = "+".join(sorted({cur.get("poc_source", ""), rec.get("poc_source", "")} - {""}))
    return merged


def _or_none(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return bool(a) or bool(b)


def write_outputs(tasks: list[dict], no_poc: list[dict], skipped_rows: list[dict]) -> None:
    per_pass = {
        "http": load_results(RESULTS_JSONL),
        "nuclei": load_results(RESULTS_NUCLEI_JSONL),
    }
    results = merge_passes({k: v for k, v in per_pass.items() if v})
    if not results:
        log("没有 results.jsonl，跳过写回")
        return
    log(f"汇总通道：{'、'.join(f'{k} {len(v)}' for k, v in per_pass.items() if v)}；"
        f"合并后覆盖 {len(results)} 个 CVE")

    task_by_cve = {t["cve"]: t for t in tasks}
    new_h3c = {c for c, r in results.items() if r.get("hit_h3c")}
    new_dptech = {c for c, r in results.items() if r.get("hit_dptech")}
    strict_h3c = {c for c, r in results.items() if r.get("strict_h3c")}
    strict_dptech = {c for c, r in results.items() if r.get("strict_dptech")}
    nuclei_only = {c for c, r in results.items()
                   if r.get("hit_dptech") and "nuclei" in (r.get("passes") or [])
                   and not per_pass["http"].get(c, {}).get("hit_dptech")}
    log(f"本次重发 {len(results)} 个 CVE：命中h3c {len(new_h3c)}，命中dptech {len(new_dptech)}；"
        f"严格首行口径 h3c {len(strict_h3c)}，dptech {len(strict_dptech)}；"
        f"仅 nuclei 通道复现 dptech {len(nuclei_only)}")

    wb = openpyxl.load_workbook(XLSX_IN)
    ws = wb[SHEET_DETAIL]
    row_to_cves: dict[int, list[str]] = {}
    for cve, task in task_by_cve.items():
        for row_no in task["rows"]:
            row_to_cves.setdefault(row_no, []).append(cve)

    detail_rows: list[list] = []
    added_h3c = added_dptech = 0
    regressed: list[str] = []
    regressed_detail: list[dict] = []
    for row_no in range(2, ws.max_row + 1):
        cves = row_to_cves.get(row_no)
        if not cves:
            continue
        res_list = [results[c] for c in cves if c in results]
        if not res_list:
            continue  # 本次没发到这一行（--only/--limit），原值原样保留
        old_h3c = ws.cell(row=row_no, column=10).value == "是"
        old_dptech = ws.cell(row=row_no, column=11).value == "是"
        row_cves = [c for c in cves if c in results]
        got_h3c = any(r.get("hit_h3c") for r in res_list)
        got_dptech = any(r.get("hit_dptech") for r in res_list)
        s_h3c = any(r.get("strict_h3c") for r in res_list)
        s_dptech = any(r.get("strict_dptech") for r in res_list)
        if got_h3c and not old_h3c:
            added_h3c += 1
        if got_dptech and not old_dptech:
            added_dptech += 1
        if (old_h3c and not got_h3c) or (old_dptech and not got_dptech):
            regressed.append(str(ws.cell(row=row_no, column=3).value))
            # 区分「nuclei 通道没模板可用」和「两条通道都发了仍不复现」，后者才是真问题
            tried_nuclei = all(c in per_pass["nuclei"] for c in row_cves)
            regressed_detail.append({
                "row": row_no,
                "cve": str(ws.cell(row=row_no, column=3).value),
                "nuclei_tried": tried_nuclei,
                "alarms": {c: results[c].get("alarm_counts") for c in row_cves},
            })
        ws.cell(row=row_no, column=10, value="是" if (old_h3c or got_h3c) else "")
        ws.cell(row=row_no, column=11, value="是" if (old_dptech or got_dptech) else "")
        detail_rows.append([
            ws.cell(row=row_no, column=1).value,
            str(ws.cell(row=row_no, column=3).value),
            "|".join(row_cves),
            "; ".join(sorted({results[c].get("poc_source", "") for c in row_cves})),
            "是" if any(r.get("success") for r in res_list) else "否",
            "是" if got_h3c else "",
            "是" if got_dptech else "",
            "是" if (s_h3c or s_dptech) else "",
            "是" if any(r.get("http2pcap_ips_matches") for r in res_list) else "",
            "; ".join(sorted({results[c].get("modality", "") for c in row_cves})),
            (res_list[0].get("error", "")[:120] if res_list else "未发包"),
        ])

    if "重发明细" in wb.sheetnames:
        del wb["重发明细"]
    ds = wb.create_sheet("重发明细")
    ds.append(["id", "cve", "实际发送CVE", "PoC来源", "发包成功", "本次命中h3c",
               "本次命中dptech", "严格首行命中", "发包服务报命中", "通道", "备注"])
    for r in detail_rows:
        ds.append(r)
    if "无本地PoC清单" in wb.sheetnames:
        del wb["无本地PoC清单"]
    ns = wb.create_sheet("无本地PoC清单")
    ns.append(["cve", "xlsx行号", "名称"])
    for item in no_poc:
        ns.append([item["cve"], ",".join(map(str, item["rows"])), (item["names"] or [""])[0]])
    for item in skipped_rows:
        ns.append([item["cve"], item["row"], item["reason"]])

    st = wb["统计"]
    h3c_total = dptech_total = both_total = 0
    for row_no in range(2, ws.max_row + 1):
        h = ws.cell(row=row_no, column=10).value == "是"
        d = ws.cell(row=row_no, column=11).value == "是"
        h3c_total += h
        dptech_total += d
        both_total += h and d
    st.cell(row=2, column=2, value=h3c_total + dptech_total - both_total)
    st.cell(row=3, column=2, value=h3c_total)
    st.cell(row=4, column=2, value=dptech_total)
    st.cell(row=5, column=2, value=both_total)
    # 原「统计」sheet 第 7 行往后是 token 成本表，不能碰，重发指标另开一张表。
    if "重发统计" in wb.sheetnames:
        del wb["重发统计"]
    rs = wb.create_sheet("重发统计")
    rs.append(["指标", "数值"])
    for label, value in [
        ("重发CVE数", len(results)),
        ("其中 原始HTTP通道", len(per_pass["http"])),
        ("其中 nuclei模板通道", len(per_pass["nuclei"])),
        ("发包成功", sum(1 for r in results.values() if r.get("success"))),
        ("重发命中h3c", len(new_h3c)),
        ("重发命中dptech", len(new_dptech)),
        ("仅nuclei通道复现dptech", len(nuclei_only)),
        ("严格首行口径h3c", len(strict_h3c)),
        ("严格首行口径dptech（仅原始HTTP通道）", len(strict_dptech)),
        ("重发新增h3c", added_h3c),
        ("重发新增dptech", added_dptech),
        ("本次未复现原命中行", len(regressed)),
        ("无本地PoC跳过", len(no_poc)),
        ("目标地址", TARGET_HOST),
        ("发包服务", HTTP2PCAP_URL),
        ("生成时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    ]:
        rs.append([label, value])
    wb.save(XLSX_OUT)
    log(f"已写出 {XLSX_OUT}（新增 h3c {added_h3c} / dptech {added_dptech}；"
        f"未复现 {len(regressed)} 行）")

    (OUT_DIR / "summary.md").write_text(
        render_summary(results, new_h3c, new_dptech, strict_h3c, strict_dptech,
                       added_h3c, added_dptech, regressed, no_poc, per_pass, nuclei_only,
                       regressed_detail),
        encoding="utf-8",
    )


def render_summary(results, new_h3c, new_dptech, strict_h3c, strict_dptech,
                   added_h3c, added_dptech, regressed, no_poc, per_pass, nuclei_only,
                   regressed_detail) -> str:
    ok = sum(1 for r in results.values() if r.get("success"))
    failed = sorted(c for c, r in results.items() if not r.get("success"))
    lines = [
        "# 迪普 IPS 失败项重新发包汇总",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 原始 HTTP 通道：{HTTP2PCAP_URL}/api/http2pcap（check_ips=true）",
        f"- nuclei 补跑通道：{HTTP2PCAP_URL}/api/nuclei-poc（check_ips=true，本地模板）",
        f"- 目标地址：{TARGET_HOST}",
        "- 判定：IPS 日志里 cve_list / CVE / attack_name 点名当前 CVE 才算命中；"
        "严格口径另要求 HttpFirstLine 与本次下发请求行一致"
        "（nuclei 通道请求行由 nuclei 渲染，不参与严格口径）",
        "",
        "| 指标 | 数值 |",
        "|---|---|",
        f"| 重发 CVE 数（合并去重） | {len(results)} |",
        f"| 其中 原始 HTTP 通道 | {len(per_pass['http'])} |",
        f"| 其中 nuclei 模板通道 | {len(per_pass['nuclei'])} |",
        f"| 发包成功 | {ok} |",
        f"| 发包失败 | {len(failed)} |",
        f"| 命中 h3c | {len(new_h3c)} |",
        f"| 命中 dptech | {len(new_dptech)} |",
        f"| 仅 nuclei 通道复现 dptech | {len(nuclei_only)} |",
        f"| 严格首行口径 h3c | {len(strict_h3c)} |",
        f"| 严格首行口径 dptech（仅原始 HTTP 通道） | {len(strict_dptech)} |",
        f"| 相对原表新增 h3c | {added_h3c} |",
        f"| 相对原表新增 dptech | {added_dptech} |",
        f"| 原命中本次未复现（行） | {len(regressed)} |",
        f"| 无本地 PoC 跳过 CVE | {len(no_poc)} |",
        "",
    ]
    if nuclei_only:
        lines += ["## 仅 nuclei 通道复现（原始 HTTP payload 不匹配）", "",
                  "```", " ".join(sorted(nuclei_only)), "```", ""]
    if failed:
        lines += ["## 发包失败（http2pcap 侧）", "", "```", " ".join(failed), "```", ""]
    if regressed:
        no_template = [d for d in regressed_detail if not d["nuclei_tried"]]
        still_miss = [d for d in regressed_detail if d["nuclei_tried"]]
        lines += ["## 原命中但本次未复现", "",
                  f"共 {len(regressed)} 行 / {len(set(regressed))} 个 CVE，分两类：", ""]
        lines += [f"### A. 无本地 nuclei 模板（补跑通道覆盖不到）{len(no_template)} 行", "",
                  "```", " ".join(sorted({d['cve'] for d in no_template})) or "（无）", "```", ""]
        lines += [f"### B. 两条通道都发过，两台设备仍未点名 {len(still_miss)} 行", "",
                  "```", " ".join(sorted({d['cve'] for d in still_miss})) or "（无）", "```", ""]
        if still_miss:
            lines += ["| xlsx行 | CVE | 本次告警统计 |", "|---|---|---|"]
            for d in still_miss:
                lines.append(f"| {d['row']} | {d['cve']} | `{json.dumps(d['alarms'], ensure_ascii=False)}` |")
            lines.append("")
    lines += ["## 本次命中 dptech（严格首行口径）", "", "```",
              " ".join(sorted(strict_dptech)) or "（无）", "```", ""]
    lines += ["## 本次命中 dptech（CVE 点名口径）", "", "```",
              " ".join(sorted(new_dptech)) or "（无）", "```", ""]
    lines += ["## 本次命中 h3c（CVE 点名口径）", "", "```",
              " ".join(sorted(new_h3c)) or "（无）", "```", ""]
    if no_poc:
        lines += ["## 无本地 PoC（未发包）", "", "```",
                  " ".join(sorted(i["cve"] for i in no_poc)), "```", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
