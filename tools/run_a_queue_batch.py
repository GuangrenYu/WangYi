"""Run A-queue top N with hard per-CVE subprocess timeout (Windows-friendly)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

QUEUE = Path("output/queue/A_ready_try_latest.txt")
OUT_DIR = Path("output/queue")
REPORT = Path("docs/reports/A档前10条本地批测分层汇总.md")
TIMEOUT_S = 240
LIMIT = 10


def load_cves() -> list[str]:
    return [line.strip().upper() for line in QUEUE.read_text(encoding="utf-8").splitlines() if line.strip()][:LIMIT]


def cleanup_docker() -> None:
    try:
        out = subprocess.check_output(
            ["docker", "ps", "-aq", "--filter", "name=cvehunter"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        ids = [line.strip() for line in out.splitlines() if line.strip()]
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], check=False, capture_output=True)
    except Exception:
        pass


def summarize_one(cve: str, index: int, elapsed: float, timed_out: bool = False, error: str = "") -> dict:
    payload: dict = {}
    result_path = Path("output") / cve / "result.json"
    manifest_path = Path("output") / cve / "repro" / "manifest.json"
    if result_path.is_file():
        try:
            # prefer result if modified recently relative to this run roughly
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
    manifest: dict = {}
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}

    milestones = payload.get("milestones") or {}

    def ms(name: str) -> str:
        item = milestones.get(name) or {}
        return str(item.get("status") or "") if isinstance(item, dict) else ""

    env = payload.get("attack_environment") or {}
    setup = payload.get("environment_setup_result") or env.get("setup_result") or {}
    status = payload.get("status") or manifest.get("status") or ("TIMEOUT" if timed_out else "UNKNOWN")
    status_code = payload.get("status_code") or manifest.get("status_code") or ("批测异常" if timed_out else "")
    success_tier = payload.get("success_tier") or manifest.get("success_tier") or ""
    failure_class = payload.get("failure_class") or manifest.get("failure_class") or ""
    success_level = str(payload.get("success_level") or "")
    if timed_out and not payload:
        status, status_code, success_tier, failure_class = "TIMEOUT", "批测异常", "无", "设施"
    passed = status == "SUCCESS" or status_code in {"数据库命中", "目标命中", "检测命中"}
    target_oracle = bool(payload.get("target_oracle_success") or success_level in {"target_oracle", "database_oracle"})
    ips = bool(payload.get("ips_matched"))
    repro = bool((payload.get("repro_bundle") or {}).get("complete") or manifest.get("complete"))
    return {
        "index": index,
        "cve_id": cve,
        "status": status,
        "status_code": status_code,
        "success_tier": success_tier,
        "failure_class": failure_class,
        "passed": passed,
        "elapsed_seconds": round(elapsed, 1),
        "message": str(payload.get("message") or error or "")[:300],
        "poc_source": payload.get("poc_source") or "",
        "protocol": payload.get("protocol") or "",
        "target_url": env.get("target_url") or "",
        "env_setup_success": bool(setup.get("success")) or ms("environment_ready") == "passed",
        "milestone_environment_ready": ms("environment_ready"),
        "milestone_request_executed": ms("request_executed"),
        "target_oracle_success": target_oracle,
        "ips_matched": ips,
        "repro_complete": repro,
        "success_level": success_level,
        "pcap_file_path": payload.get("pcap_file_path") or "",
        "timed_out": timed_out,
    }


def run_one(cve: str, index: int) -> dict:
    cleanup_docker()
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    # Use batch-style invoke: single CVE still generates report by default.
    # Avoid LLM report by running through a tiny helper flag: set GENERATE? none.
    # Workaround: call python -c execute_cve_as_batch_result
    code = (
        "from main import execute_cve_as_batch_result; "
        f"r=execute_cve_as_batch_result({index}, '{cve}', generate_report=False, local_container_mode=True); "
        "import json; print('BATCH_JSON:'+json.dumps(r.__dict__, ensure_ascii=False, default=str))"
    )
    cmd = [sys.executable, "-c", code]
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT_S,
            env=env,
            cwd=str(ROOT),
        )
        elapsed = time.time() - t0
        # Prefer structured BATCH_JSON if present
        batch_payload = None
        for line in (proc.stdout or "").splitlines():
            if line.startswith("BATCH_JSON:"):
                try:
                    batch_payload = json.loads(line[len("BATCH_JSON:") :])
                except Exception:
                    batch_payload = None
        row = summarize_one(cve, index, elapsed, timed_out=False, error=(proc.stderr or "")[-200:])
        if batch_payload:
            row["status"] = batch_payload.get("status") or row["status"]
            row["status_code"] = batch_payload.get("status_code") or row["status_code"]
            row["success_tier"] = batch_payload.get("success_tier") or row["success_tier"]
            row["failure_class"] = batch_payload.get("failure_class") or row["failure_class"]
            row["passed"] = bool(batch_payload.get("passed"))
            row["poc_source"] = batch_payload.get("poc_source") or row["poc_source"]
            row["ips_matched"] = bool(batch_payload.get("ips_matched"))
            row["repro_complete"] = bool(batch_payload.get("repro_bundle_complete") or row["repro_complete"])
            row["success_level"] = batch_payload.get("success_level") or row["success_level"]
            row["pcap_file_path"] = batch_payload.get("pcap_file_path") or row["pcap_file_path"]
            row["message"] = str(batch_payload.get("message") or row["message"])[:300]
            row["elapsed_seconds"] = batch_payload.get("elapsed_seconds") or row["elapsed_seconds"]
            milestones = batch_payload.get("milestones") or {}
            if isinstance(milestones, dict):
                env_ms = milestones.get("environment_ready") or {}
                req_ms = milestones.get("request_executed") or {}
                if isinstance(env_ms, dict):
                    row["milestone_environment_ready"] = str(env_ms.get("status") or "")
                    if env_ms.get("status") == "passed":
                        row["env_setup_success"] = True
                if isinstance(req_ms, dict):
                    row["milestone_request_executed"] = str(req_ms.get("status") or "")
            if row["success_level"] in {"target_oracle", "database_oracle"}:
                row["target_oracle_success"] = True
        return row
    except subprocess.TimeoutExpired:
        cleanup_docker()
        return summarize_one(cve, index, time.time() - t0, timed_out=True, error=f"timeout {TIMEOUT_S}s")


def write_report(final: list[dict], summary_path: Path) -> None:
    total = len(final) or 1
    env_ready = sum(1 for row in final if row.get("env_setup_success") or row.get("milestone_environment_ready") == "passed")
    executed = sum(
        1
        for row in final
        if row.get("milestone_request_executed") == "passed"
        or row.get("target_oracle_success")
        or row.get("status") == "SUCCESS"
        or row.get("success_level")
    )
    target_ev = sum(
        1
        for row in final
        if row.get("target_oracle_success")
        or row.get("ips_matched")
        or row.get("status_code") in {"数据库命中", "目标命中", "检测命中"}
        or row.get("passed")
    )
    repro = sum(1 for row in final if row.get("repro_complete"))
    passed = sum(1 for row in final if row.get("passed"))

    lines = [
        "# A档前10条本地批测分层汇总",
        "",
        f"- 时间：{datetime.now().isoformat(timespec='seconds')}",
        f"- 队列：`output/queue/A_ready_try_latest.txt` 第 1–10 条",
        f"- 模式：local_container + generate_report=False，单条硬超时 {TIMEOUT_S}s（子进程）",
        f"- 明细：`{summary_path}`",
        f"- 脚本：`tools/run_a_queue_batch.py`",
        "",
        "## 分层指标",
        "",
        "| 指标 | 数量 | 占比 |",
        "|---|---:|---:|",
        f"| 环境就绪 | {env_ready} | {env_ready / total:.0%} |",
        f"| 已执行/有 success_level | {executed} | {executed / total:.0%} |",
        f"| 目标/检测证据或 passed | {target_ev} | {target_ev / total:.0%} |",
        f"| 可复现归档 complete | {repro} | {repro / total:.0%} |",
        f"| passed | {passed} | {passed / total:.0%} |",
        "",
        "## 明细",
        "",
        "| # | CVE | status_code | tier | failure | env | evidence | repro | s |",
        "|---:|---|---|---|---|---|---|---|---:|",
    ]
    for row in final:
        evidence = row.get("target_oracle_success") or row.get("ips_matched") or row.get("passed")
        lines.append(
            f"| {row.get('index')} | {row.get('cve_id')} | {row.get('status_code') or '-'} | "
            f"{row.get('success_tier') or '-'} | {row.get('failure_class') or '-'} | "
            f"{'Y' if row.get('env_setup_success') else 'N'} | "
            f"{'Y' if evidence else 'N'} | "
            f"{'Y' if row.get('repro_complete') else 'N'} | {row.get('elapsed_seconds')} |"
        )
    lines += ["", "## 状态码分布", ""]
    for key, value in Counter(row.get("status_code") or "?" for row in final).most_common():
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## success_tier 分布", ""]
    for key, value in Counter(row.get("success_tier") or "无" for row in final).most_common():
        lines.append(f"- `{key}`: {value}")
    lines += [
        "",
        "## 初步解读",
        "",
        "- A 档=有 compose + 本地 PoC 供给，**不等于**必然成功。",
        "- 分层指标用于扩量：先看环境就绪与已执行，再看证据/归档。",
        "- HTTP 常见失败：PoC 与环境不匹配、目标未验证、超时/搜索拉长。",
        "- DB 样板（如 CVE-2012-2122）应维持「数据库命中 / 可复现归档」。",
        "",
        "## 与扩量战略",
        "",
        "- 主粮队列（A/B）需靠批测反馈修 PoC 匹配与环境稳定性。",
        "- 金标准 DB 条数少但稳；编号增长仍主要靠 HTTP 库存转化。",
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", REPORT)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cves = load_cves()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = OUT_DIR / f"A_batch_core_1_10_{ts}.json"

    # resume: merge latest incomplete summary if same 10 CVEs
    prior: dict[str, dict] = {}
    for path in sorted(OUT_DIR.glob("A_batch_core_1_10_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for row in data.get("results") or []:
            cve = str(row.get("cve_id") or "")
            if cve and cve not in prior:
                # keep non-timeout successes/failures; retry timeouts
                if row.get("status") != "TIMEOUT":
                    prior[cve] = row
        if prior:
            print(f"resume from {path.name}, kept {len(prior)}")
            break

    final: list[dict] = []
    for index, cve in enumerate(cves, 1):
        if cve in prior:
            row = dict(prior[cve])
            row["index"] = index
            final.append(row)
            print(f"[{index}/{len(cves)}] keep {cve} {row.get('status_code')}", flush=True)
            continue
        print(f"\n==== [{index}/{len(cves)}] {cve} ====", flush=True)
        row = run_one(cve, index)
        final.append(row)
        print(
            f"  -> {row['status']}/{row['status_code']} tier={row['success_tier']} "
            f"env={row['env_setup_success']} oracle={row['target_oracle_success']} "
            f"repro={row['repro_complete']} {row['elapsed_seconds']}s",
            flush=True,
        )
        summary_path.write_text(
            json.dumps({"results": final, "updated_at": datetime.now().isoformat()}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    cleanup_docker()
    summary_path.write_text(
        json.dumps({"results": final, "updated_at": datetime.now().isoformat()}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_report(final, summary_path)

    print("\n===== LAYERED SUMMARY =====")
    print("total", len(final))
    print("status_code", Counter(row.get("status_code") or "?" for row in final))
    print("success_tier", Counter(row.get("success_tier") or "无" for row in final))
    env_ready = sum(1 for row in final if row.get("env_setup_success"))
    executed = sum(1 for row in final if row.get("milestone_request_executed") == "passed" or row.get("success_level") or row.get("status") == "SUCCESS")
    target_ev = sum(1 for row in final if row.get("target_oracle_success") or row.get("ips_matched") or row.get("passed"))
    repro = sum(1 for row in final if row.get("repro_complete"))
    print(f"env_ready {env_ready}/{len(final)}")
    print(f"executed {executed}/{len(final)}")
    print(f"target_evidence {target_ev}/{len(final)}")
    print(f"repro_complete {repro}/{len(final)}")
    print("passed", sum(1 for row in final if row.get("passed")))
    print("summary", summary_path)


if __name__ == "__main__":
    main()
