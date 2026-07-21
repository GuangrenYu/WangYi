"""Full A-tier batch with resume: local-container, no report, hard timeout per CVE."""

from __future__ import annotations

import argparse
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

from cve_hunter.evidence import classify_failure, normalize_failure_class, normalize_success_tier
from cve_hunter.status_codes import normalize_status_code

OUT_DIR = ROOT / "output" / "queue"
DEFAULT_LIST = OUT_DIR / "A_ready_try_latest.txt"
STATE_NAME = "A_full_batch_state.json"


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


def load_list(path: Path) -> list[str]:
    return [line.strip().upper() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_state(path: Path) -> dict:
    if not path.is_file():
        return {"results": {}, "started_at": datetime.now().isoformat()}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"results": {}, "started_at": datetime.now().isoformat()}


def save_state(path: Path, state: dict) -> None:
    state["updated_at"] = datetime.now().isoformat()
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def run_one(cve: str, index: int, timeout_s: int) -> dict:
    cleanup_docker()
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    code = (
        "from main import execute_cve_as_batch_result; import json; "
        f"r=execute_cve_as_batch_result({index}, '{cve}', generate_report=False, local_container_mode=True); "
        "print('BATCH_JSON:' + json.dumps(r.__dict__, ensure_ascii=False, default=str))"
    )
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            env=env,
            cwd=str(ROOT),
        )
        elapsed = round(time.time() - t0, 1)
        batch = None
        for line in (proc.stdout or "").splitlines():
            if line.startswith("BATCH_JSON:"):
                try:
                    batch = json.loads(line[len("BATCH_JSON:") :])
                except Exception:
                    batch = None
                break
        payload: dict = {}
        rp = ROOT / "output" / cve / "result.json"
        if rp.is_file():
            try:
                payload = json.loads(rp.read_text(encoding="utf-8"))
            except Exception:
                payload = {}
        status = (batch or {}).get("status") or payload.get("status") or "UNKNOWN"
        status_code = normalize_status_code(
            (batch or {}).get("status_code") or payload.get("status_code") or ""
        )
        tier = normalize_success_tier(
            (batch or {}).get("success_tier") or payload.get("success_tier") or ""
        )
        fc = (batch or {}).get("failure_class") or payload.get("failure_class") or ""
        if not fc:
            fc = (
                "无"
                if status == "SUCCESS" or status_code in {"数据库命中", "目标命中", "检测命中"}
                else classify_failure(status_code)
            )
        else:
            fc = normalize_failure_class(fc)
        milestones = (batch or {}).get("milestones") or payload.get("milestones") or {}

        def ms(name: str) -> str:
            item = milestones.get(name) or {}
            return str(item.get("status") or "") if isinstance(item, dict) else ""

        env_obj = payload.get("attack_environment") or {}
        setup = payload.get("environment_setup_result") or env_obj.get("setup_result") or {}
        success_level = str((batch or {}).get("success_level") or payload.get("success_level") or "")
        passed = bool(
            (batch or {}).get("passed")
            or status == "SUCCESS"
            or status_code in {"数据库命中", "目标命中", "检测命中"}
        )
        return {
            "index": index,
            "cve_id": cve,
            "status": status,
            "status_code": status_code,
            "success_tier": tier or "",
            "failure_class": fc,
            "passed": passed,
            "elapsed_seconds": (batch or {}).get("elapsed_seconds") or elapsed,
            "poc_source": (batch or {}).get("poc_source") or payload.get("poc_source") or "",
            "protocol": payload.get("protocol") or "",
            "target_url": env_obj.get("target_url") or "",
            "env_setup_success": bool(setup.get("success")) or ms("environment_ready") == "passed",
            "milestone_environment_ready": ms("environment_ready"),
            "milestone_request_executed": ms("request_executed"),
            "target_oracle_success": bool(
                payload.get("target_oracle_success")
                or success_level in {"target_oracle", "database_oracle"}
            ),
            "ips_matched": bool((batch or {}).get("ips_matched") or payload.get("ips_matched")),
            "repro_complete": bool(
                (batch or {}).get("repro_bundle_complete")
                or (payload.get("repro_bundle") or {}).get("complete")
            ),
            "success_level": success_level,
            "message": str((batch or {}).get("message") or payload.get("message") or "")[:240],
            "phases_tried": payload.get("phases_tried") or [],
            "finished_at": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        cleanup_docker()
        return {
            "index": index,
            "cve_id": cve,
            "status": "TIMEOUT",
            "status_code": "批测异常",
            "success_tier": "无",
            "failure_class": "设施",
            "passed": False,
            "elapsed_seconds": timeout_s,
            "poc_source": "",
            "protocol": "",
            "target_url": "",
            "env_setup_success": False,
            "milestone_environment_ready": "",
            "milestone_request_executed": "",
            "target_oracle_success": False,
            "ips_matched": False,
            "repro_complete": False,
            "success_level": "",
            "message": f"timeout {timeout_s}s",
            "phases_tried": [],
            "finished_at": datetime.now().isoformat(),
        }


def write_report(results: list[dict], state_path: Path, list_path: Path) -> Path:
    total = max(len(results), 1)
    env_ready = sum(1 for r in results if r.get("env_setup_success"))
    evidence = sum(
        1
        for r in results
        if r.get("target_oracle_success")
        or r.get("ips_matched")
        or r.get("passed")
        or r.get("status_code") in {"数据库命中", "目标命中", "检测命中"}
    )
    repro = sum(1 for r in results if r.get("repro_complete"))
    passed = sum(1 for r in results if r.get("passed"))
    lines = [
        "# A档全量批测分层汇总",
        "",
        f"- 时间：{datetime.now().isoformat(timespec='seconds')}",
        f"- 清单：`{list_path}`（完成 {len(results)} 条）",
        f"- 状态：`{state_path}`",
        "- 模式：local_container + generate_report=False + local_kb 优先",
        "",
        "## 分层指标",
        "",
        "| 指标 | 数量 | 占比 |",
        "|---|---:|---:|",
        f"| 环境就绪 | {env_ready} | {env_ready / total:.0%} |",
        f"| 目标/检测证据 | {evidence} | {evidence / total:.0%} |",
        f"| 可复现归档 | {repro} | {repro / total:.0%} |",
        f"| passed | {passed} | {passed / total:.0%} |",
        "",
        "## 状态码分布",
        "",
    ]
    for key, value in Counter(r.get("status_code") or "?" for r in results).most_common():
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## 成功明细", ""]
    wins = [
        r
        for r in results
        if r.get("passed") or r.get("status_code") in {"数据库命中", "目标命中", "检测命中"}
    ]
    if not wins:
        lines.append("（无）")
    else:
        lines.append("| CVE | status_code | tier | src |")
        lines.append("|---|---|---|---|")
        for r in wins:
            lines.append(
                f"| {r.get('cve_id')} | {r.get('status_code')} | {r.get('success_tier') or '-'} | {r.get('poc_source') or '-'} |"
            )
    lines += ["", "## 全量明细", ""]
    lines.append("| # | CVE | status_code | tier | env | evidence | repro | src | s |")
    lines.append("|---:|---|---|---|---|---|---|---|---:|")
    for r in results:
        ev = (
            r.get("target_oracle_success")
            or r.get("ips_matched")
            or r.get("passed")
            or r.get("status_code") in {"数据库命中", "目标命中", "检测命中"}
        )
        lines.append(
            f"| {r.get('index')} | {r.get('cve_id')} | {r.get('status_code') or '-'} | "
            f"{r.get('success_tier') or '-'} | {'Y' if r.get('env_setup_success') else 'N'} | "
            f"{'Y' if ev else 'N'} | {'Y' if r.get('repro_complete') else 'N'} | "
            f"{r.get('poc_source') or '-'} | {r.get('elapsed_seconds')} |"
        )
    report = ROOT / "docs" / "reports" / "A档全量批测分层汇总.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default=str(DEFAULT_LIST))
    parser.add_argument("--timeout", type=int, default=200)
    parser.add_argument("--retry-timeouts", action="store_true", help="重跑 TIMEOUT/批测异常")
    parser.add_argument("--only-missing", action="store_true", help="只跑尚未有结果的")
    args = parser.parse_args()

    list_path = Path(args.file)
    cves = load_list(list_path)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    state_path = OUT_DIR / STATE_NAME
    state = load_state(state_path)
    results_map: dict[str, dict] = dict(state.get("results") or {})

    print(f"list={list_path} total={len(cves)} done={len(results_map)} timeout={args.timeout}s", flush=True)

    for index, cve in enumerate(cves, 1):
        prev = results_map.get(cve)
        if prev and prev.get("finished_at"):
            st = str(prev.get("status") or "")
            sc = str(prev.get("status_code") or "")
            is_timeout = st in {"TIMEOUT", "ERROR"} or sc in {"批测异常"}
            # 默认：有结果就跳过；仅 --retry-timeouts 时重跑超时/异常
            if not args.retry_timeouts or not is_timeout:
                print(f"[{index}/{len(cves)}] keep {cve} {sc or st}", flush=True)
                continue
            print(f"[{index}/{len(cves)}] retry-timeout {cve}", flush=True)

        print(f"\n==== [{index}/{len(cves)}] {cve} ====", flush=True)
        row = run_one(cve, index, args.timeout)
        results_map[cve] = row
        state["results"] = results_map
        save_state(state_path, state)
        print(
            f"  -> {row['status']}/{row['status_code']} tier={row.get('success_tier')} "
            f"env={row.get('env_setup_success')} passed={row.get('passed')} "
            f"src={row.get('poc_source')} {row.get('elapsed_seconds')}s",
            flush=True,
        )

    cleanup_docker()
    # ordered results
    ordered = []
    for index, cve in enumerate(cves, 1):
        row = dict(results_map.get(cve) or {"cve_id": cve, "status": "MISSING", "status_code": "批测异常", "index": index})
        row["index"] = index
        ordered.append(row)
    report = write_report(ordered, state_path, list_path)
    summary_path = OUT_DIR / f"A_full_batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    summary_path.write_text(
        json.dumps({"results": ordered, "state": str(state_path)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print("\n===== FINAL =====")
    print("done", len(ordered))
    print("status", Counter(r.get("status_code") or "?" for r in ordered))
    print(
        "passed",
        sum(1 for r in ordered if r.get("passed")),
        "env",
        sum(1 for r in ordered if r.get("env_setup_success")),
        "repro",
        sum(1 for r in ordered if r.get("repro_complete")),
    )
    print("state", state_path)
    print("summary", summary_path)
    print("report", report)


if __name__ == "__main__":
    main()
