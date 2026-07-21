"""Run a CVE list with local-container, no report, hard subprocess timeout."""

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

from cve_hunter.status_codes import normalize_status_code
from cve_hunter.evidence import normalize_success_tier, normalize_failure_class, classify_failure


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
                batch = json.loads(line[len("BATCH_JSON:") :])
                break
        payload = {}
        rp = ROOT / "output" / cve / "result.json"
        if rp.is_file():
            try:
                payload = json.loads(rp.read_text(encoding="utf-8"))
            except Exception:
                payload = {}
        status = (batch or {}).get("status") or payload.get("status") or "UNKNOWN"
        status_code = normalize_status_code((batch or {}).get("status_code") or payload.get("status_code") or "")
        tier = normalize_success_tier((batch or {}).get("success_tier") or payload.get("success_tier") or "")
        fc = (batch or {}).get("failure_class") or payload.get("failure_class") or ""
        if not fc:
            fc = "无" if status == "SUCCESS" or status_code in {"数据库命中", "目标命中", "检测命中"} else classify_failure(status_code)
        else:
            fc = normalize_failure_class(fc)
        milestones = (batch or {}).get("milestones") or payload.get("milestones") or {}
        def ms(name: str) -> str:
            item = milestones.get(name) or {}
            return str(item.get("status") or "") if isinstance(item, dict) else ""
        env_obj = payload.get("attack_environment") or {}
        setup = payload.get("environment_setup_result") or env_obj.get("setup_result") or {}
        success_level = str((batch or {}).get("success_level") or payload.get("success_level") or "")
        return {
            "index": index,
            "cve_id": cve,
            "status": status,
            "status_code": status_code,
            "success_tier": tier or "",
            "failure_class": fc,
            "passed": bool((batch or {}).get("passed") or status == "SUCCESS" or status_code in {"数据库命中", "目标命中", "检测命中"}),
            "elapsed_seconds": (batch or {}).get("elapsed_seconds") or elapsed,
            "poc_source": (batch or {}).get("poc_source") or payload.get("poc_source") or "",
            "protocol": payload.get("protocol") or "",
            "target_url": env_obj.get("target_url") or "",
            "env_setup_success": bool(setup.get("success")) or ms("environment_ready") == "passed",
            "milestone_environment_ready": ms("environment_ready"),
            "milestone_request_executed": ms("request_executed"),
            "target_oracle_success": bool(
                payload.get("target_oracle_success") or success_level in {"target_oracle", "database_oracle"}
            ),
            "ips_matched": bool((batch or {}).get("ips_matched") or payload.get("ips_matched")),
            "repro_complete": bool((batch or {}).get("repro_bundle_complete") or (payload.get("repro_bundle") or {}).get("complete")),
            "success_level": success_level,
            "message": str((batch or {}).get("message") or payload.get("message") or "")[:240],
            "phases_tried": payload.get("phases_tried") or [],
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
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int, default=0)
    args = parser.parse_args()

    path = Path(args.file)
    cves = [line.strip().upper() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.end > 0:
        cves = cves[args.start - 1 : args.end]
    else:
        cves = cves[args.start - 1 :]

    out_dir = ROOT / "output" / "queue"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = out_dir / f"cached_env_batch_{ts}.json"
    results: list[dict] = []

    for i, cve in enumerate(cves, 1):
        print(f"\n==== [{i}/{len(cves)}] {cve} ====", flush=True)
        row = run_one(cve, i, args.timeout)
        results.append(row)
        print(
            f"  -> {row['status']}/{row['status_code']} tier={row['success_tier']} "
            f"env={row['env_setup_success']} evidence={row['target_oracle_success'] or row['ips_matched'] or row['passed']} "
            f"repro={row['repro_complete']} src={row['poc_source']} {row['elapsed_seconds']}s",
            flush=True,
        )
        summary_path.write_text(
            json.dumps({"results": results, "updated_at": datetime.now().isoformat(), "source_file": str(path)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    cleanup_docker()
    total = max(len(results), 1)
    env_ready = sum(1 for r in results if r.get("env_setup_success"))
    executed = sum(
        1
        for r in results
        if r.get("milestone_request_executed") == "passed"
        or r.get("success_level")
        or r.get("status") == "SUCCESS"
        or r.get("status_code") in {"数据库命中", "目标命中", "检测命中", "目标未验证", "无利用证据", "发包服务失败"}
    )
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

    report_lines = [
        "# 现有环境批测分层汇总",
        "",
        f"- 时间：{datetime.now().isoformat(timespec='seconds')}",
        f"- 清单：`{path}`（{len(results)} 条）",
        f"- 模式：local_container + generate_report=False，超时 {args.timeout}s",
        f"- 明细：`{summary_path}`",
        "",
        "## 分层指标",
        "",
        "| 指标 | 数量 | 占比 |",
        "|---|---:|---:|",
        f"| 环境就绪 | {env_ready} | {env_ready/total:.0%} |",
        f"| 已执行/有结果 | {executed} | {executed/total:.0%} |",
        f"| 目标/检测证据 | {evidence} | {evidence/total:.0%} |",
        f"| 可复现归档 | {repro} | {repro/total:.0%} |",
        f"| passed | {passed} | {passed/total:.0%} |",
        "",
        "## 明细",
        "",
        "| # | CVE | status_code | tier | failure | env | evidence | repro | src | s |",
        "|---:|---|---|---|---|---|---|---|---|---:|",
    ]
    for r in results:
        ev = r.get("target_oracle_success") or r.get("ips_matched") or r.get("passed") or r.get("status_code") in {
            "数据库命中",
            "目标命中",
            "检测命中",
        }
        report_lines.append(
            f"| {r['index']} | {r['cve_id']} | {r.get('status_code') or '-'} | {r.get('success_tier') or '-'} | "
            f"{r.get('failure_class') or '-'} | {'Y' if r.get('env_setup_success') else 'N'} | "
            f"{'Y' if ev else 'N'} | {'Y' if r.get('repro_complete') else 'N'} | {r.get('poc_source') or '-'} | "
            f"{r.get('elapsed_seconds')} |"
        )
    report_lines += ["", "## 状态码分布", ""]
    for k, v in Counter(r.get("status_code") or "?" for r in results).most_common():
        report_lines.append(f"- `{k}`: {v}")
    report_lines += ["", "## 解读", ""]
    report_lines.append("- 本批基于「镜像已缓存 + A/DB 优先」清单，检验环境补充下载后的转化。")
    report_lines.append("- 金标准仍看数据库命中/可复现归档；HTTP 看是否从设施失败进入证据层。")
    report_path = ROOT / "docs" / "reports" / "现有环境批测分层汇总.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    print("\n===== SUMMARY =====")
    print(f"env {env_ready}/{len(results)} exec {executed}/{len(results)} evidence {evidence}/{len(results)} repro {repro}/{len(results)} passed {passed}/{len(results)}")
    print("status", Counter(r.get("status_code") for r in results))
    print("wrote", summary_path)
    print("wrote", report_path)


if __name__ == "__main__":
    main()
