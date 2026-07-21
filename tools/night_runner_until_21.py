"""Keep testing until local 21:00: finish A-tier, pull images, run more batches.

Designed for unattended overnight/evening runs on Windows.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "output" / "queue"
LOG = OUT / "night_runner_until_21.log"
STOP_HOUR = 21  # stop starting new heavy work after 21:00 local time


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def now_before_stop() -> bool:
    return datetime.now().hour < STOP_HOUR


def run(cmd: list[str] | str, timeout: int | None = None, shell: bool = False) -> int:
    log(f"$ {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            shell=shell,
            timeout=timeout,
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
        )
        log(f"exit={proc.returncode}")
        return int(proc.returncode)
    except subprocess.TimeoutExpired:
        log("TIMEOUT")
        return -9
    except Exception as exc:  # noqa: BLE001
        log(f"ERROR {exc}")
        return -1


def a_done_count() -> int:
    p = OUT / "A_full_batch_state.json"
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return len(data.get("results") or {})
    except Exception:
        return 0


def a_total() -> int:
    p = OUT / "A_ready_try_latest.txt"
    if not p.exists():
        return 59
    return len([x for x in p.read_text(encoding="utf-8").splitlines() if x.strip()])


def ensure_http2pcap() -> None:
    try:
        import urllib.request

        urllib.request.urlopen("http://127.0.0.1:3012/health", timeout=2).read()
        log("http2pcap health ok")
        return
    except Exception:
        pass
    log("starting http2pcap")
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8"}
    subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "local_http2pcap_service.py"), "--host", "127.0.0.1", "--port", "3012"],
        cwd=str(ROOT),
        env=env,
        stdout=open(OUT / "http2pcap_night.log", "a", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    time.sleep(3)


def cleanup_docker() -> None:
    try:
        out = subprocess.check_output(
            ["docker", "ps", "-aq", "--filter", "name=cvehunter"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        ids = [x.strip() for x in out.splitlines() if x.strip()]
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], check=False, capture_output=True)
            log(f"removed {len(ids)} cvehunter containers")
    except Exception as exc:  # noqa: BLE001
        log(f"cleanup docker: {exc}")


def seed_db_golds() -> None:
    state_path = OUT / "A_full_batch_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {"results": {}}
    results = state.setdefault("results", {})
    for cve in ["CVE-2012-2122", "CVE-2018-1058", "CVE-2019-9193"]:
        man = ROOT / "output" / cve / "repro" / "manifest.json"
        res = ROOT / "output" / cve / "result.json"
        payload = json.loads(res.read_text(encoding="utf-8")) if res.exists() else {}
        manifest = json.loads(man.read_text(encoding="utf-8")) if man.exists() else {}
        if payload.get("status") == "SUCCESS" or manifest.get("status") == "SUCCESS":
            results[cve] = {
                "index": 0,
                "cve_id": cve,
                "status": "SUCCESS",
                "status_code": payload.get("status_code")
                or manifest.get("status_code")
                or "数据库命中",
                "success_tier": payload.get("success_tier")
                or manifest.get("success_tier")
                or "可复现归档",
                "failure_class": "无",
                "passed": True,
                "elapsed_seconds": 0,
                "poc_source": payload.get("poc_source") or "local_kb_vulhub_sql",
                "protocol": "database",
                "env_setup_success": True,
                "milestone_environment_ready": "passed",
                "milestone_request_executed": "passed",
                "target_oracle_success": True,
                "ips_matched": False,
                "repro_complete": True,
                "success_level": "database_oracle",
                "message": "seeded-night",
                "phases_tried": ["local_kb_search"],
                "finished_at": datetime.now().isoformat(),
                "seeded": True,
            }
    state["results"] = results
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"seeded golds; A state count={len(results)}")


def phase_finish_a() -> None:
    total = a_total()
    while now_before_stop():
        done = a_done_count()
        log(f"A progress {done}/{total}")
        if done >= total:
            log("A tier complete")
            # finalize report
            run([sys.executable, str(ROOT / "tools" / "run_a_full_batch.py"), "--file", str(OUT / "A_ready_try_latest.txt"), "--timeout", "120"])
            return
        # resume batch (skips finished)
        cleanup_docker()
        rc = run(
            [
                sys.executable,
                str(ROOT / "tools" / "run_a_full_batch.py"),
                "--file",
                str(OUT / "A_ready_try_latest.txt"),
                "--timeout",
                "160",
            ],
            timeout=None,
        )
        log(f"A batch pass exit={rc} done={a_done_count()}/{total}")
        if a_done_count() >= total:
            return
        time.sleep(5)


def phase_pull_images(limit: int = 20) -> None:
    if not now_before_stop():
        return
    log(f"pull images limit={limit}")
    run(
        [sys.executable, str(ROOT / "tools" / "inventory_and_pull_images.py"), "--pull", "--limit", str(limit)],
        timeout=3600,
    )


def phase_refresh_queue() -> None:
    log("refresh screen_local_queue")
    run([sys.executable, str(ROOT / "tools" / "screen_local_queue.py")], timeout=1800)


def build_next_batch_list(n: int = 20) -> Path:
    """Build next test list from A leftovers + B with some cache + DB."""
    inv_files = sorted(OUT.glob("本地可跑队列_*.json"), key=lambda p: p.stat().st_mtime)
    rows = []
    if inv_files:
        data = json.loads(inv_files[-1].read_text(encoding="utf-8"))
        rows = data.get("results") or []
    a_state = {}
    sp = OUT / "A_full_batch_state.json"
    if sp.exists():
        a_state = (json.loads(sp.read_text(encoding="utf-8")).get("results") or {})

    # Prefer: not-yet-passed A, then B with any cached images, then remaining B
    candidates: list[str] = []
    seen: set[str] = set()

    def add(cve: str) -> None:
        cve = cve.upper()
        if cve in seen:
            return
        # skip already passed golds
        prev = a_state.get(cve) or {}
        if prev.get("passed") or prev.get("status_code") in {"数据库命中", "目标命中", "检测命中"}:
            return
        seen.add(cve)
        candidates.append(cve)

    for r in rows:
        if r.get("tier") == "A_ready_try":
            add(r["cve_id"])
    for r in rows:
        if r.get("tier") == "B_env_poc_image_maybe_missing" and (r.get("images_cached") or 0) > 0:
            add(r["cve_id"])
    for r in rows:
        if r.get("tier") == "B_env_poc_image_maybe_missing":
            add(r["cve_id"])

    batch = candidates[:n]
    path = OUT / "night_next_batch.txt"
    path.write_text("\n".join(batch) + ("\n" if batch else ""), encoding="utf-8")
    log(f"next batch size={len(batch)} -> {path}")
    return path


def phase_run_list(list_path: Path, timeout: int = 160) -> None:
    if not list_path.exists() or not list_path.read_text(encoding="utf-8").strip():
        log(f"empty list {list_path}")
        return
    # Use run_cached_env_batch which has hard timeout per CVE
    run(
        [
            sys.executable,
            str(ROOT / "tools" / "run_cached_env_batch.py"),
            "--file",
            str(list_path),
            "--timeout",
            str(timeout),
        ],
        timeout=None,
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    log("=== night runner start; stop new work after 21:00 ===")
    ensure_http2pcap()
    seed_db_golds()

    # 1) Finish A
    if now_before_stop():
        phase_finish_a()
    else:
        log("already past stop hour before A finish loop")

    # 2) Loop: pull -> refresh -> batch until 21:00
    round_id = 0
    while now_before_stop():
        round_id += 1
        log(f"=== env+test round {round_id} ===")
        cleanup_docker()
        ensure_http2pcap()
        phase_pull_images(limit=15)
        if not now_before_stop():
            break
        phase_refresh_queue()
        if not now_before_stop():
            break
        batch = build_next_batch_list(n=15)
        phase_run_list(batch, timeout=150)
        # small rest
        time.sleep(10)

    # final reports
    log("=== past 21:00 or loops done; finalize ===")
    try:
        run([sys.executable, str(ROOT / "tools" / "run_a_full_batch.py"), "--file", str(OUT / "A_ready_try_latest.txt"), "--timeout", "60"])
    except Exception as exc:  # noqa: BLE001
        log(f"finalize A report err {exc}")
    try:
        run([sys.executable, str(ROOT / "tools" / "inventory_and_pull_images.py")])
    except Exception as exc:  # noqa: BLE001
        log(f"finalize inventory err {exc}")
    log("=== night runner exit ===")


if __name__ == "__main__":
    main()
