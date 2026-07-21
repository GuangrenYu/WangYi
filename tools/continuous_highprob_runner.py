"""Continuously test high-probability local CVEs with pull->test->delete cycle.

- Skip already-passed golds
- Only docker pull (writes to Docker data dir on F:)
- After each CVE: compose teardown already removes containers; also delete used images
- Does NOT use D: for docker data
"""

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

OUT = ROOT / "output" / "queue"
LOG = OUT / "continuous_highprob.log"
STATE = OUT / "continuous_highprob_state.json"
LOCK = OUT / "continuous_highprob.lock"
PASSED = {
    "CVE-2012-2122",
    "CVE-2018-1058",
    "CVE-2019-9193",
    "CVE-2018-8715",  # continuous runner 已目标命中
}
# Images too large / known heavy (>~1.5GB or slow pull) — skip entirely
SKIP_IMAGES = {
    "vulhub/teamcity:2023.05.3",
    "vulhub/teamcity:2023.11.3",
    "budibase/couchdb:v3.3.3-sqs-v2.1.1",
    "minio/minio:RELEASE.2025-09-07T16-13-09Z",
    "vulhub/budibase:3.31.4-worker",
    "vulhub/budibase:3.31.4-apps",
    "vulhub/budibase:3.31.4-proxy",
    "vulhub/coldfusion:2018.0.15",
    "vulhub/coldfusion:8.0.1",
    "vulhub/oracle:12c-ee",
    "vulhub/gitlab:8.13.1",
    "vulhub/django:4.0.5",
    "vulhub/django:3.0.3",
    "vulhub/django:2.2.3",
    "vultarget/django_sqli-cve_2019_14234:2.2.3",
    "nacos/nacos-server:1.4.0",
    "vulhub/geoserver:2.19.1",
    "vulhub/rails:5.0.7",
}
# Substring match against image refs (case-insensitive)
SKIP_IMAGE_SUBSTR = (
    "teamcity",
    "budibase",
    "minio",
    "coldfusion",
    "oracle",
    "gitlab",
    "django",
    "geoserver",
    "nacos-server",
    "liferay",
    "weblogic",
    "metersphere",
    "kafka",
    "ofbiz",
    "confluence",
    "hugegraph",
    "jimureport",
    "linkis",
)
TIMEOUT = 240  # 160s 偏紧，成功样本常 120–150s


def _int_env(name: str, default: int) -> int:
    try:
        val = int(str(os.getenv(name, "")).strip())
        return val if val > 0 else default
    except (TypeError, ValueError):
        return default


# 单镜像 pull 超时：调短则"拉不动的大镜像"快速失败、跳过，
# 时间集中到能快速拉完的小镜像上（= 小镜像优先）。默认 200s，可用 HIGHPROB_PULL_TIMEOUT 覆盖。
PULL_TIMEOUT = _int_env("HIGHPROB_PULL_TIMEOUT", 200)

# 代理故障时可用 HIGHPROB_DISABLE_PROXY=true 让子进程禁代理直连 LLM；代理正常时默认不干预
DISABLE_PROXY = os.getenv("HIGHPROB_DISABLE_PROXY", "false").strip().lower() in {"1", "true", "yes", "on"}
# docker pull 故障时可用 HIGHPROB_CACHED_ONLY=true 只跑镜像全部已缓存的 CVE；代理正常时默认允许 pull
CACHED_ONLY = os.getenv("HIGHPROB_CACHED_ONLY", "false").strip().lower() in {"1", "true", "yes", "on"}


def subprocess_env() -> dict:
    """子进程环境：可选禁代理，避免继承 .env 里已失效的 HTTP(S)_PROXY。"""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    if DISABLE_PROXY:
        env["CVE_HUNTER_DISABLE_PROXY"] = "true"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            env.pop(k, None)
    return env


def log(msg: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def sh(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
    )


def docker_images() -> set[str]:
    r = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    return {ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip() and ln.strip() != "<none>:<none>"}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}"],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
            )
        except Exception:
            return False
        return str(pid) in (proc.stdout or "")
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def acquire_lock() -> int | None:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = f"{os.getpid()}\n{datetime.now().isoformat()}\n"
    try:
        fd = os.open(str(LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, payload.encode("utf-8"))
        return fd
    except FileExistsError:
        try:
            first = LOCK.read_text(encoding="utf-8").splitlines()[0]
            existing_pid = int(first.strip())
        except Exception:
            existing_pid = -1
        if _pid_alive(existing_pid):
            log(f"REFUSE: another continuous runner is active pid={existing_pid}")
            return None
        log(f"stale lock removed: {LOCK}")
        try:
            LOCK.unlink()
        except FileNotFoundError:
            pass
        fd = os.open(str(LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, payload.encode("utf-8"))
        return fd


def release_lock(fd: int) -> None:
    try:
        os.close(fd)
    finally:
        try:
            LOCK.unlink()
        except FileNotFoundError:
            pass


def cleanup_containers() -> None:
    r = sh(["docker", "ps", "-aq", "--filter", "name=cvehunter"])
    ids = [x.strip() for x in (r.stdout or "").splitlines() if x.strip()]
    if ids:
        sh(["docker", "rm", "-f", *ids])
        log(f"removed containers {len(ids)}")
    # Prevent "all predefined address pools have been fully subnetted"
    r = sh(["docker", "network", "ls", "--format", "{{.Name}}"])
    for name in (r.stdout or "").splitlines():
        name = name.strip()
        if not name or name in {"bridge", "host", "none"}:
            continue
        if name.startswith("cvehunter-") or "cvehunter" in name or name.endswith("_default"):
            sh(["docker", "network", "rm", name])
    sh(["docker", "network", "prune", "-f"])


def load_state() -> dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"results": {}, "started_at": datetime.now().isoformat()}


def save_state(state: dict) -> None:
    state["updated_at"] = datetime.now().isoformat()
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def load_queue_rows() -> list[dict]:
    files = sorted(OUT.glob("本地可跑队列_*.json"), key=lambda p: p.stat().st_mtime)
    if not files:
        return []
    return list(json.loads(files[-1].read_text(encoding="utf-8")).get("results") or [])


def current_passed(state: dict) -> set[str]:
    p = set(PASSED)
    for k, v in (state.get("results") or {}).items():
        if v.get("passed") or v.get("status_code") in {"数据库命中", "目标命中", "检测命中"}:
            p.add(str(k).upper())
    # also strict repro
    for man in (ROOT / "output").glob("CVE-*/repro/manifest.json"):
        try:
            m = json.loads(man.read_text(encoding="utf-8"))
        except Exception:
            continue
        if m.get("status") == "SUCCESS" and m.get("complete"):
            p.add(str(m.get("cve_id") or man.parent.parent.name).upper())
    return p


def is_large_or_skipped_image(img: str, local_sizes: dict[str, str] | None = None) -> str:
    """Return skip reason if image should be avoided, else empty string."""
    if not img:
        return ""
    if img in SKIP_IMAGES:
        return f"skip-list:{img}"
    low = img.lower()
    for sub in SKIP_IMAGE_SUBSTR:
        if sub in low:
            return f"large-pattern:{sub}:{img}"
    if local_sizes and img in local_sizes:
        sz = local_sizes[img]
        if "GB" in sz.upper():
            try:
                n = float(sz.upper().replace("GB", "").strip())
                if n >= 1.5:
                    return f"local-size>={n}GB:{img}"
            except ValueError:
                pass
    return ""


def docker_image_sizes() -> dict[str, str]:
    r = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}"])
    out: dict[str, str] = {}
    for ln in (r.stdout or "").splitlines():
        if "\t" not in ln:
            continue
        name, size = ln.split("\t", 1)
        name, size = name.strip(), size.strip()
        if name and name != "<none>:<none>":
            out[name] = size
    return out


def rank_candidates(rows: list[dict], passed: set[str], tested: set[str]) -> list[dict]:
    local = docker_images()
    sizes = docker_image_sizes()

    def score(r: dict) -> int:
        s = 0
        images = list(r.get("images") or [])
        if r.get("has_raw_http"):
            s += 30
        if r.get("has_execution_spec"):
            s += 15
        if str(r.get("local_kb_source") or "").startswith("local_kb"):
            s += 15
        if r.get("tier") == "A_ready_try":
            s += 10
        if r.get("tier") == "B_env_poc_image_maybe_missing":
            s += 5
        nimg = len(images)
        if nimg <= 1:
            s += 8
        elif nimg <= 2:
            s += 4
        elif nimg >= 5:
            s -= 10
        # Prefer fully/partially cached images (no pull delay)
        if images:
            cached = sum(1 for i in images if i in local)
            if cached == nimg:
                s += 25
            elif cached:
                s += 10
        return s

    out = []
    for r in rows:
        cve = str(r.get("cve_id") or "").upper()
        if not cve or cve in passed or cve in tested:
            continue
        if r.get("tier") not in {"A_ready_try", "B_env_poc_image_maybe_missing"}:
            continue
        if not (r.get("has_raw_http") or r.get("has_execution_spec") or r.get("has_yaml")):
            continue
        images = list(r.get("images") or [])
        skip_reason = ""
        for img in images:
            skip_reason = is_large_or_skipped_image(img, sizes)
            if skip_reason:
                break
        if skip_reason:
            continue
        # 代理/pull 故障时只跑镜像全部已缓存的 CVE，避免卡在拉取上
        if CACHED_ONLY:
            imgs = list(r.get("images") or [])
            if imgs and any(i not in local for i in imgs):
                continue
        out.append(r)
    out.sort(key=lambda r: (-score(r), r["cve_id"]))
    return out


def pull_images(images: list[str]) -> tuple[list[str], list[str]]:
    """Returns (pulled_ok, skip_or_fail_reasons)."""
    local = docker_images()
    sizes = docker_image_sizes()
    pulled = []
    problems: list[str] = []
    for img in images:
        if not img or img in local:
            continue
        reason = is_large_or_skipped_image(img, sizes)
        if reason:
            log(f"SKIP_PULL {reason}")
            problems.append(reason)
            continue
        log(f"PULL {img} (timeout={PULL_TIMEOUT}s)")
        try:
            r = sh(["docker", "pull", img], timeout=PULL_TIMEOUT)
        except subprocess.TimeoutExpired:
            log(f"PULL_TIMEOUT {img}")
            problems.append(f"pull-timeout:{img}")
            # kill stray pull if any
            try:
                sh(["docker", "pull", "--help"], timeout=5)
            except Exception:
                pass
            local = docker_images()
            continue
        if r.returncode == 0:
            pulled.append(img)
            log(f"PULL_OK {img}")
        else:
            msg = (r.stderr or r.stdout or "")[:200]
            log(f"PULL_FAIL {img} {msg}")
            problems.append(f"pull-fail:{img}")
        local = docker_images()
    return pulled, problems


def delete_images(images: list[str]) -> None:
    # User wants free space: delete used images after run (including DB deps for non-gold)
    for img in images:
        if not img:
            continue
        log(f"RMI {img}")
        r = sh(["docker", "rmi", "-f", img], timeout=120)
        if r.returncode == 0 and "no such image" not in (r.stderr or "").lower():
            log(f"RMI_OK {img}")
        else:
            log(f"RMI_SKIP {img} {(r.stderr or '')[:120]}")
    sh(["docker", "image", "prune", "-f"], timeout=120)
    cleanup_containers()


def run_cve(cve: str, index: int) -> dict:
    cleanup_containers()
    code = (
        "from main import execute_cve_as_batch_result; import json; "
        f"r=execute_cve_as_batch_result({index}, '{cve}', generate_report=False, local_container_mode=True); "
        "print('BATCH_JSON:' + json.dumps({k: getattr(r,k,None) for k in "
        "['status','status_code','success_tier','failure_class','passed','elapsed_seconds','poc_source',"
        "'repro_bundle_complete','message']}, ensure_ascii=False, default=str))"
    )
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(ROOT),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=TIMEOUT,
            env=subprocess_env(),
        )
        elapsed = round(time.time() - t0, 1)
        batch = {}
        for line in (proc.stdout or "").splitlines():
            if line.startswith("BATCH_JSON:"):
                batch = json.loads(line[len("BATCH_JSON:") :])
                break
        payload = {}
        rp = ROOT / "output" / cve / "result.json"
        if rp.exists():
            try:
                payload = json.loads(rp.read_text(encoding="utf-8"))
            except Exception:
                pass
        status = batch.get("status") or payload.get("status") or "UNKNOWN"
        status_code = batch.get("status_code") or payload.get("status_code") or ""
        # normalize lightly
        from cve_hunter.status_codes import normalize_status_code
        from cve_hunter.evidence import normalize_success_tier, normalize_failure_class, classify_failure

        status_code = normalize_status_code(status_code)
        tier = normalize_success_tier(batch.get("success_tier") or payload.get("success_tier") or "")
        fc = batch.get("failure_class") or payload.get("failure_class") or ""
        if not fc:
            fc = "无" if status == "SUCCESS" or status_code in {"数据库命中", "目标命中", "检测命中"} else classify_failure(status_code)
        else:
            fc = normalize_failure_class(fc)
        passed = bool(batch.get("passed") or status == "SUCCESS" or status_code in {"数据库命中", "目标命中", "检测命中"})
        env = payload.get("attack_environment") or {}
        setup = payload.get("environment_setup_result") or env.get("setup_result") or {}
        return {
            "cve_id": cve,
            "status": status,
            "status_code": status_code,
            "success_tier": tier,
            "failure_class": fc,
            "passed": passed,
            "elapsed_seconds": batch.get("elapsed_seconds") or elapsed,
            "poc_source": batch.get("poc_source") or payload.get("poc_source") or "",
            "env_setup_success": bool(setup.get("success")),
            "repro_complete": bool(batch.get("repro_bundle_complete") or (payload.get("repro_bundle") or {}).get("complete")),
            "message": str(batch.get("message") or payload.get("message") or "")[:200],
            "finished_at": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        cleanup_containers()
        return {
            "cve_id": cve,
            "status": "TIMEOUT",
            "status_code": "批测异常",
            "success_tier": "无",
            "failure_class": "设施",
            "passed": False,
            "elapsed_seconds": TIMEOUT,
            "poc_source": "",
            "env_setup_success": False,
            "repro_complete": False,
            "message": f"timeout {TIMEOUT}s",
            "finished_at": datetime.now().isoformat(),
        }


def write_report(state: dict) -> None:
    results = list((state.get("results") or {}).values())
    total = max(len(results), 1)
    env = sum(1 for r in results if r.get("env_setup_success"))
    passed = sum(1 for r in results if r.get("passed"))
    repro = sum(1 for r in results if r.get("repro_complete"))
    lines = [
        "# 持续高概率批测汇总",
        "",
        f"- 更新：{datetime.now().isoformat(timespec='seconds')}",
        f"- 状态：`{STATE}`",
        f"- Docker 数据目录：F:\\Docker\\data（禁止 D/C 作 data-root）",
        "",
        "## 指标",
        "",
        f"| 已测 | 环境就绪 | passed | 可复现归档 |",
        f"|---:|---:|---:|---:|",
        f"| {len(results)} | {env} | {passed} | {repro} |",
        "",
        "## 成功",
        "",
    ]
    wins = [r for r in results if r.get("passed")]
    if not wins:
        lines.append("（本轮新跑暂无新增成功；金标准 3 条不重复计入）")
    else:
        lines += ["| CVE | status_code | tier | src |", "|---|---|---|---|"]
        for r in wins:
            lines.append(
                f"| {r.get('cve_id')} | {r.get('status_code')} | {r.get('success_tier') or '-'} | {r.get('poc_source') or '-'} |"
            )
    lines += ["", "## 状态码", ""]
    for k, v in Counter(r.get("status_code") or "?" for r in results).most_common():
        lines.append(f"- `{k}`: {v}")
    lines += ["", "## 明细", ""]
    lines.append("| CVE | status_code | env | passed | repro | src | s |")
    lines.append("|---|---|---|---|---|---|---:|")
    for r in sorted(results, key=lambda x: x.get("finished_at") or ""):
        lines.append(
            f"| {r.get('cve_id')} | {r.get('status_code')} | {'Y' if r.get('env_setup_success') else 'N'} | "
            f"{'Y' if r.get('passed') else 'N'} | {'Y' if r.get('repro_complete') else 'N'} | "
            f"{r.get('poc_source') or '-'} | {r.get('elapsed_seconds')} |"
        )
    path = ROOT / "docs" / "reports" / "持续高概率批测汇总.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    log(f"report {path}")


def _main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    log("=== continuous highprob start (F: docker only) ===")
    # verify docker data path textually
    settings = Path.home() / "AppData/Roaming/Docker/settings-store.json"
    try:
        conf = json.loads(settings.read_text(encoding="utf-8"))
        log(f"Docker data dir: {conf.get('CustomWslDistroDir')}")
        if str(conf.get("CustomWslDistroDir") or "").upper().startswith("C:"):
            log("REFUSE: Docker data on C:")
            return
        if str(conf.get("CustomWslDistroDir") or "").upper().startswith("D:"):
            log("WARN: Docker data still on D: (almost full). Prefer F:")
    except Exception as exc:
        log(f"settings read fail {exc}")

    state = load_state()
    rows = load_queue_rows()
    if not rows:
        log("no queue rows; run screen_local_queue first")
        # refresh once
        sh = subprocess.run([sys.executable, str(ROOT / "tools" / "screen_local_queue.py")], cwd=str(ROOT))
        rows = load_queue_rows()

    # loop until no candidates
    round_id = 0
    while True:
        passed = current_passed(state)
        tested = set((state.get("results") or {}).keys())
        # allow retest only if previous env failure and now we can pull? for now no retest unless not in results
        cands = rank_candidates(rows, passed, tested)
        log(f"round {round_id}: passed_total_golds+new={len(passed)} tested={len(tested)} remaining_highprob={len(cands)}")
        if not cands:
            log("no more high-prob candidates")
            break

        # process one-by-one for monitoring + disk control
        r = cands[0]
        cve = r["cve_id"]
        images = list(r.get("images") or [])
        log(f"=== TEST {cve} images={images} tier={r.get('tier')} ===")
        sizes = docker_image_sizes()
        hard_skip = next(
            (is_large_or_skipped_image(img, sizes) for img in images if is_large_or_skipped_image(img, sizes)),
            "",
        )
        if hard_skip:
            result = {
                "cve_id": cve,
                "status": "SKIPPED",
                "status_code": "批测异常",
                "success_tier": "无",
                "failure_class": "设施",
                "passed": False,
                "elapsed_seconds": 0,
                "poc_source": "",
                "env_setup_success": False,
                "repro_complete": False,
                "message": f"skip: large image ({hard_skip}) exceeds pull budget",
                "finished_at": datetime.now().isoformat(),
                "skipped_reason": hard_skip,
            }
            state.setdefault("results", {})[cve] = result
            save_state(state)
            log(f"SKIP {cve} {hard_skip}")
            write_report(state)
            round_id += 1
            continue

        pulled, pull_problems = pull_images(images)
        local_now = docker_images()
        missing = [img for img in images if img and img not in local_now]
        if missing:
            result = {
                "cve_id": cve,
                "status": "SKIPPED" if pull_problems else "FAILURE",
                "status_code": "环境失败",
                "success_tier": "无",
                "failure_class": "环境",
                "passed": False,
                "elapsed_seconds": 0,
                "poc_source": "",
                "env_setup_success": False,
                "repro_complete": False,
                "message": f"images missing after pull: {missing}; problems={pull_problems[:3]}",
                "finished_at": datetime.now().isoformat(),
            }
            state.setdefault("results", {})[cve] = result
            save_state(state)
            log(f"SKIP/ENV {cve} missing={missing}")
            # free anything we just pulled
            if pulled:
                delete_images(pulled)
            write_report(state)
            round_id += 1
            continue

        result = run_cve(cve, len(tested) + 1)
        state.setdefault("results", {})[cve] = result
        save_state(state)
        log(
            f"RESULT {cve} {result.get('status')}/{result.get('status_code')} "
            f"passed={result.get('passed')} env={result.get('env_setup_success')} "
            f"src={result.get('poc_source')} {result.get('elapsed_seconds')}s"
        )
        # free only images pulled in this round; keep pre-cached images for future CVEs
        if result.get("passed"):
            log(f"KEEP images for WIN {cve}: {images}")
        elif pulled:
            delete_images(pulled)
        write_report(state)

        # refresh queue occasionally to update cache flags
        round_id += 1
        if round_id % 5 == 0:
            log("refresh queue")
            subprocess.run([sys.executable, str(ROOT / "tools" / "screen_local_queue.py")], cwd=str(ROOT))
            rows = load_queue_rows()

    write_report(state)
    log("=== continuous highprob complete ===")
    # final summary to stdout
    results = list((state.get("results") or {}).values())
    wins = [r for r in results if r.get("passed")]
    log(f"new passes this run: {len(wins)}")
    for w in wins:
        log(f"  WIN {w.get('cve_id')} {w.get('status_code')}")


def main() -> None:
    lock_fd = acquire_lock()
    if lock_fd is None:
        return
    try:
        _main()
    finally:
        release_lock(lock_fd)


if __name__ == "__main__":
    main()
