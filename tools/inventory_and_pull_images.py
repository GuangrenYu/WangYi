"""Inventory missing compose images and optionally docker pull them.

Images are stored by Docker Desktop at F:\\Docker\\data (not C:).
Prefer DB-related images, then A/B queue missing images.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "queue"
DB_NAME_MARKERS = ("mysql", "mariadb", "postgres", "redis", "mongo", "h2")
DB_PATH_MARKERS = ("/mysql/", "/postgres/", "/mariadb/", "/redis/", "/mongo/", "/h2database/")


def docker_images() -> set[str]:
    out = subprocess.check_output(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {line.strip() for line in out.splitlines() if line.strip() and line.strip() != "<none>:<none>"}


def load_queue_rows() -> tuple[list[dict], str]:
    files = sorted(OUT_DIR.glob("本地可跑队列_*.json"), key=lambda p: p.stat().st_mtime)
    if not files:
        return [], ""
    data = json.loads(files[-1].read_text(encoding="utf-8"))
    return list(data.get("results") or []), str(files[-1])


def compose_images(path: Path) -> list[str]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return []
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return []
    return [
        str(svc["image"]).strip()
        for svc in services.values()
        if isinstance(svc, dict) and svc.get("image")
    ]


def is_db_related(row: dict) -> bool:
    if row.get("protocol") == "database" or row.get("true_db_spec") or row.get("is_db_path"):
        return True
    path = str(row.get("primary_compose") or "").replace("\\", "/").lower()
    return any(marker in path for marker in DB_PATH_MARKERS)


def vulhub_db_family_missing(cached: set[str]) -> list[str]:
    missing: list[str] = []
    for rel in ("mysql", "postgres", "redis", "h2database"):
        base = ROOT / "third_party" / "vulhub" / rel
        if not base.is_dir():
            continue
        for compose in base.rglob("docker-compose.yml"):
            for img in compose_images(compose):
                if img and img not in cached:
                    missing.append(img)
    return sorted(set(missing))


def build_inventory() -> dict:
    cached = docker_images()
    rows, queue_file = load_queue_rows()
    ab_missing: Counter[str] = Counter()
    db_missing: Counter[str] = Counter()
    all_missing: Counter[str] = Counter()
    cves_missing: list[dict] = []

    for row in rows:
        images = list(row.get("images") or [])
        miss = [img for img in images if img not in cached]
        if not miss:
            continue
        db = is_db_related(row)
        cves_missing.append(
            {
                "cve": row.get("cve_id"),
                "tier": row.get("tier"),
                "missing": miss,
                "is_db": db,
                "compose": row.get("primary_compose"),
            }
        )
        for img in miss:
            all_missing[img] += 1
            if row.get("tier") in {"A_ready_try", "B_env_poc_image_maybe_missing"}:
                ab_missing[img] += 1
            if db:
                db_missing[img] += 1

    family_missing = vulhub_db_family_missing(cached)
    priority: list[str] = []
    seen: set[str] = set()
    for img, _ in db_missing.most_common():
        if img not in seen:
            priority.append(img)
            seen.add(img)
    for img in family_missing:
        if img not in seen:
            priority.append(img)
            seen.add(img)
    for img, _ in ab_missing.most_common():
        if img not in seen:
            priority.append(img)
            seen.add(img)

    db_only = [
        img
        for img in priority
        if any(marker in img.lower() for marker in DB_NAME_MARKERS) or img in set(family_missing)
    ]

    inv = {
        "generated_at": datetime.now().isoformat(),
        "docker_data_note": "Docker Desktop CustomWslDistroDir=F:\\Docker\\data (NOT C:). Pulls land on F:.",
        "do_not_use_c_drive": True,
        "cached_count": len(cached),
        "queue_file": queue_file,
        "cves_with_missing": cves_missing,
        "missing_ab": ab_missing.most_common(),
        "missing_db": db_missing.most_common(),
        "missing_all": all_missing.most_common(),
        "vulhub_db_family_missing": family_missing,
        "priority_pull": priority,
        "db_only_pull": db_only,
        "counts": {
            "cves_with_missing": len(cves_missing),
            "unique_missing_all": len(all_missing),
            "unique_missing_ab": len(ab_missing),
            "unique_missing_db": len(db_missing),
            "priority_total": len(priority),
            "db_only_total": len(db_only),
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "missing_images_inventory.json").write_text(
        json.dumps(inv, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (OUT_DIR / "images_to_pull_priority.txt").write_text(
        "\n".join(priority) + ("\n" if priority else ""), encoding="utf-8"
    )
    (OUT_DIR / "images_to_pull_db_only.txt").write_text(
        "\n".join(db_only) + ("\n" if db_only else ""), encoding="utf-8"
    )
    return inv


def pull_images(images: list[str], *, limit: int | None = None, log_path: Path) -> dict:
    selected = images[: limit or len(images)]
    results = []
    ok = fail = 0
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n==== pull start {datetime.now().isoformat()} count={len(selected)} ====\n")
        for idx, image in enumerate(selected, 1):
            print(f"[{idx}/{len(selected)}] docker pull {image}", flush=True)
            log.write(f"\n--- {image} ---\n")
            t0 = time.time()
            try:
                proc = subprocess.run(
                    ["docker", "pull", image],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=600,
                )
                elapsed = round(time.time() - t0, 1)
                success = proc.returncode == 0
                if success:
                    ok += 1
                else:
                    fail += 1
                tail = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-1000:]
                log.write(f"rc={proc.returncode} elapsed={elapsed}s\n{tail}\n")
                results.append(
                    {
                        "image": image,
                        "success": success,
                        "rc": proc.returncode,
                        "elapsed": elapsed,
                        "tail": tail[-300:],
                    }
                )
                print(
                    f"  -> {'OK' if success else 'FAIL'} {elapsed}s",
                    flush=True,
                )
            except subprocess.TimeoutExpired:
                fail += 1
                log.write("TIMEOUT 600s\n")
                results.append({"image": image, "success": False, "rc": -9, "elapsed": 600, "tail": "timeout"})
                print("  -> TIMEOUT", flush=True)
            except Exception as exc:  # noqa: BLE001
                fail += 1
                log.write(f"ERROR {exc}\n")
                results.append({"image": image, "success": False, "rc": -1, "elapsed": 0, "tail": str(exc)})
                print("  -> ERROR", exc, flush=True)
        log.write(f"\n==== pull end ok={ok} fail={fail} ====\n")
    summary = {
        "started_at": datetime.now().isoformat(),
        "requested": selected,
        "ok": ok,
        "fail": fail,
        "results": results,
        "docker_data_note": "Images stored via Docker Desktop on F:\\Docker\\data",
    }
    summary_path = OUT_DIR / f"image_pull_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print("summary", summary_path)
    return summary


def write_report(inv: dict, pull_summary: dict | None = None) -> Path:
    counts = inv.get("counts") or {}
    lines = [
        "# 环境镜像补充下载报告",
        "",
        f"- 时间：{datetime.now().isoformat(timespec='seconds')}",
        f"- Docker 数据目录：**F:\\Docker\\data**（非 C 盘；已从 D: 迁移）",
        f"- 当前已缓存镜像数：{inv.get('cached_count')}",
        f"- 队列：`{inv.get('queue_file')}`",
        "",
        "## 缺失统计",
        "",
        f"| 项 | 数量 |",
        f"|---|---:|",
        f"| 有缺失镜像的 CVE | {counts.get('cves_with_missing', 0)} |",
        f"| 唯一缺失镜像（全部） | {counts.get('unique_missing_all', 0)} |",
        f"| A+B 队列缺失 | {counts.get('unique_missing_ab', 0)} |",
        f"| DB 相关缺失 | {counts.get('unique_missing_db', 0)} |",
        f"| 优先拉取列表 | {counts.get('priority_total', 0)} |",
        f"| DB 优先子集 | {counts.get('db_only_total', 0)} |",
        "",
        "## DB / 非 HTTP 优先镜像",
        "",
    ]
    db_only = inv.get("db_only_pull") or []
    if not db_only:
        lines.append("（当前 DB 相关镜像均已缓存，或队列中无缺失）")
    else:
        for img in db_only:
            lines.append(f"- `{img}`")
    lines += ["", "## A+B 缺失 Top 20", ""]
    for img, cnt in (inv.get("missing_ab") or [])[:20]:
        lines.append(f"- `{img}` × {cnt}")
    if pull_summary is not None:
        lines += [
            "",
            "## 本次拉取执行",
            "",
            f"- 请求：{len(pull_summary.get('requested') or [])}",
            f"- 成功：{pull_summary.get('ok')}",
            f"- 失败：{pull_summary.get('fail')}",
            "",
        ]
        for row in pull_summary.get("results") or []:
            lines.append(
                f"- {'OK' if row.get('success') else 'FAIL'} `{row.get('image')}` ({row.get('elapsed')}s)"
            )
    lines += [
        "",
        "## 产物",
        "",
        "- `output/queue/missing_images_inventory.json`",
        "- `output/queue/images_to_pull_priority.txt`",
        "- `output/queue/images_to_pull_db_only.txt`",
        "",
        "## 说明",
        "",
        "- **禁止把 Docker 数据目录放到 C 盘**；当前配置为 **F:\\Docker\\data**。",
        "- 拉取顺序：DB 相关 → vulhub mysql/postgres/redis/h2 家族 → A+B 其余。",
        "- 代理：系统/Docker 若已配 7890 则走代理；镜像层写入 F:\\Docker\\data，不写 C: 仓库目录。",
        "",
    ]
    path = ROOT / "docs" / "reports" / "环境镜像补充下载报告.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", path)
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pull", action="store_true", help="执行 docker pull")
    parser.add_argument("--db-only", action="store_true", help="只拉 DB 相关镜像")
    parser.add_argument("--limit", type=int, default=0, help="最多拉取 N 个（0=不限制）")
    args = parser.parse_args()

    inv = build_inventory()
    counts = inv.get("counts") or {}
    print("inventory:", counts)
    print("docker_data_note:", inv.get("docker_data_note"))

    pull_summary = None
    if args.pull:
        images = list(inv.get("db_only_pull") or []) if args.db_only else list(inv.get("priority_pull") or [])
        limit = args.limit or None
        log_path = OUT_DIR / "image_pull.log"
        pull_summary = pull_images(images, limit=limit, log_path=log_path)
        # refresh inventory after pull
        inv = build_inventory()
    write_report(inv, pull_summary)


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    main()
