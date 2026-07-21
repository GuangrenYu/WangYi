"""Screen 未测试_已有本地环境 for runnable queue: compose + local exploit supply.

Optimized: build compose/readme indexes once; avoid full pcap rglob per CVE.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# repo root on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml

from cve_hunter.agents import (
    _compose_files_for_cve,
    _configured_compose_roots,
    _guess_target_url_from_compose,
)
from cve_hunter.config import cfg
from cve_hunter.poc_parser import extract_http_requests
from cve_hunter.tools.db_spec import extract_database_spec_from_paths

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
LIST_PATH = Path("data/test_cases/未测试_已有本地环境.txt")
OUT_DIR = Path("output/queue")
REPORT_PATH = Path("docs/reports/本地可跑队列筛查_未测试_已有本地环境.md")
DB_MARKERS = ("mysql", "postgres", "mariadb", "redis", "mongo", "sql")
COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def load_cves(path: Path) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = CVE_RE.search(line)
        if not match:
            continue
        cve = match.group(0).upper()
        if cve in seen:
            continue
        seen.add(cve)
        ordered.append(cve)
    return ordered


def docker_images() -> set[str]:
    try:
        out = subprocess.check_output(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:  # noqa: BLE001
        print("docker images failed:", exc)
        return set()
    return {line.strip() for line in out.splitlines() if line.strip() and line.strip() != "<none>:<none>"}


def compose_images(compose_path: Path) -> list[str]:
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
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


def readmes_near_compose(compose_path: Path) -> list[Path]:
    names = ("README.zh-cn.md", "README.md", "README.txt")
    dirs = [compose_path.parent]
    cve_dir = next(
        (
            parent
            for parent in compose_path.parents
            if re.fullmatch(r"CVE-\d{4}-\d{4,7}", parent.name, re.IGNORECASE)
        ),
        None,
    )
    if cve_dir is not None and cve_dir != compose_path.parent:
        dirs.append(cve_dir)
    found: list[Path] = []
    for directory in dirs:
        for name in names:
            path = directory / name
            if path.is_file():
                found.append(path)
    return found


def local_exploit_for_cve(cve_id: str, compose_hits: list[dict]) -> dict:
    """Lightweight local exploit probe (no full pcap index)."""
    year = cve_id[4:8]
    custom = Path(cfg.poc_kb_dir) / "custom" / year / f"{cve_id}.md"
    if custom.is_file():
        text = custom.read_text(encoding="utf-8", errors="ignore")
        raw_list = extract_http_requests(text) or []
        raw = raw_list[0] if raw_list else ""
        if not raw:
            match = re.search(
                r"```(?:http)?\s*\n((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+[\s\S]*?)```",
                text,
                re.I,
            )
            raw = match.group(1).strip() if match else ""
        yaml_match = re.search(r"```(?:yaml|yml)?\s*\n(id:\s*[\s\S]*?)```", text, re.I)
        return {
            "found": bool(raw or yaml_match),
            "source": "local_kb_custom",
            "raw_http": bool(raw),
            "yaml_content": bool(yaml_match),
            "execution_spec": False,
            "db_action": "",
        }

    readmes: list[Path] = []
    for hit in compose_hits:
        readmes.extend(readmes_near_compose(Path(hit["compose"])))
    # unique
    uniq: list[Path] = []
    seen: set[str] = set()
    for path in readmes:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(path)

    raw_http = False
    for path in uniq:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if extract_http_requests(text) or re.search(
            r"```(?:http)?\s*\n(?:GET|POST|PUT|DELETE|PATCH)\s+",
            text,
            re.I,
        ):
            raw_http = True
            break

    spec = extract_database_spec_from_paths(uniq, cve_id=cve_id) if uniq else None
    return {
        "found": bool(raw_http or spec),
        "source": "local_kb_vulhub_sql" if spec else ("local_kb_vulhub" if raw_http else ""),
        "raw_http": raw_http,
        "yaml_content": False,
        "execution_spec": bool(spec),
        "db_action": str((spec or {}).get("action") or ""),
    }


def classify_row(*, has_compose: bool, has_exploit: bool, all_images: list[str], cached: int) -> str:
    if has_compose and has_exploit:
        if all_images and cached == 0:
            return "B_env_poc_image_maybe_missing"
        return "A_ready_try"
    if has_compose and not has_exploit:
        return "C_env_no_local_poc"
    if not has_compose and has_exploit:
        return "D_poc_no_compose"
    return "E_neither"


def main() -> None:
    cves = load_cves(LIST_PATH)
    print(f"loaded {len(cves)} CVEs from {LIST_PATH}")
    images = docker_images()
    print(f"docker images cached: {len(images)}")
    roots = _configured_compose_roots()
    # warm compose indexes once
    for spec in roots:
        root = Path(spec["path"]).expanduser()
        if root.is_dir():
            print(f"warming compose index: {root}")
            _compose_files_for_cve(root, "CVE-2099-0000")

    rows: list[dict] = []
    for idx, cve in enumerate(cves, 1):
        compose_hits: list[dict] = []
        for spec in roots:
            root = Path(spec["path"]).expanduser()
            if not root.is_dir():
                continue
            for compose_file in _compose_files_for_cve(root, cve):
                compose_hits.append(
                    {
                        "compose": str(compose_file),
                        "source": spec.get("source"),
                        "provider": spec.get("provider"),
                        "target_guess": _guess_target_url_from_compose(compose_file),
                        "images": compose_images(compose_file),
                    }
                )

        exploit = local_exploit_for_cve(cve, compose_hits)
        has_compose = bool(compose_hits)
        has_exploit = bool(exploit["raw_http"] or exploit["execution_spec"] or exploit["yaml_content"])
        path_blob = " ".join(item["compose"].lower() for item in compose_hits)
        # 仅路径含真实 DB 产品名才算 db_path；避免 app 名带 sql 误伤
        is_db_path = any(
            f"/{marker}/" in path_blob.replace("\\", "/")
            or f"\\{marker}\\" in path_blob
            or f"/{marker}" in path_blob.replace("\\", "/")
            for marker in ("mysql", "postgres", "mariadb", "redis", "mongo", "h2database")
        )
        all_images: list[str] = []
        for hit in compose_hits:
            all_images.extend(hit.get("images") or [])
        cached = sum(1 for img in all_images if img in images)
        missing = [img for img in all_images if img not in images]
        tier = classify_row(
            has_compose=has_compose,
            has_exploit=has_exploit,
            all_images=all_images,
            cached=cached,
        )
        # execution_spec  alone 不够（auth_bypass 抽取可能误伤 HTTP 应用）
        true_db_spec = bool(exploit["execution_spec"]) and (
            is_db_path
            or exploit["db_action"] in {"multi_session"}
            or any(marker in path_blob for marker in ("mysql", "postgres", "mariadb"))
        )
        protocol = "database" if true_db_spec or is_db_path else (
            "http_candidate" if has_compose else "unknown"
        )
        if true_db_spec:
            protocol = "database"

        rows.append(
            {
                "cve_id": cve,
                "tier": tier,
                "protocol": protocol,
                "has_compose": has_compose,
                "compose_count": len(compose_hits),
                "compose_sources": sorted({hit["source"] for hit in compose_hits if hit.get("source")}),
                "target_guess": next((hit["target_guess"] for hit in compose_hits if hit.get("target_guess")), ""),
                "images": all_images,
                "images_cached": cached,
                "images_missing": missing,
                "local_kb_found": bool(exploit["found"]),
                "local_kb_source": exploit["source"],
                "has_raw_http": exploit["raw_http"],
                "has_execution_spec": exploit["execution_spec"],
                "true_db_spec": true_db_spec,
                "has_yaml": exploit["yaml_content"],
                "db_action": exploit["db_action"],
                "is_db_path": is_db_path,
                "primary_compose": compose_hits[0]["compose"] if compose_hits else "",
            }
        )
        if idx % 20 == 0 or idx == len(cves):
            print(f"progress {idx}/{len(cves)}")

    tier_c = Counter(row["tier"] for row in rows)
    proto_c = Counter(row["protocol"] for row in rows)
    print("total", len(rows))
    print("tiers", dict(tier_c))
    print("protocol", dict(proto_c))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = OUT_DIR / f"本地可跑队列_未测试_已有本地环境_{ts}.json"
    json_path.write_text(
        json.dumps(
            {
                "source_list": str(LIST_PATH),
                "generated_at": datetime.now().isoformat(),
                "total": len(rows),
                "tier_counts": dict(tier_c),
                "protocol_counts": dict(proto_c),
                "results": rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    def write_list(name: str, predicate) -> tuple[Path, int]:
        path = OUT_DIR / name
        items = [row["cve_id"] for row in rows if predicate(row)]
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
        return path, len(items)

    path_a, n_a = write_list("A_ready_try.txt", lambda row: row["tier"] == "A_ready_try")
    path_ab, n_ab = write_list(
        "A_plus_B_try.txt",
        lambda row: row["tier"] in {"A_ready_try", "B_env_poc_image_maybe_missing"},
    )
    _path_db, n_db = write_list(
        "database_candidates.txt",
        lambda row: row["protocol"] == "database" or row.get("true_db_spec") or row["is_db_path"],
    )
    _path_c, n_c = write_list("C_env_no_local_poc.txt", lambda row: row["tier"] == "C_env_no_local_poc")
    (OUT_DIR / "A_ready_try_latest.txt").write_text(path_a.read_text(encoding="utf-8"), encoding="utf-8")
    (OUT_DIR / "A_plus_B_try_latest.txt").write_text(path_ab.read_text(encoding="utf-8"), encoding="utf-8")

    lines = [
        "# 本地可跑队列筛查报告",
        "",
        f"- 生成时间：{datetime.now().isoformat(timespec='seconds')}",
        f"- 源清单：`{LIST_PATH}`（{len(rows)} 条唯一 CVE）",
        f"- 明细 JSON：`{json_path}`",
        f"- 生成脚本：`tools/screen_local_queue.py`",
        "",
        "## 1. 结论摘要",
        "",
        "| 档位 | 含义 | 数量 |",
        "|---|---|---:|",
        f"| **A_ready_try** | 有 compose + 本地 PoC/spec | **{tier_c.get('A_ready_try', 0)}** |",
        f"| **B_env_poc_image_maybe_missing** | 有 compose + 本地 PoC，镜像可能未缓存 | **{tier_c.get('B_env_poc_image_maybe_missing', 0)}** |",
        f"| **C_env_no_local_poc** | 有 compose，本地无 raw/spec/yaml | **{tier_c.get('C_env_no_local_poc', 0)}** |",
        f"| **D_poc_no_compose** | 有本地 PoC，无 compose | **{tier_c.get('D_poc_no_compose', 0)}** |",
        f"| **E_neither** | 两端都弱 | **{tier_c.get('E_neither', 0)}** |",
        "",
        f"**优先批测队列（A+B）= {n_ab} 条**（`output/queue/A_plus_B_try_latest.txt`）。",
        f"- A 单独：{n_a}",
        f"- C 有环境无本地 PoC：{n_c}",
        f"- 数据库相关候选：{n_db}",
        "",
        "## 2. 预估失败结构（跑 A+B，非实测）",
        "",
        "| 预估结果类 | 可能来自 | 直觉占比 |",
        "|---|---|---|",
        "| 环境失败 / 镜像拉取 | B 档、端口冲突 | 中 |",
        "| 无利用证据 / 仅通用检测 / 目标未验证 | A 档 PoC 与环境不匹配 | 高 |",
        "| 检测命中 / 目标命中 | PoC 贴合 | 低～中 |",
        "| 数据库命中 | DB 候选且模板匹配 | 极低（个位） |",
        "",
        "## 3. 协议粗分",
        "",
    ]
    for key, value in proto_c.most_common():
        lines.append(f"- `{key}`: {value}")
    lines += [
        "",
        "## 4. A 档样例（最多 30）",
        "",
        "| CVE | 来源 | target_guess | 本地供给 | 镜像缓存 |",
        "|---|---|---|---|---|",
    ]
    for row in [item for item in rows if item["tier"] == "A_ready_try"][:30]:
        supply = []
        if row["has_raw_http"]:
            supply.append("http")
        if row["has_execution_spec"]:
            supply.append("db_spec")
        if row["has_yaml"]:
            supply.append("yaml")
        lines.append(
            f"| {row['cve_id']} | {','.join(row['compose_sources']) or '-'} | "
            f"`{row['target_guess'] or '-'}` | {','.join(supply) or '-'} | "
            f"{row['images_cached']}/{len(row['images'])} |"
        )
    lines += ["", "## 5. 数据库相关候选", ""]
    db_rows = [
        row
        for row in rows
        if row["protocol"] == "database" or row.get("true_db_spec") or row["is_db_path"]
    ]
    if not db_rows:
        lines.append("（无）")
    else:
        lines += ["| CVE | tier | action | compose |", "|---|---|---|---|"]
        for row in db_rows:
            lines.append(
                f"| {row['cve_id']} | {row['tier']} | {row['db_action'] or '-'} | "
                f"`{row['primary_compose'] or '-'}` |"
            )
    lines += [
        "",
        "## 6. 推荐执行命令",
        "",
        "```bash",
        "export PYTHONIOENCODING=utf-8 PYTHONUTF8=1",
        "python main.py --batch --file output/queue/A_ready_try_latest.txt --start 1 --end 10 --local-container",
        "```",
        "",
        "## 7. 与扩量战略的关系",
        "",
        "- **库存驱动**：本报告对「已有本地环境」分层，优先 A/B。",
        "- **PoC 优先**：C 档应补 KB，不先占满批测。",
        "- **DB 细粮**：database_candidates 单独维护。",
        "- **公告→镜像**：B 档优先 pull tag，而非官网安装包。",
        "",
    ]
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", json_path)
    print("wrote", REPORT_PATH)
    print("A", n_a, "A+B", n_ab, "DB", n_db, "C", n_c)


if __name__ == "__main__":
    main()
