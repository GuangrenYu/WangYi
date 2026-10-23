#!/usr/bin/env python3
"""归档本轮成功 CVE，并把命中结果写回原始统计表。

做两件事（都不调 LLM；只从内网 http2pcap 服务拉 pcap，不碰公网）：

1. `archives/successful_cve_0917/<CVE>/` —— 补齐本轮有 CVE 点名证据、但归档里还缺的
   CVE：`poc.http` / `poc.yaml` + 原始 pcap 文件名 + `result.json`（归因记录）。
2. `工作流迪普IPS结果统计new.xlsx` —— J/K 列取「原值 or 本次命中」的并集，
   「统计」sheet 的 B2..B5 重算。原表第 7 行往后的 token 成本表不动。

归档判定只认**本轮 IPS 日志点名该 CVE** 的记录。表内某行标了「是」但本轮无点名证据的
（多 CVE 行由同行另一个 CVE 带上的、属于用户排除的双命中交集的），不伪造归档条目，
只写进 `unverified_success_cves.json` 供人工判断。
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from datetime import datetime
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import httpx
import openpyxl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # 直接以脚本路径运行时也能 import cve_hunter

from cve_hunter.evidence import _remote_pcap_name  # noqa: E402
RESEND = ROOT / "output" / "resend_20260917"
HTTP_JSONL = RESEND / "results.jsonl"
NUCLEI_JSONL = RESEND / "results_nuclei.jsonl"
NO_POC_JSON = RESEND / "no_poc_cves.json"

ARCHIVE = ROOT / "archives" / "successful_cve_0917"
XLSX = ROOT / "工作流迪普IPS结果统计new.xlsx"
SHEET_DETAIL = "迪普IPS待补充CVE运行结果"
SHEET_STATS = "统计"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def load_resend_module():
    """复用 scripts/resend_failed_cves.py 的 PoC 解析，保证与发包时同一份 payload。"""
    spec = spec_from_file_location("resend_failed_cves", ROOT / "scripts" / "resend_failed_cves.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with (RESEND / "archive.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def last_records(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("cve"):
            out[rec["cve"]] = rec
    return out


def merge_records() -> dict[str, dict]:
    """两条通道合成一个视图：任一条点名命中即算命中，同时保留各自的原始记录。"""
    merged: dict[str, dict] = {}
    for modality, path in (("http", HTTP_JSONL), ("nuclei", NUCLEI_JSONL)):
        for cve, rec in last_records(path).items():
            entry = merged.setdefault(cve, {"cve": cve, "runs": {}})
            entry["runs"][modality] = rec
            entry["hit_h3c"] = entry.get("hit_h3c", False) or bool(rec.get("hit_h3c"))
            entry["hit_dptech"] = entry.get("hit_dptech", False) or bool(rec.get("hit_dptech"))
    return merged


def backup_xlsx() -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = XLSX.with_name(f"{XLSX.name}.bak_{stamp}")
    shutil.copy2(XLSX, backup)
    return backup


def update_xlsx(merged: dict[str, dict]) -> tuple[set[str], set[str]]:
    """J/K 取并集写回原表；返回 (更新后标是的 CVE 集合, 本次新增命中的 CVE 集合)。"""
    wb = openpyxl.load_workbook(XLSX)
    ws = wb[SHEET_DETAIL]
    success: set[str] = set()
    newly: set[str] = set()

    for row_no in range(2, ws.max_row + 1):
        cves = [m.group(0).upper() for m in CVE_RE.finditer(str(ws.cell(row=row_no, column=3).value or ""))]
        if not cves:
            continue
        res = [merged[c] for c in cves if c in merged]
        old_h3c = ws.cell(row=row_no, column=10).value == "是"
        old_dptech = ws.cell(row=row_no, column=11).value == "是"
        got_h3c = any(r["hit_h3c"] for r in res)
        got_dptech = any(r["hit_dptech"] for r in res)

        if got_h3c and not old_h3c:
            newly |= {c for c in cves if merged.get(c, {}).get("hit_h3c")}
        if got_dptech and not old_dptech:
            newly |= {c for c in cves if merged.get(c, {}).get("hit_dptech")}

        final_h3c = old_h3c or got_h3c
        final_dptech = old_dptech or got_dptech
        ws.cell(row=row_no, column=10, value="是" if final_h3c else "")
        ws.cell(row=row_no, column=11, value="是" if final_dptech else "")
        if final_h3c or final_dptech:
            success |= set(cves)

    st = wb[SHEET_STATS]
    h3c_total = dptech_total = both = 0
    for row_no in range(2, ws.max_row + 1):
        h = ws.cell(row=row_no, column=10).value == "是"
        d = ws.cell(row=row_no, column=11).value == "是"
        h3c_total += h
        dptech_total += d
        both += h and d
    st.cell(row=2, column=2, value=h3c_total + dptech_total - both)
    st.cell(row=3, column=2, value=h3c_total)
    st.cell(row=4, column=2, value=dptech_total)
    st.cell(row=5, column=2, value=both)
    wb.save(XLSX)
    wb.close()
    return success, newly


def download_pcap(url: str, dest_dir: Path) -> str:
    """从内网服务拉 pcap，保留对方的原始文件名（evidence._remote_pcap_name 同一规则）。"""
    with httpx.stream("GET", url, timeout=httpx.Timeout(90, connect=10),
                      follow_redirects=True, trust_env=False) as response:
        response.raise_for_status()
        name = _remote_pcap_name(response.headers.get("content-disposition", ""), "", url)
        destination = dest_dir / name
        pending = dest_dir / (name + ".part")
        try:
            with pending.open("wb") as handle:
                for chunk in response.iter_bytes():
                    handle.write(chunk)
            with pending.open("rb") as handle:
                header = handle.read(24)
            if len(header) < 24 or header[:4] not in {
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
            }:
                raise ValueError("下载内容不是有效的 PCAP/PCAPNG 文件头")
            pending.replace(destination)
        finally:
            pending.unlink(missing_ok=True)
    return destination.name


def archive_one(cve: str, entry: dict, resend, poc_index: dict, nuclei_index: dict) -> dict:
    dest = ARCHIVE / cve
    dest.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}

    http_rec = entry["runs"].get("http")
    nuclei_rec = entry["runs"].get("nuclei")
    task = {"cve": cve}

    def hit(rec: dict | None) -> bool:
        return bool(rec) and (bool(rec.get("hit_h3c")) or bool(rec.get("hit_dptech")))

    # 只保存真正打出命中那条通道的 payload；另一条通道的 payload 不复现，存了会误导。
    if hit(http_rec):
        raw, label, path = resend.resolve_poc(task, poc_index)
        if raw:
            (dest / "poc.http").write_text(
                resend.normalize_raw_http(raw, resend.TARGET_HOST), encoding="utf-8")
            written["poc"] = f"poc.http ({label}) {path}"

    if hit(nuclei_rec):
        yaml_text, label, path = resend.resolve_nuclei(task, nuclei_index)
        if yaml_text:
            (dest / "poc.yaml").write_text(yaml_text, encoding="utf-8")
            written["nuclei"] = f"poc.yaml ({label}) {path}"

    pcap_name = ""
    pcap_source = http_rec if (http_rec or {}).get("pcap_url") else nuclei_rec
    url = (pcap_source or {}).get("pcap_url") or ""
    if url:
        try:
            pcap_name = download_pcap(url, dest)
            written["pcap"] = f"{pcap_name} <- {url}"
        except Exception as exc:  # noqa: BLE001
            written["pcap_error"] = f"{type(exc).__name__}: {exc}"

    result = {
        "cve_id": cve,
        "status": "SUCCESS",
        "success_level": "ips_cve_match",
        "note": "2026-09-17 重发批次，IPS 日志点名该 CVE 才计入",
        "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hit_h3c": entry.get("hit_h3c", False),
        "hit_dptech": entry.get("hit_dptech", False),
        "pcap": pcap_name,
        "poc": written,
        "runs": entry["runs"],
    }
    (dest / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"cve": cve, "pcap": pcap_name, "poc": written}


def rewrite_readme(cves: list[str], unverified: list[str], credited: list[str] | None = None) -> None:
    credited = credited or []
    lines = [
        "# 成功 CVE 归档",
        "",
        f"共 {len(cves)} 个（仅 xlsx 清单内）。",
        "",
        "每个目录含：`poc.http` / `poc.yaml`（下发内容）、原始命名的 `.pcap`、`result.json`（归因记录）。",
        "",
    ]
    if credited:
        lines += [
            f"## 跨 CVE 认领 {len(credited)} 个",
            "",
            "这些 CVE 本身没有独立的命中 PoC，但 IPS 的一条特征覆盖了同族多个 CVE —— 发兄弟 CVE 的",
            "PoC 时告警同时点名了它们，同样算已复现。目录里放的是**触发它的那次发送**的 PoC 与 pcap，",
            "`result.json` 的 `credited_by` 写明来源：",
            "",
            "```",
            " ".join(credited),
            "```",
            "",
        ]
    if unverified:
        lines += [
            f"## 表内标「是」但无 CVE 点名证据 {len(unverified)} 个（未归档）",
            "",
            "这些 CVE 在 xlsx 里位于「同行另一个 CVE 实际命中」的行上，或属于双命中交集，",
            "IPS 日志全域检索也从未点名过它们，故不生成归档条目：",
            "",
            "```",
            " ".join(unverified),
            "```",
            "",
        ]
    lines += [f"- {cve}" for cve in cves]
    lines.append("")
    (ARCHIVE / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    if not HTTP_JSONL.exists():
        log("没有 results.jsonl，无法归档")
        return 1
    resend = load_resend_module()
    merged = merge_records()
    log(f"读入本轮结果：{len(merged)} 个 CVE（其中命中 {sum(1 for m in merged.values() if m['hit_h3c'] or m['hit_dptech'])} 个）")

    backup = backup_xlsx()
    log(f"原表已备份 → {backup.name}")

    success, newly = update_xlsx(merged)
    log(f"xlsx 已更新：表内标是 {len(success)} 个 CVE，本次新增命中 {len(newly)} 个")

    have = {p.name for p in ARCHIVE.iterdir() if p.is_dir()} if ARCHIVE.exists() else set()
    gap = sorted(success - have)
    provable = [c for c in gap if merged.get(c, {}).get("hit_h3c") or merged.get(c, {}).get("hit_dptech")]
    unverified = [c for c in gap if c not in set(provable)]
    log(f"归档缺口 {len(gap)} 个：本轮可证 {len(provable)} 个，无点名证据 {len(unverified)} 个")

    poc_index = resend.build_poc_index()
    nuclei_index = resend.build_nuclei_index()
    archived = []
    for i, cve in enumerate(provable, start=1):
        try:
            info = archive_one(cve, merged[cve], resend, poc_index, nuclei_index)
            archived.append(info)
            log(f"[{i}/{len(provable)}] {cve} pcap={info['pcap'] or '（无）'} poc={list(info['poc'])}")
        except Exception as exc:  # noqa: BLE001
            log(f"[{i}/{len(provable)}] {cve} 归档失败：{type(exc).__name__}: {exc}")
        time.sleep(0.2)

    (RESEND / "unverified_success_cves.json").write_text(
        json.dumps(unverified, ensure_ascii=False, indent=2), encoding="utf-8")

    all_cves = sorted({p.name for p in ARCHIVE.iterdir() if p.is_dir()})
    rewrite_readme(all_cves, unverified)
    log(f"README 已重写：归档共 {len(all_cves)} 个；本次新增 {len(archived)} 个")
    no_pcap = [a["cve"] for a in archived if not a["pcap"]]
    if no_pcap:
        log(f"注意：{len(no_pcap)} 个归档缺 pcap：{' '.join(no_pcap)}")
    if unverified:
        log(f"表内标是但无证据（未归档）：{' '.join(unverified)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
