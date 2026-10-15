"""Compare per-device spreadsheet gaps and evaluate cached source evidence offline."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cve_hunter.tools.ref_cache import load_reference_cache
from cve_hunter.tools.reference_evidence import reference_prompt_text, structure_reference


def device_hits(path: Path) -> dict[str, set[str]]:
    book = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        rows = book["迪普IPS待补充CVE运行结果"].iter_rows(values_only=True)
        headers = next(rows)
        hits: dict[str, set[str]] = {}
        for row in rows:
            item = dict(zip(headers, row))
            for cve_id in re.findall(r"CVE-\d{4}-\d+", str(item.get("cve") or ""), re.I):
                devices = hits.setdefault(cve_id.upper(), set())
                for column, device in (("命中h3c", "h3c"), ("命中dptech", "dptech")):
                    if item.get(column) == "是":
                        devices.add(device)
        return hits
    finally:
        book.close()


def evaluate(other: Path, ours: Path) -> dict:
    other_hits, own_hits = device_hits(other), device_hits(ours)
    differences = {cve: sorted(devices - own_hits.get(cve, set()))
                   for cve, devices in other_hits.items() if devices - own_hits.get(cve, set())}
    results = []
    for cve_id, missing in sorted(differences.items()):
        cached = load_reference_cache(cve_id)
        pages = [structure_reference(page, cve_id) for page in cached]
        old_prompt = "".join(f"\n### {page.get('title', '')} ({page.get('url', '')})\n{str(page.get('content') or '')[:2000]}\n"
                             for page in cached)[:8000]
        new_prompt = reference_prompt_text(pages)
        blocks = [block["text"] for page in pages for block in page["poc_evidence"]["code_blocks"]]
        conditions = [quote["quote"] for page in pages
                      for quotes in page["poc_evidence"]["conditions"].values() for quote in quotes]
        links = sorted({link["url"] for page in pages for link in page["poc_evidence"]["poc_links"]})
        results.append({
            "cve_id": cve_id, "missing_devices": missing,
            "cached_pages": len(pages), "poc_links": links,
            "code_blocks": len(blocks),
            "baseline_complete_blocks_in_prompt": sum(block in old_prompt for block in blocks),
            "enhanced_complete_blocks_in_prompt": sum(block in new_prompt for block in blocks),
            "baseline_condition_quotes_in_prompt": sum(quote in old_prompt for quote in conditions),
            "enhanced_condition_quotes_in_prompt": sum(quote in new_prompt for quote in conditions),
            "conditions": [{"url": page["url"], "conditions": page["poc_evidence"]["conditions"]}
                           for page in pages if any(page["poc_evidence"]["conditions"].values())],
        })
    return {
        "evaluation_mode": "offline_cache_only_no_llm_no_poc_execution",
        "comparison": "per-device hits, union across rows for each CVE; spreadsheet labels are not new verification",
        "summary": {
            "difference_cves": len(results),
            "missing_h3c": sum("h3c" in item["missing_devices"] for item in results),
            "missing_dptech": sum("dptech" in item["missing_devices"] for item in results),
            "with_cached_pages": sum(bool(item["cached_pages"]) for item in results),
            "with_poc_links": sum(bool(item["poc_links"]) for item in results),
            "with_code_blocks": sum(bool(item["code_blocks"]) for item in results),
            "cves_with_more_complete_code_in_prompt": sum(item["enhanced_complete_blocks_in_prompt"] > item["baseline_complete_blocks_in_prompt"] for item in results),
            "cves_with_more_condition_quotes_in_prompt": sum(item["enhanced_condition_quotes_in_prompt"] > item["baseline_condition_quotes_in_prompt"] for item in results),
        },
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--other", type=Path, default=ROOT / "工作流迪普IPS结果统计.xlsx")
    parser.add_argument("--ours", type=Path, default=ROOT / "工作流迪普IPS结果统计0917.xlsx")
    parser.add_argument("--report", type=Path, default=ROOT / "output/reference_evidence_evaluation.json")
    args = parser.parse_args()
    report = evaluate(args.other, args.ours)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print(f"Report: {args.report}")


if __name__ == "__main__":
    main()
