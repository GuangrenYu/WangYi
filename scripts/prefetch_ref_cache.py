#!/usr/bin/env python3
"""Prefetch NVD reference pages into poc_kb/ref_cache for a CVE list."""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cve_hunter.tools.nvd import query_nvd
from cve_hunter.tools.ref_cache import load_reference_cache
from cve_hunter.agents import run_reference_agent
from cve_hunter.state import CVEState


def prefetch_one(cve_id: str, *, use_tavily: bool, max_urls: int) -> dict:
    cached = load_reference_cache(cve_id)
    info = query_nvd(cve_id)
    refs = list(info.get("references") or [])[:max_urls]
    if not refs:
        return {
            "cve_id": cve_id,
            "status": "no_nvd_refs",
            "cached": len(cached),
            "fetched": 0,
            "saved": 0,
        }

    result = run_reference_agent(CVEState(
        cve_id=cve_id, nvd_references=list(info.get("references") or []),
        allow_reference_links=use_tavily,
    ), max_urls=max_urls)
    trace = result.get("trace", {}).get("data", {})
    merged = load_reference_cache(cve_id)
    return {
        "cve_id": cve_id,
        "status": "ok" if merged else "empty",
        "nvd_refs": len(refs),
        "cached_before": len(cached),
        "fetched": trace.get("fetched", 0),
        "saved": len(merged),
        "path": trace.get("cache_path", ""),
        "errors": result.get("errors", [])[:3],
        "followup_pages": trace.get("followup_pages", 0),
        "crawl_elapsed_sec": trace.get("crawl_elapsed_sec", 0),
        "crawl_timed_out": trace.get("crawl_timed_out", False),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve_list", type=Path, help="Text file with one CVE per line")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--max-urls", type=int, default=6)
    parser.add_argument("--tavily", action="store_true", help="Prefer Tavily then fallback")
    parser.add_argument("--limit", type=int, default=0, help="Optional limit for smoke tests")
    parser.add_argument("--report", type=Path, default=Path("output/ref_cache_prefetch_0921test2.json"))
    args = parser.parse_args()

    cves = [line.strip().upper() for line in args.cve_list.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.limit > 0:
        cves = cves[: args.limit]

    args.report.parent.mkdir(parents=True, exist_ok=True)
    results = []
    t0 = time.time()
    print(f"prefetch {len(cves)} CVEs workers={args.workers} tavily={args.tavily}")

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futs = {
            pool.submit(prefetch_one, cve, use_tavily=args.tavily, max_urls=args.max_urls): cve
            for cve in cves
        }
        done = 0
        for fut in as_completed(futs):
            done += 1
            try:
                item = fut.result()
            except Exception as exc:
                item = {"cve_id": futs[fut], "status": "error", "error": str(exc)}
            results.append(item)
            if done % 20 == 0 or done == len(cves):
                ok = sum(1 for r in results if r.get("saved", 0) > 0 or r.get("status") == "ok")
                print(f"progress {done}/{len(cves)} with_content~{ok} elapsed={time.time()-t0:.0f}s")

    results.sort(key=lambda r: r.get("cve_id") or "")
    summary = {
        "total": len(results),
        "with_content": sum(1 for r in results if int(r.get("saved") or 0) > 0),
        "empty": sum(1 for r in results if r.get("status") == "empty"),
        "no_nvd_refs": sum(1 for r in results if r.get("status") == "no_nvd_refs"),
        "errors": sum(1 for r in results if r.get("status") == "error"),
        "elapsed_sec": round(time.time() - t0, 1),
        "results": results,
    }
    args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"done with_content={summary['with_content']} empty={summary['empty']} "
        f"no_nvd_refs={summary['no_nvd_refs']} errors={summary['errors']} "
        f"report={args.report}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
