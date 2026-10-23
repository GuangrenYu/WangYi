"""Run live crawler regression against the 95 missing-path baseline; never execute PoCs."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
import json
from pathlib import Path
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cve_hunter.tools import reference_crawl
from cve_hunter.tools.nvd_local import query_nvd_local
from cve_hunter.tools.ref_cache import load_reference_cache
from cve_hunter.tools.reference_utils import normalize_reference_urls
from cve_hunter.tools.reference_evidence import has_complete_poc_source


def complete_poc_sources(cve: str, pages: list[dict]) -> list[str]:
    """Conservatively count whole public source files, never prose/snippets.

    This checks source retrieval completeness, not exploit functionality.
    Markdown examples remain uncounted until reviewed for completeness.
    """
    return [str(page.get('resolved_url') or page.get('url')) for page in pages
            if has_complete_poc_source(page, cve)]


def check(row: dict) -> dict:
    cve = row["cve"]
    info = query_nvd_local(cve) or {}
    urls = normalize_reference_urls(info.get("references") or [])
    cached = load_reference_cache(cve)
    roots = [page for page in cached if page["url"] in urls] if urls else cached
    result = reference_crawl.enrich_references(
        cve, roots, cached, reference_urls=urls,
        discovery_context=" ".join(filter(None, [
            info.get("description", ""),
            *[str(product) for product in (info.get("affected_products") or [])[:5]],
        ])),
    )
    corpus = []
    for page in result["pages"]:
        blocks = [*(page.get("code_blocks") or []),
                  *(page.get("poc_evidence", {}).get("code_blocks") or [])]
        corpus.append(unquote("\n".join([
            str(page.get("content") or ""), str(page.get("title") or ""),
            *[str(block.get("text") or "") for block in blocks],
        ])).lower())
    # Peer paths enter only the assertion, after crawling finishes.
    hits = []
    for request in row.get("peer_reqs") or []:
        path = str(request.get("path") or "")
        needle = unquote(path).lower()
        hits.append({"path": path, "found": bool(needle) and any(needle in text for text in corpus)})
    full_sources = complete_poc_sources(cve, result['pages'])
    return {
        "cve": cve, "any_full_path": any(hit["found"] for hit in hits), "hits": hits,
        "complete_public_poc_source": bool(full_sources), "complete_poc_source_urls": full_sources,
        "pages": len(result["pages"]), "timed_out": result["timed_out"],
        "elapsed_sec": result.get("elapsed_sec"), "attempted_urls": result.get("attempted_urls", []),
        "errors": result["errors"], "discovery": result.get("discovery", {}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path,
                        default=ROOT / "output/audits/gap_peer_path_in_crawl_evidence.json")
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=2)
    parser.add_argument("--budget", type=float, default=60)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--uncovered-from", type=Path, help="Rerun only CVEs without either coverage metric in a prior result")
    parser.add_argument('--paid-fallback', action='store_true', help='Use configured paid search fallback')
    args = parser.parse_args()
    if not 1 <= args.budget <= 60:
        parser.error("--budget must be between 1 and 60 seconds")
    rows = [row for row in json.loads(args.baseline.read_text())["rows"]
            if row.get("root_cause_bucket") == "crawl_missing_peer_path"]
    if len(rows) != 95 or len({row["cve"] for row in rows}) != 95:
        parser.error("baseline must contain exactly 95 distinct missing-path CVEs")
    if args.uncovered_from:
        prior = json.loads(args.uncovered_from.read_text())["results"]
        uncovered = {row["cve"] for row in prior
                     if not row.get("any_full_path") and not row.get("complete_public_poc_source")}
        rows = [row for row in rows if row["cve"] in uncovered]
    reference_crawl.cfg = replace(
        reference_crawl.cfg, reference_crawl_budget=args.budget,
        search_paid_fallback=args.paid_fallback, reference_discovery_enabled=True,
    )
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check, row): row["cve"] for row in rows}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = {"cve": futures[future], "any_full_path": False, "exception": str(exc)}
            results.append(result)
            print(f"[{len(results)}/{len(rows)}] {result['cve']} path={result['any_full_path']}", flush=True)
    summary = {
        "count": len(results), "path_found": sum(row["any_full_path"] for row in results),
        "complete_public_poc_source": sum(bool(row.get('complete_public_poc_source')) for row in results),
        "timeouts": sum(bool(row.get("timed_out")) for row in results),
        "exceptions": sum("exception" in row for row in results),
        "metric": "Exact path text and complete public source file retrieval are separate, overlapping metrics; no exploit/IPS verification. Markdown snippets require review and are excluded from complete-source counts.",
    }
    print(json.dumps(summary, ensure_ascii=False))
    if args.output:
        args.output.write_text(json.dumps({"summary": summary, "results": sorted(
            results, key=lambda row: row["cve"],
        )}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
