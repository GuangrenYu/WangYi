"""Live public-reference and LLM benchmark. Never imports or calls executors."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cve_hunter.config import cfg
from scripts.evaluate_reference_evidence import device_hits


def safe_error(exc: Exception) -> str:
    text = str(exc)
    for value in (cfg.llm_api_key, cfg.tavily_api_key, cfg.nvd_api_key):
        if value:
            text = text.replace(value, "[redacted]")
    return text[:1500]


def one(cve_id: str, output: Path, references_file: Path | None = None) -> dict:
    from cve_hunter.agents import run_reference_agent
    from cve_hunter.llm import get_llm
    from cve_hunter.poc_parser import parse_nuclei_yaml_candidates_json
    from cve_hunter.prompts.templates import POC_GENERATION_NUCLEI_YAML_FROM_REFS
    from cve_hunter.state import CVEState
    from cve_hunter.tools.nvd import query_nvd
    from cve_hunter.tools.reference_evidence import reference_prompt_text

    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    result = {"cve_id": cve_id, "status": "started", "model": cfg.llm_model,
              "poc_execution": False, "schema_valid_templates": 0, "evidence_supported_templates": 0}

    def save():
        result["elapsed_sec"] = round(time.monotonic() - started, 3)
        (output / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        info = query_nvd(cve_id, local_only=True)
        result["nvd_error"] = info.get("error", "")
        if not info.get("references") and not references_file:
            result["status"] = "no_local_references"
            save()
            return result
        state = CVEState(cve_id=cve_id, nvd_references=info["references"], allow_reference_links=True,
                         nvd_description=info.get("description", ""))
        crawl_started = time.monotonic()
        if references_file:
            fetched = {"reference_contents": json.loads(references_file.read_text()), "trace": {"data": {}}, "errors": []}
        else:
            fetched = run_reference_agent(state)
        pages = fetched["reference_contents"]
        result.update({"reference_elapsed_sec": round(time.monotonic() - crawl_started, 3),
                       "reference_pages": len(pages), "reference_trace": fetched["trace"]["data"],
                       "reference_errors": fetched["errors"],
                       "poc_links": sum(len(page.get("poc_evidence", {}).get("poc_links", [])) for page in pages),
                       "code_blocks": sum(len(page.get("poc_evidence", {}).get("code_blocks", [])) for page in pages),
                       "condition_quotes": sum(len(quotes) for page in pages for quotes in page.get("poc_evidence", {}).get("conditions", {}).values())})
        (output / "references.json").write_text(json.dumps(pages, ensure_ascii=False, indent=2), encoding="utf-8")
        save()
        if not pages:
            result["status"] = "no_reference_content"
            save()
            return result
        context = reference_prompt_text(pages)
        prompt = POC_GENERATION_NUCLEI_YAML_FROM_REFS.format(
            cve_id=cve_id, description=info.get("description", ""),
            cvss_score=info.get("cvss_score", 0), cvss_severity=info.get("cvss_severity", ""),
            affected_products=", ".join(map(str, info.get("affected_products", [])[:5])),
            vuln_type="按原文确认", trigger_context="无规则推断；只使用来源证据", reference_contents=context,
        )
        (output / "prompt.txt").write_text(prompt, encoding="utf-8")
        llm = get_llm(temperature=0.2, max_tokens=4096)
        if llm is None:
            raise ValueError("LLM_API_KEY is not configured; benchmark refuses rule fallback")
        bounded_llm = llm.model_copy(update={"request_timeout": 60, "max_retries": 0})
        bounded_llm.client = llm.root_client.with_options(timeout=60, max_retries=0).chat.completions
        llm_started = time.monotonic()
        response = bounded_llm.invoke(prompt)
        result["llm_elapsed_sec"] = round(time.monotonic() - llm_started, 3)
        result["token_usage"] = response.usage_metadata or {}
        text = str(response.content)
        (output / "model_response.txt").write_text(text, encoding="utf-8")
        candidates = parse_nuclei_yaml_candidates_json(text)
        source_urls = {str(page.get("url") or "") for page in pages}
        source_urls.update(str(page.get("resolved_url") or "") for page in pages)
        source_urls.update(str(page.get("poc_evidence", {}).get("evidence_url") or "") for page in pages)
        source_text = "\n".join(str(page.get("content") or "") + "\n" + "\n".join(
            block["text"] for block in page.get("poc_evidence", {}).get("code_blocks", [])) for page in pages)
        reviews = []
        import yaml
        for index, candidate in enumerate(candidates):
            document = yaml.safe_load(candidate["nuclei_yaml"])
            valid = bool(document.get("id") and isinstance(document.get("info"), dict)
                         and document["info"].get("name") and document["info"].get("severity"))
            quote = candidate.get("evidence_quote", "").strip()
            known_url = candidate.get("evidence_url", "") in source_urls
            cited_pages = [page for page in pages if candidate.get("evidence_url", "") in {
                page.get("url", ""), page.get("resolved_url", ""),
                page.get("poc_evidence", {}).get("evidence_url", ""),
            }]
            cited_text = "\n".join(str(page.get("content") or "") + "\n" + "\n".join(
                block["text"] for block in page.get("poc_evidence", {}).get("code_blocks", [])) for page in cited_pages)
            exact_quote = bool(quote) and quote in cited_text
            whitespace_quote = bool(quote) and " ".join(quote.split()) in " ".join(cited_text.split())
            # Heuristic evidence check, deliberately distinct from semantic validation.
            paths = []
            for request in document.get("http", []):
                if not isinstance(request, dict):
                    continue
                for raw in request.get("raw", []):
                    match = re.match(r"[A-Z]+\s+(\S+)\s+HTTP/", str(raw).strip())
                    if match:
                        paths.append(match[1])
                paths.extend(re.sub(r"\{\{BaseURL\}\}", "", str(path)) for path in request.get("path", []))
            supported_paths = bool(paths) and all(path and path != "/" and path in cited_text for path in paths)
            supported = valid and whitespace_quote and known_url and supported_paths
            reviews.append({**candidate, "schema_valid": valid, "known_source_url": known_url,
                            "exact_source_quote": exact_quote, "paths_supported_verbatim": supported_paths,
                            "source_quote_matches_ignoring_whitespace": whitespace_quote,
                            "evidence_supported_heuristic": supported})
            (output / f"candidate_{index + 1}.yaml").write_text(candidate["nuclei_yaml"], encoding="utf-8")
        (output / "candidate_reviews.json").write_text(json.dumps(reviews, ensure_ascii=False, indent=2), encoding="utf-8")
        result["schema_valid_templates"] = sum(item["schema_valid"] for item in reviews)
        result["evidence_supported_templates"] = sum(item["evidence_supported_heuristic"] for item in reviews)
        result["status"] = "templates_generated" if result["schema_valid_templates"] else "no_valid_templates"
        save()
        return result
    except Exception as exc:
        result.update({"status": "error", "error": safe_error(exc)})
        save()
        return result


def summarize(results):
    from collections import Counter
    return {"completed": len(results), "statuses": dict(Counter(item["status"] for item in results)),
            "with_reference_content": sum(bool(item.get("reference_pages")) for item in results),
            "with_code": sum(bool(item.get("code_blocks")) for item in results),
            "with_conditions": sum(bool(item.get("condition_quotes")) for item in results),
            "with_schema_valid_nuclei": sum(bool(item.get("schema_valid_templates")) for item in results),
            "with_evidence_supported_nuclei": sum(bool(item.get("evidence_supported_templates")) for item in results),
            "crawl_budget_exhausted": sum(bool(item.get("reference_trace", {}).get("crawl_timed_out")) for item in results)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", default="")
    parser.add_argument("--output", type=Path, default=ROOT / "output" / ("reference_live_" + datetime.now().strftime("%Y%m%d_%H%M%S")))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--references-file", type=Path)
    args = parser.parse_args()
    if args.child:
        one(args.child, args.output / args.child, args.references_file)
        return
    ours = device_hits(ROOT / "工作流迪普IPS结果统计0917.xlsx")
    theirs = device_hits(ROOT / "工作流迪普IPS结果统计.xlsx")
    cves = sorted(cve for cve, devices in theirs.items() if devices - ours.get(cve, set()))
    if args.limit:
        cves = cves[:args.limit]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "cves.txt").write_text("\n".join(cves) + "\n", encoding="utf-8")
    def worker(cve):
        directory = args.output / cve
        directory.mkdir(exist_ok=True)
        path = directory / "result.json"
        if path.exists():
            previous = json.loads(path.read_text())
            if previous.get("status") != "started":
                return previous
        try:
            completed = subprocess.run([sys.executable, __file__, "--child", cve, "--output", str(args.output)],
                                       capture_output=True, text=True, timeout=150, cwd=ROOT)
            if path.exists():
                result = json.loads(path.read_text())
                if result["status"] != "started":
                    return result
            return {"cve_id": cve, "status": "worker_error", "error": safe_error(ValueError(completed.stderr))}
        except subprocess.TimeoutExpired:
            result = json.loads(path.read_text()) if path.exists() else {"cve_id": cve}
            result["status"] = "worker_timeout"
            path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            return result
    results = []
    started = time.monotonic()
    print(f"Public-source + LLM benchmark: {len(cves)} CVEs, {args.workers} workers, no execution; output={args.output}", flush=True)
    with ThreadPoolExecutor(max_workers=max(1, min(24, args.workers))) as pool:
        futures = [pool.submit(worker, cve) for cve in cves]
        for future in as_completed(futures):
            results.append(future.result())
            summary = summarize(results)
            report = {"total": len(cves), "elapsed_sec": round(time.monotonic() - started, 1),
                      "mode": "live_public_sources_and_llm_no_poc_execution", "summary": summary,
                      "limitations": "Schema and verbatim evidence checks only; no Nuclei execution, vulnerability verification or IPS checks.",
                      "results": sorted(results, key=lambda item: item["cve_id"])}
            (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            if len(results) % 10 == 0 or len(results) == len(cves):
                print(json.dumps({"elapsed_sec": report["elapsed_sec"], **summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
