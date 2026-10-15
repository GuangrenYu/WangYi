"""Cold free-source discovery timeline and paired static Nuclei generation budget comparison."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cve_hunter.config import cfg
from cve_hunter.tools.reference_crawl import crawl_targets
from cve_hunter.tools.reference_evidence import has_http_evidence, reference_prompt_text
from cve_hunter.tools.nvd import query_nvd


def select_sample(baseline, per_group=4, *, holdout=False):
    groups = ["templates_generated", "no_valid_templates", "no_reference_content", "error"]
    sample = []
    for group in groups:
        candidates = sorted([item["cve_id"] for item in baseline["results"] if item["status"] == group])
        if candidates:
            if holdout:
                excluded = {candidates[min(len(candidates)-1, int(i*(len(candidates)-1)/max(1,per_group-1)))]
                            for i in range(per_group)}
                candidates = [cve for cve in candidates if cve not in excluded]
            if not candidates:
                continue
            sample.extend(candidates[min(len(candidates)-1, int((i+.5)*len(candidates)/per_group)
                                          if holdout else int(i*(len(candidates)-1)/max(1,per_group-1)))] for i in range(per_group))
    return sorted(set(sample))


def crawl_one(cve, output, crawl_budget=45):
    directory = output / cve
    directory.mkdir(parents=True, exist_ok=True)
    cached_timeline = directory / "timeline.json"
    if cached_timeline.exists():
        stored = json.loads(cached_timeline.read_text())
        return cve, stored["pages"], stored["summary"]
    info = query_nvd(cve, local_only=True)
    seeds = [{"url": url, "content": ""} for url in info.get("references", [])]
    targets = crawl_targets(seeds, cve)[:3]
    if len(targets) < 3:
        have = {item["url"] for item in targets}
        targets.extend({"url": item["url"], "kind": "page", "score": 0} for item in seeds if item["url"] not in have)
        targets = targets[:3]
    payload = {"cve_id": cve, "targets": targets, "budget": crawl_budget, "request_timeout": 6,
               "proxy": cfg.httpx_proxy, "discover": True, "paid_fallback": False,
               "searxng_url": cfg.searxng_url, "stream_results": True}
    started = time.monotonic()
    pages = []
    summary = {}
    stdout = ''
    try:
        result = subprocess.run([sys.executable, "-m", "cve_hunter.tools.reference_crawl"],
                                input=json.dumps(payload), text=True, capture_output=True, timeout=crawl_budget+2, cwd=ROOT)
        stdout = result.stdout
        if result.returncode:
            summary["worker_error"] = result.stderr[:600]
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ''
        if isinstance(stdout,bytes):stdout=stdout.decode('utf-8',errors='replace')
        summary['timed_out']=True
        summary["worker_error"] = "cold crawl worker deadline exceeded"
    for line in stdout.split("\n"):
        if not line.strip():continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if "page" in item:pages.append(item["page"])
        if "summary" in item:summary.update(item["summary"])
    (directory / "timeline.json").write_text(json.dumps({"pages":pages,"summary":summary,"elapsed_sec":time.monotonic()-started},ensure_ascii=False,indent=2))
    return cve,pages,summary


def generate(cve, budget, pages, output):
    root = output / f"budget_{budget}"
    directory = root / cve
    directory.mkdir(parents=True, exist_ok=True)
    refs = directory / "input_references.json"
    refs.write_text(json.dumps(pages,ensure_ascii=False,indent=2))
    path = directory / "result.json"
    try:
        subprocess.run([sys.executable, "scripts/benchmark_reference_generation.py", "--child", cve,
                        "--output", str(root), "--references-file", str(refs)],
                       text=True,capture_output=True,timeout=75,cwd=ROOT)
        result = json.loads(path.read_text())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        result = {"cve_id":cve,"status":"generation_timeout"}
    result.update({"budget_sec":budget,"http_evidence":any(has_http_evidence(page) for page in pages),
                   "new_pages":len(pages),"unique_sources":len({p['url'] for p in pages})})
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline",type=Path,default=ROOT/'output/reference_live_20261014/report.json')
    parser.add_argument("--output",type=Path,default=ROOT/'output/discovery_budget_20261014')
    parser.add_argument("--validate-budget",type=int,default=0,help="Independent holdout sample with an actual total deadline")
    args=parser.parse_args()
    baseline=json.loads(args.baseline.read_text())
    args.output.mkdir(parents=True,exist_ok=True)
    sample_path=args.output/'sample.json'
    sample=json.loads(sample_path.read_text()) if sample_path.exists() else select_sample(baseline, holdout=bool(args.validate_budget))
    sample_path.write_text(json.dumps(sample,indent=2))
    print('Cold free-source crawl sample',len(sample),flush=True)
    timelines={}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for future in as_completed([pool.submit(crawl_one,cve,args.output,args.validate_budget or 45) for cve in sample]):
            cve,pages,summary=future.result();timelines[cve]=pages
            print(json.dumps({'cve':cve,'pages':len(pages),'http_evidence':any(has_http_evidence(p) for p in pages),'timeout':summary.get('timed_out')},ensure_ascii=False),flush=True)
    jobs=[]
    aliases=[]
    budgets=[args.validate_budget] if args.validate_budget else [10,20,30,45]
    for cve,pages in timelines.items():
        contexts={}
        for budget in budgets:
            snapshot=[page for page in pages if page.get('arrived_sec',999)<=budget]
            key=hashlib.sha256(reference_prompt_text(snapshot).encode()).hexdigest()
            if key in contexts:
                aliases.append((cve,budget,contexts[key],snapshot))
            else:
                contexts[key]=budget;jobs.append((cve,budget,snapshot))
    print('Distinct real LLM calls',len(jobs),'identical contexts reused',len(aliases),flush=True)
    results=[]
    with ThreadPoolExecutor(max_workers=6) as pool:
        for future in as_completed([pool.submit(generate,cve,budget,pages,args.output) for cve,budget,pages in jobs]):
            result=future.result();results.append(result)
            print(result['cve_id'],result['budget_sec'],result['status'],result.get('schema_valid_templates',0),flush=True)
    for cve,budget,original,snapshot in aliases:
        match=next(r for r in results if r['cve_id']==cve and r['budget_sec']==original)
        result={**match,'budget_sec':budget,'reused_identical_prompt_budget':original,'new_pages':len(snapshot)}
        results.append(result)
    summaries=[]
    for budget in budgets:
        rows=[r for r in results if r['budget_sec']==budget]
        summaries.append({'budget_sec':budget,'cves':len(rows),'with_pages':sum(bool(r['new_pages']) for r in rows),
                          'with_http_evidence':sum(r['http_evidence'] for r in rows),
                          'with_valid_nuclei':sum(bool(r.get('schema_valid_templates')) for r in rows),
                          'with_supported_nuclei':sum(bool(r.get('evidence_supported_templates')) for r in rows),
                          'with_code_and_conditions':sum(bool(r.get('code_blocks')) and bool(r.get('condition_quotes')) for r in rows),
                          'model_errors':sum(r['status'] in {'error','generation_timeout'} for r in rows)})
    # Minimum budget within 95% of the best observed supported-template and HTTP-evidence count.
    best_supported=max(r['with_supported_nuclei'] for r in summaries)
    best_evidence=max(r['with_http_evidence'] for r in summaries)
    eligible=[r for r in summaries if r['with_supported_nuclei']>=.95*best_supported and r['with_http_evidence']>=.95*best_evidence]
    selected=eligible[0]['budget_sec']
    report={'sample':sample,'sampling':'four evenly spaced CVEs per previous result stratum; diagnostic sample, not population estimate',
            'mode':'free discovery only; no crawler cache reads; no PoC execution',
            'actual_deadline_validation':bool(args.validate_budget),'budgets':summaries,'selected_budget_sec':selected,
            'selection_rule':'shortest budget retaining >=95% of best observed supported-template count and HTTP-evidence count',
            'limitations':'prefix snapshots of a single 45s crawl per CVE; identical prompts reuse generation, model errors and small sample limit conclusions',
            'results':results}
    (args.output/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps({'budgets':summaries,'selected_budget_sec':selected},ensure_ascii=False,indent=2),flush=True)


if __name__=='__main__':main()
