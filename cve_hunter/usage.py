"""Local usage aggregation and batch exports; never calls a model."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

COUNTERS = (
    "calls", "cache_hits", "reported_tokens", "input_tokens", "output_tokens",
    "cached_input_tokens", "reasoning_tokens", "unknown_calls", "pending_calls", "errors",
)


def merge_usage(summaries) -> dict:
    result = {key: 0 for key in COUNTERS}
    result.update(usage_incomplete=False, by_purpose={})
    for summary in summaries:
        for key in COUNTERS:
            result[key] += summary.get(key, 0) or 0
        result["usage_incomplete"] |= bool(summary.get("usage_incomplete"))
        for purpose, bucket in summary.get("by_purpose", {}).items():
            target = result["by_purpose"].setdefault(purpose, {**{key: 0 for key in COUNTERS}, "usage_incomplete": False})
            for key in COUNTERS:
                target[key] += bucket.get(key, 0) or 0
            target["usage_incomplete"] |= bool(bucket.get("usage_incomplete"))
    return result


def batch_usage(task: dict) -> dict:
    return merge_usage(
        item.get("llm_usage") or item.get("result_summary", {}).get("llm_usage") or {}
        for item in task.get("items", {}).values()
    )


def finish_usage(usage: dict) -> dict:
    """An interrupted in-flight request has unknown billable usage."""
    for bucket in [usage, *usage.get("by_purpose", {}).values()]:
        pending = bucket.get("pending_calls", 0)
        if pending:
            bucket["unknown_calls"] = bucket.get("unknown_calls", 0) + pending
            bucket["pending_calls"] = 0
            bucket["usage_incomplete"] = True
    return usage


def beijing_time(value):
    return datetime.fromisoformat(value).astimezone(ZoneInfo("Asia/Shanghai")).isoformat() if value else None


def export_batch(task: dict) -> None:
    """Save a final JSON report and a spreadsheet-friendly CSV atomically."""
    directory = Path(task["usage_directory"])
    directory.mkdir(parents=True, exist_ok=True)
    report = {
        "task_id": task["id"], "created_at": beijing_time(task["created_at"]),
        "updated_at": beijing_time(task.get("updated_at")), "status": task["status"],
        "timezone": "Asia/Shanghai", "usage": batch_usage(task),
        "notes": [
            "Totals use relay-reported total_tokens; token categories may overlap.",
            "Cached input is part of input tokens. Reasoning may already be in output or total.",
            "Unknown and pending calls may incur charges; missing usage is never treated as a known zero.",
        ],
        "cves": {cve: {"status": item.get("status"), "usage": item.get("llm_usage")
                           or item.get("result_summary", {}).get("llm_usage") or {}}
                 for cve, item in task.get("items", {}).items()},
    }
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=["scope", "cve_id", "purpose", *COUNTERS, "usage_incomplete"])
    writer.writeheader()
    def row(scope, usage, cve="", purpose=""):
        writer.writerow({"scope": scope, "cve_id": cve, "purpose": purpose,
                         **{key: usage.get(key, 0) for key in COUNTERS},
                         "usage_incomplete": usage.get("usage_incomplete", False)})
    row("batch", report["usage"])
    for cve, item in report["cves"].items():
        row("cve", item["usage"], cve)
        for purpose, bucket in item["usage"].get("by_purpose", {}).items():
            row("purpose", bucket, cve, purpose)
    for name, content, encoding in (
        ("summary.json", json.dumps(report, ensure_ascii=False, indent=2), "utf-8"),
        ("summary.csv", output.getvalue(), "utf-8-sig"),
    ):
        temporary = directory / (name + ".tmp")
        temporary.write_text(content, encoding=encoding)
        temporary.replace(directory / name)
