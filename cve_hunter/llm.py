"""LLM 调用封装。

当 LLM_API_KEY 未配置时自动降级为规则模式。
"""

from __future__ import annotations

import json
import re
import hashlib
import time
import uuid
import threading
from datetime import datetime
from zoneinfo import ZoneInfo
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from cve_hunter.config import cfg
from cve_hunter.runtime import is_local_only

_llm_cache = {}
_run_usage = ContextVar("llm_run_usage", default=None)


@contextmanager
def llm_run_scope(directory: Path, *, on_usage=None, task_id="", cve_id=""):
    """Keep memoization, call budget and a content-free ledger isolated per CVE."""
    ledger = {"path": directory / "llm_usage.jsonl", "calls": 0, "cache": {}, "events": [],
              "pending": {}, "run_id": uuid.uuid4().hex, "task_id": task_id,
              "cve_id": cve_id, "on_usage": on_usage, "lock": threading.RLock()}
    token = _run_usage.set(ledger)
    try:
        yield
    finally:
        try:
            _publish_usage(ledger)
        finally:
            _run_usage.reset(token)


def _record_usage(ledger, event):
    if ledger is not None:
        with ledger["lock"]:
            event = {**event, "at": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
                     "run_id": ledger["run_id"], "task_id": ledger["task_id"], "cve_id": ledger["cve_id"]}
            ledger["pending"].pop(event.get("call_id"), None)
            ledger["events"].append(event)
            try:
                ledger["path"].parent.mkdir(parents=True, exist_ok=True)
                with ledger["path"].open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            except OSError:
                # Usage logging must never discard an otherwise valid PoC result.
                pass
        _publish_usage(ledger)


def _publish_usage(ledger):
    if ledger.get("on_usage"):
        try:
            ledger["on_usage"](_ledger_summary(ledger))
        except Exception:
            # UI/disconnection failures must not cause a paid request to be retried.
            pass


def llm_usage_summary() -> dict:
    ledger = _run_usage.get()
    if ledger is None:
        return {}
    return _ledger_summary(ledger)


def _ledger_summary(ledger) -> dict:
    from cve_hunter.usage import COUNTERS, merge_usage
    by_purpose = {}
    with ledger["lock"]:
        events = list(ledger["events"])
        pending = list(ledger["pending"].values())
    for event in [*events, *pending]:
        bucket = by_purpose.setdefault(event.get("purpose") or "unspecified", {key: 0 for key in COUNTERS})
        if event.get("status") == "cache_hit":
            bucket["cache_hits"] += 1
        elif event.get("status") in {"success", "error", "cancelled", "pending"}:
            bucket["calls"] += 1
            if event.get("status") == "pending":
                bucket["pending_calls"] += 1
            elif event.get("total_tokens") is None:
                bucket["unknown_calls"] += 1
        if event.get("status") == "error":
            bucket["errors"] += 1
        bucket["reported_tokens"] += event.get("total_tokens") or 0
        for key in ("input_tokens", "output_tokens", "cached_input_tokens", "reasoning_tokens"):
            bucket[key] += event.get(key) or 0
        bucket["usage_incomplete"] = bool(bucket["unknown_calls"] or bucket["pending_calls"])
    result = merge_usage(by_purpose.values())
    result.update(by_purpose=by_purpose, run_id=ledger["run_id"])
    return result


def _is_llm_available() -> bool:
    return bool(cfg.llm_api_key)


def get_llm(*, model: str | None = None, temperature: float = 0.2, max_tokens: int = 4096):
    cache_key = (model or cfg.llm_model, temperature, max_tokens)
    if cache_key not in _llm_cache:
        if not _is_llm_available():
            return None
        import httpx as _httpx
        from langchain_openai import ChatOpenAI
        # LLM 网关直连：不要走系统/Clash 代理。代理波动会导致 Connection error，
        # 而 tinysnow 等国内可达网关直连更稳；搜索(Tavily)仍可单独走 cfg.httpx_proxy。
        http_client = _httpx.Client(proxy=None, trust_env=False)
        _llm_cache[cache_key] = ChatOpenAI(
            model=cache_key[0],
            api_key=cfg.llm_api_key,
            base_url=cfg.llm_base_url,
            temperature=temperature,
            max_tokens=max_tokens,
            http_client=http_client,
            max_retries=0,
            timeout=getattr(cfg, "llm_timeout", 60),
        )
    return _llm_cache[cache_key]


def invoke_llm(prompt: str, *, model: str | None = None, temperature: float = 0.2, max_tokens: int = 4096, purpose: str = "unspecified") -> str:
    """调用 LLM 并返回纯文本结果。无 API Key 时使用规则降级。"""
    llm = get_llm(model=model, temperature=temperature, max_tokens=max_tokens)
    if llm is not None:
        ledger = _run_usage.get()
        key = hashlib.sha256(json.dumps([model or cfg.llm_model, temperature, max_tokens, prompt]).encode()).hexdigest()
        event = {"purpose": purpose, "model": model or cfg.llm_model,
                 "prompt_sha256": key, "prompt_chars": len(prompt), "call_id": uuid.uuid4().hex}
        if ledger is not None and key in ledger["cache"]:
            _record_usage(ledger, {**event, "status": "cache_hit", "total_tokens": 0})
            return ledger["cache"][key]
        limit = getattr(cfg, "llm_max_calls_per_cve", 12)
        if ledger is not None and limit > 0 and ledger["calls"] >= limit:
            _record_usage(ledger, {**event, "status": "budget_exhausted", "total_tokens": 0})
            raise RuntimeError("LLM call budget exhausted for this CVE")
        if ledger is not None:
            ledger["calls"] += 1
            with ledger["lock"]:
                ledger["pending"][event["call_id"]] = {**event, "status": "pending"}
            _publish_usage(ledger)
        started = time.monotonic()
        try:
            resp = llm.invoke(prompt)
        except BaseException as exc:
            _record_usage(ledger, {**event, "status": "error" if isinstance(exc, Exception) else "cancelled", "error_type": type(exc).__name__,
                                   "elapsed_sec": round(time.monotonic() - started, 3), "total_tokens": None})
            raise
        usage = getattr(resp, "usage_metadata", None) or {}
        metadata = getattr(resp, "response_metadata", None) or {}
        usage = usage or metadata.get("token_usage", {})
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens"))
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens"))
        total_tokens = usage.get("total_tokens")
        if total_tokens is None and input_tokens is not None and output_tokens is not None:
            total_tokens = input_tokens + output_tokens
        input_details = usage.get("input_token_details") or usage.get("prompt_tokens_details") or {}
        output_details = usage.get("output_token_details") or usage.get("completion_tokens_details") or {}
        _record_usage(ledger, {**event, "status": "success",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "cached_input_tokens": input_details.get("cache_read", input_details.get("cached_tokens")),
            "reasoning_tokens": output_details.get("reasoning", output_details.get("reasoning_tokens")),
            "elapsed_sec": round(time.monotonic() - started, 3)})
        if ledger is not None:
            ledger["cache"][key] = resp.content
        return resp.content

    return _fallback_rule_based(prompt)


def _fallback_rule_based(prompt: str) -> str:
    """无 LLM 时的规则降级处理。"""
    lower = prompt.lower()

    if "is_http_vuln" in lower:
        http_keywords = [
            "http", "web", "url", "rce", "xss", "sqli", "sql injection",
            "remote code", "command injection", "path traversal",
            "directory traversal", "ssrf", "csrf", "file upload",
            "deserialization", "authentication bypass", "api",
        ]
        is_http = any(kw in lower for kw in http_keywords)
        return json.dumps({"is_http_vuln": is_http, "vuln_type": "HTTP/Web漏洞" if is_http else "非HTTP漏洞", "reason": "基于关键词规则判断"})

    if "raw http request" in lower or "poc" in lower.split("\n")[0].lower():
        return _generate_fallback_poc(prompt)

    if "分析报告" in prompt or "analysis" in lower:
        return _generate_fallback_report(prompt)

    return "（LLM 未配置，使用规则降级模式）"


def _generate_fallback_poc(prompt: str) -> str:
    """规则模式下尝试从已有信息中拼装 PoC。"""
    paths = re.findall(r'(?:GET|POST)\s+(/\S+)', prompt)
    if not paths:
        paths = re.findall(r'(?:路径|path|endpoint)[：:]\s*(/\S+)', prompt, re.IGNORECASE)
    if not paths:
        paths = ["/"]

    return f"""```http
GET {paths[0]} HTTP/1.1
Host: {{{{TARGET_HOST}}}}
User-Agent: Mozilla/5.0
Accept: */*

```"""


def _generate_fallback_report(prompt: str) -> str:
    """规则模式下生成简单报告。"""
    cve_match = re.search(r'CVE-\d{4}-\d+', prompt)
    cve_id = cve_match.group(0) if cve_match else "未知CVE"
    return f"""# {cve_id} 漏洞复现报告

## 概述
本报告由规则模式自动生成（LLM 未配置）。

## 复现结果
详见输出目录中的 result.json 文件。

## 备注
配置 LLM_API_KEY 后可获取更详细的 AI 分析报告。
"""
