"""LLM 调用封装。

当 LLM_API_KEY 未配置时自动降级为规则模式。
"""

from __future__ import annotations

import json
import re

from cve_hunter.config import cfg

_llm = None


def _is_llm_available() -> bool:
    return bool(cfg.llm_api_key)


def get_llm():
    global _llm
    if _llm is None:
        if not _is_llm_available():
            return None
        import httpx as _httpx
        from langchain_openai import ChatOpenAI
        http_client = _httpx.Client(proxy=cfg.httpx_proxy) if cfg.httpx_proxy else None
        _llm = ChatOpenAI(
            model=cfg.llm_model,
            api_key=cfg.llm_api_key,
            base_url=cfg.llm_base_url,
            temperature=0.2,
            max_tokens=4096,
            http_client=http_client,
        )
    return _llm


def invoke_llm(prompt: str) -> str:
    """调用 LLM 并返回纯文本结果。无 API Key 时使用规则降级。"""
    llm = get_llm()
    if llm is not None:
        resp = llm.invoke(prompt)
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
