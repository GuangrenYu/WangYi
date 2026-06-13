"""网页内容提取模块：直接请求 + trafilatura 提取正文。"""

from __future__ import annotations

import httpx
import trafilatura

from cve_hunter.config import cfg


def extract_url_content(url: str) -> dict[str, str]:
    """提取 URL 页面正文内容。

    如果配置了 wayback_url 外部服务则优先调用；外部服务失败时回退到
    内置 httpx + trafilatura，避免离开实验室网络后 Reference 提取直接中断。
    """
    if cfg.wayback_url:
        service_result = _extract_via_service(url)
        if service_result.get("content"):
            return service_result

        builtin_result = _extract_builtin(url)
        service_error = service_result.get("error", "")
        builtin_error = builtin_result.get("error", "")
        if builtin_result.get("content"):
            if service_error:
                builtin_result["fallback_from"] = "wayback"
                builtin_result["service_error"] = service_error
            return builtin_result

        if service_error and builtin_error:
            builtin_result["error"] = f"wayback: {service_error}; builtin: {builtin_error}"
            return builtin_result
        if service_error:
            fallback_result = builtin_result or {"url": url, "title": "", "content": ""}
            fallback_result["error"] = service_error
            return fallback_result
        return builtin_result
    return _extract_builtin(url)


def _extract_via_service(url: str) -> dict[str, str]:
    """通过 wayback-cve 服务提取。"""
    try:
        resp = httpx.post(
            f"{cfg.wayback_url.rstrip('/')}/extract",
            json={"url": url, "use_archive": True, "favor_recall": True},
            timeout=60,
            proxy=cfg.httpx_proxy,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("success"):
            return {
                "url": url,
                "title": data.get("page_title", ""),
                "content": data.get("extracted_text", ""),
            }
        return {"url": url, "title": "", "content": "", "error": data.get("error", "")}
    except Exception as e:
        return {"url": url, "title": "", "content": "", "error": str(e)}


def _extract_builtin(url: str) -> dict[str, str]:
    """内置方式：httpx 获取 HTML → trafilatura 提取。"""
    try:
        resp = httpx.get(
            url,
            timeout=cfg.request_timeout,
            follow_redirects=True,
            proxy=cfg.httpx_proxy,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )
        resp.raise_for_status()
        html = resp.text
        title = ""
        if "<title>" in html.lower():
            start = html.lower().index("<title>") + 7
            end = html.lower().index("</title>", start)
            title = html[start:end].strip()

        extracted = trafilatura.extract(
            html, include_tables=True, include_comments=False, favor_recall=True
        )
        return {"url": url, "title": title, "content": extracted or ""}
    except Exception as e:
        return {"url": url, "title": "", "content": "", "error": str(e)}
