"""网页内容提取模块：直接请求 + trafilatura 提取正文。"""

from __future__ import annotations

import httpx
from typing import Any

from cve_hunter.config import cfg
from cve_hunter.tools.tavily_http import post_tavily
from cve_hunter.tools.reference_evidence import page_from_response, structure_reference

# 过短正文视为失败，继续下一通道（避免空壳页被当成成功）。
MIN_REFERENCE_CONTENT_LEN = 80


def _source_timeout() -> int:
    """Return the bounded timeout used by non-target web sources."""
    for value in (
        getattr(cfg, "web_source_timeout", None),
        getattr(cfg, "request_timeout", 30),
    ):
        try:
            return max(3, int(value))
        except (TypeError, ValueError):
            continue
    return 30


def _content_usable(content: str, *, min_len: int = MIN_REFERENCE_CONTENT_LEN) -> bool:
    return len(str(content or "").strip()) >= max(1, int(min_len))


def extract_reference_url(
    url: str,
    *,
    prefer_tavily: bool = False,
    min_len: int = MIN_REFERENCE_CONTENT_LEN,
) -> dict[str, Any]:
    """Unified reference-page extractor with ordered channel fallback.

    Order:
    1) Tavily (when prefer_tavily=True and key configured)
    2) wayback service (when configured) then builtin
    3) builtin httpx + trafilatura
    """
    errors: list[str] = []

    if prefer_tavily:
        tavily_result = _extract_via_tavily(url)
        if _content_usable(tavily_result.get("content", ""), min_len=min_len):
            tavily_result["source"] = "tavily"
            return tavily_result
        if tavily_result.get("error"):
            errors.append(f"tavily: {tavily_result.get('error')}")
        elif tavily_result.get("content"):
            errors.append("tavily: content too short")

    # extract_url_content already does wayback -> builtin when wayback is configured.
    fallback = extract_url_content(url)
    if _content_usable(fallback.get("content", ""), min_len=min_len):
        if prefer_tavily and errors:
            fallback["fallback_from"] = "tavily"
            fallback["service_error"] = "; ".join(errors)
        if not fallback.get("source"):
            fallback["source"] = str(fallback.get("fallback_from") or "builtin")
        return fallback

    if fallback.get("error"):
        errors.append(f"fallback: {fallback.get('error')}")
    elif fallback.get("content"):
        errors.append("fallback: content too short")

    return {
        "url": url,
        "title": str(fallback.get("title") or ""),
        "content": "",
        "error": "; ".join(errors) if errors else "未提取到可用参考正文",
    }


def extract_url_content(url: str) -> dict[str, Any]:
    """提取 URL 页面正文内容。

    如果配置了 wayback_url 外部服务则优先调用；外部服务失败时回退到
    内置 httpx + trafilatura，避免离开实验室网络后 Reference 提取直接中断。
    """
    if getattr(cfg, "wayback_url", ""):
        service_result = _extract_via_service(url)
        if service_result.get("content"):
            service_result["source"] = "wayback"
            return service_result

        builtin_result = _extract_builtin(url)
        service_error = service_result.get("error", "")
        builtin_error = builtin_result.get("error", "")
        if builtin_result.get("content"):
            builtin_result["source"] = "builtin"
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
    result = _extract_builtin(url)
    if result.get("content"):
        result["source"] = "builtin"
    return result


def extract_url_content_tavily(url: str) -> dict[str, str]:
    """Fetch one NVD reference through Tavily, falling back to wayback/builtin."""
    # Preserve the legacy helper's contract: a non-empty Tavily response is
    # usable even when it is only a short fixture/snippet.  ReferenceAgent
    # uses ``extract_reference_url`` directly with its stricter default bound.
    return extract_reference_url(url, prefer_tavily=True, min_len=1)


def _extract_via_tavily(url: str) -> dict[str, str]:
    try:
        api_key = getattr(cfg, "tavily_api_key", "")
        if not api_key:
            return {"url": url, "title": "", "content": "", "error": "TAVILY_API_KEY 未配置"}
        result = post_tavily(
            "extract",
            api_key=api_key,
            payload={"urls": [url], "include_images": False},
            proxy=getattr(cfg, "httpx_proxy", None),
            timeout=_source_timeout(),
        )
        if not result.get("results") and result.get("failed_results"):
            failure = result["failed_results"][0]
            return {
                "url": url,
                "title": "",
                "content": "",
                "error": str(failure.get("error") or "Tavily 未提取到参考正文"),
            }
        item = (result.get("results") or [{}])[0]
        content = item.get("raw_content", "") or item.get("content", "") or ""
        return {
            "url": url,
            "title": item.get("title", ""),
            "content": content,
        }
    except Exception as exc:
        return {"url": url, "title": "", "content": "", "error": str(exc)}


def _extract_via_service(url: str) -> dict[str, str]:
    """通过 wayback-cve 服务提取。"""
    try:
        # 实验室内网服务直连，不走 Clash；否则易出现代理环/超时/502。
        resp = httpx.post(
            f"{getattr(cfg, 'wayback_url', '').rstrip('/')}/extract",
            json={"url": url, "use_archive": True, "favor_recall": True},
            timeout=_source_timeout(),
            proxy=None,
            trust_env=False,
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


def _extract_builtin(url: str) -> dict[str, Any]:
    """内置方式：httpx 获取 HTML → trafilatura 提取。"""
    try:
        resp = httpx.get(
            url,
            timeout=_source_timeout(),
            follow_redirects=True,
            proxy=getattr(cfg, "httpx_proxy", None),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )
        resp.raise_for_status()
        page = page_from_response(str(resp.url), resp.text, resp.headers.get("content-type", ""))
        page["requested_url"] = url
        page["resolved_url"] = str(resp.url)
        return structure_reference(page)
    except Exception as e:
        return {"url": url, "title": "", "content": "", "error": str(e)}
