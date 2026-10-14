"""联网搜索：免费 SearXNG/DuckDuckGo 优先，Brave/Tavily 付费补充。"""

from __future__ import annotations

import httpx

from cve_hunter.config import cfg
from cve_hunter.tools.tavily_http import post_tavily


def _source_timeout() -> int:
    """Return a bounded timeout for non-target web providers."""
    for value in (
        getattr(cfg, "web_source_timeout", None),
        getattr(cfg, "request_timeout", 30),
    ):
        try:
            return max(3, int(value))
        except (TypeError, ValueError):
            continue
    return 30


def search_web(query: str, max_results: int = 5) -> list[dict[str, str]]:
    """优先使用免费搜索，配置允许时使用付费补充。

    返回 [{"title": ..., "url": ..., "content": ...}, ...]
    """
    free_errors = []
    if getattr(cfg, "searxng_url", ""):
        results = _search_searxng(query, max_results)
        if _has_usable_results(results):
            return results
        free_errors.extend(results)
    duckduckgo_results = _search_duckduckgo(query, max_results)
    if _has_usable_results(duckduckgo_results):
        return duckduckgo_results
    if getattr(cfg, "search_paid_fallback", True) and getattr(cfg, "brave_search_api_key", ""):
        results = _search_brave(query, max_results)
        if _has_usable_results(results):
            return results
        free_errors.extend(results)
    if getattr(cfg, "search_paid_fallback", True) and getattr(cfg, "tavily_api_key", ""):
        tavily_results = _search_tavily(query, max_results)
        if _has_usable_results(tavily_results):
            return tavily_results

        return _combined_search_errors(tavily_results, duckduckgo_results) or tavily_results or duckduckgo_results
    return free_errors + duckduckgo_results


def _search_searxng(query: str, max_results: int) -> list[dict[str, str]]:
    try:
        response = httpx.get(cfg.searxng_url.rstrip("/") + "/search",
                             params={"q": query, "format": "json"},
                             timeout=_source_timeout(), proxy=cfg.httpx_proxy, trust_env=False)
        response.raise_for_status()
        return [{"title": item.get("title", ""), "url": item["url"], "content": item.get("content", "")}
                for item in response.json().get("results", [])[:max_results] if item.get("url")]
    except Exception as exc:
        return [{"title": "搜索错误", "url": "", "content": "SearXNG: " + str(exc)}]


def _search_brave(query: str, max_results: int) -> list[dict[str, str]]:
    try:
        response = httpx.get("https://api.search.brave.com/res/v1/web/search",
                             params={"q": query, "count": min(20, max_results)},
                             headers={"X-Subscription-Token": cfg.brave_search_api_key},
                             timeout=_source_timeout(), proxy=cfg.httpx_proxy, trust_env=False)
        response.raise_for_status()
        return [{"title": item.get("title", ""), "url": item["url"], "content": item.get("description", "")}
                for item in response.json().get("web", {}).get("results", [])[:max_results] if item.get("url")]
    except Exception as exc:
        return [{"title": "搜索错误", "url": "", "content": "Brave: " + str(exc).replace(cfg.brave_search_api_key, "[redacted]")}]


def _search_tavily(query: str, max_results: int) -> list[dict[str, str]]:
    """Tavily 搜索。"""
    try:
        results = post_tavily(
            "search", api_key=getattr(cfg, "tavily_api_key", ""),
            payload={"query": query, "max_results": max_results,
                     "search_depth": "advanced", "include_raw_content": False},
            proxy=getattr(cfg, "httpx_proxy", None),
            timeout=_source_timeout(),
        )
        return [
            {
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "content": r.get("content", ""),
            }
            for r in results.get("results", [])
        ]
    except Exception as e:
        return [{"title": "搜索错误", "url": "", "content": str(e)}]


def _search_duckduckgo(query: str, max_results: int) -> list[dict[str, str]]:
    """备用：简单的 DuckDuckGo HTML 搜索。"""
    try:
        resp = httpx.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=_source_timeout(),
            follow_redirects=True,
            proxy=getattr(cfg, "httpx_proxy", None),
            trust_env=False,
        )
        resp.raise_for_status()
        from cve_hunter.tools.source_discovery import parse_search_html
        return parse_search_html(resp.text)[:max_results]
    except Exception as e:
        return [{"title": "搜索错误", "url": "", "content": str(e)}]


def _has_usable_results(results: list[dict[str, str]]) -> bool:
    """判断搜索结果中是否有可用于后续提取的条目。"""
    return any(
        item.get("title") != "搜索错误" and (item.get("url") or item.get("content"))
        for item in results
    )


def _combined_search_errors(
    primary_results: list[dict[str, str]],
    fallback_results: list[dict[str, str]],
) -> list[dict[str, str]]:
    errors = []
    for label, results in (("Tavily", primary_results), ("DuckDuckGo", fallback_results)):
        for item in results:
            if item.get("title") == "搜索错误" and item.get("content"):
                errors.append(f"{label}: {item['content']}")

    if not errors:
        return []
    return [{"title": "搜索错误", "url": "", "content": "; ".join(errors)}]
