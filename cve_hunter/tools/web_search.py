"""联网搜索模块：Tavily / 备用 DuckDuckGo。"""

from __future__ import annotations

import httpx

from cve_hunter.config import cfg


def search_web(query: str, max_results: int = 5) -> list[dict[str, str]]:
    """使用 Tavily 搜索引擎搜索漏洞相关信息。

    返回 [{"title": ..., "url": ..., "content": ...}, ...]
    """
    if cfg.tavily_api_key:
        return _search_tavily(query, max_results)
    return _search_duckduckgo(query, max_results)


def _search_tavily(query: str, max_results: int) -> list[dict[str, str]]:
    """Tavily 搜索。"""
    try:
        from tavily import TavilyClient

        client = TavilyClient(api_key=cfg.tavily_api_key)
        results = client.search(
            query=query,
            max_results=max_results,
            search_depth="advanced",
            include_raw_content=False,
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
            timeout=cfg.request_timeout,
            follow_redirects=True,
            proxy=cfg.httpx_proxy,
        )
        results = []
        import re

        for m in re.finditer(
            r'<a rel="nofollow" class="result__a" href="([^"]+)"[^>]*>(.+?)</a>',
            resp.text,
        ):
            url, title = m.group(1), re.sub(r"<[^>]+>", "", m.group(2))
            results.append({"title": title.strip(), "url": url, "content": ""})
            if len(results) >= max_results:
                break
        return results
    except Exception as e:
        return [{"title": "搜索错误", "url": "", "content": str(e)}]
