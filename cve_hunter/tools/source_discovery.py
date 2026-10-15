"""Free-first source discovery. Search results are leads, never execution evidence."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, quote, urlsplit

from lxml import html

from cve_hunter.tools.reference_evidence import source_url


def parse_search_html(text: str) -> list[dict[str, str]]:
    if any(marker in text.lower() for marker in ("anomaly.js", "challenge-form", "confirm this search was made by a human")):
        raise ValueError("search provider returned a human verification challenge")
    document = html.fromstring(text)
    results = []
    for node in document.xpath('//a[contains(@class,"result__a") or contains(@class,"result-link")]'):
        href = node.get("href", "")
        if href.startswith("//"):
            href = "https:" + href
        if urlsplit(href).hostname and "duckduckgo.com" in urlsplit(href).hostname:
            href = parse_qs(urlsplit(href).query).get("uddg", [""])[0]
        url = source_url(href)
        if url:
            results.append({"url": url, "title": node.text_content().strip(), "content": ""})
    return results[:6]


async def discover_sources(cve_id: str, get, *, searxng_url: str = "") -> dict:
    """Run public index, official-template and free search discovery concurrently."""
    import asyncio
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id, re.I):
        return {"leads": [], "errors": ["invalid CVE identifier"], "providers": {}}
    year = cve_id.split("-")[1]
    query = quote(cve_id + " PoC exploit usage")
    index = f"https://cdn.jsdelivr.net/gh/nomi-sec/PoC-in-GitHub@master/{year}/{cve_id}.json"
    nuclei = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/{year}/{cve_id}.yaml"
    providers = {}
    errors = []
    leads = []

    async def read(name, url, parser):
        try:
            _, text, _ = await get(url)
            found = parser(text)
            providers[name] = {"status": "ok", "results": len(found), "url": url}
            for item in found:
                item.update({"discovered_from": url, "discovery_provider": name})
                leads.append(item)
        except Exception as exc:
            providers[name] = {"status": "error", "error": str(exc)[:300], "url": url}
            errors.append(f"{name}: {str(exc)[:300]}")

    def parse_repos(text):
        data = json.loads(text)
        items = data if isinstance(data, list) else data.get("items", [])
        return [{"url": item["html_url"], "kind": "github_repo", "score": 10}
                for item in items[:3] if source_url(str(item.get("html_url") or ""))]

    def parse_template(text):
        if not re.search(r"(?m)^id:\s*" + re.escape(cve_id) + r"\s*$", text, re.I):
            raise ValueError("official template does not identify requested CVE")
        return [{"url": nuclei, "kind": "page", "score": 20, "prefetched_text": text}]

    def parse_searx(text):
        return [{"url": item["url"], "title": item.get("title", ""), "score": 7}
                for item in json.loads(text).get("results", [])[:4] if source_url(item.get("url", ""))]

    calls = [read("poc_index", index, parse_repos), read("official_nuclei", nuclei, parse_template)]
    if searxng_url:
        calls.append(read("searxng", searxng_url.rstrip("/") + "/search?format=json&q=" + query, parse_searx))
    else:
        calls.append(read("duckduckgo", "https://html.duckduckgo.com/html/?q=" + query,
                          lambda text: [{**item, "score": 7} for item in parse_search_html(text)]))
    await asyncio.gather(*calls)
    if not any(item.get("kind") == "github_repo" for item in leads):
        await read("github_search", f"https://api.github.com/search/repositories?q={quote(cve_id)}&per_page=3", parse_repos)
    return {"leads": sorted(leads, key=lambda item: -item.get("score", 0)), "errors": errors, "providers": providers}


async def paid_discovery(query: str, client, *, brave_key: str = "", tavily_key: str = "") -> dict:
    """Optional paid fallback only after free discovery. No key in logs or URLs."""
    try:
        if brave_key:
            response = await client.get("https://api.search.brave.com/res/v1/web/search",
                                        params={"q": query, "count": 4}, headers={"X-Subscription-Token": brave_key})
            response.raise_for_status()
            items = response.json().get("web", {}).get("results", [])
            provider = "brave"
        elif tavily_key:
            response = await client.post("https://api.tavily.com/search", headers={"Authorization": "Bearer " + tavily_key},
                                         json={"query": query, "max_results": 4, "search_depth": "basic"})
            response.raise_for_status()
            items = response.json().get("results", [])
            provider = "tavily"
        else:
            return {"leads": [], "errors": [], "provider": "unconfigured"}
        return {"leads": [{"url": item["url"], "score": 7, "discovered_from": provider + ":" + query}
                          for item in items if source_url(item.get("url", ""))], "errors": [], "provider": provider}
    except Exception as exc:
        message = str(exc)
        for key in (brave_key, tavily_key):
            if key:
                message = message.replace(key, "[redacted]")
        return {"leads": [], "errors": ["paid discovery: " + message[:300]], "provider": "failed"}
