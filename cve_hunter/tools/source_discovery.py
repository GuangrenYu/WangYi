"""Free-first source discovery. Search results are leads, never execution evidence."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, quote, urlsplit

from lxml import html

from cve_hunter.tools.reference_evidence import source_url

_CONTEXT_STOPWORDS = {
    "a", "about", "affect", "affected", "allow", "allows", "an", "and", "are",
    "as", "at", "attacker", "attackers", "attacks", "before", "by", "code",
    "could", "critical", "description", "denial", "execution", "for", "from",
    "in", "into", "issue", "is", "its", "may", "network", "of", "on", "or",
    "remote", "request", "requests", "security", "server", "service", "site",
    "software", "the", "their", "this", "through", "to", "unauthenticated",
    "authenticated", "using", "via", "vulnerability", "vulnerabilities", "vulnerable",
    "version", "versions", "was", "were", "which", "with", "would",
    "found", "been", "has", "have", "some", "unknown", "function", "file",
    "classified", "critical", "issue", "affects", "affected", "leads", "manipulation",
    "attack", "launch", "launched", "remotely", "disclosed", "public", "used",
    "vendor", "contacted", "early", "respond", "response", "allows", "allowing",
    "one", "more", "related", "certain", "through", "including", "contains",
}


def _search_context(context: str, limit: int = 6) -> str:
    """Keep product/component names while dropping generic NVD description words."""
    words = re.findall(r"[A-Za-z][A-Za-z0-9._+-]{2,}", str(context or ""))
    selected = []
    seen = set()
    for word in words:
        key = word.lower().strip("._+-")
        if not key or key in _CONTEXT_STOPWORDS or key in seen or key.startswith("cve-"):
            continue
        seen.add(key)
        selected.append(word)
        if len(selected) >= limit:
            break
    return " ".join(selected)


def _search_component_terms(context: str, limit: int = 3) -> str:
    """Prioritize concrete source paths and endpoints named in descriptions."""
    values = []
    seen = set()
    file_paths = re.findall(
        r"(?<![A-Za-z0-9])/?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:php|jsp|java|js|py|rb|aspx?|xml|do|action)\b",
        str(context or ""), re.I,
    )
    # CVE descriptions often name a route without a file extension, e.g.
    # "the file /user/getAllList" or "via /public_html/apply_vacancy".
    # Those exact paths are useful search terms, but remain leads only: this
    # function does not turn description text into request evidence.
    endpoint_paths = re.findall(
        r"\b(?:file|endpoint|request|url|path|route|via|at|through|under)\s+"
        r"(?:the\s+)?(?P<path>/(?:[A-Za-z0-9_.~%+-]+/?)+)",
        str(context or ""), re.I,
    )
    for path in [*file_paths, *endpoint_paths]:
        path = path.rstrip(".,;:)]}>")
        if "://" in path or path.startswith("//"):
            continue
        normalized = path.strip("/")
        for value in (path, normalized.rsplit("/", 1)[-1]):
            key = value.lower()
            if key not in seen:
                seen.add(key)
                values.append(value)
            if len(values) >= limit:
                return " ".join(values)
    return " ".join(values)


def _rank_lead(item: dict, cve_id: str, context_terms: str = "") -> dict:
    result = dict(item)
    haystack = (str(result.get("url") or "") + " " + str(result.get("title") or "")).lower()
    score = int(result.get("score") or 0)
    if cve_id.lower() in haystack:
        score += 8
    if re.search(r"\b(?:poc|exploit|proof.of.concept|advisory|vulnerability)\b", haystack, re.I):
        score += 2
    context_words = [word.lower() for word in context_terms.split() if len(word) > 3]
    if context_words and any(word in haystack for word in context_words):
        score += 3
    result["score"] = score
    return result


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


async def discover_sources(cve_id: str, get, *, searxng_url: str = "", context: str = "") -> dict:
    """Run public index, official-template and free search discovery concurrently."""
    import asyncio
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id, re.I):
        return {"leads": [], "errors": ["invalid CVE identifier"], "providers": {}}
    year = cve_id.split("-")[1]
    context_terms = _search_context(context)
    component_terms = _search_component_terms(context)
    query_text = " ".join(part for part in (cve_id, component_terms, context_terms, "PoC exploit HTTP") if part)
    query = quote(query_text)
    index = f"https://cdn.jsdelivr.net/gh/nomi-sec/PoC-in-GitHub@master/{year}/{cve_id}.json"
    nuclei = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/{year}/{cve_id}.yaml"
    public_index = f"https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id}.md"
    mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    providers = {}
    errors = []
    leads = []

    async def read(name, url, parser, *, headers=None):
        try:
            if headers:
                try:
                    _, text, _ = await get(url, headers=headers)
                except TypeError:
                    # Keep the small callback contract used by offline tests
                    # and alternate readers that only accept the URL.
                    _, text, _ = await get(url)
            else:
                _, text, _ = await get(url)
            found = [_rank_lead(item, cve_id, context_terms) for item in parser(text)]
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

    def parse_public_index(text):
        if not re.search(r"^###\s+\[" + re.escape(cve_id) + r"\]", text, re.M | re.I):
            raise ValueError("public PoC index does not identify requested CVE")
        return [{"url": public_index, "kind": "page", "score": 9, "prefetched_text": text}]

    def parse_mitre(text):
        """Use CVE Program references as additional source leads.

        MITRE data can include product pages and advisories as well as PoCs;
        these are crawl leads only and still pass the normal bounded reader.
        """
        data = json.loads(text)
        containers = data.get("containers") or {}
        references = list((containers.get("cna") or {}).get("references") or [])
        for container in containers.get("adp") or []:
            references.extend((container or {}).get("references") or [])
        found = {}
        for item in references:
            url = source_url(str(item.get("url") or ""))
            if not url:
                continue
            lead = {"url": url, "title": " ".join(str(tag) for tag in (item.get("tags") or [])), "score": 5}
            lead = _rank_lead(lead, cve_id, context_terms)
            if url not in found or lead["score"] > found[url]["score"]:
                found[url] = lead
        return list(found.values())[:12]

    def parse_exploitdb(text):
        data = json.loads(text)
        found = []
        for item in (data.get("data") or [])[:6]:
            exploit_id = str(item.get("id") or "").strip()
            if not exploit_id.isdigit():
                continue
            description = item.get("description") or ""
            if isinstance(description, list):
                title = " ".join(str(value) for value in description)
            else:
                title = str(description)
            found.append({
                "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                "title": title, "kind": "page", "score": 18,
            })
        return found

    def parse_searx(text):
        return [{"url": item["url"], "title": item.get("title", ""), "score": 7}
                for item in json.loads(text).get("results", [])[:8] if source_url(item.get("url", ""))]

    exploitdb = f"https://www.exploit-db.com/search?cve={quote(cve_id.removeprefix('CVE-'))}"
    calls = [
        read("poc_index", index, parse_repos),
        read("public_poc_index", public_index, parse_public_index),
        read("official_nuclei", nuclei, parse_template),
        read("exploit_db", exploitdb, parse_exploitdb, headers={
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
        }),
    ]
    # CVE records are useful for cases with no NVD references or descriptions,
    # so query the CVE Program record on every discovery pass.  It is still a
    # lead source only and remains bounded by the shared crawl budget.
    calls.append(read("mitre_cve", mitre, parse_mitre))
    if searxng_url:
        calls.append(read("searxng", searxng_url.rstrip("/") + "/search?format=json&q=" + query, parse_searx))
    else:
        calls.append(read("duckduckgo", "https://html.duckduckgo.com/html/?q=" + query,
                          lambda text: [{**item, "score": 7} for item in parse_search_html(text)]))
    await asyncio.gather(*calls)
    if not any(item.get("kind") == "github_repo" for item in leads):
        # GitHub repository names are often exactly the CVE identifier.
        # Adding every description token makes the repository query too strict;
        # use product context for ranking and the web query instead.
        await read("github_search", f"https://api.github.com/search/repositories?q={quote(cve_id)}&per_page=3", parse_repos)
    deduped = {}
    for item in leads:
        key = str(item.get("url") or "")
        if key and (key not in deduped or item.get("score", 0) > deduped[key].get("score", 0)):
            deduped[key] = item
    return {"leads": sorted(deduped.values(), key=lambda item: -item.get("score", 0)),
            "errors": errors, "providers": providers, "query": query_text}


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
        return {"leads": [{"url": item["url"], "title": item.get("title", ""),
                           "score": 7, "discovered_from": provider + ":" + query}
                          for item in items if source_url(item.get("url", ""))], "errors": [], "provider": provider}
    except Exception as exc:
        message = str(exc)
        for key in (brave_key, tavily_key):
            if key:
                message = message.replace(key, "[redacted]")
        return {"leads": [], "errors": ["paid discovery: " + message[:300]], "provider": "failed"}
