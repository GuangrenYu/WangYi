"""Bounded public-source follow-up crawling, isolated from PoC executors."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from cve_hunter.config import cfg
from cve_hunter.tools.reference_evidence import (
    link_score, page_from_response, source_url, structure_reference,
)

MAX_PAGES = 16
MAX_BYTES = 512 * 1024


def crawl_targets(pages: list[dict[str, Any]], cve_id: str) -> list[dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for page in pages:
        origin = str(page.get("url") or "")
        evidence = structure_reference(page, cve_id)["poc_evidence"]
        candidates = [*evidence["poc_links"]]
        if link_score(origin, cve_id=cve_id) >= 3:
            candidates.append({"url": origin, "score": link_score(origin, cve_id=cve_id)})
        for item in candidates:
            url = str(item["url"])
            if urlsplit(url).hostname == "github.com" and urlsplit(url).path.strip("/").count("/") == 1:
                # One repository metadata call replaces serial main/master filename guesses.
                kind = "github_repo"
            elif urlsplit(url).hostname == "gist.github.com":
                kind = "github_gist"
            else:
                kind = "page"
            target = {"url": url, "kind": kind, "discovered_from": origin, "score": item["score"]}
            if url not in targets or target["score"] > targets[url]["score"]:
                targets[url] = target
    return sorted(targets.values(), key=lambda item: -item["score"])[:MAX_PAGES]


def _raw_url(url: str) -> str:
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if parsed.hostname == "github.com" and len(parts) >= 5 and parts[2] == "blob":
        return "https://raw.githubusercontent.com/" + "/".join(parts[:2] + parts[3:])
    if parsed.hostname in {"exploit-db.com", "www.exploit-db.com"} and len(parts) == 2 and parts[0] == "exploits" and parts[1].isdigit():
        return f"https://www.exploit-db.com/raw/{parts[1]}"
    return url


async def _public_destination(url: str) -> bool:
    parsed = urlsplit(url)
    if not source_url(url) or parsed.port not in {None, 80, 443}:
        return False
    host = parsed.hostname or ""
    if host.lower() in {"localhost", "host.docker.internal"}:
        return False
    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
        return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)
    except (ValueError, OSError):
        return False


async def _get(client: httpx.AsyncClient, url: str, *, trusted_search_url: str = "") -> tuple[str, str, str]:
    for _ in range(4):
        # The configured search endpoint may be self-hosted; page-discovered links never receive this exception.
        configured_search = bool(trusted_search_url) and url == trusted_search_url and bool(source_url(url))
        if not configured_search and not await _public_destination(url):
            raise ValueError("reference destination is not a public HTTP source")
        async with client.stream("GET", url) as response:
            if response.is_redirect:
                url = source_url(response.headers.get("location", ""), url)
                continue
            response.raise_for_status()
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > MAX_BYTES:
                    raise ValueError("reference exceeds the bounded response size")
            return str(response.url), bytes(chunks).decode(response.encoding or "utf-8", errors="replace"), response.headers.get("content-type", "")
    raise ValueError("too many reference redirects")


async def _crawl(payload: dict[str, Any]) -> dict[str, Any]:
    pages: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set(payload.get("known_urls") or [])
    semaphore = asyncio.Semaphore(4)
    tasks: set[asyncio.Task] = set()
    scheduled = 0
    cve_id = str(payload.get("cve_id") or "")
    timeout = min(6.0, max(0.1, float(payload.get("request_timeout", 6))))
    started = time.monotonic()
    discovery = {"providers": {}}
    discovery_finished = not payload.get("discover", False)

    async with httpx.AsyncClient(
        timeout=timeout, proxy=payload.get("proxy"), trust_env=False,
        follow_redirects=False, headers={"User-Agent": "CVE-Hunter-reference-reader", "Accept": "*/*"},
    ) as client:
        def schedule(target: dict[str, Any], depth: int) -> None:
            nonlocal scheduled
            url = target["url"]
            canonical = _raw_url(url) if target.get("kind", "page") == "page" else url
            if url in seen or canonical in seen or scheduled >= MAX_PAGES:
                return
            # Reserve slots for search discoveries so prolific reference navigation cannot consume them all.
            if depth > 0 and not discovery_finished and scheduled >= MAX_PAGES - 6:
                return
            seen.add(url)
            seen.add(canonical)
            scheduled += 1
            task = asyncio.create_task(fetch(target, depth))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        async def fetch(target: dict[str, Any], depth: int) -> None:
            url = target["url"]
            try:
                async with semaphore:
                    kind = target.get("kind", "page")
                    if kind == "github_repo":
                        repo = urlsplit(url).path.strip("/")
                        try:
                            _, text, _ = await _get(client, f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1")
                            tree = json.loads(text)
                            sha = str(tree.get("sha") or "")
                            if not sha:
                                raise ValueError("GitHub tree did not provide a revision")
                            file_items = tree.get("tree") or []
                        except (httpx.HTTPError, ValueError):
                            _, text, _ = await _get(client, url)
                            branch = re.search(r'"defaultBranch":"([^"]+)"', text)
                            sha = branch[1] if branch else "main"
                            file_items = [{"path": path, "type": "blob"} for path in
                                          re.findall(r'"path":"([^"]+)"', text)]
                        entries = []
                        for item in file_items:
                            path = str(item.get("path") or "")
                            if not path.lower().endswith((".md", ".rst", ".txt", ".py", ".rb", ".sh", ".go", ".js", ".http", ".yaml", ".yml")):
                                continue
                            score = link_score("https://raw.githubusercontent.com/" + repo + "/" + sha + "/" + path, path, cve_id)
                            if path.lower().endswith(("readme.md", "readme.rst", "readme.txt")):
                                score = max(score, 5)
                            if item.get("type") == "blob" and score >= 3 and int(item.get("size") or 0) <= MAX_BYTES:
                                entries.append((score, path))
                        sources = [f"https://raw.githubusercontent.com/{repo}/{sha}/{quote(path, safe='/')}"
                                   for _, path in sorted(entries, key=lambda item: -item[0])[:4]]
                        for source in sources:
                            schedule({"url": source, "discovered_from": url, "related_sources": sources}, depth + 1)
                        return
                    if kind == "github_gist":
                        gist_id = urlsplit(url).path.strip("/").split("/")[-1]
                        _, text, _ = await _get(client, f"https://api.github.com/gists/{gist_id}")
                        data = json.loads(text)
                        for item in list((data.get("files") or {}).values())[:4]:
                            if item.get("raw_url"):
                                schedule({"url": item["raw_url"], "discovered_from": url}, depth + 1)
                        return
                    if target.get("prefetched_text"):
                        final_url, text, content_type = url, target["prefetched_text"], "text/plain"
                    else:
                        final_url, text, content_type = await _get(client, _raw_url(url))
                    seen.add(final_url)
                    page = page_from_response(final_url, text, content_type)
                    if not str(page.get("content") or "").strip() and not page.get("code_blocks"):
                        raise ValueError("empty source content")
                    page.update({"source": "reference_followup", "discovered_from": target.get("discovered_from", url),
                                 "related_sources": target.get("related_sources", [])})
                    page["arrived_sec"] = round(time.monotonic() - started, 3)
                    page["discovery_provider"] = target.get("discovery_provider", "reference")
                    page = structure_reference(page, cve_id)
                    pages.append(page)
                    # Flush each completed source so a hard timeout retains useful progress.
                    if payload.get("stream_results"):
                        print(json.dumps({"page": page}, ensure_ascii=False), flush=True)
                    if depth < 2:
                        for child in crawl_targets([page], cve_id)[:4]:
                            schedule(child, depth + 1)
            except (httpx.HTTPError, ValueError, OSError, KeyError, TypeError) as exc:
                errors.append(f"{url}: {exc}")

        async def discover() -> None:
            nonlocal discovery_finished
            from cve_hunter.tools.source_discovery import discover_sources

            async def get(url):
                async with semaphore:
                    searxng = payload.get("searxng_url", "").rstrip("/")
                    trusted = url if searxng and url.startswith(searxng + "/search?") else ""
                    return await _get(client, url, trusted_search_url=trusted)
            result = await discover_sources(cve_id, get, searxng_url=payload.get("searxng_url", ""))
            discovery_finished = True
            discovery["providers"] = result["providers"]
            errors.extend(result["errors"])
            for lead in result["leads"]:
                inferred = crawl_targets([{"url": lead["url"], "content": ""}], cve_id)
                if not lead.get("kind") and inferred:
                    lead["kind"] = inferred[0]["kind"]
                schedule(lead, 0)

        async def drain():
            while tasks:
                await asyncio.wait(list(tasks), return_when=asyncio.FIRST_COMPLETED)

        async def work() -> None:
            for target in (payload.get("targets") or [])[:4]:
                schedule(target, 0)
            if payload.get("discover"):
                task = asyncio.create_task(discover())
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            await drain()
            # Paid search is a final fallback when free sources provide no HTTP evidence.
            from cve_hunter.tools.reference_evidence import has_http_evidence
            if payload.get("paid_fallback") and not any(has_http_evidence(page) for page in pages):
                from cve_hunter.tools.source_discovery import paid_discovery
                result = await paid_discovery(cve_id + " PoC HTTP request", client,
                                             brave_key=getattr(cfg, "brave_search_api_key", ""),
                                             tavily_key=getattr(cfg, "tavily_api_key", ""))
                discovery["paid_provider"] = result["provider"]
                errors.extend(result["errors"])
                for lead in result["leads"]:
                    inferred = crawl_targets([{"url": lead["url"], "content": ""}], cve_id)
                    if inferred:
                        lead["kind"] = inferred[0]["kind"]
                    schedule(lead, 0)
                await drain()

        timed_out = False
        try:
            await asyncio.wait_for(work(), timeout=max(0.01, float(payload.get("budget", 28))))
        except asyncio.TimeoutError:
            timed_out = True
        finally:
            pending = list(tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
    return {"pages": pages, "errors": errors[:20], "timed_out": timed_out, "scheduled": scheduled,
            "discovery": discovery}


def enrich_references(
    cve_id: str, references: list[dict[str, Any]], cached: list[dict[str, Any]],
    *, allow_network: bool = True, reference_urls: list[str] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    budget = min(60.0, max(0.0, float(getattr(cfg, "reference_crawl_budget", 20))))
    pages = [structure_reference(page, cve_id) for page in references]
    seeds = [{"url": url, "content": ""} for url in reference_urls or []]
    cache_by_url = {str(page.get("url") or ""): page for page in cached}
    included = {str(page.get("url") or "") for page in pages}
    origins = included | set(reference_urls or [])
    # Include previously discovered descendants even though they are not NVD URLs.
    for _ in range(3):
        origins.update(target["url"] for target in crawl_targets(pages + seeds, cve_id))
        for page in cached:
            url = str(page.get("url") or "")
            if url not in included and (url in origins or page.get("discovered_from") in origins):
                pages.append(structure_reference(page, cve_id))
                included.add(url)
                origins.add(url)
    targets = crawl_targets(pages + seeds, cve_id)
    missing = []
    for target in targets:
        existing = cache_by_url.get(target["url"]) or cache_by_url.get(_raw_url(target["url"]))
        # Landing-page HTML is not a substitute for an Exploit-DB raw source.
        if existing and existing.get("poc_evidence") and not (
            "/exploits/" in target["url"] and not existing.get("poc_evidence", {}).get("code_blocks")
        ):
            if existing["url"] not in included:
                pages.append(structure_reference(existing, cve_id))
                included.add(existing["url"])
            continue
        # Repository metadata need not be reloaded if its source files are cached.
        if target.get("kind") in {"github_repo", "github_gist"} and any(
            page.get("discovered_from") == target["url"]
            and (page.get("related_sources") or (
                page.get("poc_evidence", {}).get("code_blocks")
                and not urlsplit(page["url"]).path.rsplit("/", 1)[-1].lower().startswith("readme")
            ))
            for page in pages
        ):
            continue
        missing.append(target)
    result: dict[str, Any] = {"pages": pages, "errors": [], "timed_out": False, "scheduled": 0}
    remaining = budget - (time.monotonic() - started)
    from cve_hunter.tools.reference_evidence import has_http_evidence
    needs_discovery = getattr(cfg, "reference_discovery_enabled", True) and not any(has_http_evidence(page) for page in pages)
    if allow_network and (missing or needs_discovery) and remaining > 0.5:
        reader_timeout = remaining - 0.25
        payload = {
            "cve_id": cve_id, "targets": missing,
            "known_urls": [page["url"] for page in pages if page.get("source") == "reference_followup"],
            "budget": max(0.01, reader_timeout - 0.5),
            "request_timeout": getattr(cfg, "web_source_timeout", 6),
            "proxy": getattr(cfg, "httpx_proxy", None), "stream_results": True,
            "discover": needs_discovery,
            "searxng_url": getattr(cfg, "searxng_url", ""),
            "paid_fallback": getattr(cfg, "search_paid_fallback", True) and needs_discovery,
        }
        output = ""
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "cve_hunter.tools.reference_crawl"],
                input=json.dumps(payload), text=True, capture_output=True,
                cwd=Path(__file__).resolve().parents[2], timeout=reader_timeout,
            )
            output = completed.stdout
            if completed.returncode:
                result["errors"].append("reference follow-up reader failed")
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            result["timed_out"] = True
        except OSError as exc:
            result["errors"].append(str(exc))
        for line in output.split("\n"):
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(item.get("page"), dict):
                result["pages"].append(item["page"])
            if "summary" in item:
                result.update(item["summary"])
    result["pages"] = list({page["url"]: page for page in result["pages"] if str(page.get("content") or "").strip()}.values())
    result["elapsed_sec"] = round(time.monotonic() - started, 3)
    result["budget_sec"] = budget
    return result


def main() -> None:
    payload = json.load(sys.stdin)
    result = asyncio.run(_crawl(payload))
    result.pop("pages", None)
    print(json.dumps({"summary": result}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
