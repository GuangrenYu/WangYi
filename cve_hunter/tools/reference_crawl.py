"""Bounded public-source follow-up crawling, isolated from PoC executors."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

import httpx

from cve_hunter.config import cfg
from cve_hunter.tools.reference_evidence import (
    MAX_CONTENT, has_complete_poc_source, has_cve_related_http_evidence, link_score, page_from_response, source_url,
    structure_reference,
)

MAX_PAGES = 22
DISCOVERY_PAGE_RESERVE = 6
FOLLOWUP_PAGE_RESERVE = 4
MAX_BYTES = 512 * 1024
GITHUB_DIFF_BYTES = 256 * 1024
GITHUB_API_BYTES = 2 * MAX_BYTES
DNS_TIMEOUT = 5.0


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
            parsed = urlsplit(url)
            parts = parsed.path.strip("/").split("/")
            if parsed.hostname == "github.com" and len(parts) == 2:
                # One repository metadata call replaces serial main/master filename guesses.
                kind = "github_repo"
            elif urlsplit(url).hostname == "gist.github.com":
                kind = "github_gist"
            elif parsed.hostname == "github.com" and len(parts) >= 4 and parts[2] in {"commit", "commits"}:
                kind = "github_commit"
            elif parsed.hostname == "github.com" and len(parts) >= 4 and parts[2] in {"pull", "pulls"} and parts[3].isdigit():
                kind = "github_pull_request"
            elif parsed.hostname == "github.com" and len(parts) >= 4 and parts[2] == "issues" and parts[3].isdigit():
                kind = "github_issue"
            else:
                kind = "page"
            target = {"url": url, "kind": kind, "discovered_from": origin, "score": item["score"],
                      "discovery_provider": page.get("discovery_provider", "reference")}
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
    if parsed.hostname == "plugins.trac.wordpress.org":
        revision = parse_qs(parsed.query).get("rev", [""])[0]
        if len(parts) >= 3 and parts[0] == "browser":
            prefix = f"!svn/bc/{revision}/" if revision.isdigit() else ""
            return "https://plugins.svn.wordpress.org/" + prefix + "/".join(parts[1:])
        if len(parts) >= 4 and parts[0] == "changeset" and parts[1].isdigit():
            return "https://plugins.svn.wordpress.org/!svn/bc/" + "/".join(parts[1:])
    return url


def _github_diff_url(url: str, kind: str) -> str:
    """Map GitHub commit/PR pages to their compact public text diff."""
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if parsed.hostname != "github.com" or len(parts) < 4:
        raise ValueError("invalid GitHub source URL")
    if kind == "github_commit" and parts[2] in {"commit", "commits"}:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + ".patch", "", ""))
    if kind == "github_pull_request" and parts[2] in {"pull", "pulls"} and parts[3].isdigit():
        return urlunsplit((parsed.scheme, parsed.netloc, "/".join(parts[:3] + [parts[3] + ".patch"]), "", ""))
    raise ValueError("invalid GitHub diff URL")


def _github_api_diff_url(url: str, kind: str) -> str:
    """Build a compact file-patch API URL for oversized GitHub diffs."""
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if parsed.hostname != "github.com" or len(parts) < 4:
        raise ValueError("invalid GitHub diff URL")
    repo = "/".join(parts[:2])
    if kind == "github_commit" and parts[2] in {"commit", "commits"}:
        return f"https://api.github.com/repos/{repo}/commits/{parts[3]}"
    if kind == "github_pull_request" and parts[2] in {"pull", "pulls"} and parts[3].isdigit():
        return f"https://api.github.com/repos/{repo}/pulls/{parts[3]}/files?per_page=30"
    raise ValueError("invalid GitHub diff URL")


def _github_issue_api_url(url: str) -> str:
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if parsed.hostname != "github.com" or len(parts) < 4 or parts[2] != "issues" or not parts[3].isdigit():
        raise ValueError("invalid GitHub issue URL")
    repo = "/".join(parts[:2])
    return f"https://api.github.com/repos/{repo}/issues/{parts[3]}"


def _github_issue_page(url: str, data: Any, cve_id: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("GitHub issue response is not an object")
    title = str(data.get("title") or "")
    body = str(data.get("body") or "")
    content = "\n\n".join(value for value in (title, body) if value)
    return structure_reference({
        "url": url, "title": title, "content": content[:MAX_CONTENT],
        "content_format": "text", "discovery_provider": "reference",
    }, cve_id)


def _github_api_diff_page(url: str, kind: str, data: Any, cve_id: str) -> dict[str, Any]:
    """Turn the compact GitHub API response into normal source evidence."""
    if kind == "github_commit" and isinstance(data, dict):
        files = data.get("files") or []
        title = str((data.get("commit") or {}).get("message") or "").splitlines()[0]
    else:
        files = data if isinstance(data, list) else []
        title = url
    ranked_blocks = []
    for item in files:
        filename = str(item.get("filename") or "")
        patch = str(item.get("patch") or "")
        if not patch:
            continue
        lowered_name = filename.lower()
        lowered_patch = patch.lower()
        score = 0
        if lowered_name.endswith((".py", ".php", ".jsp", ".java", ".js", ".rb", ".go", ".aspx", ".cs")):
            score += 5
        if re.search(r"(?:router|routes?|controller|handler|endpoint|request|api|web|auth|upload)", lowered_name):
            score += 4
        if re.search(r"(?:@(?:router|app)\.|\.route\s*\(|route\s*=|endpoint|request\.path|url\s*=|path\s*=|/api/|/admin/)", lowered_patch):
            score += 5
        if re.search(r"(?m)^\+[^\n]*(?:GET|POST|PUT|DELETE|PATCH)\s+/|^\+[^\n]*https?://", patch, re.I):
            score += 8
        if any(token in lowered_name for token in ("readme", "changelog", "license", "docs/", "documentation/")):
            score -= 6
        if cve_id.lower() in lowered_patch:
            score += 3
        block = {"language": filename.rsplit(".", 1)[-1], "text": patch,
                 "evidence_url": str(item.get("blob_url") or url)}
        ranked_blocks.append((score, filename, block))
    ranked_blocks.sort(key=lambda item: (-item[0], item[1].lower()))
    blocks = [item[2] for item in ranked_blocks[:12]]
    content = "\n\n".join(
        f"--- {filename} ---\n{block['text']}"
        for _, filename, block in ranked_blocks[:24]
    )
    return structure_reference({
        "url": url, "title": title or url, "content": content[:MAX_CONTENT],
        "code_blocks": blocks[:12], "content_format": "text",
        "discovery_provider": "reference",
    }, cve_id)


async def _github_api_get(
    client: httpx.AsyncClient, url: str, *, headers: dict[str, str] | None = None,
    max_bytes: int = MAX_BYTES,
) -> tuple[str, str, str]:
    """Read a public GitHub API endpoint through the configured crawl client."""
    return await _get(client, url, headers=headers, max_bytes=max_bytes)


async def _resolve_addresses(host: str, port: int) -> list:
    """Keep a stalled libc DNS lookup from holding the isolated reader open."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def deliver(addresses, error):
        if not future.done():
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(addresses)

    def resolve():
        try:
            addresses, error = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), None
        except OSError as exc:
            addresses, error = [], exc
        try:
            loop.call_soon_threadsafe(deliver, addresses, error)
        except RuntimeError:
            pass  # The bounded reader has already closed its event loop.

    threading.Thread(target=resolve, daemon=True, name="reference-dns").start()
    return await asyncio.wait_for(future, timeout=DNS_TIMEOUT)


async def _public_destination(url: str) -> bool:
    parsed = urlsplit(url)
    if not source_url(url) or parsed.port not in {None, 80, 443}:
        return False
    host = parsed.hostname or ""
    if host.lower() in {"localhost", "host.docker.internal"}:
        return False
    try:
        addresses = await _resolve_addresses(host, parsed.port or 443)
        return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)
    except (ValueError, OSError, asyncio.TimeoutError):
        return False


async def _get(
    client: httpx.AsyncClient, url: str, *, trusted_search_url: str = "",
    headers: dict[str, str] | None = None, max_bytes: int = MAX_BYTES,
) -> tuple[str, str, str]:
    original_url = url
    for _ in range(4):
        # The configured search endpoint may be self-hosted; page-discovered links never receive this exception.
        configured_search = bool(trusted_search_url) and url == trusted_search_url and bool(source_url(url))
        if not configured_search and not await _public_destination(url):
            raise ValueError("reference destination is not a public HTTP source")
        async with client.stream("GET", url, headers=headers if url == original_url else None) as response:
            if response.is_redirect:
                url = source_url(response.headers.get("location", ""), url)
                continue
            response.raise_for_status()
            content_range = response.headers.get("content-range", "")
            range_match = re.fullmatch(r"bytes\s+\d+-([0-9]+)/([0-9]+|\*)", content_range, re.I)
            if range_match and range_match[2] != "*" and int(range_match[1]) + 1 < int(range_match[2]):
                raise ValueError("reference exceeds the bounded response size")
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > max_bytes:
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
    # Discovery runs use a fixed cap so an unusually large NVD reference list
    # cannot consume the discovery and follow-up reserves. When discovery is
    # disabled, retain the historical behavior of visiting every explicit root target.
    page_limit = MAX_PAGES if payload.get("discover") else max(
        MAX_PAGES, len(payload.get("targets") or []),
    )
    cve_id = str(payload.get("cve_id") or "")
    timeout = min(6.0, max(0.1, float(payload.get("request_timeout", 6))))
    started = time.monotonic()
    discovery = {"providers": {}}
    discovery_finished = not payload.get("discover", False)
    attempted_urls: set[str] = set()

    async with httpx.AsyncClient(
        timeout=timeout, proxy=payload.get("proxy"), trust_env=False,
        follow_redirects=False, headers={"User-Agent": "CVE-Hunter-reference-reader", "Accept": "*/*"},
    ) as client:
        def schedule(target: dict[str, Any], depth: int, *, discovery_root: bool = False) -> None:
            nonlocal scheduled
            url = target["url"]
            canonical = _raw_url(url) if target.get("kind", "page") == "page" else url
            if url in seen or canonical in seen or scheduled >= page_limit:
                return
            # Reserve slots for search discoveries so root references as well
            # as prolific descendant links cannot consume them all.
            if (payload.get("discover") and not discovery_finished and not discovery_root
                    and scheduled >= page_limit - DISCOVERY_PAGE_RESERVE - FOLLOWUP_PAGE_RESERVE):
                return
            # Keep a small part of the discovery allocation for links found in
            # advisories/repositories. Without this distinction, a large batch
            # of search results can fill every remaining slot before any PoC
            # source linked from those results gets a chance to load.
            if discovery_root and scheduled >= page_limit - FOLLOWUP_PAGE_RESERVE:
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
                    attempted_urls.add(url)
                    if payload.get("stream_results"):
                        print(json.dumps({"attempted": url}, ensure_ascii=False), flush=True)
                    if kind == "github_repo":
                        repo = urlsplit(url).path.strip("/")
                        try:
                            _, text, _ = await _github_api_get(
                                client, f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1",
                            )
                            tree = json.loads(text)
                            sha = str(tree.get("sha") or "")
                            if not sha:
                                raise ValueError("GitHub tree did not provide a revision")
                            file_items = tree.get("tree") or []
                        except (httpx.HTTPError, ValueError):
                            try:
                                _, text, _ = await _get(
                                    client, f"https://data.jsdelivr.com/v1/package/gh/{repo}@HEAD/flat",
                                    max_bytes=GITHUB_API_BYTES,
                                )
                                files = json.loads(text)["files"]
                                sha = "HEAD"
                                file_items = [{"path": item["name"].lstrip("/"),
                                               "type": "blob", "size": item.get("size", 0)} for item in files]
                            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                                _, text, _ = await _get(client, url)
                                branch = re.search(r'"defaultBranch":"([^"]+)"', text)
                                sha = branch[1] if branch else "main"
                                file_items = [{"path": path, "type": "blob"} for path in
                                              re.findall(r'"path":"([^"]+)"', text)]
                        entries = []
                        for item in file_items:
                            path = str(item.get("path") or "")
                            if any(part.startswith(".") for part in path.split("/")):
                                continue
                            if not path.lower().endswith((
                                ".md", ".rst", ".txt", ".py", ".rb", ".sh", ".go", ".js",
                                ".ts", ".php", ".jsp", ".java", ".asp", ".aspx", ".cs",
                                ".pl", ".http", ".yaml", ".yml",
                            )):
                                continue
                            score = link_score("https://raw.githubusercontent.com/" + repo + "/" + sha + "/" + path, path, cve_id)
                            if path.lower().endswith(("readme.md", "readme.rst", "readme.txt")):
                                score = max(score, 5)
                            if item.get("type") == "blob" and score >= 3 and int(item.get("size") or 0) <= MAX_BYTES:
                                entries.append((score, path))
                        sources = [f"https://raw.githubusercontent.com/{repo}/{sha}/{quote(path, safe='/')}"
                                   for _, path in sorted(entries, key=lambda item: -item[0])[:4]]
                        for source in sources:
                            schedule({"url": source, "discovered_from": url, "related_sources": sources,
                                      "discovery_provider": target.get("discovery_provider", "reference")}, depth + 1)
                        return
                    if kind == "github_gist":
                        gist_id = urlsplit(url).path.strip("/").split("/")[-1]
                        _, text, _ = await _github_api_get(
                            client, f"https://api.github.com/gists/{gist_id}",
                        )
                        data = json.loads(text)
                        for item in list((data.get("files") or {}).values())[:4]:
                            if item.get("raw_url"):
                                schedule({"url": item["raw_url"], "discovered_from": url,
                                          "discovery_provider": target.get("discovery_provider", "reference")}, depth + 1)
                        return
                    if kind == "github_issue":
                        api_url = _github_issue_api_url(url)
                        try:
                            _, issue_text, _ = await _github_api_get(
                                client, api_url,
                                headers={"Accept": "application/vnd.github+json",
                                         "X-GitHub-Api-Version": "2022-11-28"},
                            )
                            page = _github_issue_page(url, json.loads(issue_text), cve_id)
                        except (httpx.HTTPError, ValueError):
                            final_url, text, content_type = await _get(client, url)
                            page = structure_reference(page_from_response(final_url, text, content_type), cve_id)
                            if not str(page.get("content") or "").strip() and not page.get("code_blocks"):
                                raise ValueError("empty GitHub issue content")
                        page.update({"source": "reference_followup",
                                     "discovered_from": target.get("discovered_from", url),
                                     "related_sources": target.get("related_sources", []),
                                     "arrived_sec": round(time.monotonic() - started, 3),
                                     "discovery_provider": target.get("discovery_provider", "reference")})
                        pages.append(page)
                        if payload.get("stream_results"):
                            print(json.dumps({"page": page}, ensure_ascii=False), flush=True)
                        if depth < 2:
                            for child in crawl_targets([page], cve_id)[:4]:
                                schedule(child, depth + 1)
                        return
                    github_api_page = None
                    if target.get("prefetched_text"):
                        final_url, text, content_type = url, target["prefetched_text"], "text/plain"
                    else:
                        fetch_url = _github_diff_url(url, kind) if kind in {
                            "github_commit", "github_pull_request"
                        } else _raw_url(url)
                        try:
                            final_url, text, content_type = await _get(
                                client, fetch_url,
                                headers={"Range": f"bytes=0-{GITHUB_DIFF_BYTES - 1}"}
                                if kind in {"github_commit", "github_pull_request"} else None,
                                max_bytes=GITHUB_DIFF_BYTES if kind in {
                                    "github_commit", "github_pull_request"
                                } else MAX_BYTES,
                            )
                        except ValueError as exc:
                            # Large GitHub diffs are common for dependency or
                            # generated-file commits.  Fall back to the
                            # compact public API response and retain only
                            # changed-file patches instead of dropping the
                            # whole source.
                            if kind not in {"github_commit", "github_pull_request"} \
                                    or "bounded response size" not in str(exc):
                                raise
                            api_url = _github_api_diff_url(url, kind)
                            _, api_text, _ = await _github_api_get(
                                client, api_url,
                                headers={"Accept": "application/vnd.github+json",
                                         "X-GitHub-Api-Version": "2022-11-28"},
                                max_bytes=GITHUB_API_BYTES,
                            )
                            github_api_page = _github_api_diff_page(
                                url, kind, json.loads(api_text), cve_id,
                            )
                            final_url, text, content_type = url, "", "text/plain"
                    seen.add(final_url)
                    page = github_api_page or page_from_response(final_url, text, content_type)
                    if github_api_page is None and kind in {"github_commit", "github_pull_request"} and text.strip():
                        page["code_blocks"] = [{"language": "diff", "text": text[:MAX_CONTENT],
                                                "evidence_url": final_url}]
                        page["content"] = text[:MAX_CONTENT]
                        page["title"] = url
                        page["url"] = url
                        page = structure_reference(page, cve_id)
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
            except Exception as exc:
                errors.append(f"{url}: {exc}")

        async def paid_followup(*, primary: bool = False) -> None:
            from cve_hunter.tools.source_discovery import (
                _search_component_terms, _search_context, paid_discovery,
            )
            context = payload.get("discovery_context", "")
            component = _search_component_terms(context, limit=1)
            query = " ".join(part for part in (
                component or cve_id, _search_context(context, limit=2), "PoC",
            ) if part)
            if primary:
                query = f"{cve_id} PoC exploit"
            result = await paid_discovery(
                query, client, brave_key=("" if payload.get("paid_priority") and getattr(cfg, "tavily_api_key", "")
                                         else getattr(cfg, "brave_search_api_key", "")),
                tavily_key=getattr(cfg, "tavily_api_key", ""),
            )
            discovery["paid_provider"] = result["provider"]
            discovery.setdefault("paid_queries", []).append({
                "query": query, "provider": result["provider"], "results": len(result["leads"]),
            })
            errors.extend(result["errors"])
            for lead in result["leads"]:
                named_cves = re.findall(r"CVE-\d{4}-\d+", lead["url"] + " " + lead.get("title", ""), re.I)
                if named_cves and cve_id.lower() not in {value.lower() for value in named_cves}:
                    continue
                lead.setdefault("discovery_provider", result["provider"])
                inferred = crawl_targets([{"url": lead["url"], "content": ""}], cve_id)
                if inferred:
                    lead["kind"] = inferred[0]["kind"]
                schedule(lead, 0, discovery_root=True)

        async def discover() -> None:
            nonlocal discovery_finished
            from cve_hunter.tools.source_discovery import discover_sources

            async def get(url, *, headers=None):
                async with semaphore:
                    # Only the configured search request itself may use a
                    # local/self-hosted endpoint.  Search result links and
                    # redirects still go through the public-destination
                    # check in _get().
                    searxng = payload.get("searxng_url", "").rstrip("/")
                    is_searxng = bool(searxng) and url.startswith(searxng + "/search?")
                    is_duckduckgo = url.startswith("https://html.duckduckgo.com/html/?")
                    trusted = url if is_searxng or is_duckduckgo else ""
                    return await _get(client, url, trusted_search_url=trusted, headers=headers)
            result = await discover_sources(
                cve_id, get, searxng_url=payload.get("searxng_url", ""),
                context=payload.get("discovery_context", ""),
            )
            discovery_finished = True
            discovery["providers"] = result["providers"]
            errors.extend(result["errors"])
            for lead in result["leads"]:
                inferred = crawl_targets([{"url": lead["url"], "content": ""}], cve_id)
                if not lead.get("kind") and inferred:
                    lead["kind"] = inferred[0]["kind"]
                schedule(lead, 0, discovery_root=True)
            search = result["providers"].get("searxng") or result["providers"].get("duckduckgo") or {}
            if (payload.get("paid_fallback") and not payload.get("paid_priority")
                    and search.get("status") == "error"
                    and not any(has_cve_related_http_evidence(page, cve_id) for page in pages)):
                await paid_followup()

        async def drain():
            while tasks:
                if payload.get("stop_on_complete_evidence") and any(
                    has_complete_poc_source(page, cve_id) for page in pages
                ):
                    return True
                await asyncio.wait(list(tasks), return_when=asyncio.FIRST_COMPLETED)
            return False

        async def work() -> None:
            if payload.get("discover") and payload.get("paid_fallback") and payload.get("paid_priority"):
                # Start both CVE and component searches immediately. Some public
                # reproductions are indexed by product/endpoint without a CVE ID.
                for primary in (True, False):
                    task = asyncio.create_task(paid_followup(primary=primary))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
            for target in sorted(
                payload.get("targets") or [],
                key=lambda item: int(item.get("score") or 0), reverse=True,
            ):
                schedule(target, 0)
            if payload.get("discover"):
                task = asyncio.create_task(discover())
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            if await drain():
                return
            # Paid search is a final fallback when free sources provide no
            # request evidence related to this CVE. A random HTTP snippet from
            # a broad repository index must not suppress the fallback.
            if payload.get("paid_fallback") and "paid_provider" not in discovery and not any(
                has_cve_related_http_evidence(page, cve_id) for page in pages
            ):
                await paid_followup()
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
            "attempted_urls": sorted(attempted_urls),
            "discovery": discovery}


def enrich_references(
    cve_id: str, references: list[dict[str, Any]], cached: list[dict[str, Any]],
    *, allow_network: bool = True, reference_urls: list[str] | None = None,
    discovery_context: str = "",
) -> dict[str, Any]:
    started = time.monotonic()
    budget = min(60.0, max(0.0, float(getattr(cfg, "reference_crawl_budget", 60))))
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
    # All supplied reference links are eligible, including advisory pages with
    # no PoC-looking URL. Fetch roots and descendants under the SAME deadline.
    target_urls = {target["url"] for target in targets}
    targets = [
        {"url": url, "kind": "page", "discovered_from": url,
         "score": max(1, link_score(url, cve_id=cve_id))}
        for url in reference_urls or [] if url not in target_urls
    ] + targets
    targets.sort(key=lambda item: int(item.get("score") or 0), reverse=True)
    missing = []
    for target in targets:
        canonical = _raw_url(target["url"]) if target.get("kind", "page") == "page" else target["url"]
        existing = cache_by_url.get(canonical)
        # A landing page or code-view page cannot stand in for its raw source,
        # even when the landing page includes one example code block.
        if existing and str(existing.get("content") or "").strip() and not existing.get("content_truncated"):
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
    result["attempted_urls"] = []
    remaining = budget - (time.monotonic() - started)
    # With the CVE description available, keep a bounded free-discovery pass
    # even when a cache page contains one request-shaped snippet: a different
    # endpoint in the successful PoC may still be absent.  Calls that do not
    # provide context retain the cache-only fast path used by offline callers.
    needs_discovery = bool(getattr(cfg, "reference_discovery_enabled", True)) and (
        bool(str(discovery_context or "").strip())
        or not any(has_cve_related_http_evidence(page, cve_id) for page in pages)
    )
    if allow_network and (missing or needs_discovery) and remaining > 0.5:
        reader_timeout = remaining - 0.25
        payload = {
            "cve_id": cve_id, "targets": missing,
            "known_urls": [page["url"] for page in pages if page.get("source") == "reference_followup"],
            "budget": max(0.01, reader_timeout - 0.5),
            "request_timeout": getattr(cfg, "web_source_timeout", 6),
            "proxy": getattr(cfg, "httpx_proxy", None), "stream_results": True,
            "stop_on_complete_evidence": True,
            "discover": needs_discovery,
            "discovery_context": str(discovery_context or "")[:1200],
            "searxng_url": getattr(cfg, "searxng_url", ""),
            "paid_fallback": getattr(cfg, "search_paid_fallback", True) and needs_discovery,
            "paid_priority": True,
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
            if item.get("attempted"):
                result["attempted_urls"].append(str(item["attempted"]))
            if "summary" in item:
                deadline_exceeded = result["timed_out"]
                result.update(item["summary"])
                result["timed_out"] = deadline_exceeded or result["timed_out"]
    result["pages"] = list({page["url"]: page for page in result["pages"] if str(page.get("content") or "").strip()}.values())
    result["attempted_urls"] = sorted(set(result["attempted_urls"]) | {
        str(page.get("url") or "") for page in result["pages"]
    })
    result["elapsed_sec"] = round(time.monotonic() - started, 3)
    result["budget_sec"] = budget
    return result


def main() -> None:
    payload = json.load(sys.stdin)

    async def read() -> None:
        result = await _crawl(payload)
        result.pop("pages", None)
        # DNS executor shutdown can outlast the crawl deadline. Flush the
        # completed crawl state before asyncio.run waits for those threads.
        print(json.dumps({"summary": result}, ensure_ascii=False), flush=True)

    asyncio.run(read())


if __name__ == "__main__":
    main()
