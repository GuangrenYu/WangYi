"""Source-preserving reference evidence; no inference or PoC execution."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from lxml import html as lxml_html
import trafilatura

MAX_CONTENT = 24000
EVIDENCE_VERSION = 1
_URL = re.compile(r'https?://[^\s<>"`\[\]]+')
_FENCE = re.compile(r"```([^\n`]*)\n(.*?)```", re.S)
_CONDITIONS = {
    "affected_versions": r"\b(?:affected|vulnerable|versions?|before|prior to|through)\b|受影响|版本",
    "authentication": r"\b(?:authenticat\w*|unauthenticat\w*|credentials?|log[ -]?in|session|privileges?)\b|认证|登录|权限",
    "dependencies": r"\b(?:pip install|requirements|dependencies|requires?|python|ruby|nodejs|npm install)\b|依赖|安装",
    "configuration": r"\b(?:configuration|configured|enabled|disabled|prerequisites?|preconditions?|deployment)\b|配置|前提|部署",
    "usage": r"\b(?:usage|how to|run the|execute the)\b|(?:python[23]?|ruby|bash)\s+\S+\.(?:py|rb|sh)|用法|使用方法",
}


def has_http_evidence(page: dict[str, Any]) -> bool:
    """Require HTTP request or request-producing source, not arbitrary code fences."""
    evidence = page.get("poc_evidence") or {}
    blocks = evidence.get("code_blocks") or []
    chunks = [str(block.get("text") or "") for block in blocks if block.get("text")]
    # Prefer code blocks, but still inspect page prose/content. Advisories often
    # keep raw HTTP in the body while code fences only hold helper scripts; if
    # blocks alone miss request evidence, fall back to content instead of
    # treating the page as empty.
    content = str(page.get("content") or "")
    if content and content not in chunks:
        chunks.append(content)
    if not chunks:
        return False
    for text in chunks:
        if re.search(r"(?m)^\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S*\s+HTTP/", text):
            return True
        if re.search(r"(?m)^\s*curl\s+[^\n]*https?://[^\s\"'<>]+/[^\s\"'<>]*", text):
            return True
        request_code = re.search(
            r"(?:requests|session|urllib|axios)\.(?:get|post|put|request|urlopen)|\bfetch\s*\(|"
            r"\bsend_request_(?:cgi|raw)\s*\(", text
        )
        endpoint = re.search(
            r"https?://[^\s\"'<>]+/[^\s\"'<>]*|"
            r"[\"'`](?:\{\{BaseURL\}\}|\{\{RootURL\}\})/[^\s\"'`]*[\"'`]|"
            r"\{\{(?:BaseURL|RootURL)\}\}/\S*|"
            r"^\s*(?:url|uri|path|endpoint)\s*=\s*f?[\"'`]/[^\s\"'`]*[\"'`]",
            text, re.MULTILINE,
        )
        if request_code and endpoint:
            if blocks:
                return True
            request_line = re.compile(
                r"(?:requests|session|urllib|axios)\.(?:get|post|put|request|urlopen)|"
                r"\bfetch\s*\(|\bsend_request_(?:cgi|raw)\s*\(")
            endpoint_line = re.compile(
                r"https?://[^\s\"'<>]+/[^\s\"'<>]*|"
                r"[\"'`](?:\{\{BaseURL\}\}|\{\{RootURL\}\})/[^\s\"'`]*[\"'`]|"
                r"\{\{(?:BaseURL|RootURL)\}\}/\S*|"
                r"^\s*(?:url|uri|path|endpoint)\s*=\s*f?[\"'`]/[^\s\"'`]*[\"'`]")
            if any(request_line.search(line) and endpoint_line.search(line)
                   for line in text.splitlines()):
                return True
        # Nuclei accepts both block-list and inline-list YAML forms, for
        # example ``path:\n - "{{BaseURL}}/x"`` and
        # ``path: ["{{BaseURL}}/x"]``.  Treat either as an HTTP request
        # example while keeping a bare ``path:`` field insufficient.
        nuclei_path = re.search(
            r"(?im)^\s*(?:-\s*)?(?:paths?|endpoint):\s*(?:"
            r"\[[^\]\n]*(?:\{\{(?:BaseURL|RootURL)\}\}|/)[^\]\n]*\]|"
            r"\n\s*-\s*[\"']?(?:\{\{(?:BaseURL|RootURL)\}\})?/|"
            r"[\"']?(?:\{\{(?:BaseURL|RootURL)\}\})?/(?!/))",
            text,
        )
        if re.search(r"(?m)^\s*(?:http|requests):\s*$", text) and nuclei_path:
            return True
    return False


def _conflicting_cve_identity(page: dict[str, Any], cve_id: str) -> bool:
    identity = " ".join(str(page.get(key) or "") for key in ("url", "resolved_url", "title"))
    named = re.findall(r"CVE-\d{4}-\d+", identity, re.I)
    if not named:
        named = re.findall(
            r"(?im)^\s*(?:#\s*)?(?:CVE(?:\s+ID)?\s*[:=]\s*|id:\s*)?(CVE-\d{4}-\d+)\b",
            str(page.get("content") or "")[:1200],
        )
    return bool(named and cve_id.lower() not in {value.lower() for value in named})


def page_extract_text(page: dict[str, Any]) -> str:
    """Join prose and code-block text for request extraction."""
    parts = [str(page.get("content") or "")]
    evidence = page.get("poc_evidence") or {}
    for block in evidence.get("code_blocks") or page.get("code_blocks") or []:
        if isinstance(block, dict):
            parts.append(str(block.get("text") or block.get("code") or ""))
        else:
            parts.append(str(block))
    return "\n".join(parts)


def page_has_extractable_cve_http(page: dict[str, Any], cve_id: str) -> bool:
    """Whether this cached page yields HTTP requests clearly tied to ``cve_id``.

    Used to pull already-cached PoC pages into ReferenceAgent even when they are
    not descendants of the current NVD seed URL graph.
    """
    from cve_hunter.poc_parser import extract_http_requests, score_evidence_request

    cve = str(cve_id or "").strip().upper()
    if not cve or _conflicting_cve_identity(page, cve):
        return False
    page_url = str(page.get("resolved_url") or page.get("url") or "")
    host = (urlsplit(page_url).hostname or "").lower()
    if host in {
        "portswigger.net", "www.portswigger.net", "hacksplaining.com",
        "owasp.org", "www.owasp.org",
    }:
        return False
    text = page_extract_text(page)
    page_identity = "\n".join(
        str(page.get(key) or "") for key in ("url", "resolved_url", "title")
    )
    blob = f"{page_identity}\n{text}".upper()
    identity_hit = cve in blob
    provenance_hit = cve in str(page.get("discovered_from") or "").upper()
    poc_host = any(
        token in host
        for token in (
            "exploit-db.com",
            "githubusercontent.com",
            "giteeusercontent.com",
            "packetstorm",
            "seebug.org",
            "cxsecurity.com",
        )
    )
    # Require CVE linkage, except strong requests on known PoC hosts where the
    # CVE id appears in URL/title/body/provenance (identity_hit already covers).
    if not identity_hit and not provenance_hit:
        return False
    for request in extract_http_requests(text):
        first = request.splitlines()[0] if request else ""
        if re.search(r"(?i)^(GET|POST|PUT|DELETE|PATCH)\s+/(?:install|setup|download)(?:\s|$|\?)", first):
            continue
        if not first.strip():
            continue
        score = score_evidence_request(request, cve_id=cve, source_text=text)
        if score >= 5:
            return True
        # Keep low-score but explicit raw requests when CVE-linked.
        if re.search(r"(?m)^\s*(?:GET|POST|PUT|DELETE|PATCH)\s+/\S+\s+HTTP/", request):
            return True
        if poc_host and score >= 0 and ("?" in first or "\n\n" in request):
            return True
    return False


def has_cve_related_http_evidence(page: dict[str, Any], cve_id: str) -> bool:
    """Ignore request-shaped snippets from unrelated repositories/search hits.

    A crawler may follow a broad repository index that contains HTTP examples
    for many CVEs. Such a snippet must not stop discovery for the CVE currently
    being processed. Direct NVD references stay trusted; search-discovered
    descendants need an explicit CVE connection in their URL/content/provenance.
    """
    if _conflicting_cve_identity(page, cve_id) or not has_http_evidence(page):
        return False

    provider = str(page.get("discovery_provider") or "").strip().lower()
    if provider in {"", "reference"}:
        return True

    needle = str(cve_id or "").strip().upper()
    if not needle:
        return False
    haystack = "\n".join(
        str(value or "")
        for value in (
            page.get("url"), page.get("resolved_url"), page.get("title"),
            page.get("content"), page.get("discovered_from"),
            *(page.get("related_sources") or []),
        )
    ).upper()
    return needle in haystack


def has_complete_poc_source(page: dict[str, Any], cve_id: str) -> bool:
    """A whole attributed PoC source file; does not verify exploit success.

    Prose, Markdown snippets and truncated files require separate review.
    """
    if _conflicting_cve_identity(page, cve_id):
        return False
    url = str(page.get("resolved_url") or page.get("url") or "")
    content = str(page.get("content") or "")
    provider = page.get("discovery_provider") or "reference"
    related = provider == "reference" or cve_id.lower() in (
        url + content + str(page.get("discovered_from") or "")).lower()
    source_file = re.search(r"\.(?:py|rb|sh|yaml|yml|js|go|php|jsp|java|asp|aspx|cs|pl|html?)$|/raw/\d+$", url)
    whole_file = any(str(block.get("text") or "") == content
                     for block in (page.get("poc_evidence") or {}).get("code_blocks") or [])
    browser_source = bool(re.search(r"<(?:script|object)\b", content, re.I))
    return bool(related and source_file and whole_file and not page.get("content_truncated")
                and page.get("content_format") != "html" and (has_http_evidence(page) or browser_source))


def _request_block_score(text: str) -> int:
    """Rank extracted snippets so real request examples survive HTML noise."""
    score = 0
    if re.search(r"(?m)^\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/", text):
        score += 8
    if re.search(r"(?m)^\s*curl\s+", text):
        score += 5
    if re.search(r"(?:requests|session|urllib|axios)\.(?:get|post|put|request|urlopen)|\bfetch\s*\(", text):
        score += 4
    if re.search(r"(?m)^\s*(?:http|requests):\s*$", text):
        score += 6
    if re.search(r"(?m)^\s*path:\s*(?:\n\s*-\s*)?[\"']?(?:\{\{(?:BaseURL|RootURL)\}\})?/", text):
        score += 5
    if re.search(r"(?m)^\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", text):
        score += 2
    return score


def source_url(value: str, base: str = "") -> str:
    try:
        value = urljoin(base, value.strip().rstrip(".,;"))
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return ""
        # Request examples and target placeholders are evidence, not crawl targets.
        if any(token in value.lower() for token in ("{{", "}}", "<target", "your-target", "target_host")):
            return ""
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    except ValueError:
        return ""


def link_score(url: str, label: str = "", cve_id: str = "") -> int:
    if not source_url(url):
        return 0
    lower = url.lower()
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    named_cves = re.findall(r"CVE-\d{4}-\d+", url + " " + label, re.I)
    if cve_id and named_cves and cve_id.lower() not in {value.lower() for value in named_cves}:
        return 0
    if host == "github.com" and parsed.path.strip("/").split("/")[0].lower() in {
        "features", "security", "enterprise", "pricing", "solutions", "resources",
        "marketplace", "sponsors", "settings", "login", "signup", "about", "site",
        "customer-stories", "collections", "topics", "trending", "explore", "search",
        "orgs", "users", "notifications",
    }:
        return 0
    if parsed.query or re.search(r"\.(?:png|jpg|gif|zip|exe|pdf|pcap)(?:$|\?)", lower):
        return 0
    if host == "github.com":
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 3 and parts[2] in {
            "issues", "pull", "pulls", "discussions", "actions", "projects", "releases",
            "tags", "branches", "stargazers", "watchers", "forks", "network",
        } and (len(parts) == 3 or (parts[2] in {"issues", "pull", "pulls", "discussions"} and not parts[3].isdigit())):
            return 0
    score = 0
    if host in {"github.com", "gist.github.com", "raw.githubusercontent.com", "gist.githubusercontent.com"}:
        if len(parsed.path.strip("/").split("/")) >= 2:
            score += 4
        if cve_id:
            cve_lower = cve_id.lower()
            year_match = re.match(r"CVE-(\d{4})-", cve_id, re.I)
            path = parsed.path.lower()
            if cve_lower in path:
                score += 8
            elif year_match and re.search(rf"(?:^|[/_-])(?:cve[_-])?{year_match[1]}(?:[/_.-]|$)", path):
                score += 3
            elif year_match and re.search(r"(?:^|[/_-])cve[_-]?\d{4}(?:[/_.-]|$)", path):
                score -= 3
            if re.search(r"(?:^|/)readme(?:\.[^/]*)?$", path) and cve_lower not in path:
                if not (year_match and re.search(rf"(?:^|[/_-])(?:cve[_-])?{year_match[1]}(?:[/_.-]|$)", path)):
                    score -= 4
    if host in {"exploit-db.com", "www.exploit-db.com"} and re.search(r"/(?:exploits|raw)/\d+", parsed.path):
        score += 6
    if host in {"exploit-db.com", "www.exploit-db.com"} and not re.search(r"/(?:exploits|raw)/\d+$", parsed.path):
        return 0
    if re.search(r"(?:poc|exploit|proof.of.concept|复现|利用)", label + " " + parsed.path, re.I):
        score += 3
    if cve_id and cve_id.lower() in lower:
        score += 3
    if re.search(r"\.(?:py|rb|sh|http|yaml|yml|md|txt)$", parsed.path, re.I):
        score += 2
    return score


def extract_links(content: str, base: str, cve_id: str = "") -> list[dict[str, Any]]:
    candidates = []
    for label, href in re.findall(r"\[([^\]]*)\]\(([^\s)]+)(?:\s+[^)]*)?\)", content):
        candidates.append((href, label))
    for href in _URL.findall(content):
        candidates.append((href.rstrip(").,;]"), ""))
    links: dict[str, dict[str, Any]] = {}
    for href, label in candidates:
        url = source_url(href, base)
        if not url or url == source_url(base):
            continue
        score = link_score(url, label, cve_id)
        if score < 3:
            continue
        if url not in links or score > links[url]["score"]:
            links[url] = {"url": url, "label": label[:200], "score": score}
    return sorted(links.values(), key=lambda item: -item["score"])[:32]


def page_from_response(url: str, text: str, content_type: str = "") -> dict[str, Any]:
    """Preserve HTML code and anchor destinations, and bypass prose extraction for source files."""
    mime = content_type.lower().split(";", 1)[0].strip()
    # Raw browser PoCs are HTML *source*, commonly served as text/plain.
    # Prose extraction removes their object/script elements and destroys the
    # exploit evidence. Only sniff HTML when the server omitted its MIME type.
    is_html = "html" in mime or (not mime and bool(re.match(r"\s*(?:<!doctype html|<html)", text, re.I)))
    if not is_html:
        blocks = [{"language": language.strip(), "text": code, "evidence_url": url}
                  for language, code in _FENCE.findall(text) if code.strip() and len(code) <= 12000]
        blocks.sort(key=lambda block: -_request_block_score(block["text"]))
        return {"url": url, "title": "", "content": text[:MAX_CONTENT], "links": [],
                "code_blocks": blocks[:12], "content_format": "text", "content_truncated": len(text) > MAX_CONTENT}
    document = lxml_html.fromstring(text, base_url=url)
    title = " ".join(document.xpath("//title/text()"))
    content = trafilatura.extract(
        text, include_tables=True, include_comments=False,
        include_links=True, include_formatting=True, favor_recall=True,
    ) or ""
    blocks = []
    for position, node in enumerate(document.xpath("//pre")):
        code = node.text_content().strip("\n")
        if code.strip() and len(code) <= 12000:
            blocks.append({"language": "", "text": code, "evidence_url": url,
                           "_request_score": _request_block_score(code), "_position": position})
    links = []
    for node in document.xpath("//a[@href]"):
        href = source_url(node.get("href", ""), url)
        if href:
            links.append({"url": href, "label": node.text_content().strip()[:200]})
    if not content and blocks:
        content = "\n".join("```\n" + block["text"] + "\n```" for block in blocks)
    # Some advisories place the request after long policy/changelog examples.
    # Keep the limit, but prioritize blocks that actually describe HTTP traffic.
    blocks.sort(key=lambda block: (-block["_request_score"], block["_position"]))
    for block in blocks:
        block.pop("_request_score", None)
        block.pop("_position", None)
    return {"url": url, "title": title, "content": content[:MAX_CONTENT], "links": links[:256], "code_blocks": blocks[:12], "content_format": "html", "content_truncated": len(content) > MAX_CONTENT}


def structure_reference(page: dict[str, Any], cve_id: str = "") -> dict[str, Any]:
    result = dict(page)
    url = str(result.get("resolved_url") or result.get("url") or "")
    original = str(result.get("content") or "")
    content = original[:MAX_CONTENT]
    result["content_truncated"] = bool(result.get("content_truncated")) or len(original) > MAX_CONTENT
    result["content"] = content
    links = extract_links(content, url, cve_id)
    source_links = list(result.get("links") or [])
    source_links.extend({"url": href, "label": "repository source"} for href in result.get("related_sources") or [])
    for item in source_links:
        href = source_url(str(item.get("url") or ""), url)
        if href and link_score(href, str(item.get("label") or ""), cve_id) >= 3:
            links.append({"url": href, "label": str(item.get("label") or ""), "score": link_score(href, str(item.get("label") or ""), cve_id)})
    links = sorted({item["url"]: item for item in links}.values(), key=lambda item: -item["score"])[:32]
    blocks = list(result.get("code_blocks") or [])
    blocks.extend({"language": language.strip(), "text": code, "evidence_url": url}
                  for language, code in _FENCE.findall(content) if code.strip() and len(code) <= 12000)
    path = urlsplit(source_url(url)).path.lower()
    if not blocks and result.get("content_format") != "html" and not result["content_truncated"] and (re.search(r"\.(?:py|rb|sh|http|yaml|yml|js|go|ts|php|jsp|java|asp|aspx|cs|pl)$", path) or re.search(r"/raw/\d+$", path)):
        blocks.append({"language": path.rsplit(".", 1)[-1], "text": content, "evidence_url": url})
    unique_blocks = {str(block.get("text") or ""): block for block in blocks if block.get("text")}
    conditions = {}
    # Store exact quotations, including negation; absence stays unknown.
    prose = _FENCE.sub("", content)
    for kind, pattern in _CONDITIONS.items():
        quotes = []
        for line in prose.splitlines():
            line = line.strip()
            if line and len(line) <= 1200 and re.search(pattern, line, re.I):
                quotes.append({"quote": line, "evidence_url": url})
        conditions[kind] = quotes[:6]
    result["poc_evidence"] = {
        "version": EVIDENCE_VERSION, "evidence_url": url,
        "poc_links": links, "code_blocks": list(unique_blocks.values())[:12],
        "conditions": conditions,
    }
    return result


def reference_prompt_text(pages: list[dict[str, Any]], *, max_chars: int = 12000) -> str:
    """Allocate prompt space to source evidence before page introductions."""
    sections = []
    remaining = max_chars
    structured = [structure_reference(page) for page in pages]
    structured.sort(key=lambda page: -bool(page["poc_evidence"]["code_blocks"]))
    for page in structured:
        evidence = page["poc_evidence"]
        header = f"\n### {page.get('title', '')} ({evidence['evidence_url']})\n"
        metadata = {
            "reference_url": page.get("url", ""),
            "discovered_from": page.get("discovered_from", ""),
            "content_truncated": page.get("content_truncated", False),
            "poc_links": evidence["poc_links"][:4],
            "conditions": {kind: quotes[:2] for kind, quotes in evidence["conditions"].items()},
        }
        details = json.dumps(metadata, ensure_ascii=False)
        section = header
        for block in evidence["code_blocks"]:
            code = f"```{block.get('language', '')}\n{block['text']}\n```\n"
            if len(section) + len(code) <= remaining:
                section += code
        if len(section) + len(details) <= remaining:
            section += details + "\n"
        # A short prose excerpt complements the full code and condition quotes.
        room = min(1500, remaining - len(section))
        if room > 0 and not evidence["code_blocks"]:
            section += _FENCE.sub("", str(page.get("content") or ""))[:room]
        if len(section) <= remaining:
            sections.append(section)
            remaining -= len(section)
    return "".join(sections)
