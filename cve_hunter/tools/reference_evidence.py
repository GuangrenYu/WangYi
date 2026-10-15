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
_URL = re.compile(r'https?://[^\s<>"`]+')
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
    # If there are no extracted code blocks, permit plain-text examples. When
    # blocks exist, keep them separate from prose so unrelated PoC links cannot
    # complete a generic requests.post(url) into apparent request evidence.
    if not chunks and page.get("content"):
        chunks = [str(page["content"])]
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
        if re.search(r"(?m)^\s*(?:http|requests):\s*$", text) and re.search(
            r"^\s*path:\s*\n(?:\s+-\s*)?[\"']?(?:\{\{(?:BaseURL|RootURL)\}\})?/|"
            r"^\s*(?:path|endpoint):\s*[\"']?/(?!/)", text, re.MULTILINE,
        ):
            return True
    return False


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
    if parsed.query or re.search(r"\.(?:png|jpg|gif|zip|exe|pdf|pcap)(?:$|\?)", lower):
        return 0
    score = 0
    if host in {"github.com", "gist.github.com", "raw.githubusercontent.com", "gist.githubusercontent.com"}:
        if len(parsed.path.strip("/").split("/")) >= 2:
            score += 4
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
    is_html = "html" in content_type.lower() or bool(re.match(r"\s*(?:<!doctype html|<html)", text, re.I))
    if not is_html:
        return {"url": url, "title": "", "content": text[:MAX_CONTENT], "links": [], "content_format": "text", "content_truncated": len(text) > MAX_CONTENT}
    document = lxml_html.fromstring(text, base_url=url)
    title = " ".join(document.xpath("//title/text()"))
    content = trafilatura.extract(
        text, include_tables=True, include_comments=False,
        include_links=True, include_formatting=True, favor_recall=True,
    ) or ""
    blocks = []
    for node in document.xpath("//pre"):
        code = node.text_content().strip("\n")
        if code.strip() and len(code) <= 12000:
            blocks.append({"language": "", "text": code, "evidence_url": url})
    links = []
    for node in document.xpath("//a[@href]"):
        href = source_url(node.get("href", ""), url)
        if href:
            links.append({"url": href, "label": node.text_content().strip()[:200]})
    if not content and blocks:
        content = "\n".join("```\n" + block["text"] + "\n```" for block in blocks)
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
    if not blocks and result.get("content_format") != "html" and not result["content_truncated"] and (re.search(r"\.(?:py|rb|sh|http|yaml|yml|js|go)$", path) or re.search(r"/raw/\d+$", path)):
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
