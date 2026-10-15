"""PoC candidate parsing and Raw HTTP rendering helpers."""

from __future__ import annotations

import json
import re
import shlex
from typing import Any
from urllib.parse import urlsplit

import yaml


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
MAX_NUCLEI_YAML_CHARS = 20000


def _normalize_nuclei_request_hosts(doc: dict[str, Any]) -> None:
    """Remove captured lab IPs from raw-template Host headers.

    Peer templates often contain the address used during their run.  Keeping
    that literal makes a structurally correct template target the wrong
    service when reused.  Preserve symbolic hosts and ports through Nuclei's
    ``Host`` variable while leaving payload bytes untouched.
    """
    ip_host = re.compile(r"(?im)(^\s*Host:\s*)\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\s*$")

    def visit(value: Any) -> Any:
        if isinstance(value, str):
            return ip_host.sub(r"\1{{Host}}", value)
        if isinstance(value, list):
            return [visit(item) for item in value]
        if isinstance(value, dict):
            for key, item in list(value.items()):
                value[key] = visit(item)
            return value
        return value

    visit(doc)


def validate_nuclei_yaml(text: str) -> tuple[str, str]:
    """Validate nuclei YAML. Returns (normalized_yaml, error)."""
    raw = str(text or "").strip()
    if not raw:
        return "", "empty yaml"
    if len(raw) > MAX_NUCLEI_YAML_CHARS:
        return "", f"yaml too long (>{MAX_NUCLEI_YAML_CHARS})"
    # Strip accidental markdown fences
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:yaml|yml)?\s*", "", raw, flags=re.I)
        raw = re.sub(r"\s*```$", "", raw)
        raw = raw.strip()
    try:
        doc = yaml.safe_load(raw)
    except Exception as exc:
        return "", f"yaml parse error: {exc}"
    if not isinstance(doc, dict):
        return "", "yaml root must be a mapping"
    # A number of otherwise useful templates use the peer runner's
    # ``requests`` alias.  Nuclei itself expects ``http``; normalize the
    # alias here so a valid raw template is not silently discarded or sent
    # to the executor in an unsupported shape.
    if not doc.get("http") and doc.get("requests"):
        doc["http"] = doc.pop("requests")
    _normalize_nuclei_request_hosts(doc)
    http = doc.get("http")
    if not http:
        return "", "missing http/requests section"
    if isinstance(http, list) and not http:
        return "", "empty http/requests list"
    if not isinstance(http, list):
        return "", "http/requests section must be a list"
    if not any(isinstance(item, dict) and (item.get("raw") or item.get("path")) for item in http):
        return "", "http list has no raw/path request"
    # Prefer stable dump for fingerprinting/execution
    try:
        normalized = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True).strip()
    except Exception:
        normalized = raw
    return normalized, ""


def raw_http_to_nuclei_yaml(raw_http: str, cve_id: str) -> str:
    """Wrap an evidenced raw request in a minimal executable Nuclei template.

    This is an adapter for the YAML-first verification path. It preserves the
    request bytes and deliberately adds no guessed matcher; the external IPS
    CVE matcher remains the success oracle when the source supplied no
    response evidence.
    """
    request = str(raw_http or "").replace("{{TARGET_HOST}}", "{{Host}}")
    if not re.match(r"(?im)^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/", request):
        return ""
    doc = {
        "id": str(cve_id or "http-evidence").lower(),
        "info": {"name": f"{cve_id} evidenced HTTP request", "author": "cve-hunter", "severity": "info"},
        "http": [{"raw": [request]}],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True).strip()


def nuclei_yaml_to_raw_http(yaml_text: str) -> str:
    """Extract a single Raw HTTP request from a nuclei HTTP template.

    Prefer ``raw:`` blocks. Fall back to method/path/headers/body style.
    Nuclei host placeholders become ``{{TARGET_HOST}}`` so the existing
    http2pcap prepare path can rewrite them.
    """
    requests = nuclei_yaml_to_raw_http_list(yaml_text)
    return requests[0] if requests else ""


def nuclei_yaml_to_raw_http_list(yaml_text: str) -> list[str]:
    """Extract ordered Raw HTTP requests from a nuclei HTTP template."""
    raw = str(yaml_text or "").strip()
    if not raw:
        return []
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:yaml|yml)?\s*", "", raw, flags=re.I)
        raw = re.sub(r"\s*```$", "", raw)
        raw = raw.strip()
    try:
        doc = yaml.safe_load(raw)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    http = doc.get("http") or doc.get("requests")
    if not isinstance(http, list):
        return []

    out: list[str] = []
    for item in http:
        if not isinstance(item, dict):
            continue
        for request in _nuclei_item_to_raw_requests(item):
            cleaned = _normalize_nuclei_raw_placeholders(request)
            if cleaned and cleaned not in out:
                out.append(cleaned)
    return out


def _nuclei_item_to_raw_requests(item: dict[str, Any]) -> list[str]:
    raw_blocks = item.get("raw")
    if isinstance(raw_blocks, str) and raw_blocks.strip():
        return [raw_blocks.strip()]
    if isinstance(raw_blocks, list):
        return [str(block).strip() for block in raw_blocks if str(block or "").strip()]

    method = str(item.get("method") or "GET").strip().upper() or "GET"
    if method not in HTTP_METHODS:
        return []

    paths = item.get("path") or item.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not paths:
        return []

    headers = _normalize_headers(item.get("headers"))
    body = str(item.get("body") or item.get("data") or "")
    requests: list[str] = []
    for path in paths:
        path_text = _nuclei_path_to_request_target(str(path or ""))
        if not path_text:
            continue
        header_map = dict(headers)
        if not any(key.lower() == "host" for key in header_map):
            header_map = {"Host": "{{TARGET_HOST}}", **header_map}
        lines = [f"{method} {path_text} HTTP/1.1"]
        lines.extend(f"{key}: {value}" for key, value in header_map.items() if key and value is not None)
        lines.append("")
        if body:
            lines.append(body)
        requests.append("\n".join(lines).strip())
    return requests


def _nuclei_path_to_request_target(path: str) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    text = text.replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
    text = text.replace("{{baseurl}}", "").replace("{{rooturl}}", "")
    if text.startswith(("http://", "https://")):
        parsed = urlsplit(text)
        text = parsed.path or "/"
        if parsed.query:
            text += "?" + parsed.query
    if not text.startswith("/"):
        text = "/" + text
    return text or "/"


def _normalize_nuclei_raw_placeholders(raw_http: str) -> str:
    text = str(raw_http or "").replace("\r\n", "\n").strip()
    if not text:
        return ""
    text = text.replace("{{Hostname}}", "{{TARGET_HOST}}")
    text = text.replace("{{Host}}", "{{TARGET_HOST}}")
    text = text.replace("{{hostname}}", "{{TARGET_HOST}}")
    text = text.replace("{{host}}", "{{TARGET_HOST}}")
    if not re.search(r"(?im)^Host\s*:", text):
        lines = text.split("\n")
        if lines:
            lines.insert(1, "Host: {{TARGET_HOST}}")
            text = "\n".join(lines)
    return text.strip()


def parse_nuclei_yaml_candidates_json(text: str) -> list[dict[str, Any]]:
    """Parse LLM JSON output into validated nuclei_yaml candidates."""
    candidates: list[dict[str, Any]] = []
    for value in _iter_json_values(text):
        for item in _candidate_items(value):
            yaml_text = _first_text(item, ("nuclei_yaml", "yaml", "yaml_content", "template"))
            if not yaml_text:
                continue
            normalized, err = validate_nuclei_yaml(yaml_text)
            if err or not normalized:
                continue
            candidates.append({
                "nuclei_yaml": normalized,
                "evidence_url": str(item.get("evidence_url") or item.get("source_url") or ""),
                "confidence": _coerce_confidence(item.get("confidence"), default=0.5),
                "reason": str(item.get("reason") or item.get("description") or ""),
                "evidence_quote": str(item.get("evidence_quote") or ""),
                "preconditions": item.get("preconditions") if isinstance(item.get("preconditions"), list) else [],
            })
        if candidates:
            return _dedupe_nuclei_candidates(candidates)
    return []


def _dedupe_nuclei_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in candidates:
        key = re.sub(r"\s+", " ", str(item.get("nuclei_yaml") or "")).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def parse_poc_candidates_json(text: str) -> list[dict[str, Any]]:
    """Parse JSON-first LLM PoC output into rendered Raw HTTP candidates.

    Accepted shapes:
      {"candidates": [{...}]}
      [{...}]
      {...single candidate...}

    Each candidate can contain either raw_http/raw_request/request, or structured
    method/path/headers/body fields.
    """
    candidates: list[dict[str, Any]] = []
    for value in _iter_json_values(text):
        for candidate in _candidate_items(value):
            request_steps = _render_request_steps(candidate.get("request_steps"))
            if request_steps:
                candidates.append({
                    "raw_http": request_steps[0].get("raw_http", ""),
                    "request_steps": request_steps,
                    "evidence_url": str(candidate.get("evidence_url") or candidate.get("source_url") or ""),
                    "evidence_type": str(candidate.get("evidence_type") or ""),
                    "evidence_quote": str(candidate.get("evidence_quote") or ""),
                    "path_source": str(candidate.get("path_source") or ""),
                    "variant_group": str(candidate.get("variant_group") or ""),
                    "encoding_preserved": candidate.get("encoding_preserved", True) is not False,
                    "confidence": _coerce_confidence(candidate.get("confidence"), default=0.5),
                    "reason": str(candidate.get("reason") or candidate.get("description") or ""),
                })
                continue
            raw_http = render_raw_http(candidate)
            if not raw_http:
                continue
            extracted = extract_http_requests(str(candidate.get("raw_http") or candidate.get("raw_request") or candidate.get("request") or ""))
            candidates.append({
                "raw_http": raw_http,
                "request_steps": [{"raw_http": item} for item in extracted] if len(extracted) > 1 else [],
                "evidence_url": str(candidate.get("evidence_url") or candidate.get("source_url") or ""),
                "evidence_type": str(candidate.get("evidence_type") or ""),
                "evidence_quote": str(candidate.get("evidence_quote") or ""),
                "path_source": str(candidate.get("path_source") or ""),
                "variant_group": str(candidate.get("variant_group") or ""),
                "encoding_preserved": candidate.get("encoding_preserved", True) is not False,
                "confidence": _coerce_confidence(candidate.get("confidence"), default=0.5),
                "reason": str(candidate.get("reason") or candidate.get("description") or ""),
            })
        if candidates:
            return _dedupe_candidates(candidates)
    return []


def _render_request_steps(value: Any) -> list[dict[str, Any]]:
    """Render an ordered structured request_steps list without normalizing payloads."""
    if not isinstance(value, list):
        return []
    rendered: list[dict[str, Any]] = []
    for index, step in enumerate(value, start=1):
        if isinstance(step, str):
            extracted = extract_http_requests(step)
            if extracted:
                rendered.append({"raw_http": extracted[0], "step_index": index})
            continue
        if not isinstance(step, dict):
            continue
        raw = render_raw_http(step)
        if not raw:
            continue
        item = {"raw_http": raw, "step_index": index}
        for key in ("name", "extract", "depends_on", "evidence_quote"):
            if step.get(key) is not None:
                item[key] = step[key]
        rendered.append(item)
    return rendered


def render_raw_http(candidate: dict[str, Any]) -> str:
    """Render a structured JSON candidate to Raw HTTP."""
    raw_http = _first_text(candidate, ("raw_http", "raw_request", "request"))
    if raw_http:
        requests = extract_http_requests(raw_http)
        return requests[0] if requests else ""

    method = str(candidate.get("method", "GET")).strip().upper()
    path = str(candidate.get("path", "") or candidate.get("url_path", "")).strip()
    if method not in HTTP_METHODS or not path:
        return ""

    version = str(candidate.get("http_version", "HTTP/1.1")).strip() or "HTTP/1.1"
    if not version.upper().startswith("HTTP/"):
        version = "HTTP/1.1"

    headers = _normalize_headers(candidate.get("headers"))
    host_key = next((key for key in headers if key.lower() == "host"), "")
    if host_key:
        headers[host_key] = "{{TARGET_HOST}}"
    else:
        headers = {"Host": "{{TARGET_HOST}}", **headers}

    body = str(candidate.get("body") or candidate.get("payload") or "")
    lines = [f"{method} {path} {version}"]
    lines.extend(f"{key}: {value}" for key, value in headers.items() if key and value is not None)
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines).strip()


def extract_http_requests(text: str) -> list[str]:
    """Extract Raw HTTP requests from markdown, prose, or legacy LLM output."""
    if not text:
        return []

    requests: list[str] = []

    for block in _iter_code_blocks(text):
        if _looks_like_raw_http(block):
            requests.extend(_split_raw_http_requests(block))

    requests.extend(_split_raw_http_requests(_remove_code_blocks(text)))
    requests.extend(_extract_curl_requests(text))
    requests.extend(_extract_code_http_calls(text))
    return _dedupe_requests(requests)


def _extract_curl_requests(text: str) -> list[str]:
    """Extract executable requests from explicit curl command lines."""
    requests: list[str] = []
    for line in str(text or "").splitlines():
        if not re.search(r"(?i)(?:^|\s)curl(?:\s|$)", line):
            continue
        try:
            argv = shlex.split(line.strip(), posix=True)
        except ValueError:
            continue
        if not argv or argv[0].lower() != "curl":
            continue
        method = "GET"
        headers: list[str] = []
        body = ""
        url = ""
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in {"-X", "--request"} and i + 1 < len(argv):
                method = argv[i + 1].upper(); i += 2; continue
            if arg in {"-H", "--header"} and i + 1 < len(argv):
                headers.append(argv[i + 1]); i += 2; continue
            if arg in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"} and i + 1 < len(argv):
                body = argv[i + 1]
                if method == "GET": method = "POST"
                i += 2; continue
            if arg.startswith("-"):
                i += 1; continue
            if not url and (arg.startswith(("http://", "https://", "/")) or "?" in arg):
                url = arg
            i += 1
        if url:
            requests.append(_structured_url_request(method, url, headers, body))
    return [item for item in requests if item]


def _extract_code_http_calls(text: str) -> list[str]:
    """Extract literal URLs used by common HTTP client calls in exploit code."""
    requests: list[str] = []
    patterns = (
        r"(?i)requests\.(get|post|put|patch|delete|head)\s*\(\s*['\"]([^'\"]+)['\"]([^)]*)\)",
        r"(?i)(?:urllib\.request\.urlopen|urlopen)\s*\(\s*['\"]([^'\"]+)['\"]([^)]*)\)",
        r"(?i)fetch\s*\(\s*['\"]([^'\"]+)['\"]([^)]*)\)",
    )
    for index, pattern in enumerate(patterns):
        for match in re.finditer(pattern, str(text or "")):
            if index == 0:
                method, url, tail = match.group(1).upper(), match.group(2), match.group(3)
            else:
                method, url, tail = ("GET" if index != 2 else "GET"), match.group(1), match.group(2)
            body_match = re.search(r"(?i)(?:data|params|body)\s*=\s*['\"]([^'\"]*)['\"]", tail)
            body = body_match.group(1) if body_match else ""
            requests.append(_structured_url_request(method, url, [], body))
    return [item for item in requests if item]


def _structured_url_request(method: str, url: str, headers: list[str], body: str = "") -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value if value.startswith(("http://", "https://")) else f"http://target{value if value.startswith('/') else '/' + value}")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    out_headers = ["Host: {{TARGET_HOST}}"]
    for header in headers:
        if ":" in header and not header.lower().startswith("host:"):
            out_headers.append(header)
    if body and not any(h.lower().startswith("content-type:") for h in out_headers):
        out_headers.append("Content-Type: application/x-www-form-urlencoded")
    lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1", *out_headers, ""]
    if body:
        lines.append(body)
    return "\n".join(lines)


def _iter_json_values(text: str) -> list[Any]:
    values = []
    decoder = json.JSONDecoder()

    for block in _iter_json_blocks(text):
        try:
            values.append(json.loads(block))
            continue
        except json.JSONDecodeError:
            pass

    for start, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            continue
        values.append(value)
    return values


def _iter_json_blocks(text: str) -> list[str]:
    return [
        match.group(1).strip()
        for match in re.finditer(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    ]


def _candidate_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get("candidates"), list):
        return [item for item in value["candidates"] if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _normalize_headers(headers: Any) -> dict[str, str]:
    if isinstance(headers, dict):
        return {str(key).strip(): str(value).strip() for key, value in headers.items() if str(key).strip()}

    if isinstance(headers, list):
        normalized = {}
        for item in headers:
            if isinstance(item, dict):
                key = str(item.get("name") or item.get("key") or "").strip()
                value = str(item.get("value") or "").strip()
                if key:
                    normalized[key] = value
            elif isinstance(item, str) and ":" in item:
                key, value = item.split(":", 1)
                normalized[key.strip()] = value.strip()
        return normalized

    return {}


def _iter_code_blocks(text: str) -> list[str]:
    return [
        match.group(1).strip()
        for match in re.finditer(r"```(?:http|text|raw)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    ]


def _remove_code_blocks(text: str) -> str:
    return re.sub(r"```[a-zA-Z]*\s*\n.*?```", "", text, flags=re.DOTALL)


def _split_raw_http_requests(text: str) -> list[str]:
    starts = [
        match.start()
        for match in re.finditer(
            r"(?im)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?\s*$",
            text,
        )
    ]
    requests = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        request = _clean_raw_http(text[start:end])
        if _looks_like_raw_http(request):
            requests.append(request)
    return requests


def _clean_raw_http(text: str) -> str:
    lines = text.replace("\r\n", "\n").strip().split("\n")
    while lines and lines[-1].strip() in {"```", "---"}:
        lines.pop()
    return "\n".join(lines).strip()


def _looks_like_raw_http(text: str) -> bool:
    first_line = text.strip().splitlines()[0] if text.strip() else ""
    return bool(
        re.match(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?$", first_line, re.IGNORECASE)
        and "HTTP/" in first_line.upper()
        and len(text.strip()) > 20
    )


def _first_text(candidate: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = candidate.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _coerce_confidence(value: Any, *, default: float) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, confidence))


def _dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for candidate in candidates:
        key = candidate["raw_http"].strip()
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _dedupe_requests(requests: list[str]) -> list[str]:
    seen = set()
    unique = []
    for request in requests:
        cleaned = request.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
    return unique
