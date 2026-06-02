"""PoC candidate parsing and Raw HTTP rendering helpers."""

from __future__ import annotations

import json
import re
from typing import Any


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


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
            raw_http = render_raw_http(candidate)
            if not raw_http:
                continue
            candidates.append({
                "raw_http": raw_http,
                "evidence_url": str(candidate.get("evidence_url") or candidate.get("source_url") or ""),
                "confidence": _coerce_confidence(candidate.get("confidence"), default=0.5),
                "reason": str(candidate.get("reason") or candidate.get("description") or ""),
            })
        if candidates:
            return _dedupe_candidates(candidates)
    return []


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
    return _dedupe_requests(requests)


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
