"""Bounded, deterministic HTTP PoC mutations.

These helpers deliberately make small changes to an already evidenced request.
They do not discover endpoints, invent payloads, or call an LLM.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode


MAX_VARIANTS = 2
_REQUEST_LINE = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)(\s+)(\S+)(\s+HTTP/\d(?:\.\d)?)$", re.I)
_CONTENT_TYPE = re.compile(r"(?im)^Content-Type:\s*([^\r\n]+)")
_CONTENT_LENGTH = re.compile(r"(?im)^Content-Length:\s*([^\r\n]+)")


def _replace_request_line(raw_http: str, *, method: str | None = None, path: str | None = None) -> str:
    lines = str(raw_http or "").splitlines()
    if not lines:
        return ""
    match = _REQUEST_LINE.match(lines[0].strip())
    if not match:
        return ""
    lines[0] = f"{method or match.group(1).upper()} {path or match.group(3)} {match.group(4).strip()}"
    return "\n".join(lines).strip()


def _replace_content_type(raw_http: str, content_type: str, body: str) -> str:
    if not _CONTENT_TYPE.search(raw_http):
        return ""
    header_replaced = _CONTENT_TYPE.sub(f"Content-Type: {content_type}", raw_http, count=1)
    head, _, _ = header_replaced.partition("\n\n")
    return f"{head}\n\n{body}".strip()


def _body(raw_http: str) -> str:
    parts = str(raw_http or "").split("\n\n", 1)
    return parts[1] if len(parts) == 2 else ""


def _add_content_length(raw_http: str, body: str) -> str:
    if _CONTENT_LENGTH.search(raw_http) or not body:
        return ""
    head, _, _ = raw_http.partition("\n\n")
    length = len(body.encode("iso-8859-1", errors="ignore"))
    return f"{head}\nContent-Length: {length}\n\n{body}".strip()


def _variant(candidate: dict[str, Any], raw_http: str, action: str, field: str, old: str, new: str, reason: str) -> dict[str, Any]:
    item = copy.deepcopy(candidate)
    item.update({
        "kind": "raw_http",
        "raw_http": raw_http,
        "nuclei_yaml": "",
        "source": "rule_variant",
        "is_variant": True,
        "parent_candidate_index": candidate.get("candidate_index"),
        "variant_action": action,
        "variant_reason": reason,
        "variant_change": {"field": field, "from": old, "to": new},
        "confidence": min(float(candidate.get("confidence") or 0.5), 0.7),
    })
    return item


def generate_bounded_variants(
    candidate: dict[str, Any],
    *,
    status_code: int = 0,
    generic_ips_matched: bool = False,
    max_variants: int = MAX_VARIANTS,
) -> list[dict[str, Any]]:
    """Generate at most two cheap mutations for an evidenced raw HTTP request."""
    if max_variants <= 0 or candidate.get("request_steps") or candidate.get("nuclei_yaml"):
        return []
    raw_http = str(candidate.get("raw_http") or "").strip()
    match = _REQUEST_LINE.match(raw_http.splitlines()[0].strip()) if raw_http else None
    if not match:
        return []

    variants: list[dict[str, Any]] = []
    method, _, path, _ = match.groups()
    body = _body(raw_http)
    reason = f"HTTP {status_code}" if status_code else "通用 IPS 命中"

    if method.upper() in {"POST", "PUT", "PATCH"} and body and not _CONTENT_LENGTH.search(raw_http):
        with_length = _add_content_length(raw_http, body)
        if with_length:
            variants.append(_variant(candidate, with_length, "adjust_header", "Content-Length", "missing", str(len(body.encode("iso-8859-1", errors="ignore"))), reason))

    if status_code == 404 and len(variants) < max_variants:
        new_path = "" if path == "/" else path[:-1] if path.endswith("/") else f"{path}/"
        if new_path and new_path != path:
            variants.append(_variant(candidate, _replace_request_line(raw_http, path=new_path), "adjust_path", "path", path, new_path, reason))

    if status_code == 405 and len(variants) < max_variants:
        alternate = "POST" if method.upper() == "GET" else "GET" if method.upper() == "POST" else ""
        if alternate:
            variants.append(_variant(candidate, _replace_request_line(raw_http, method=alternate), "adjust_method", "method", method.upper(), alternate, reason))

    if status_code in {400, 415} and len(variants) < max_variants and body:
        content_match = _CONTENT_TYPE.search(raw_http)
        current = content_match.group(1).strip().lower() if content_match else ""
        target = "application/json" if "form-urlencoded" in current else "application/x-www-form-urlencoded" if "json" in current else ""
        converted_body = ""
        if "json" in current:
            try:
                value = json.loads(body)
                if isinstance(value, dict):
                    converted_body = urlencode(value, doseq=True)
            except (TypeError, ValueError):
                converted_body = ""
        elif "form-urlencoded" in current:
            try:
                pairs = parse_qsl(body, keep_blank_values=True)
                converted_body = json.dumps(dict(pairs), ensure_ascii=False, separators=(",", ":")) if pairs else ""
            except (TypeError, ValueError):
                converted_body = ""
        if target and converted_body:
            converted = _replace_content_type(raw_http, target, converted_body)
            if converted:
                variants.append(_variant(candidate, converted, "adjust_content_type", "Content-Type", current, target, reason))

    if generic_ips_matched and len(variants) < max_variants:
        encoded = re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), raw_http, count=1)
        if encoded != raw_http:
            variants.append(_variant(candidate, encoded, "adjust_payload_encoding", "encoding", "lowercase-percent", "uppercase-percent", reason))

    return variants[:max_variants]
