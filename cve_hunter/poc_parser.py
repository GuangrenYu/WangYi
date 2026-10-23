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
    requests.extend(_extract_concat_url_requests(text))
    requests.extend(_extract_bare_http_urls(text))
    requests.extend(_extract_python_payload_posts(text))
    requests.extend(_extract_payload_label_queries(text))
    requests.extend(_extract_python_json_dumps_posts(text))
    requests.extend(_extract_python_argv_path_calls(text))
    requests.extend(_extract_curl_multipart_uploads(text))
    requests.extend(_extract_powershell_web_requests(text))
    requests.extend(_extract_quoted_path_posts(text))
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


def _extract_concat_url_requests(text: str) -> list[str]:
    """Extract path/query fragments from concatenated or f-string exploit URLs.

    PoCs often build endpoints like::
        deployurl = 'http://localhost:'+port+'/axis/services/AdminService?method=...'
        self.admin_service = f\"{self.target}/services/AdminService\"
    These are not valid as a single literal for ``requests.get('...')`` extractors.
    """
    requests: list[str] = []
    patterns = (
        # '...'+var+'/path?query...'  or  "..."+var+"/path"
        r"""['\"]https?://[^'\"]*['\"]\s*\+\s*[^\"'\n]+?\+\s*['\"](/[^'\"]+)['\"]""",
        # f"{target}/services/AdminService" or f'{target}/path?x=1'
        r"""f['\"]\{[^}]+\}(/[^'\"]+)['\"]""",
        # path = "/axis/services/AdminService?method=..."
        r"""(?i)(?:url|uri|path|endpoint|deployurl|undeployurl|admin_service|service_url)\s*=\s*['\"](/[^'\"]+)['\"]""",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, str(text or "")):
            path = match.group(1).strip()
            if len(path) < 2 or path in {"/", "//"}:
                continue
            # Skip package/install noise.
            if re.search(r"(?i)^/(?:install|setup|download)(?:/|$)", path):
                continue
            if _path_has_unexpanded_template(path):
                continue
            method = "GET"
            if re.search(r"(?i)(?:post|put|delete|patch)", match.group(0)):
                method = re.search(r"(?i)(post|put|delete|patch)", match.group(0)).group(1).upper()
            requests.append(_structured_url_request(method, path, [], ""))
    return [item for item in requests if item]


def _extract_bare_http_urls(text: str) -> list[str]:
    """Extract standalone http(s) URLs that advisories show without a GET line.

    Example (Tenable PoCs)::
        ```
        https://192.168.1.208/nagiosxi/ajaxhelper.php?cmd=...&nsp=...
        ```
    """
    requests: list[str] = []
    # Prefer fenced/standalone lines; avoid sweeping every markdown href
    # (shields.io badges, campaign links, etc.).
    pattern = (
        r"(?im)^\s*(?:```[^\n]*\n)?\s*(https?://[^\s`<>\"']+/[^\s`<>\"']+\?[^\s`<>\"']{6,})\s*(?:\n```)?\s*$"
    )
    seen: set[str] = set()
    for match in re.finditer(pattern, str(text or "")):
        url = match.group(1).rstrip(").,;]")
        if url in seen:
            continue
        lower = url.lower()
        if re.search(r"(?i)/(?:install|setup|download|static/v1|CVERecord|cvename\.cgi)(?:/|$|\?)", lower):
            continue
        if any(host in lower for host in ("shields.io", "github.com/badge", "camo.githubusercontent", "utm_campaign=")):
            continue
        if not re.search(r"[?&](?:cmd|opts|nsp|func|action|method|expression|id|path|file|user)=", lower):
            # Require at least one exploit-ish query key.
            if not re.search(r"(?i)/(?:ajaxhelper|admin|api|service|rest|cgi-bin)/", lower):
                continue
        seen.add(url)
        req = _structured_url_request("GET", url, [], "")
        if req and not _path_has_unexpanded_template(req.splitlines()[0]):
            requests.append(req)
    return requests


def _path_has_unexpanded_template(path_or_request_line: str) -> bool:
    """Reject Python/JS template leftovers like ``{self.service_name}``."""
    text = str(path_or_request_line or "")
    # Encoded JSON in queries uses %7B/%7D — those are fine.
    if re.search(r"\{(?:self|this|target|host|port|url|user|pass)[.\w]*\}", text, re.I):
        return True
    if re.search(r"\{\{[^{}]+\}\}", text):
        # Keep nuclei/runtime placeholders like {{TARGET_HOST}} / {{BaseURL}}.
        if re.search(r"\{\{(?:TARGET_HOST|Host|Hostname|BaseURL|RootURL|interactsh-url)\}\}", text):
            return False
        return True
    return False


def _extract_payload_label_queries(text: str) -> list[str]:
    """Extract prose PoCs like ``payload:field=...&keyword=...`` with nearby path."""
    source = str(text or "")
    requests: list[str] = []
    for match in re.finditer(
        r"(?im)(?:^|\n)\s*payload\s*:\s*([^\s\r\n]+(?:&[^\s\r\n]+)*)",
        source,
    ):
        query = match.group(1).strip().rstrip(".,;")
        # Unescape common markdown/README noise: \* -> *
        query = query.replace("\\*", "*").replace("\\/", "/")
        if "=" not in query or len(query) < 8:
            continue
        if not re.search(r"(?i)(updatexml|union|select|sleep\(|alert\(|\.\./|cmd=|exec)", query):
            continue
        prev = source[max(0, match.start() - 600):match.start()]
        path_match = re.search(
            r"(?i)((?:/)?(?:api\.php/[A-Za-z0-9_./-]+|[A-Za-z0-9_./-]+\.(?:php|cgi|do|action)[A-Za-z0-9_./-]*))",
            prev,
        )
        path = path_match.group(1) if path_match else ""
        if not path:
            # e.g. "via the api.php/Cms/search order parameter"
            path_match = re.search(r"(?i)((?:/)?api\.php/[A-Za-z0-9_./-]+)", source[max(0, match.start()-1200):match.end()+200])
            path = path_match.group(1) if path_match else "/api.php/Cms/search"
        path = "/" + path.lstrip("/")
        requests.append(_structured_url_request("GET", f"{path}?{query}", [], ""))
    return [item for item in requests if item]


def _extract_balanced_braces(source: str, start_idx: int) -> str | None:
    if start_idx < 0 or start_idx >= len(source) or source[start_idx] != "{":
        return None
    depth = 0
    for index, char in enumerate(source[start_idx:], start_idx):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start_idx:index + 1]
    return None


def _extract_python_json_dumps_posts(text: str) -> list[str]:
    """Extract ``session.post(url, data=json.dumps(body_var))`` with nearby dict body."""
    import ast

    source = str(text or "")
    requests: list[str] = []

    str_vars: dict[str, str] = {}
    for match in re.finditer(
        r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(\s*)?(?:f?\"\"\"([\s\S]*?)\"\"\"|f?'''([\s\S]*?)'''|f?\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|f?'([^'\\]*(?:\\.[^'\\]*)*)')",
        source,
    ):
        name = match.group(1)
        raw = next(g for g in match.groups()[1:] if g is not None)
        str_vars[name] = raw.strip()

    for match in re.finditer(
        r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(\s*((?:f?[\"']{1,3}[\s\S]*?[\"']{1,3}\s*)+)\)",
        source,
    ):
        name, blob = match.group(1), match.group(2)
        parts = re.findall(
            r"f?\"\"\"([\s\S]*?)\"\"\"|f?'''([\s\S]*?)'''|f?\"([^\"\\]*(?:\\.[^\"\\]*)*)\"|f?'([^'\\]*(?:\\.[^'\\]*)*)'",
            blob,
        )
        joined = "".join(next(part for part in tup if part is not None) for tup in parts)
        if joined:
            joined = joined.replace("{{", "{").replace("}}", "}")
            for key, val in list(str_vars.items()):
                joined = joined.replace("{" + key + "}", val)
            str_vars[name] = joined

    dict_vars: dict[str, str] = {}
    for match in re.finditer(r"(?m)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{", source):
        body = _extract_balanced_braces(source, match.end() - 1)
        if body:
            dict_vars[match.group(1)] = body

    url_vars: dict[str, str] = {}
    for match in re.finditer(
        r"""(?im)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*f?["'][^"']*?(/service/[^"']+|/[A-Za-z0-9_./-]+)["']""",
        source,
    ):
        url_vars[match.group(1)] = match.group(2)

    for match in re.finditer(
        r"(?is)(?:session|requests)\.post\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,([\s\S]{0,800})\)",
        source,
    ):
        url_name, tail = match.group(1), match.group(2)
        # Require json.dumps in this call; ignore ordinary form posts.
        body_match = re.search(r"(?i)data\s*=\s*json\.dumps\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", tail)
        if not body_match:
            continue
        path = url_vars.get(url_name, "")
        if not path:
            continue
        body_src = dict_vars.get(body_match.group(1))
        if not body_src:
            continue
        body_filled = body_src
        for key, val in str_vars.items():
            body_filled = re.sub(
                rf"(?m)(?<=\[)\s*{re.escape(key)}\s*(?=\])",
                json.dumps(val, ensure_ascii=False),
                body_filled,
            )
            body_filled = re.sub(
                rf"(?m):\s*{re.escape(key)}\s*(?=,|\}})",
                ": " + json.dumps(val, ensure_ascii=False),
                body_filled,
            )
        try:
            cleaned = re.sub(r"(?m):\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=,|\})", r': "\1"', body_filled)
            cleaned = re.sub(r"(?m)(?<=\[)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?=\])", r'"\1"', cleaned)
            obj = ast.literal_eval(cleaned)
            body = json.dumps(obj, ensure_ascii=False)
        except Exception:
            body = body_filled
        headers = [
            "Content-Type: application/json",
            "X-Requested-With: XMLHttpRequest",
            "X-Nexus-UI: true",
        ]
        requests.append(_structured_url_request("POST", path, headers, body))
    return [item for item in requests if item]


def _extract_python_argv_path_calls(text: str) -> list[str]:
    """Extract ``requests.post(sys.argv[N] + '/path', data=var)`` style calls."""
    import ast

    source = str(text or "")
    requests: list[str] = []

    # urlencode / dict bodies assigned to variables
    body_vars: dict[str, str] = {}
    for match in re.finditer(
        r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*urllib\.urlencode\s*\(\s*(\{[\s\S]*?\})\s*\)",
        source,
    ):
        try:
            obj = ast.literal_eval(match.group(2))
            body_vars[match.group(1)] = "&".join(f"{k}={v}" for k, v in obj.items())
        except Exception:
            continue
    for match in re.finditer(r"(?m)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{", source):
        body = _extract_balanced_braces(source, match.end() - 1)
        if not body:
            continue
        # Skip if already captured as urlencode target name collision
        name = match.group(1)
        if name in body_vars:
            continue
        # XML/text payloads in triple quotes nearby preferred via other extractors.
    for match in re.finditer(
        r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:f?'''([\s\S]*?)'''|f?\"\"\"([\s\S]*?)\"\"\")",
        source,
    ):
        name = match.group(1)
        raw = next(g for g in match.groups()[1:] if g is not None)
        if re.search(r"(?i)<\?xml|DOCTYPE|plist|soapenv", raw):
            body_vars[name] = raw.strip()

    for match in re.finditer(
        r"(?is)requests\.(get|post|put|delete|patch)\s*\(\s*sys\.argv\[\d+\]\s*\+\s*['\"](/[^'\"]+)['\"]\s*,([\s\S]{0,600})",
        source,
    ):
        method, path, tail = match.group(1).upper(), match.group(2), match.group(3)
        body = ""
        headers: list[str] = []
        data_match = re.search(r"(?i)data\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", tail)
        if data_match:
            body = body_vars.get(data_match.group(1), "")
        # headers={'Content-Type': '...'}
        ctype = re.search(r"(?i)['\"]Content-Type['\"]\s*:\s*['\"]([^'\"]+)['\"]", tail)
        if ctype:
            headers.append(f"Content-Type: {ctype.group(1)}")
        elif body.startswith("<?xml") or body.startswith("<!DOCTYPE") or "<plist" in body[:80]:
            headers.append("Content-Type: application/xml")
        elif body and "=" in body and not body.lstrip().startswith(("{", "<")):
            headers.append("Content-Type: application/x-www-form-urlencoded")
        requests.append(_structured_url_request(method, path, headers, body))
    return [item for item in requests if item]


def _extract_curl_multipart_uploads(text: str) -> list[str]:
    """Extract ``curl -F files=@shell.php http://host/path`` upload one-liners."""
    requests: list[str] = []
    for match in re.finditer(
        r"(?im)curl\s+[^\n]*?-F\s*['\"]([^'\"]+)['\"][^\n]*?(https?://[^\s'\"]+|/server/[^\s'\"]+|/[^\s'\"]+\.(?:php|cgi|asp)[^\s'\"]*)",
        str(text or ""),
    ):
        form_field, url = match.group(1), match.group(2)
        path = url
        if url.startswith("http"):
            try:
                parsed = urlsplit(url)
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
            except ValueError:
                path = "/" + url.split("/", 3)[-1]
        # Normalize demo hosts like /jQuery-File-Upload-x/server/php/index.php -> /server/php/
        if "/server/php" in path and not path.endswith("/server/php/") and "index.php" in path:
            # keep full path from first /server/
            idx = path.find("/server/")
            if idx >= 0:
                path = path[idx:]
        body = (
            "------------------------boundary\r\n"
            f'Content-Disposition: form-data; name="{form_field.split("=")[0]}"; filename="shell.php"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            "<?php system($_GET['cmd']); ?>\r\n"
            "------------------------boundary--\r\n"
        )
        headers = ["Content-Type: multipart/form-data; boundary=----------------------boundary"]
        # Prefer field form files=@shell.php
        if "files=" in form_field or form_field.startswith("files"):
            pass
        requests.append(_structured_url_request("POST", path, headers, body))
    return [item for item in requests if item]


def _extract_powershell_web_requests(text: str) -> list[str]:
    """Extract basic ``Invoke-WebRequest -Uri ... -Method ...`` calls."""
    requests: list[str] = []
    for match in re.finditer(
        r"(?is)Invoke-(?:WebRequest|RestMethod)\s+[^\n]*?-Uri\s+['\"]([^'\"]+)['\"][^\n]*?",
        str(text or ""),
    ):
        url = match.group(1)
        chunk = match.group(0)
        method_match = re.search(r"(?i)-Method\s+(\w+)", chunk)
        method = (method_match.group(1) if method_match else "GET").upper()
        body = ""
        body_match = re.search(r"(?i)-Body\s+['\"]([^'\"]*)['\"]", chunk)
        if body_match:
            body = body_match.group(1)
        try:
            parsed = urlsplit(url if url.startswith("http") else f"http://t{url if url.startswith('/') else '/' + url}")
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        except ValueError:
            continue
        if len(path) < 2:
            continue
        headers = []
        if body and not body.lstrip().startswith("<"):
            headers.append("Content-Type: application/x-www-form-urlencoded")
        requests.append(_structured_url_request(method, path, headers, body))
    return [item for item in requests if item]


def _extract_quoted_path_posts(text: str) -> list[str]:
    """Extract path literals used with requests.post(url, data=..., headers=...)."""
    source = str(text or "")
    requests: list[str] = []
    # "/flex2gateway/amf" appears inside concatenations then posted
    for match in re.finditer(
        r"""['\"](/(?:flex2gateway|zdm|cgi-bin|api|wp-admin|server)/[^'\"]+)['\"]""",
        source,
    ):
        path = match.group(1)
        # Look ahead for content-type / post nearby
        window = source[max(0, match.start() - 80):match.end() + 250]
        if not re.search(r"(?i)requests\.(post|put)|Content-Type|amf", window):
            continue
        headers = []
        ctype = re.search(r"(?i)['\"]Content-Type['\"]\s*:\s*['\"]([^'\"]+)['\"]", window)
        if ctype:
            headers.append(f"Content-Type: {ctype.group(1)}")
        elif "amf" in path.lower():
            headers.append("Content-Type: application/x-amf")
        requests.append(_structured_url_request("POST", path, headers, ""))
    # "/flex2gateway/amf" assigned then posted
    path_vars: dict[str, str] = {}
    for match in re.finditer(
        r"""(?im)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[^'\"\n]*['\"](/(?:flex2gateway|cgi-bin|api|wp-admin|server)[^'\"]*)['\"])""",
        source,
    ):
        path_vars[match.group(1)] = match.group(2)
    for match in re.finditer(
        r"(?is)requests\.post\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,([\s\S]{0,400})\)",
        source,
    ):
        path = path_vars.get(match.group(1), "")
        if not path:
            continue
        tail = match.group(2)
        headers = []
        ctype = re.search(r"(?i)['\"]Content-Type['\"]\s*:\s*['\"]([^'\"]+)['\"]", tail)
        if ctype:
            headers.append(f"Content-Type: {ctype.group(1)}")
        # binary/amf payloads cannot be reproduced faithfully; still emit path marker request
        body = ""
        if "amf" in path.lower():
            body = ""  # keep empty; path+content-type may still matter for signatures
            if not any(h.lower().startswith("content-type:") for h in headers):
                headers.append("Content-Type: application/x-amf")
        requests.append(_structured_url_request("POST", path, headers, body))
    # Direct: requests.post(base + "/path"
    for match in re.finditer(
        r"(?is)requests\.(get|post|put)\s*\(\s*[^,\)]*\+\s*['\"](/[^'\"]+)['\"]\s*,([\s\S]{0,500})",
        source,
    ):
        method, path, tail = match.group(1).upper(), match.group(2), match.group(3)
        if re.search(r"(?i)sys\.argv", match.group(0)):
            continue  # handled elsewhere
        headers = []
        ctype = re.search(r"(?i)['\"]Content-Type['\"]\s*:\s*['\"]([^'\"]+)['\"]", tail)
        if ctype:
            headers.append(f"Content-Type: {ctype.group(1)}")
        body = ""
        data_match = re.search(r"(?i)data\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", tail)
        # leave body empty if unknown var; path alone still useful when CT set
        requests.append(_structured_url_request(method, path, headers, body))
    return [item for item in requests if item]


def _substitute_simple_code_templates(text: str) -> str:
    """Fill common exploit-code placeholders so SOAP/XML bodies become sendable."""
    out = str(text or "")
    out = re.sub(r"\{self\.service_name\}", "exploitservice", out)
    out = re.sub(r"\{self\.webshell_name\}", "exploit.jsp", out)
    out = re.sub(r"\{self\.[a-zA-Z_][a-zA-Z0-9_]*\}", "x", out)
    out = re.sub(r"\{(?:command|cmd|payload)\}", "id", out, flags=re.I)
    return out


def _extract_python_payload_posts(text: str) -> list[str]:
    """Build POST requests from ``payload = '''...'''`` + ``requests.post(..., data=payload)``.

    Axis/Nexus style Python PoCs often keep the exploit body in a named variable
    instead of an inline string, which plain call extractors miss.
    """
    source = str(text or "")
    payloads: dict[str, str] = {}
    for match in re.finditer(
        r"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*f?(?:'''|\"\"\")([\s\S]{30,20000}?)(?:'''|\"\"\")",
        source,
    ):
        name, body = match.group(1), match.group(2)
        body = _substitute_simple_code_templates(body).strip()
        if re.search(r"(?i)<(?:soapenv:|soap:)?Envelope\b|<\?xml\b", body) or (
            body.startswith("{") and len(body) > 40
        ):
            payloads[name] = body
    if not payloads:
        return []

    # Map URL variables like admin_service = f"{self.target}/services/AdminService"
    url_vars: dict[str, str] = {}
    for match in re.finditer(
        r"""(?im)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*f?['\"][^'\"]*?(/[^'\"]+)['\"]""",
        source,
    ):
        path = match.group(2).strip()
        if path.startswith("/") and not _path_has_unexpanded_template(path):
            url_vars[match.group(1)] = path
    for match in re.finditer(
        r"""(?im)\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*f['\"]\{[^}]+\}(/[^'\"]+)['\"]""",
        source,
    ):
        path = match.group(2).strip()
        if path.startswith("/") and not _path_has_unexpanded_template(
            _substitute_simple_code_templates(path)
        ):
            url_vars[match.group(1)] = _substitute_simple_code_templates(path)

    requests: list[str] = []
    for match in re.finditer(
        r"(?is)requests\.post\s*\(\s*(?:self\.)?([A-Za-z_][A-Za-z0-9_]*)\s*,([\s\S]{0,400}?)\)",
        source,
    ):
        url_name, tail = match.group(1), match.group(2)
        path = url_vars.get(url_name, "")
        if not path:
            # Direct path rare; skip if unknown variable.
            continue
        body_name = ""
        body_match = re.search(r"(?i)(?:data|json)\s*=\s*(?:self\.)?([A-Za-z_][A-Za-z0-9_]*)", tail)
        if body_match:
            body_name = body_match.group(1)
        body = payloads.get(body_name, "")
        if not body:
            continue
        headers = ["Content-Type: application/xml"]
        if re.search(r"(?i)SOAPAction", source[max(0, match.start() - 400):match.start() + 200]):
            headers.append("SOAPAction: something")
        if body.lstrip().startswith("{"):
            headers = ["Content-Type: application/json"]
        requests.append(_structured_url_request("POST", path, headers, body))
    return [item for item in requests if item]


def build_multistep_http_candidate(
    requests: list[str],
    *,
    source: str = "reference_evidence",
    evidence_url: str = "",
    confidence: float = 0.78,
    reason: str = "",
) -> dict | None:
    """Package ordered raw HTTP requests as one multi-step candidate."""
    steps = [str(item).strip() for item in requests if str(item or "").strip()]
    if len(steps) < 2:
        return None
    return {
        "kind": "raw_http",
        "source": source,
        "raw_http": steps[0],
        "request_steps": [{"raw_http": step, "step_index": index} for index, step in enumerate(steps, start=1)],
        "evidence_type": "raw_http",
        "encoding_preserved": True,
        "nuclei_yaml": "",
        "evidence_url": evidence_url,
        "confidence": confidence,
        "reason": reason or "从参考代码组装的多步 HTTP 请求",
        "validation_hint": {},
    }


def score_evidence_request(request: str, *, cve_id: str = "", source_text: str = "") -> int:
    """Rank extracted requests so exploit endpoints beat unrelated sibling PoCs."""
    text = str(request or "")
    if not text.strip() or _path_has_unexpanded_template(text.splitlines()[0] if text else ""):
        return -100
    first = text.splitlines()[0]
    method, _, rest = first.partition(" ")
    path = rest.split(" HTTP/", 1)[0].strip()
    query = path.split("?", 1)[1] if "?" in path else ""
    path_only = path.split("?", 1)[0]
    body = text.split("\n\n", 1)[1] if "\n\n" in text else ""
    score = 0
    score += min(len(query), 300) // 20
    score += min(len(body.strip()), 400) // 40
    if method.upper() in {"POST", "PUT", "PATCH"} and body.strip():
        score += 6
    if re.search(
        r"(?i)(select|union|updatexml|sleep\(|alert\(|script|cmd=|exec|eval|"
        r"set_random|ajaxhelper|AdminService|deployment|expression|getClass|"
        r"previewAssets|passwd|\.\./|nsp=|opts=|soapenv:|LogHandler)",
        path + "\n" + body,
    ):
        score += 10
    # Prefer deploy over undeploy for Axis-style AdminService chains.
    if re.search(r"(?i)undeployment", path + "\n" + body):
        score -= 8
    elif re.search(r"(?i)(?:\b|ns1:|<)deployment\b", path + "\n" + body):
        score += 8
    if re.search(r"(?i)soapenv:Envelope|LogHandler\.fileName", body):
        score += 8
    if cve_id and source_text:
        # Locate this exact request, not just the shared path basename — multi-CVE
        # advisories reuse endpoints (e.g. ajaxhelper.php) under different IDs.
        anchors = []
        if query:
            anchors.append(query[:60])
            for token in re.findall(r"(?i)(?:func|cmd|action|method|expression)=([^&]{4,40})", query):
                anchors.append(token)
        if body.strip():
            anchors.append(body.strip()[:40])
        anchors.append(path[:120])
        pos = -1
        for anchor in anchors:
            if anchor and anchor in source_text:
                pos = source_text.find(anchor)
                break
        if pos >= 0:
            preceding = source_text[max(0, pos - 1200):pos]
            cves = re.findall(r"CVE-\d{4}-\d+", preceding, re.I)
            current = str(cve_id).upper()
            if cves:
                nearest = cves[-1].upper()
                if nearest == current:
                    score += 20
                elif current and current in source_text.upper():
                    # Dual-CVE writeups (e.g. 19487/19488) still belong to this CVE.
                    score += 5
                else:
                    score -= 25
    return score


def _structured_url_request(method: str, url: str, headers: list[str], body: str = "") -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(
            value if value.startswith(("http://", "https://"))
            else f"http://target{value if value.startswith('/') else '/' + value}"
        )
    except ValueError:
        # Prose sometimes yields placeholders like Host: site or bad bracket hosts.
        path = value if value.startswith("/") else "/" + value.split("://", 1)[-1].split("/", 1)[-1]
        if not path.startswith("/"):
            path = "/" + path
        parsed_query = ""
        if "?" in path:
            path, parsed_query = path.split("?", 1)
        path = path or "/"
        if parsed_query:
            path += "?" + parsed_query
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
