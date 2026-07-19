"""Discover real-product lab candidates from official vendor advisories."""

from __future__ import annotations

import html as html_lib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from cve_hunter.config import cfg


ORACLE_INDEX_URL = "https://www.oracle.com/security-alerts/"
ORACLE_CVE_MAPPING_URL = (
    "https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.html"
)
JENKINS_RSS_URL = "https://www.jenkins.io/security/advisories/rss.xml"
TOMCAT_SECURITY_URLS = (
    "https://tomcat.apache.org/security-11.html",
    "https://tomcat.apache.org/security-10.html",
    "https://tomcat.apache.org/security-9.html",
    "https://tomcat.apache.org/security-8.html",
    "https://tomcat.apache.org/security-7.html",
)
MSRC_CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
MSRC_INDEX_URL = (
    "https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US/vulnerability"
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_ORACLE_ADVISORY_RE = re.compile(
    r"/security-alerts/(?P<kind>cpu(?!archive)|cspu|alert-cve-)[^/]*\.html$",
    re.IGNORECASE,
)
_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
_MSRC_SERVER_PRODUCT_MARKERS = (
    "windows server",
    "sharepoint server",
    "exchange server",
    "sql server",
    "internet information services",
    "remote desktop web client",
    "active directory federation services",
)


class _OfficialHttpClient:
    """Prefer the configured proxy, then retry official sites directly."""

    def __init__(self, *, timeout: int, headers: dict[str, str]) -> None:
        proxy = getattr(cfg, "httpx_proxy", None)
        self._clients = []
        if proxy:
            self._clients.append(httpx.Client(
                timeout=timeout,
                follow_redirects=True,
                proxy=proxy,
                trust_env=False,
                headers=headers,
            ))
        self._clients.append(httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
            headers=headers,
        ))

    def __enter__(self) -> "_OfficialHttpClient":
        return self

    def __exit__(self, *_args) -> None:
        for client in self._clients:
            client.close()

    def get(self, url: str) -> httpx.Response:
        last_error: Exception | None = None
        for index, client in enumerate(self._clients):
            try:
                response = client.get(url)
                if response.status_code < 400 or index == len(self._clients) - 1:
                    return response
                last_error = httpx.HTTPStatusError(
                    f"HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )
            except httpx.RequestError as exc:
                last_error = exc
        if last_error:
            raise last_error
        raise RuntimeError("No HTTP client available")

    def get_json(self, url: str) -> tuple[httpx.Response, dict[str, Any]]:
        last_error: Exception | None = None
        for client in self._clients:
            try:
                response = client.get(url, headers={"Accept": "application/json"})
                response.raise_for_status()
                payload = response.json()
                if isinstance(payload, dict):
                    return response, payload
                last_error = ValueError("JSON response is not an object")
            except (httpx.RequestError, httpx.HTTPStatusError, json.JSONDecodeError, ValueError) as exc:
                last_error = exc
        if last_error:
            raise last_error
        raise RuntimeError("No HTTP client available")

    def head(self, url: str) -> httpx.Response:
        last_error: Exception | None = None
        for index, client in enumerate(self._clients):
            try:
                response = client.head(url)
                if response.status_code < 400 or index == len(self._clients) - 1:
                    return response
                last_error = httpx.HTTPStatusError(
                    f"HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )
            except httpx.RequestError as exc:
                last_error = exc
        if last_error:
            raise last_error
        raise RuntimeError("No HTTP client available")


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.tables: list[list[list[str]]] = []
        self.table_links: list[list[list[tuple[str, str]]]] = []
        self.sections: list[dict[str, str]] = []
        self._skip_depth = 0
        self._link_href = ""
        self._link_text: list[str] = []
        self._table_depth = 0
        self._table: list[list[str]] = []
        self._table_links: list[list[list[tuple[str, str]]]] = []
        self._row: list[dict[str, Any]] | None = None
        self._cell: list[str] | None = None
        self._cell_links: list[tuple[str, str]] = []
        self._cell_rowspan = 1
        self._cell_colspan = 1
        self._row_spans: dict[int, tuple[int, str, list[tuple[str, str]]]] = {}
        self._section_heading: list[str] | None = None
        self._section_title = ""
        self._section_body: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        if tag in {"script", "style"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "a":
            self._link_href = str(attrs_map.get("href") or "")
            self._link_text = []
        elif tag == "table":
            if self._table_depth == 0:
                self._table = []
                self._table_links = []
                self._row_spans = {}
            self._table_depth += 1
        elif tag == "tr" and self._table_depth:
            self._row = []
        elif tag in {"td", "th"} and self._table_depth and self._row is not None:
            self._cell = []
            self._cell_links = []
            self._cell_rowspan = _positive_int(attrs_map.get("rowspan"))
            self._cell_colspan = _positive_int(attrs_map.get("colspan"))
        elif tag == "h3":
            self._finish_section()
            self._section_heading = []
            self._section_title = ""
            self._section_body = []
        elif tag == "h2":
            self._finish_section()

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag == "a" and self._link_href:
            link = (self._link_href, _clean_text(self._link_text))
            self.links.append(link)
            if self._cell is not None:
                self._cell_links.append(link)
            self._link_href = ""
            self._link_text = []
        elif tag in {"td", "th"} and self._cell is not None and self._row is not None:
            self._row.append({
                "text": _clean_text(self._cell),
                "links": list(self._cell_links),
                "rowspan": self._cell_rowspan,
                "colspan": self._cell_colspan,
            })
            self._cell = None
            self._cell_links = []
        elif tag == "tr" and self._row is not None:
            row, row_links = self._expand_row(self._row)
            if any(row):
                self._table.append(row)
                self._table_links.append(row_links)
            self._row = None
        elif tag == "table" and self._table_depth:
            self._table_depth -= 1
            if self._table_depth == 0 and self._table:
                self.tables.append(self._table)
                self.table_links.append(self._table_links)
                self._table = []
                self._table_links = []
                self._row_spans = {}
        elif tag == "h3" and self._section_heading is not None:
            self._section_title = _clean_text(self._section_heading)
            self._section_heading = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not data.strip():
            return
        if self._link_href:
            self._link_text.append(data)
        if self._cell is not None:
            self._cell.append(data)
        if self._section_heading is not None:
            self._section_heading.append(data)
        elif self._section_title:
            self._section_body.append(data)

    def close(self) -> None:
        super().close()
        self._finish_section()

    def _finish_section(self) -> None:
        if not self._section_title and self._section_heading is None:
            return
        title = self._section_title or _clean_text(self._section_heading or [])
        if title:
            self.sections.append({"title": title, "text": _clean_text(self._section_body)})
        self._section_heading = None
        self._section_title = ""
        self._section_body = []

    def _expand_row(
        self,
        cells: list[dict[str, Any]],
    ) -> tuple[list[str], list[list[tuple[str, str]]]]:
        values: list[str] = []
        links: list[list[tuple[str, str]]] = []
        column = 0

        def consume_span() -> None:
            nonlocal column
            remaining, value, cell_links = self._row_spans[column]
            values.append(value)
            links.append(cell_links)
            if remaining <= 1:
                del self._row_spans[column]
            else:
                self._row_spans[column] = (remaining - 1, value, cell_links)
            column += 1

        for cell in cells:
            while column in self._row_spans:
                consume_span()
            for _ in range(cell["colspan"]):
                value = str(cell["text"])
                cell_links = list(cell["links"])
                values.append(value)
                links.append(cell_links)
                if cell["rowspan"] > 1:
                    self._row_spans[column] = (cell["rowspan"] - 1, value, cell_links)
                column += 1
        if self._row_spans:
            last_column = max(self._row_spans)
            while column <= last_column:
                if column in self._row_spans:
                    consume_span()
                else:
                    values.append("")
                    links.append([])
                    column += 1
        return values, links


def _clean_text(parts: list[str] | str) -> str:
    value = " ".join(parts) if isinstance(parts, list) else parts
    return " ".join(html_lib.unescape(value).split())


def _positive_int(value: Any) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


def _parse_html_document(html: str) -> _DocumentParser:
    parser = _DocumentParser()
    parser.feed(html)
    parser.close()
    return parser


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _lab_profile(vendor: str, product: str, affected_versions: str) -> dict[str, Any]:
    vendor_key = vendor.lower()
    product_key = product.lower()
    if vendor_key == "jenkins":
        version = _first_version(affected_versions)
        return {
            "lab_readiness": "docker_recipe_candidate",
            "lab_type": "docker_real_product",
            "deployment_type": "docker",
            "environment_status": "not_present",
            "image_repository": "jenkins/jenkins",
            "version_pin": version,
            "media_url": f"https://get.jenkins.io/war/{version}/jenkins.war" if version else "",
            "media_status": "unverified" if version else "not_identified",
            "acquisition": "Official Jenkins container image; verify the historical tag before launch.",
            "license_requirement": "open_source",
        }
    if vendor_key == "apache" and "tomcat" in product_key:
        version = _last_version(affected_versions)
        major = version.split(".", 1)[0] if version else ""
        return {
            "lab_readiness": "docker_recipe_candidate",
            "lab_type": "docker_real_product",
            "deployment_type": "docker",
            "environment_status": "not_present",
            "image_repository": "tomcat",
            "version_pin": version,
            "media_url": (
                f"https://archive.apache.org/dist/tomcat/tomcat-{major}/v{version}/bin/"
                f"apache-tomcat-{version}.tar.gz"
                if version else ""
            ),
            "media_status": "unverified" if version else "not_identified",
            "acquisition": "Official Tomcat image or Apache archive; pin an affected version.",
            "license_requirement": "open_source",
        }
    if vendor_key == "oracle" and re.match(r"mysql server(?:,|$)", product_key):
        return {
            "lab_readiness": "docker_recipe_candidate",
            "lab_type": "docker_real_product",
            "deployment_type": "docker",
            "environment_status": "not_present",
            "image_repository": "mysql",
            "version_pin": "",
            "media_url": "",
            "media_status": "not_identified",
            "acquisition": "Official MySQL image; select a tag explicitly listed as affected.",
            "license_requirement": "oracle_image_terms",
        }
    if vendor_key == "oracle":
        return {
            "lab_readiness": "manual_media_required",
            "lab_type": "manual_licensed_real_product",
            "deployment_type": "manual",
            "environment_status": "not_present",
            "image_repository": "",
            "version_pin": "",
            "media_url": "",
            "media_status": "license_required",
            "acquisition": "Use customer-authorized Oracle media or Oracle Container Registry artifacts.",
            "license_requirement": "oracle_support_or_license_acceptance",
        }
    if vendor_key == "microsoft":
        return {
            "lab_readiness": "isolated_vm_required",
            "lab_type": "vm_real_product",
            "deployment_type": "vm",
            "environment_status": "not_present",
            "image_repository": "",
            "version_pin": "",
            "media_url": "",
            "media_status": "license_or_evaluation_required",
            "acquisition": "Use licensed/evaluation media and an isolated pre-patch VM snapshot.",
            "license_requirement": "microsoft_evaluation_or_license",
        }
    return {
        "lab_readiness": "manual_media_required",
        "lab_type": "manual_real_product",
        "deployment_type": "manual",
        "environment_status": "not_present",
        "image_repository": "",
        "version_pin": "",
        "media_url": "",
        "media_status": "not_identified",
        "acquisition": "Acquire an affected release from the vendor's official distribution channel.",
        "license_requirement": "vendor_specific",
    }


def _first_version(text: str) -> str:
    match = re.search(r"\d+(?:\.\d+){1,3}(?:[-.]M\d+)?", text)
    return match.group(0) if match else ""


def _last_version(text: str) -> str:
    matches = re.findall(r"\d+(?:\.\d+){1,3}(?:[-.]M\d+)?", text)
    return matches[-1] if matches else ""


def _candidate(
    *,
    vendor: str,
    cve_id: str,
    product: str,
    advisory_url: str,
    advisory_title: str,
    affected_versions: str = "",
    fixed_versions: str = "",
    component: str = "",
    protocol: str = "",
    severity: str = "unknown",
    cvss_score: float = 0.0,
    remote_without_auth: bool = False,
    description: str = "",
    affected_products: list[str] | None = None,
) -> dict[str, Any]:
    profile = _lab_profile(vendor, product, affected_versions)
    return {
        "vendor": vendor,
        "cve_id": cve_id.upper(),
        "product": product,
        "component": component,
        "severity": severity.lower(),
        "cvss_score": cvss_score,
        "protocol": protocol,
        "remote_without_auth": remote_without_auth,
        "affected_versions": affected_versions,
        "fixed_versions": fixed_versions,
        "affected_products": affected_products or [],
        "description": description[:1200],
        "advisory_title": advisory_title,
        "advisory_url": advisory_url,
        "real_environment": True,
        "local_environment_matches": [],
        **profile,
    }


def parse_oracle_advisory(html: str, advisory_url: str, advisory_title: str) -> list[dict[str, Any]]:
    document = _parse_html_document(html)
    candidates: list[dict[str, Any]] = []
    for table in document.tables:
        for row in table:
            if len(row) < 7 or not _CVE_RE.fullmatch(row[0]):
                continue
            score = _float(row[5])
            versions = row[-2] if len(row) >= 8 else row[-1]
            candidates.append(_candidate(
                vendor="Oracle",
                cve_id=row[0],
                product=row[1],
                component=row[2],
                protocol=row[3],
                remote_without_auth=row[4].strip().lower() == "yes",
                cvss_score=score,
                severity=_severity_from_score(score),
                affected_versions=versions,
                description=row[-1] if len(row) >= 8 else "",
                advisory_url=advisory_url,
                advisory_title=advisory_title,
            ))
    return _dedupe_candidates(candidates)


def parse_jenkins_advisory(html: str, advisory_url: str, advisory_title: str) -> list[dict[str, Any]]:
    document = _parse_html_document(html)
    candidates: list[dict[str, Any]] = []
    for section in document.sections:
        text = section["text"]
        cves = sorted({match.upper() for match in _CVE_RE.findall(text)})
        if not cves or "Jenkins " not in text:
            continue
        affected_match = re.search(
            r"(?:In\s+)?Jenkins\s+(.{1,120}?and earlier,\s+LTS\s+.{1,80}?and earlier)",
            text,
            re.IGNORECASE,
        )
        affected = f"Jenkins {affected_match.group(1)}" if affected_match else ""
        fixed_match = re.search(r"Jenkins\s+(\d+(?:\.\d+)+),\s+LTS\s+(\d+(?:\.\d+)+)", text)
        fixed = f"Jenkins {fixed_match.group(1)}, LTS {fixed_match.group(2)}" if fixed_match else ""
        severity_match = re.search(r"Severity\s*\(CVSS\):\s*(Critical|High|Medium|Low)", text, re.IGNORECASE)
        severity = severity_match.group(1).lower() if severity_match else "unknown"
        for cve_id in cves:
            candidates.append(_candidate(
                vendor="Jenkins",
                cve_id=cve_id,
                product="Jenkins Core",
                component=section["title"],
                severity=severity,
                affected_versions=affected,
                fixed_versions=fixed,
                protocol="HTTP",
                description=text,
                advisory_url=advisory_url,
                advisory_title=advisory_title,
            ))
    return _dedupe_candidates(candidates)


def parse_tomcat_security(
    html: str,
    advisory_url: str,
    max_releases: int | None = 1,
) -> list[dict[str, Any]]:
    document = _parse_html_document(html)
    candidates: list[dict[str, Any]] = []
    releases_seen = 0
    pattern = re.compile(
        r"(?P<severity>Critical|Important|High|Moderate|Low):\s+"
        r"(?P<title>.+?)\s+(?P<cve>CVE-\d{4}-\d{4,7})\s+"
        r"(?P<body>.*?)(?=(?:Critical|Important|High|Moderate|Low):\s+|$)",
        re.IGNORECASE,
    )
    for section in document.sections:
        fixed_match = re.search(r"Fixed in Apache Tomcat\s+(\S+)", section["title"], re.IGNORECASE)
        if not fixed_match:
            continue
        if max_releases is not None and releases_seen >= max_releases:
            break
        releases_seen += 1
        fixed_version = fixed_match.group(1)
        for match in pattern.finditer(section["text"]):
            body = _clean_text(match.group("body"))
            affected_match = re.search(r"Affects:\s*(.+?)\s*$", body, re.IGNORECASE)
            affected = affected_match.group(1) if affected_match else ""
            candidates.append(_candidate(
                vendor="Apache",
                cve_id=match.group("cve"),
                product="Apache Tomcat",
                component=_clean_text(match.group("title")),
                severity=match.group("severity").lower(),
                affected_versions=affected,
                fixed_versions=fixed_version,
                protocol="HTTP",
                description=body,
                advisory_url=advisory_url,
                advisory_title=section["title"],
            ))
    return _dedupe_candidates(candidates)


def parse_msrc_document(payload: dict[str, Any], advisory_url: str) -> list[dict[str, Any]]:
    product_map: dict[str, str] = {}
    _collect_msrc_products(payload.get("ProductTree"), product_map)
    candidates: list[dict[str, Any]] = []
    for vuln in _as_list(payload.get("Vulnerability")):
        if not isinstance(vuln, dict) or not _CVE_RE.fullmatch(str(vuln.get("CVE") or "")):
            continue
        affected_ids: list[str] = []
        for status in _as_list(vuln.get("ProductStatuses")):
            status_type = status.get("Type") if isinstance(status, dict) else None
            if not isinstance(status, dict) or not (
                status_type in {3, "3"} or "affected" in str(status_type or "").lower()
            ):
                continue
            affected_ids.extend(str(item) for item in _as_list(status.get("ProductID")))
        products = [product_map[item] for item in dict.fromkeys(affected_ids) if product_map.get(item)]
        scores = [_float(item.get("BaseScore")) for item in _as_list(vuln.get("CVSSScoreSets")) if isinstance(item, dict)]
        score = max(scores, default=0.0)
        severity = ""
        for threat in _as_list(vuln.get("Threats")):
            if isinstance(threat, dict) and str(threat.get("Type")) == "3":
                severity = _value(threat.get("Description")).lower()
                break
        title = _value(vuln.get("Title")) or str(vuln.get("CVE"))
        notes = " ".join(
            _value(note.get("Value"))
            for note in _as_list(vuln.get("Notes"))
            if isinstance(note, dict) and _value(note.get("Value"))
        )
        vectors = " ".join(
            str(item.get("Vector") or "")
            for item in _as_list(vuln.get("CVSSScoreSets"))
            if isinstance(item, dict)
        )
        lab_products = [
            product
            for product in products
            if any(marker in product.lower() for marker in _MSRC_SERVER_PRODUCT_MARKERS)
            and "online" not in product.lower()
        ]
        if "AV:N" not in vectors or not lab_products:
            continue
        primary_product = _select_msrc_product(title, lab_products)
        candidates.append(_candidate(
            vendor="Microsoft",
            cve_id=str(vuln["CVE"]),
            product=primary_product,
            affected_products=lab_products[:50],
            affected_versions="; ".join(lab_products[:10]),
            severity=severity or _severity_from_score(score),
            cvss_score=score,
            remote_without_auth="AV:N" in vectors and "PR:N" in vectors,
            description=notes,
            advisory_url=advisory_url,
            advisory_title=title,
        ))
    return _dedupe_candidates(candidates)


def _select_msrc_product(title: str, products: list[str]) -> str:
    title_key = title.lower()
    for title_marker, product_marker in (
        ("sharepoint", "sharepoint"),
        ("exchange server", "exchange server"),
        ("sql server", "sql server"),
        ("remote desktop", "remote desktop"),
        ("active directory", "active directory"),
        ("windows", "windows server"),
    ):
        if title_marker in title_key:
            match = next((product for product in products if product_marker in product.lower()), None)
            if match:
                return match
    return products[0]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _collect_msrc_products(node: Any, product_map: dict[str, str]) -> None:
    if isinstance(node, dict):
        product_id = node.get("ProductID")
        value = node.get("Value")
        if product_id is not None and value:
            product_map[str(product_id)] = str(value)
        for child in node.values():
            _collect_msrc_products(child, product_map)
    elif isinstance(node, list):
        for child in node:
            _collect_msrc_products(child, product_map)


def _value(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("Value") or value.get("value") or "")
    return str(value or "")


def _oracle_links(index_html: str, max_advisories: int) -> list[tuple[str, str]]:
    document = _parse_html_document(index_html)
    grouped: dict[str, list[tuple[str, str]]] = {"cpu": [], "cspu": [], "alert": []}
    for href, title in document.links:
        absolute = urljoin(ORACLE_INDEX_URL, href)
        path = httpx.URL(absolute).path
        match = _ORACLE_ADVISORY_RE.search(path)
        if not match or "pre-release" in title.lower():
            continue
        raw_kind = match.group("kind").lower()
        kind = "alert" if raw_kind.startswith("alert") else raw_kind
        item = (absolute, title)
        if item not in grouped[kind]:
            grouped[kind].append(item)
    return [item for kind in ("alert", "cspu", "cpu") for item in grouped[kind][:max_advisories]]


def _oracle_mapping_links(mapping_html: str, cve_ids: set[str]) -> list[tuple[str, str]]:
    document = _parse_html_document(mapping_html)
    links: list[tuple[str, str]] = []
    for table, link_table in zip(document.tables, document.table_links):
        for row, link_row in zip(table, link_table):
            row_cves = {match.upper() for value in row for match in _CVE_RE.findall(value)}
            if not row_cves.intersection(cve_ids):
                continue
            for cell_links in link_row:
                for href, title in cell_links:
                    absolute = urljoin(ORACLE_CVE_MAPPING_URL, href)
                    if _ORACLE_ADVISORY_RE.search(httpx.URL(absolute).path):
                        item = (absolute, title or absolute)
                        if item not in links:
                            links.append(item)
    return links


def read_cve_file(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8-sig")
    return {match.upper() for match in _CVE_RE.findall(text)}


def _filter_candidates(
    candidates: list[dict[str, Any]],
    cve_ids: set[str] | None,
) -> list[dict[str, Any]]:
    if not cve_ids:
        return candidates
    return [candidate for candidate in candidates if candidate.get("cve_id") in cve_ids]


def discover_official_lab_candidates(
    *,
    vendors: list[str] | None = None,
    max_advisories: int = 1,
    msrc_month: str | None = None,
    historical: bool = False,
    cve_ids: set[str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    target_cves = {cve.upper() for cve in (cve_ids or set())}
    if historical and not target_cves:
        raise ValueError("historical discovery requires at least one target CVE")
    selected = {item.strip().lower() for item in (vendors or ["oracle", "jenkins", "tomcat", "microsoft"]) if item.strip()}
    candidates: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    headers = {"User-Agent": "CVE-Hunter/official-advisory-discovery"}
    with _OfficialHttpClient(timeout=timeout, headers=headers) as client:
        if "oracle" in selected:
            _discover_oracle(
                client, max_advisories, candidates, sources, errors,
                target_cves or None, historical,
            )
        if "jenkins" in selected:
            _discover_jenkins(
                client, max_advisories, candidates, sources, errors,
                target_cves or None, historical,
            )
        if "tomcat" in selected or "apache" in selected:
            _discover_tomcat(
                client, max_advisories, candidates, sources, errors,
                target_cves or None, historical,
            )
        if "microsoft" in selected or "msrc" in selected:
            if historical:
                months = _msrc_months_from_index(client, target_cves, sources, errors)
            else:
                months = [msrc_month or datetime.now(timezone.utc).strftime("%Y-%b")]
            for month in months:
                _discover_msrc(
                    client, month, candidates, sources, errors,
                    target_cves or None,
                )
        unique = _dedupe_candidates(candidates)
        _verify_media_urls(client, unique, errors)

    local_index = index_local_environments()
    for candidate in unique:
        matches = local_index.get(candidate["cve_id"], [])
        candidate["local_environment_matches"] = matches
        product_match = _local_environment_matches_product(candidate["product"], matches)
        candidate["local_environment_product_match"] = product_match
        if product_match:
            candidate["lab_readiness"] = "available_local"
            candidate["lab_type"] = "existing_real_product_environment"
            candidate["environment_status"] = "available_local"
    unique.sort(key=_candidate_sort_key)
    matched_cves = sorted({item["cve_id"] for item in unique})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vendors": sorted(selected),
        "historical": historical,
        "requested_cves": sorted(target_cves),
        "requested_cve_count": len(target_cves),
        "matched_cves": matched_cves,
        "matched_cve_count": len(matched_cves),
        "source_count": len(sources),
        "candidate_count": len(unique),
        "sources": sources,
        "errors": errors,
        "candidates": unique,
    }


def _discover_oracle(
    client, limit, candidates, sources, errors, cve_ids=None, historical=False,
) -> None:
    try:
        index_url = ORACLE_CVE_MAPPING_URL if historical else ORACLE_INDEX_URL
        index_response = client.get(index_url)
        index_response.raise_for_status()
        links = (
            _oracle_mapping_links(index_response.text, cve_ids or set())
            if historical else _oracle_links(index_response.text, limit)
        )
    except Exception as exc:
        errors.append({"vendor": "Oracle", "url": index_url, "error": str(exc)})
        return
    checked = 0
    for url, title in links:
        try:
            response = client.get(url)
            response.raise_for_status()
            parsed = parse_oracle_advisory(response.text, url, title)
            candidates.extend(_filter_candidates(parsed, cve_ids))
            checked += 1
        except Exception as exc:
            errors.append({"vendor": "Oracle", "url": url, "error": str(exc)})
    sources.append({"vendor": "Oracle", "url": index_url, "advisories_checked": checked})


def _discover_jenkins(
    client, limit, candidates, sources, errors, cve_ids=None, historical=False,
) -> None:
    try:
        response = client.get(JENKINS_RSS_URL)
        response.raise_for_status()
        root = ET.fromstring(response.text)
    except Exception as exc:
        errors.append({"vendor": "Jenkins", "url": JENKINS_RSS_URL, "error": str(exc)})
        return
    checked = 0
    for item in root.findall("./channel/item"):
        description = _clean_text(item.findtext("description") or "")
        if "Affects Jenkins Core" not in description:
            continue
        url = (item.findtext("link") or "").strip()
        title = _clean_text(item.findtext("title") or "Jenkins Security Advisory")
        listed_cves = {match.upper() for match in _CVE_RE.findall(f"{title} {description}")}
        if historical and cve_ids and listed_cves and not listed_cves.intersection(cve_ids):
            continue
        try:
            advisory = client.get(url)
            advisory.raise_for_status()
            parsed = parse_jenkins_advisory(advisory.text, url, title)
            candidates.extend(_filter_candidates(parsed, cve_ids))
            checked += 1
        except Exception as exc:
            errors.append({"vendor": "Jenkins", "url": url, "error": str(exc)})
        if not historical and checked >= limit:
            break
    sources.append({"vendor": "Jenkins", "url": JENKINS_RSS_URL, "advisories_checked": checked})


def _discover_tomcat(
    client, limit, candidates, sources, errors, cve_ids=None, historical=False,
) -> None:
    checked = 0
    for url in TOMCAT_SECURITY_URLS:
        try:
            response = client.get(url)
            response.raise_for_status()
            parsed = parse_tomcat_security(
                response.text,
                url,
                max_releases=None if historical else limit,
            )
            candidates.extend(_filter_candidates(parsed, cve_ids))
            checked += 1
        except Exception as exc:
            errors.append({"vendor": "Apache", "url": url, "error": str(exc)})
    sources.append({"vendor": "Apache Tomcat", "url": TOMCAT_SECURITY_URLS[0], "advisories_checked": checked})


def _discover_msrc(client, month, candidates, sources, errors, cve_ids=None) -> None:
    url = MSRC_CVRF_URL.format(month=month)
    try:
        _response, payload = client.get_json(url)
        parsed = parse_msrc_document(payload, url)
        candidates.extend(_filter_candidates(parsed, cve_ids))
        sources.append({"vendor": "Microsoft", "url": url, "advisories_checked": 1})
    except Exception as exc:
        errors.append({"vendor": "Microsoft", "url": url, "error": str(exc)})


def _msrc_months_from_index(client, cve_ids, sources, errors) -> list[str]:
    months: set[str] = set()
    matched_cves: set[str] = set()
    page_size = 1000
    skip = 0
    pages_checked = 0
    next_url = ""
    try:
        while True:
            if not next_url:
                next_url = (
                    f"{MSRC_INDEX_URL}?$filter=issuingCna%20eq%20%27Microsoft%27"
                    f"&$top={page_size}&$skip={skip}"
                )
            _response, payload = client.get_json(next_url)
            pages_checked += 1
            values = payload.get("value")
            rows = values if isinstance(values, list) else []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve_id = str(row.get("cveNumber") or "").upper()
                if cve_id not in cve_ids:
                    continue
                release_date = str(row.get("releaseDate") or "")
                try:
                    month = datetime.fromisoformat(release_date.replace("Z", "+00:00")).strftime("%Y-%b")
                except ValueError:
                    continue
                matched_cves.add(cve_id)
                months.add(month)
            if matched_cves == cve_ids:
                break
            next_link = str(payload.get("@odata.nextLink") or payload.get("odata.nextLink") or "")
            if next_link:
                next_url = urljoin(MSRC_INDEX_URL, next_link)
                continue
            if len(rows) < page_size:
                break
            skip += page_size
            next_url = ""
        sources.append({
            "vendor": "Microsoft index",
            "url": MSRC_INDEX_URL,
            "advisories_checked": pages_checked,
            "matched_cves": sorted(matched_cves),
        })
    except Exception as exc:
        errors.append({"vendor": "Microsoft index", "url": next_url or MSRC_INDEX_URL, "error": str(exc)})
    return sorted(months)


def _is_exact_installer_url(url: str) -> bool:
    path = httpx.URL(url).path.lower()
    return bool(re.search(
        r"\.(?:zip|tgz|tar\.gz|tar\.bz2|war|jar|msi|exe|iso|deb|rpm|dmg|pkg)$",
        path,
    ))


def _verify_media_urls(client, candidates, errors) -> None:
    cache: dict[str, tuple[str, int | None]] = {}
    checked_at = datetime.now(timezone.utc).isoformat()
    for candidate in candidates:
        url = str(candidate.get("media_url") or "")
        if not url:
            continue
        if not _is_exact_installer_url(url):
            candidate["media_status"] = "not_exact_package_url"
            continue
        if url not in cache:
            try:
                response = client.head(url)
                status_code = response.status_code
                if 200 <= status_code < 300:
                    status = "verified_download"
                elif status_code in {404, 410}:
                    status = "unavailable"
                elif status_code == 405:
                    status = "head_not_supported"
                else:
                    status = "inaccessible"
                cache[url] = (status, status_code)
            except Exception as exc:
                cache[url] = ("probe_error", None)
                errors.append({
                    "vendor": str(candidate.get("vendor") or "Media"),
                    "url": url,
                    "error": f"HEAD probe failed: {exc}",
                })
        media_status, status_code = cache[url]
        candidate["media_status"] = media_status
        candidate["media_http_status"] = status_code
        candidate["media_checked_at"] = checked_at


def index_local_environments(roots: list[Path] | None = None) -> dict[str, list[str]]:
    if roots is None:
        roots = [
            Path(value).expanduser()
            for value in (
                getattr(cfg, "vulhub_dir", ""),
                getattr(cfg, "reapoc_dir", ""),
                getattr(cfg, "vulnerability_poc_dir", ""),
                getattr(cfg, "metarget_dir", ""),
            )
            if str(value or "").strip()
        ]
    result: dict[str, list[str]] = {}
    for root in roots:
        if not root.is_dir():
            continue
        try:
            paths = root.rglob("*")
            for path in paths:
                if not path.is_file():
                    continue
                is_compose = path.name.lower() in _COMPOSE_NAMES
                is_metarget_manifest = "metarget" in root.name.lower() and path.suffix.lower() in {".yml", ".yaml"}
                if not (is_compose or is_metarget_manifest):
                    continue
                cves = {match.upper() for match in _CVE_RE.findall(str(path))}
                for cve_id in cves:
                    result.setdefault(cve_id, []).append(str(path.resolve()))
        except OSError:
            continue
    return {cve: sorted(set(paths)) for cve, paths in result.items()}


def _local_environment_matches_product(product: str, paths: list[str]) -> bool:
    product_key = product.lower()
    aliases = [
        alias
        for marker, alias in (
            ("jenkins", "jenkins"),
            ("tomcat", "tomcat"),
            ("mysql", "mysql"),
            ("weblogic", "weblogic"),
            ("peopletools", "peoplesoft"),
            ("sharepoint", "sharepoint"),
            ("exchange server", "exchange"),
            ("sql server", "sqlserver"),
        )
        if marker in product_key
    ]
    return bool(aliases) and any(alias in path.lower() for alias in aliases for path in paths)


def _dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for candidate in candidates:
        key = (
            str(candidate.get("vendor") or ""),
            str(candidate.get("cve_id") or ""),
            str(candidate.get("product") or ""),
            str(candidate.get("affected_versions") or ""),
        )
        unique.setdefault(key, candidate)
    return list(unique.values())


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, int, float, str]:
    readiness_order = {
        "available_local": 0,
        "docker_recipe_candidate": 1,
        "manual_media_required": 2,
        "isolated_vm_required": 3,
    }
    return (
        readiness_order.get(str(candidate.get("lab_readiness")), 9),
        0 if candidate.get("remote_without_auth") else 1,
        -_float(candidate.get("cvss_score")),
        str(candidate.get("cve_id") or ""),
    )


def render_official_lab_report(report: dict[str, Any]) -> str:
    candidates = report.get("candidates") or []
    requested = set(report.get("requested_cves") or [])
    matched = set(report.get("matched_cves") or [])
    media_counts = _count_by(candidates, "media_status")
    deployment_counts = _count_by(candidates, "deployment_type")
    environment_counts = _count_by(candidates, "environment_status")
    lines = [
        "# Official Advisory Real-Lab Candidates",
        "",
        f"Generated: {report.get('generated_at', '')}",
        f"Candidates: {len(candidates)}",
        f"Requested CVEs: {len(requested)}",
        f"Matched CVEs: {len(matched)}",
        f"Historical mode: {bool(report.get('historical'))}",
        f"Deployment: {_format_counts(deployment_counts)}",
        f"Environment: {_format_counts(environment_counts)}",
        f"Media: {_format_counts(media_counts)}",
        "",
        "Only official vendor advisories are used as vulnerability evidence. A candidate is not marked local-ready unless an existing environment file is present. Media is verified only when HEAD succeeds for an exact installer/package URL.",
        "",
        "| Environment | Deployment | Media | Vendor | CVE | Product | Severity | Affected | Fixed | Official advisory |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item in candidates:
        lines.append(
            "| {environment} | {deployment} | {media} | {vendor} | {cve} | {product} | {severity} | {affected} | {fixed} | [source]({url}) |".format(
                environment=_md(item.get("environment_status")),
                deployment=_md(item.get("deployment_type")),
                media=_md(item.get("media_status")),
                vendor=_md(item.get("vendor")),
                cve=_md(item.get("cve_id")),
                product=_md(item.get("product")),
                severity=_md(item.get("severity")),
                affected=_md(item.get("affected_versions")),
                fixed=_md(item.get("fixed_versions")),
                url=item.get("advisory_url") or "",
            )
        )
    missing = sorted(requested - matched)
    if missing:
        lines.extend(["", "## Unmatched Requested CVEs", "", *[f"- {cve}" for cve in missing]])
    if report.get("errors"):
        lines.extend(["", "## Source Errors", ""])
        for error in report["errors"]:
            lines.append(f"- {error.get('vendor')}: {error.get('url')} - {error.get('error')}")
    return "\n".join(lines) + "\n"


def _count_by(candidates: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        key = str(candidate.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items())) or "none"


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def write_official_lab_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "official_lab_candidates.json"
    markdown_path = output_dir / "official_lab_candidates.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(render_official_lab_report(report), encoding="utf-8")
    return json_path, markdown_path
