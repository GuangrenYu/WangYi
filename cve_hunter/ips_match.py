"""IPS 命中结果的 CVE 归因判定。"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CVE_NUMBER_PATTERN = re.compile(r"(?<!\d)(\d{4}-\d{4,})(?!\d)")
EMPTY_CVE_VALUES = {"", "-", "--", "---", "N/A", "NA", "NONE", "NULL", "无", "未知"}


def classify_ips_matches(matches: list[dict[str, Any]] | None, current_cve: str) -> dict[str, Any]:
    """按防火墙日志 CVE 字段把 IPS 命中归因为当前 CVE 或通用命中。

    成功口径（多设备 OR）：**任一**设备（H3C / 迪普等）的日志 CVE 字段明确
    包含 ``current_cve`` 即 ``ips_matched=True``。一台通用命中、另一台精确命中
    时，精确命中优先，不能因某一台未命中/仅通用而判失败。两台设备的告警都保留
    在 ``all_matches`` 里。

    CVE 字段为空、---、缺失或只指向其他 CVE 时，归入 generic_matches。
    """
    current = current_cve.strip().upper()
    all_matches: list[dict[str, Any]] = []
    cve_matches: list[dict[str, Any]] = []
    generic_matches: list[dict[str, Any]] = []
    other_cve_matches: list[dict[str, Any]] = []
    missing_cve_matches: list[dict[str, Any]] = []
    sources_current: set[str] = set()
    sources_generic: set[str] = set()
    sources_all: set[str] = set()

    for match in matches or []:
        annotated = _annotate_match(match, current)
        all_matches.append(annotated)
        source = _match_source(annotated)
        if source:
            sources_all.add(source)

        parsed_cves = set(annotated.get("_parsed_cves", []))
        if current and current in parsed_cves:
            annotated["_ips_match_type"] = "current_cve"
            cve_matches.append(annotated)
            if source:
                sources_current.add(source)
        else:
            annotated["_ips_match_type"] = "generic"
            generic_matches.append(annotated)
            if source:
                sources_generic.add(source)
            if parsed_cves:
                other_cve_matches.append(annotated)
            else:
                missing_cve_matches.append(annotated)

    return {
        # OR across devices: one exact CVE hit is enough.
        "ips_matched": len(cve_matches) > 0,
        "generic_ips_matched": len(generic_matches) > 0,
        "all_matches": all_matches,
        "cve_matches": cve_matches,
        "generic_matches": generic_matches,
        "other_cve_matches": other_cve_matches,
        "missing_cve_matches": missing_cve_matches,
        "total_count": len(all_matches),
        "cve_match_count": len(cve_matches),
        "generic_match_count": len(generic_matches),
        "other_cve_match_count": len(other_cve_matches),
        "missing_cve_match_count": len(missing_cve_matches),
        "sources": sorted(sources_all),
        "cve_match_sources": sorted(sources_current),
        "generic_match_sources": sorted(sources_generic),
        "hit_h3c": "h3c" in sources_current,
        "hit_dptech": "dptech" in sources_current,
    }


def extract_cves_from_ips_match(match: dict[str, Any]) -> list[str]:
    """从一条 IPS 命中记录的 CVE 字段中提取标准 CVE 编号。"""
    cves: set[str] = set()
    for value in _cve_field_values(match):
        cves.update(_normalize_cve_value(value))
    return sorted(cves)


def summarize_ips_classification(classification: dict[str, Any]) -> dict[str, int | bool]:
    """生成适合写入 JSON 的简洁统计。"""
    return {
        "ips_matched": bool(classification.get("ips_matched")),
        "generic_ips_matched": bool(classification.get("generic_ips_matched")),
        "total_count": int(classification.get("total_count") or 0),
        "cve_match_count": int(classification.get("cve_match_count") or 0),
        "generic_match_count": int(classification.get("generic_match_count") or 0),
        "other_cve_match_count": int(classification.get("other_cve_match_count") or 0),
        "missing_cve_match_count": int(classification.get("missing_cve_match_count") or 0),
        "hit_h3c": bool(classification.get("hit_h3c")),
        "hit_dptech": bool(classification.get("hit_dptech")),
        "cve_match_sources": list(classification.get("cve_match_sources") or []),
        "generic_match_sources": list(classification.get("generic_match_sources") or []),
        "sources": list(classification.get("sources") or []),
    }


def _match_source(match: dict[str, Any]) -> str:
    raw = str(match.get("source") or match.get("hostname") or "").strip().lower()
    if "h3c" in raw:
        return "h3c"
    if "dptech" in raw or "dp" == raw or raw.startswith("dp"):
        return "dptech"
    return raw


def _annotate_match(match: dict[str, Any], current_cve: str) -> dict[str, Any]:
    annotated = deepcopy(match) if isinstance(match, dict) else {"raw": match}
    raw_values = [str(value).strip() for value in _cve_field_values(annotated)]
    annotated["_expected_cve"] = current_cve
    annotated["_cve_field_values"] = raw_values
    annotated["_parsed_cves"] = extract_cves_from_ips_match(annotated)
    return annotated


def _cve_field_values(match: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    if not isinstance(match, dict):
        return values

    fields = match.get("fields")
    if not isinstance(fields, dict):
        fields = match.get("Fields")
    if isinstance(fields, dict):
        for key in ("CVE", "cve", "Cve", "cve_list", "CVE_LIST"):
            if key in fields:
                values.append(fields.get(key))

    # 日志服务顶层 cve_list（|CVE-a|CVE-b|）与 CVE 字段都要读，不能只认 fields.CVE。
    for key in ("CVE", "cve", "Cve", "cve_list", "CVE_LIST"):
        if key in match:
            values.append(match.get(key))

    return values


def _normalize_cve_value(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        cves: set[str] = set()
        for item in value:
            cves.update(_normalize_cve_value(item))
        return cves

    text = str(value).strip()
    if text.upper() in EMPTY_CVE_VALUES:
        return set()

    cves = {match.group(0).upper() for match in CVE_PATTERN.finditer(text)}
    if cves:
        return cves

    # 兼容防火墙只返回 2021-44228 这类不带 CVE- 前缀的字段。
    return {f"CVE-{match.group(1)}".upper() for match in CVE_NUMBER_PATTERN.finditer(text)}
