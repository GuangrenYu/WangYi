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

    只有日志 CVE 字段明确包含 ``current_cve`` 时，才算当前 CVE 命中。
    CVE 字段为空、---、缺失或指向其他 CVE 时，都归入 generic_matches。
    """
    current = current_cve.strip().upper()
    all_matches: list[dict[str, Any]] = []
    cve_matches: list[dict[str, Any]] = []
    generic_matches: list[dict[str, Any]] = []
    other_cve_matches: list[dict[str, Any]] = []
    missing_cve_matches: list[dict[str, Any]] = []

    for match in matches or []:
        annotated = _annotate_match(match, current)
        all_matches.append(annotated)

        parsed_cves = set(annotated.get("_parsed_cves", []))
        if current and current in parsed_cves:
            annotated["_ips_match_type"] = "current_cve"
            cve_matches.append(annotated)
        else:
            annotated["_ips_match_type"] = "generic"
            generic_matches.append(annotated)
            if parsed_cves:
                other_cve_matches.append(annotated)
            else:
                missing_cve_matches.append(annotated)

    return {
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
    }


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
        for key in ("CVE", "cve", "Cve"):
            if key in fields:
                values.append(fields.get(key))

    for key in ("CVE", "cve", "Cve"):
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
