"""CVE HTTP/Web 类型快速分类。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from cve_hunter.llm import invoke_llm
from cve_hunter.prompts.templates import VULN_TYPE_CHECK
from cve_hunter.tools.nvd import query_nvd


@dataclass
class VulnTypeResult:
    cve_id: str
    is_http_vuln: bool
    vuln_type: str
    nvd_description: str = ""
    nvd_references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_severity: str = ""
    error: str = ""


def classify_http_vuln(cve_id: str) -> VulnTypeResult:
    """只执行 NVD 查询与 AI HTTP/Web 类型判断，不跑 PoC 和发包。"""
    normalized_cve = cve_id.strip().upper()

    try:
        info = query_nvd(normalized_cve)
    except Exception as exc:
        return VulnTypeResult(
            cve_id=normalized_cve,
            is_http_vuln=True,
            vuln_type="未知",
            error=f"NVD 查询失败: {exc}",
        )

    if "error" in info:
        return VulnTypeResult(
            cve_id=normalized_cve,
            is_http_vuln=True,
            vuln_type="未知",
            error=info["error"],
        )

    return classify_http_vuln_from_info(
        cve_id=normalized_cve,
        description=info.get("description", ""),
        references=info.get("references", []),
        affected_products=info.get("affected_products", []),
        cvss_score=info.get("cvss_score", 0.0),
        cvss_severity=info.get("cvss_severity", ""),
    )


def classify_http_vuln_from_info(
    *,
    cve_id: str,
    description: str,
    references: list[str] | None = None,
    affected_products: list[str] | None = None,
    cvss_score: float = 0.0,
    cvss_severity: str = "",
) -> VulnTypeResult:
    """基于已有 NVD 信息执行 AI HTTP/Web 类型判断。"""
    normalized_cve = cve_id.strip().upper()
    references = references or []
    affected_products = affected_products or []

    if not description:
        return VulnTypeResult(
            cve_id=normalized_cve,
            is_http_vuln=True,
            vuln_type="未知",
            nvd_description=description,
            nvd_references=references,
            affected_products=affected_products,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            error="无 NVD 描述，按现有工作流默认归为 HTTP/Web",
        )

    prompt = VULN_TYPE_CHECK.format(
        cve_id=normalized_cve,
        description=description,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        affected_products=", ".join(affected_products[:5]),
    )

    try:
        result = invoke_llm(prompt)
        cleaned = re.sub(r"```json\s*|\s*```", "", result).strip()
        data = json.loads(cleaned)
        is_http = bool(data.get("is_http_vuln", True))
        vuln_type = str(data.get("vuln_type", "未知"))
        error = ""
    except Exception as exc:
        is_http = True
        vuln_type = "未知"
        error = f"AI 判断解析失败，按现有工作流默认归为 HTTP/Web: {exc}"

    return VulnTypeResult(
        cve_id=normalized_cve,
        is_http_vuln=is_http,
        vuln_type=vuln_type,
        nvd_description=description,
        nvd_references=references,
        affected_products=affected_products,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        error=error,
    )
