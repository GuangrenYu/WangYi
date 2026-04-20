"""NVD API 查询模块。"""

from __future__ import annotations

import httpx

from cve_hunter.config import cfg

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(cve_id: str) -> dict:
    """查询 NVD 获取 CVE 详细信息。

    返回包含 description, references, affected_products, cvss 等字段的字典。
    """
    headers = {}
    if cfg.nvd_api_key:
        headers["apiKey"] = cfg.nvd_api_key

    resp = httpx.get(
        NVD_API,
        params={"cveId": cve_id},
        headers=headers,
        timeout=cfg.request_timeout,
    )
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"NVD 中未找到 {cve_id}"}

    cve_item = vulns[0].get("cve", {})

    # 提取描述
    descriptions = cve_item.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # 提取 References
    refs = [r.get("url", "") for r in cve_item.get("references", [])]

    # 提取受影响产品
    products = []
    for node in cve_item.get("configurations", []):
        for n in node.get("nodes", []):
            for match in n.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    products.append(cpe)

    # 提取 CVSS
    metrics = cve_item.get("metrics", {})
    cvss_score = 0.0
    cvss_severity = ""
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_severity = cvss_data.get("baseSeverity", "")
            break

    return {
        "cve_id": cve_id,
        "description": desc_en,
        "references": refs,
        "affected_products": products,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
    }
