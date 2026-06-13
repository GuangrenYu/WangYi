"""NVD API 查询模块（本地优先 + API 回退）。"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from cve_hunter.config import cfg
from cve_hunter.tools.reference_utils import normalize_reference_urls

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_NVD_TIMEOUT = 60
_NVD_MAX_RETRIES = 2
_NVD_RATE_LIMIT_MAX_ATTEMPTS = 3
_NVD_RATE_LIMIT_INITIAL_DELAY = 30
_NVD_RATE_LIMIT_MAX_DELAY = 300


def _parse_retry_after(value: str | None) -> int | None:
    """解析 Retry-After，返回需要等待的秒数。"""
    if not value:
        return None

    value = value.strip()
    if not value:
        return None

    if value.isdigit():
        return max(1, int(value))

    try:
        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        delay = int((retry_at - datetime.now(timezone.utc)).total_seconds())
        return max(1, delay)
    except Exception:
        return None


def _is_nvd_rate_limited(resp: httpx.Response) -> bool:
    """判断 NVD 响应是否为频繁访问限流。"""
    if resp.status_code == 429:
        return True

    if resp.status_code not in (403, 503):
        return False

    if resp.headers.get("Retry-After"):
        return True

    try:
        body = resp.text.lower()
    except Exception:
        body = ""

    rate_limit_markers = (
        "rate limit",
        "too many requests",
        "quota",
        "exceeded",
        "request forbidden by administrative rules",
        "temporarily unavailable",
    )
    return any(marker in body for marker in rate_limit_markers)


def _nvd_rate_limit_sleep_seconds(resp: httpx.Response, attempt: int) -> int:
    retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
    if retry_after is not None:
        return retry_after

    return min(
        _NVD_RATE_LIMIT_INITIAL_DELAY * attempt,
        _NVD_RATE_LIMIT_MAX_DELAY,
    )


def _print_rate_limit_retry(cve_id: str, delay: int, attempt: int) -> None:
    output = sys.__stdout__ or sys.stdout
    print(
        f"NVD 访问触发限流，{delay}s 后重试 {cve_id} "
        f"(第 {attempt} 次等待)",
        file=output,
        flush=True,
    )


def query_nvd(cve_id: str) -> dict:
    """查询 NVD 获取 CVE 详细信息（优先本地数据，回退 API）。

    返回包含 description, references, affected_products, cvss 等字段的字典。
    """
    # ── 优先从本地 NVD 数据查询 ──
    try:
        from cve_hunter.tools.nvd_local import query_nvd_local

        local_result = query_nvd_local(cve_id)
        if local_result is not None:
            _print_local_hit(cve_id)
            return local_result
    except Exception:
        pass

    # ── 回退到远程 NVD API ──
    return _query_nvd_api(cve_id)


def _print_local_hit(cve_id: str) -> None:
    output = sys.__stdout__ or sys.stdout
    print(f"NVD 本地命中: {cve_id}", file=output, flush=True)


def _query_nvd_api(cve_id: str) -> dict:
    headers = {"User-Agent": "CVEHunter/1.0"}
    if cfg.nvd_api_key:
        headers["apiKey"] = cfg.nvd_api_key

    retry_attempt = 0
    rate_limit_attempt = 0
    while True:
        try:
            resp = httpx.get(
                NVD_API,
                params={"cveId": cve_id},
                headers=headers,
                timeout=_NVD_TIMEOUT,
                proxy=cfg.httpx_proxy,
            )
            if _is_nvd_rate_limited(resp):
                rate_limit_attempt += 1
                if rate_limit_attempt > _NVD_RATE_LIMIT_MAX_ATTEMPTS:
                    raise RuntimeError(
                        f"NVD API 访问限流或配额耗尽: status={resp.status_code}, "
                        f"retry_after={resp.headers.get('Retry-After', '')}"
                    )
                delay = _nvd_rate_limit_sleep_seconds(resp, rate_limit_attempt)
                _print_rate_limit_retry(cve_id, delay, rate_limit_attempt)
                time.sleep(delay)
                continue

            resp.raise_for_status()
            data = resp.json()
            break
        except Exception as e:
            if retry_attempt < _NVD_MAX_RETRIES:
                retry_attempt += 1
                time.sleep(2 * retry_attempt)
                continue
            raise

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"NVD 中未找到 {cve_id}"}

    cve_item = vulns[0].get("cve", {})

    # 提取描述
    descriptions = cve_item.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # 提取 References
    refs = normalize_reference_urls([r.get("url", "") for r in cve_item.get("references", [])])

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
