"""PoC 多源检索模块：nuclei / exploit-db / imfht。"""

from __future__ import annotations

import re

import httpx
import yaml

from cve_hunter.config import cfg


# ── Nuclei 官方 PoC 库 (GitHub raw) ──

_NUCLEI_RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves"


def search_nuclei(cve_id: str) -> dict:
    """在 nuclei-templates 仓库搜索 CVE 对应的 YAML 模板。

    按照 nuclei 仓库目录结构：http/cves/<year>/<CVE-XXXX-XXXX>.yaml
    """
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id, re.IGNORECASE)
    if not m:
        return {"found": False, "error": "CVE 编号格式错误"}

    year = m.group(1)
    cve_lower = cve_id.upper()
    url = f"{_NUCLEI_RAW}/{year}/{cve_lower}.yaml"

    try:
        resp = httpx.get(url, timeout=cfg.request_timeout, follow_redirects=True, proxy=cfg.httpx_proxy)
        if resp.status_code == 200:
            content = resp.text
            try:
                parsed = yaml.safe_load(content)
                info = parsed.get("info", {})
            except Exception:
                info = {}
            return {
                "found": True,
                "source": "nuclei",
                "yaml_content": content,
                "url": url,
                "name": info.get("name", ""),
                "severity": info.get("severity", ""),
            }
        if resp.status_code not in (404,):
            return {"found": False, "source": "nuclei", "error": f"nuclei 请求失败: HTTP {resp.status_code}"}
        return {"found": False, "source": "nuclei"}
    except Exception as e:
        return {"found": False, "source": "nuclei", "error": str(e)}


# ── Exploit-DB ──

_EXPLOITDB_SEARCH = "https://exploit-db.com/search"


def search_exploitdb(cve_id: str) -> dict:
    """在 Exploit-DB 搜索 CVE 对应的 exploit。

    使用 exploit-db.com 的搜索 API。
    """
    try:
        resp = httpx.get(
            "https://www.exploit-db.com/search",
            params={"cve": cve_id.replace("CVE-", "")},
            headers={
                "User-Agent": "Mozilla/5.0",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
            timeout=cfg.request_timeout,
            follow_redirects=True,
            proxy=cfg.httpx_proxy,
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                records = data.get("data", [])
                if records:
                    results = []
                    for r in records[:3]:
                        exploit_id = r.get("id", "")
                        results.append({
                            "id": exploit_id,
                            "title": r.get("description", [{}])[0] if isinstance(r.get("description"), list) else str(r.get("description", "")),
                            "url": f"https://www.exploit-db.com/exploits/{exploit_id}",
                        })
                    return {"found": True, "source": "exploit-db", "results": results}
            except Exception:
                return {"found": False, "source": "exploit-db"}
            return {"found": False, "source": "exploit-db"}
        if resp.status_code not in (404,):
            return {"found": False, "source": "exploit-db", "error": f"Exploit-DB 请求失败: HTTP {resp.status_code}"}
        return {"found": False, "source": "exploit-db"}
    except Exception as e:
        return {"found": False, "source": "exploit-db", "error": str(e)}


# ── imfht 漏洞库 ──

_IMFHT_API = "https://cve.imfht.com"


def search_imfht(cve_id: str) -> dict:
    """在 imfht 漏洞库搜索 CVE 信息。"""
    try:
        url = f"{_IMFHT_API}/{cve_id}"
        resp = httpx.get(
            url,
            timeout=cfg.request_timeout,
            follow_redirects=True,
            proxy=cfg.httpx_proxy,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            content = resp.text
            if cve_id.upper() in content.upper() and len(content) > 200:
                extracted = _extract_imfht_content(content)
                return {
                    "found": True,
                    "source": "imfht",
                    "url": url,
                    "content": extracted,
                }
        if resp.status_code not in (404,):
            return {"found": False, "source": "imfht", "error": f"imfht 请求失败: HTTP {resp.status_code}"}
        return {"found": False, "source": "imfht"}
    except Exception as e:
        return {"found": False, "source": "imfht", "error": str(e)}


def _extract_imfht_content(html: str) -> str:
    """从 imfht 页面提取关键信息。"""
    import trafilatura
    text = trafilatura.extract(html, include_tables=True, favor_recall=True)
    return text or ""
