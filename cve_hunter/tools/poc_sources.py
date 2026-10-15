"""PoC 多源检索模块。

除了 Nuclei、GitHub、Exploit-DB 和 IMFHT，联网搜索阶段还会定向覆盖
Packet Storm、WPScan/WordPress Trac、SourceCodester、VulDB/Vulners 以及
厂商公告；这些站点的正文仍必须经过请求证据提取，不能把摘要直接当 PoC。
"""

from __future__ import annotations

import re

import httpx
import yaml

from cve_hunter.config import cfg


def _source_timeout() -> int:
    """Return the bounded timeout for non-target PoC providers.

    ``SimpleNamespace`` config substitutes used by tests may only expose the
    legacy ``request_timeout`` field, so both names are intentionally optional.
    """
    for value in (
        getattr(cfg, "web_source_timeout", None),
        getattr(cfg, "request_timeout", 30),
    ):
        try:
            return max(3, int(value))
        except (TypeError, ValueError):
            continue
    return 30


def _proxy():
    return getattr(cfg, "httpx_proxy", None)


ADDITIONAL_REFERENCE_SOURCES = (
    "packetstormsecurity.com",
    "wpscan.com",
    "wordpress.org/trac",
    "sourcecodester.com",
    "vuldb.com",
    "vulners.com",
)


# ── Nuclei 官方 PoC 库 ──
# 国内 raw.githubusercontent.com 常被墙，优先走 jsdelivr CDN 镜像（可达、快、无频率限制），
# 失败再回退到 raw 和 GitHub API。

_NUCLEI_CDN = "https://cdn.jsdelivr.net/gh/projectdiscovery/nuclei-templates@main/http/cves"
_NUCLEI_RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves"
_NUCLEI_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"


def _fetch_nuclei_content(path: str) -> str:
    """依次尝试 CDN / raw / GitHub API 获取 nuclei 模板原文，返回文本或空串。"""
    endpoints = [
        f"{_NUCLEI_CDN}/{path}",
        f"{_NUCLEI_RAW}/{path}",
    ]
    for url in endpoints:
        try:
            resp = httpx.get(url, timeout=_source_timeout(), follow_redirects=True, proxy=_proxy())
            if resp.status_code == 200 and resp.text.strip():
                return resp.text
            if resp.status_code == 404:
                return ""
        except Exception:
            continue

    # GitHub API 兜底：返回 base64 内容
    try:
        resp = httpx.get(
            f"{_NUCLEI_API}/{path}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=_source_timeout(),
            follow_redirects=True,
            proxy=_proxy(),
        )
        if resp.status_code == 200:
            import base64
            data = resp.json()
            content = data.get("content", "")
            if content:
                return base64.b64decode(content).decode("utf-8", "ignore")
    except Exception:
        pass
    return ""


def search_nuclei(cve_id: str) -> dict:
    """在 nuclei-templates 仓库搜索 CVE 对应的 YAML 模板。

    按照 nuclei 仓库目录结构：http/cves/<year>/<CVE-XXXX-XXXX>.yaml
    """
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id, re.IGNORECASE)
    if not m:
        return {"found": False, "error": "CVE 编号格式错误"}

    year = m.group(1)
    cve_upper = cve_id.upper()
    path = f"{year}/{cve_upper}.yaml"

    content = _fetch_nuclei_content(path)
    if not content:
        return {"found": False, "source": "nuclei"}

    try:
        parsed = yaml.safe_load(content)
        info = parsed.get("info", {}) if isinstance(parsed, dict) else {}
    except Exception:
        info = {}

    return {
        "found": True,
        "source": "nuclei",
        "yaml_content": content,
        "url": f"{_NUCLEI_CDN}/{path}",
        "name": info.get("name", ""),
        "severity": info.get("severity", ""),
    }


# ── PoC-in-GitHub 聚合库 ──

_POC_IN_GITHUB = "https://cdn.jsdelivr.net/gh/nomi-sec/PoC-in-GitHub@master"


def search_poc_in_github(cve_id: str) -> dict:
    """在 PoC-in-GitHub 聚合库中搜索 CVE 对应的 PoC 仓库链接。

    返回命中仓库的 full_name / html_url / 描述，供后续抓取 PoC 内容。
    """
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id, re.IGNORECASE)
    if not m:
        return {"found": False, "error": "CVE 编号格式错误"}

    year = m.group(1)
    cve_upper = cve_id.upper()
    url = f"{_POC_IN_GITHUB}/{year}/{cve_upper}.json"

    try:
        resp = httpx.get(url, timeout=_source_timeout(), follow_redirects=True, proxy=_proxy())
        if resp.status_code != 200:
            return {"found": False, "source": "poc-in-github"}
        data = resp.json()
        if not isinstance(data, list):
            return {"found": False, "source": "poc-in-github"}
        repos = []
        for item in data[:10]:
            if not isinstance(item, dict):
                continue
            full_name = item.get("full_name") or ""
            html_url = item.get("html_url") or ""
            if not full_name:
                continue
            repos.append({
                "full_name": full_name,
                "html_url": html_url,
                "name": item.get("name", ""),
                "description": (item.get("description") or "")[:200],
            })
        if repos:
            return {"found": True, "source": "poc-in-github", "repos": repos}
        return {"found": False, "source": "poc-in-github"}
    except Exception as e:
        return {"found": False, "source": "poc-in-github", "error": str(e)}


_POC_REPO_FILES = [
    "README.md", "README.txt", "README.rst",
    "poc.py", "exploit.py", "exp.py", "poc.rb", "exploit.rb",
    "poc.sh", "exploit.sh", "poc.txt", "exploit.txt",
    "poc.http", "exploit.http", "request.http",
    "template.yaml", "template.yml", "nuclei.yaml", "nuclei.yml",
]


def fetch_github_repo_poc(repo_full_name: str) -> str:
    """从单个 GitHub 仓库抓取可能含 PoC 的文件文本（走 jsdelivr CDN）。"""
    for branch in ("main", "master"):
        for filename in _POC_REPO_FILES:
            url = f"https://cdn.jsdelivr.net/gh/{repo_full_name}@{branch}/{filename}"
            try:
                resp = httpx.get(url, timeout=_source_timeout(), follow_redirects=True, proxy=_proxy())
                if resp.status_code == 200 and len(resp.text) > 50:
                    return resp.text
            except Exception:
                continue
        # Repositories in the aggregate index often keep the request under a
        # nested exploit/ or nuclei/ directory. Use the Git tree API only as a
        # bounded fallback and fetch text-like files, preserving the original
        # source content for evidence extraction.
        try:
            tree = httpx.get(
                f"https://api.github.com/repos/{repo_full_name}/git/trees/{branch}",
                params={"recursive": "1"},
                headers={"Accept": "application/vnd.github+json"},
                timeout=_source_timeout(),
                follow_redirects=True,
                proxy=_proxy(),
            )
            if tree.status_code != 200:
                continue
            paths = []
            for item in (tree.json().get("tree") or []):
                path = str(item.get("path") or "")
                if item.get("type") != "blob" or len(path) > 180:
                    continue
                lower = path.lower()
                if lower.endswith((".py", ".rb", ".go", ".js", ".sh", ".http", ".txt", ".md", ".yaml", ".yml")) and any(
                    token in lower for token in ("poc", "exploit", "exp", "request", "template", "cve")
                ):
                    paths.append(path)
            for path in paths[:12]:
                url = f"https://cdn.jsdelivr.net/gh/{repo_full_name}@{branch}/{path}"
                try:
                    resp = httpx.get(url, timeout=_source_timeout(), follow_redirects=True, proxy=_proxy())
                    if resp.status_code == 200 and len(resp.text) > 50:
                        return resp.text
                except Exception:
                    continue
        except Exception:
            continue
    return ""


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
            timeout=_source_timeout(),
            follow_redirects=True,
            proxy=_proxy(),
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


def fetch_exploitdb_content(exploit_id: str) -> dict[str, str]:
    """Fetch Exploit-DB's raw exploit endpoint before HTML extraction.

    The HTML page is frequently blocked or rendered without the code. The raw
    endpoint contains the curl/Python request construction that the evidence
    parser can turn into an exact request.
    """
    value = str(exploit_id or "").strip()
    if not value.isdigit():
        return {"content": "", "error": "invalid exploit id"}
    url = f"https://www.exploit-db.com/raw/{value}"
    try:
        resp = httpx.get(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "text/plain,*/*"},
            timeout=_source_timeout(),
            follow_redirects=True,
            proxy=_proxy(),
        )
        if resp.status_code == 200 and resp.text.strip():
            return {"content": resp.text, "url": url}
        return {"content": "", "url": url, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"content": "", "url": url, "error": str(exc)}


# ── imfht 漏洞库 ──

_IMFHT_API = "https://cve.imfht.com"


def search_imfht(cve_id: str) -> dict:
    """在 imfht 漏洞库搜索 CVE 信息。"""
    try:
        url = f"{_IMFHT_API}/{cve_id}"
        resp = httpx.get(
            url,
            timeout=_source_timeout(),
            follow_redirects=True,
            proxy=_proxy(),
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
