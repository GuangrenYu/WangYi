"""本地 PoC 知识库检索与存储模块。

优先级：
  1. custom/  —— 自行验证保存的 PoC（含完整 HTTP 请求）
  2. trickest-cve/ —— trickest/cve git submodule（PoC 目录与 GitHub 链接）

对 trickest-cve 命中时，会尝试从关联 GitHub 仓库获取实际 PoC 代码。
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import httpx

from cve_hunter.config import cfg
from cve_hunter.poc_parser import extract_http_requests


# ── 路径辅助 ──

def _cve_to_relpath(cve_id: str) -> tuple[str, str] | None:
    """将 CVE-ID 转换为 (year, filename)。"""
    m = re.match(r"(CVE-\d{4}-\d+)", cve_id, re.IGNORECASE)
    if not m:
        return None
    cve_upper = m.group(1).upper()
    year = cve_upper[4:8]
    return year, f"{cve_upper}.md"


def _kb_base() -> Path:
    return Path(cfg.poc_kb_dir)


# ── 搜索 ──

def search_local_kb(cve_id: str) -> dict:
    """在本地知识库中搜索 CVE PoC。

    Returns:
        dict with keys:
          found, source, kb_path, raw_http, yaml_content,
          github_repos, references, content, error
    """
    rel = _cve_to_relpath(cve_id)
    if not rel:
        return {"found": False, "source": "local_kb", "error": "CVE 编号格式错误"}

    year, filename = rel
    base = _kb_base()

    # 1) custom/ —— 自行验证保存的 PoC（最高优先级）
    custom_file = base / "custom" / year / filename
    if custom_file.exists():
        result = _parse_custom_kb(custom_file.read_text(encoding="utf-8"), cve_id)
        if result.get("raw_http"):
            result["found"] = True
            result["source"] = "local_kb_custom"
            result["kb_path"] = str(custom_file)
            return result

    # 2) trickest-cve/ —— 外部 PoC 目录
    trickest_file = base / "trickest-cve" / year / filename
    if trickest_file.exists():
        content = trickest_file.read_text(encoding="utf-8")
        parsed = _parse_trickest_md(content, cve_id)
        if parsed.get("github_repos"):
            # 尝试从关联 GitHub 仓库获取 PoC
            poc = _fetch_poc_from_github_repos(parsed["github_repos"], cve_id)
            if poc and (poc.get("raw_http") or poc.get("yaml_content")):
                return {
                    "found": True,
                    "source": "local_kb_trickest",
                    "kb_path": str(trickest_file),
                    "raw_http": poc.get("raw_http", ""),
                    "yaml_content": poc.get("yaml_content", ""),
                    "github_repos": parsed["github_repos"],
                    "references": parsed.get("references", []),
                }
        return {
            "found": True,
            "source": "local_kb_trickest",
            "kb_path": str(trickest_file),
            "raw_http": "",
            "github_repos": parsed.get("github_repos", []),
            "references": parsed.get("references", []),
            "content": parsed.get("description", ""),
        }

    return {"found": False, "source": "local_kb"}


# ── 解析 ──

def _parse_custom_kb(content: str, cve_id: str) -> dict:
    """解析 custom/ 目录下的 PoC 文件，提取 HTTP 请求。"""
    result: dict = {"raw_http": "", "yaml_content": ""}

    # 提取 ```http ... ``` 代码块
    m = re.search(r"```(?:http)?\s*\n((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+[\s\S]*?)```", content)
    if m:
        result["raw_http"] = m.group(1).strip()

    # 提取 ```yaml ... ``` 代码块
    m = re.search(r"```(?:yaml|yml)?\s*\n(id:\s*[\s\S]*?)```", content)
    if m:
        result["yaml_content"] = m.group(1).strip()

    return result


def _parse_trickest_md(content: str, cve_id: str) -> dict:
    """解析 trickest/cve 风格的 markdown。"""
    result = {
        "description": "",
        "references": [],
        "github_repos": [],
    }

    # 提取 Description 段落
    m = re.search(r"### Description\s*\n+(.*?)(?:\n###|\n---|\Z)", content, re.DOTALL)
    if m:
        result["description"] = m.group(1).strip()

    # 提取 markdown 链接 [label](url)
    url_pattern = r"\[([^\]]*)\]\((https?://[^\)]+)\)"
    for match in re.finditer(url_pattern, content):
        label = match.group(1)
        url = match.group(2)
        if "github.com" in url:
            result["github_repos"].append({"label": label, "url": url})
        else:
            result["references"].append({"label": label, "url": url})

    # 提取裸 GitHub URL（trickest-cve 常用格式：- https://github.com/...）
    bare_url_pattern = r"^-\s*(https?://github\.com/[\w\-\./]+)"
    for match in re.finditer(bare_url_pattern, content, re.MULTILINE):
        url = match.group(1).rstrip("/")
        if not any(r["url"] == url for r in result["github_repos"]):
            result["github_repos"].append({"label": url.split("/")[-1], "url": url})

    # 提取裸非 GitHub URL
    bare_ref_pattern = r"^-\s*(https?://(?!github\.com)[^\s\)]+)"
    for match in re.finditer(bare_ref_pattern, content, re.MULTILINE):
        url = match.group(1)
        if not any(r["url"] == url for r in result["references"]):
            result["references"].append({"label": url, "url": url})

    return result


# ── GitHub PoC 抓取 ──

def _fetch_poc_from_github_repos(repos: list[dict], cve_id: str) -> dict[str, str] | None:
    """从 trickest 关联的 GitHub 仓库中尝试获取原始 PoC 代码。

    优先采样 CVE 专属仓库和 PoC/Exploit 仓库的 raw/README 内容，提取
    Raw HTTP 请求；若只有 nuclei 模板则返回 YAML 候选。
    """
    if not repos:
        return None

    candidates = []
    for repo in _prioritize_github_repos(repos, cve_id)[:12]:
        url = repo["url"]
        raw_urls = _guess_raw_urls(url, cve_id)
        candidates.extend(raw_urls)

    if not candidates:
        return None

    yaml_candidate = ""
    with httpx.Client(timeout=cfg.request_timeout, proxy=cfg.httpx_proxy) as client:
        for raw_url in _dedupe_strings(candidates)[:120]:
            try:
                resp = client.get(raw_url, follow_redirects=True)
                if resp.status_code == 200 and len(resp.text) > 100:
                    pocs = _extract_http_requests(resp.text, cve_id)
                    if pocs:
                        return {"raw_http": pocs[0], "yaml_content": ""}
                    if not yaml_candidate:
                        yaml_candidate = _extract_nuclei_yaml(resp.text, cve_id)
            except Exception:
                continue
            time.sleep(0.3)  # 避免触发 GitHub rate limit

    if yaml_candidate:
        return {"raw_http": "", "yaml_content": yaml_candidate}
    return None


def _guess_raw_urls(github_url: str, cve_id: str = "") -> list[str]:
    """根据 GitHub 仓库 URL 猜测可能的 raw 文件路径。"""
    file_url = _raw_file_url(github_url)
    if file_url:
        return [file_url]

    url = _github_repo_root(github_url)
    if not url:
        return []

    repo_name = url.rstrip("/").split("/")[-1]
    cve_match = re.search(r"CVE-\d{4}-\d+", github_url, re.IGNORECASE)
    cve_slug = (cve_match.group(0) if cve_match else cve_id).upper()
    cve_lower = cve_slug.lower()

    candidates = []
    paths = _candidate_repo_paths(cve_slug, cve_lower, repo_name)
    raw_base = url.replace("https://github.com", "https://raw.githubusercontent.com")
    for branch in ("master", "main"):
        for path in paths:
            candidates.append(f"{raw_base}/{branch}/{path}")
    return candidates


def _candidate_repo_paths(cve_slug: str, cve_lower: str, repo_name: str) -> list[str]:
    paths = [
        "README.md", "README.txt", "README.rst",
        "poc.py", "exploit.py", "exp.py", "poc.rb", "exploit.rb",
        "poc.sh", "exploit.sh", "poc.txt", "exploit.txt",
        "poc.http", "exploit.http", "request.http",
        "poc.yaml", "poc.yml", "template.yaml", "template.yml", "nuclei.yaml", "nuclei.yml",
    ]
    if cve_slug:
        paths = [
            f"{cve_slug}.md", f"{cve_slug}.py", f"{cve_slug}.rb", f"{cve_slug}.txt",
            f"{cve_slug}.yaml", f"{cve_slug}.yml", f"{cve_slug}.http",
            f"{cve_lower}.md", f"{cve_lower}.py", f"{cve_lower}.txt",
            f"{cve_lower}.yaml", f"{cve_lower}.yml", f"{cve_lower}.http",
            *paths,
        ]
    if repo_name:
        paths.extend([f"{repo_name}.md", f"{repo_name}.py", f"{repo_name}.txt"])
    return _dedupe_strings(paths)


def _github_repo_root(github_url: str) -> str:
    m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s#?]+)", github_url.rstrip("/"))
    if not m:
        return ""
    owner, repo = m.group(1), m.group(2).removesuffix(".git")
    return f"https://github.com/{owner}/{repo}"


def _raw_file_url(github_url: str) -> str:
    m = re.match(
        r"https?://github\.com/([^/\s]+)/([^/\s]+)/blob/([^/\s]+)/(.+)",
        github_url.rstrip("/"),
    )
    if not m:
        return ""
    owner, repo, branch, path = m.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def _prioritize_github_repos(repos: list[dict], cve_id: str) -> list[dict]:
    cve_lower = cve_id.lower()

    def sort_key(item: tuple[int, dict]) -> tuple[int, int]:
        index, repo = item
        text = f"{repo.get('label', '')} {repo.get('url', '')}".lower()
        score = 0
        if cve_lower in text:
            score -= 100
        if any(marker in text for marker in ("poc", "exploit", "vulhub", "reproduce")):
            score -= 25
        if "nuclei" in text:
            score -= 10
        if any(marker in text for marker in ("awesome", "bookmark", "bookmarks", "cvemon")):
            score += 20
        return score, index

    return [repo for _, repo in sorted(enumerate(repos), key=sort_key)]


def _extract_http_requests(text: str, cve_id: str) -> list[str]:
    """从文本中提取 HTTP 请求。"""
    return extract_http_requests(text)


def _extract_nuclei_yaml(text: str, cve_id: str) -> str:
    """从文本或 markdown 代码块中提取当前 CVE 的 nuclei YAML。"""
    blocks = re.findall(r"```(?:yaml|yml)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    candidates = blocks or [text]
    for candidate in candidates:
        content = candidate.strip()
        if not content or "id:" not in content[:500].lower():
            continue
        if cve_id.lower() not in content.lower():
            continue
        if "requests:" in content or "http:" in content:
            return content
    return ""


def _dedupe_strings(values: list[str]) -> list[str]:
    seen = set()
    unique = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


# ── 保存 ──

def save_to_local_kb(
    cve_id: str,
    poc_raw_http: str = "",
    poc_nuclei_yaml: str = "",
    metadata: dict | None = None,
) -> str | None:
    """将验证成功的 PoC 保存到 custom/ 本地知识库。

    Args:
        cve_id: CVE 编号
        poc_raw_http: 原始 HTTP 请求 PoC
        poc_nuclei_yaml: Nuclei YAML 模板
        metadata: 额外元数据 (cvss_score, description, references 等)

    Returns:
        保存的文件路径，失败返回 None
    """
    metadata = metadata or {}
    rel = _cve_to_relpath(cve_id)
    if not rel:
        return None

    year, filename = rel
    custom_dir = _kb_base() / "custom" / year
    custom_dir.mkdir(parents=True, exist_ok=True)

    md = _build_custom_md(cve_id, poc_raw_http, poc_nuclei_yaml, metadata)
    filepath = custom_dir / filename
    filepath.write_text(md, encoding="utf-8")
    return str(filepath)


def _build_custom_md(
    cve_id: str,
    poc_raw_http: str,
    poc_nuclei_yaml: str,
    metadata: dict,
) -> str:
    """构建 custom/ PoC 的 markdown 内容。"""
    lines = [
        f"# {cve_id.upper()}",
        "",
        f"**Status**: {metadata.get('status', 'verified')}",
        f"**PoC Source**: {metadata.get('poc_source', 'unknown')}",
        f"**CVSS Score**: {metadata.get('cvss_score', 'N/A')}",
        f"**CVSS Severity**: {metadata.get('cvss_severity', 'N/A')}",
        f"**Vuln Type**: {metadata.get('vuln_type', 'N/A')}",
        f"**Description**: {metadata.get('nvd_description', metadata.get('description', 'N/A'))}",
        f"**Saved At**: {metadata.get('timestamp', '')}",
        "",
    ]

    if poc_raw_http:
        lines.extend(["## HTTP PoC", "", "```http", poc_raw_http, "```", ""])

    if poc_nuclei_yaml:
        lines.extend(["## Nuclei YAML", "", "```yaml", poc_nuclei_yaml, "```", ""])

    refs = metadata.get("references", [])
    if refs:
        lines.append("## References")
        lines.append("")
        for ref in refs:
            lines.append(f"- <{ref}>")
        lines.append("")

    return "\n".join(lines)
