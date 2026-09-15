"""NVD 本地数据 Feed 模块。

从 NVD 官网下载 CVE JSON 2.0 年度数据压缩包，本地化查询。
优先级高于远程 API 调用，命中失败时回退到 API。

Feed 地址: https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz
更新频率: 年度包每日更新，modified/recent 约每两小时更新
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sys
import time
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from cve_hunter.config import cfg
from cve_hunter.tools.reference_utils import normalize_reference_urls

NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"

# 年度包文件模板
_YEAR_FILE = "nvdcve-2.0-{year}.json.gz"
_MODIFIED_FILE = "nvdcve-2.0-modified.json.gz"
_RECENT_FILE = "nvdcve-2.0-recent.json.gz"

# 有效年份范围
_YEAR_MIN = 2002
_YEAR_MAX = datetime.now().year

# 已加载的年度数据缓存（最多缓存 2 个年份）
_year_cache: dict[str, dict] = {}
_cache_order: list[str] = []
_cve_index_cache: dict[str, dict[str, dict]] = {}
_feed_signatures: dict[str, tuple[int, int]] = {}
_MAX_CACHE_SIZE = 2


def _nvd_local_dir() -> Path:
    # Migrated Windows relative paths must not become literal backslash names
    # on Ubuntu. Resolve relative configuration against the application root.
    path = Path(str(cfg.nvd_local_dir).replace("\\", "/")).expanduser()
    return path if path.is_absolute() else Path(__file__).resolve().parents[2] / path


def _feed_url(year: int) -> str:
    return f"{NVD_FEED_BASE}/{_YEAR_FILE.format(year=year)}"


def _meta_url(year: int) -> str:
    return f"{NVD_FEED_BASE}/nvdcve-2.0-{year}.meta"


def _meta_url_for_feed(feed_url: str) -> str:
    """Return the NVD metadata URL for a ``.json.gz`` feed URL."""
    suffix = ".json.gz"
    if feed_url.endswith(suffix):
        return f"{feed_url[:-len(suffix)]}.meta"
    return f"{feed_url}.meta"


def _cve_year(cve_id: str) -> int | None:
    m = re.match(r"CVE-(\d{4})-\d+", cve_id, re.IGNORECASE)
    return int(m.group(1)) if m else None


# ═══════════════════════════════════════════════════════════
# 下载与更新
# ═══════════════════════════════════════════════════════════


def download_nvd_feeds(
    years: list[int] | None = None,
    include_modified: bool = True,
    force: bool = False,
    progress_callback=None,
) -> dict:
    """下载 NVD 年度数据包到本地。

    Args:
        years: 要下载的年份列表，默认所有年份 (2002-至今)
        include_modified: 是否一并下载 modified/recent 包
        force: 是否强制重新下载（忽略本地已有文件）
        progress_callback: 进度回调 callable(year, status, msg)

    Returns:
        {"downloaded": [...], "skipped": [...], "errors": [...]}
    """
    result = {"downloaded": [], "skipped": [], "errors": []}
    local_dir = _nvd_local_dir()
    local_dir.mkdir(parents=True, exist_ok=True)

    if years is None:
        years = list(range(_YEAR_MIN, _YEAR_MAX + 1))

    downloads: list[tuple[str, str, str]] = []
    for y in years:
        downloads.append((_YEAR_FILE.format(year=y), _feed_url(y), f"{y}"))
    if include_modified:
        downloads.append((_MODIFIED_FILE, f"{NVD_FEED_BASE}/{_MODIFIED_FILE}", "modified"))
        downloads.append((_RECENT_FILE, f"{NVD_FEED_BASE}/{_RECENT_FILE}", "recent"))

    # Prefer the configured proxy, but do not make a stale local proxy block
    # feed updates. A transport error falls back to a direct client.
    proxies = [cfg.httpx_proxy] if cfg.httpx_proxy else []
    if None not in proxies:
        proxies.append(None)
    with ExitStack() as stack:
        clients = [
            stack.enter_context(
                httpx.Client(
                    timeout=httpx.Timeout(300.0, connect=10.0),
                    follow_redirects=True,
                    proxy=proxy,
                    trust_env=False,
                )
            )
            for proxy in proxies
        ]

        def get_with_fallback(url: str):
            last_error = None
            for client in clients:
                try:
                    return client.get(url)
                except (httpx.RequestError, httpx.TimeoutException) as exc:
                    last_error = exc
            if last_error is not None:
                raise last_error
            raise RuntimeError("No NVD HTTP route available")

        for filename, url, label in downloads:
            filepath = local_dir / filename

            if filepath.exists() and not force:
                # 检查远端 meta 决定是否需要更新
                try:
                    meta_resp = get_with_fallback(_meta_url_for_feed(url))
                    if meta_resp.status_code == 200:
                        remote_sha = _parse_meta_sha256(meta_resp.text)
                        if remote_sha and _file_sha256(filepath) == remote_sha:
                            if progress_callback:
                                progress_callback(label, "skip", "already current")
                            result["skipped"].append(label)
                            continue
                except Exception:
                    pass

            if progress_callback:
                progress_callback(label, "download", url)

            try:
                resp = get_with_fallback(url)
                resp.raise_for_status()
                # Write atomically so an interrupted download cannot corrupt a
                # previously usable feed.
                temp_path = filepath.with_name(f".{filepath.name}.part")
                temp_path.write_bytes(resp.content)
                temp_path.replace(filepath)
                result["downloaded"].append(label)
                if progress_callback:
                    progress_callback(label, "done", f"{len(resp.content) / 1024 / 1024:.1f} MB")
            except Exception as e:
                result["errors"].append({"label": label, "error": str(e)})
                if progress_callback:
                    progress_callback(label, "error", str(e))

    # 清除缓存，下次查询重新加载
    _year_cache.clear()
    _cache_order.clear()
    _cve_index_cache.clear()
    _feed_signatures.clear()

    return result


def _parse_meta_sha256(meta_text: str) -> str | None:
    """从 NVD .meta 文件提取 sha256。"""
    for line in meta_text.splitlines():
        if line.lower().startswith("sha256:"):
            return line.split(":", 1)[1].strip()
    return None


def _file_sha256(filepath: Path) -> str:
    return hashlib.sha256(filepath.read_bytes()).hexdigest()


# ═══════════════════════════════════════════════════════════
# 查询
# ═══════════════════════════════════════════════════════════


def query_nvd_local(cve_id: str) -> dict | None:
    """在本地 NVD 数据中查询 CVE。

    Returns:
        成功返回与 query_nvd() 相同格式的 dict，未找到返回 None
    """
    year = _cve_year(cve_id)
    if year is None:
        return None

    local_dir = _nvd_local_dir()

    # 1) 先查对应年份文件
    files = [local_dir / f"nvdcve-2.0-{label}{suffix}"
             for label in ("modified", "recent", str(year))
             for suffix in (".json.gz", ".json")]
    files = [path for path in files if path.is_file()]
    if not files:
        raise FileNotFoundError(
            f"NVD 目录 {local_dir} 中没有 {year} 年 Feed 或 modified/recent 包；"
            f"请下载 {year} 年数据（CVE 年份与下载年份必须对应）"
        )
    errors = []
    for path in files:
        try:
            cve_data = _search_in_feed(cve_id.strip(), path)
            if cve_data:
                result = _parse_cve_item(cve_id, cve_data)
                result["metadata"]["feed_path"] = str(path)
                return result
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise ValueError("本地 Feed 读取失败：" + "; ".join(errors))
    return None


def _load_feed(filepath: Path) -> dict:
    """加载 NVD feed JSON 文件（带缓存）。"""
    key = str(filepath)
    if key in _year_cache:
        return _year_cache[key]

    # LRU 淘汰
    while len(_cache_order) >= _MAX_CACHE_SIZE:
        old = _cache_order.pop(0)
        if old in _year_cache:
            del _year_cache[old]
        _cve_index_cache.pop(old, None)

    data = _read_gz_json(filepath)
    _year_cache[key] = data
    _cache_order.append(key)
    return data


def _read_gz_json(filepath: Path) -> dict:
    opener = gzip.open if filepath.suffix == ".gz" else open
    with opener(filepath, "rb") as f:
        return json.loads(f.read())


def _search_in_feed(cve_id: str, filepath: Path) -> dict | None:
    """在单个 feed 文件中搜索 CVE。"""
    try:
        key = str(filepath)
        stat = filepath.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        if _feed_signatures.get(key) != signature:
            _year_cache.pop(key, None)
            _cve_index_cache.pop(key, None)
            if key in _cache_order:
                _cache_order.remove(key)
            _feed_signatures[key] = signature
        index = _cve_index_cache.get(key)
        if index is None:
            data = _load_feed(filepath)
            # Annual feeds contain tens of thousands of entries; indexing once
            # avoids rescanning the full JSON for every CVE in a batch.
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise ValueError("不是 NVD JSON 2.0 格式（缺少 vulnerabilities 数组），请重新下载 2.0 Feed")
            index = {
                str(item.get("cve", {}).get("id", "")).upper(): item.get("cve", {})
                for item in data.get("vulnerabilities", [])
                if item.get("cve", {}).get("id")
            }
            _cve_index_cache[key] = index
        return index.get(cve_id.upper())
    except Exception as exc:
        raise ValueError(f"无法解析 NVD Feed: {exc}") from exc


def _parse_cve_item(cve_id: str, cve_item: dict) -> dict:
    """解析 CVE JSON 条目（与 API 返回格式一致）。"""
    descriptions = cve_item.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    if not desc_en and descriptions:
        desc_en = descriptions[0].get("value", "")

    refs = normalize_reference_urls([r.get("url", "") for r in cve_item.get("references", [])])

    products = []
    for node in cve_item.get("configurations", []):
        for n in node.get("nodes", []):
            for match in n.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    products.append(cpe)

    metrics = cve_item.get("metrics", {})
    cvss_score = 0.0
    cvss_severity = ""
    cvss_vector = ""
    for vk in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(vk, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_severity = cvss_data.get("baseSeverity", metric_list[0].get("baseSeverity", ""))
            cvss_vector = cvss_data.get("vectorString", "")
            break

    return {
        "cve_id": cve_id,
        "description": desc_en,
        "references": refs,
        "affected_products": products,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "metadata": {
            "cvss_vector": cvss_vector,
            "weaknesses": cve_item.get("weaknesses", []),
            "configurations": cve_item.get("configurations", []),
            "reference_details": cve_item.get("references", []),
            "last_modified": cve_item.get("lastModified", ""),
        },
    }


def get_nvd_local_status() -> dict:
    """获取本地 NVD 数据状态摘要。"""
    local_dir = _nvd_local_dir()
    if not local_dir.exists():
        return {"exists": False, "dir": str(local_dir), "years_available": [], "total_size_mb": 0}

    years = []
    total_size = 0
    for year in range(_YEAR_MIN, _YEAR_MAX + 1):
        feeds = [local_dir / f"nvdcve-2.0-{year}{suffix}" for suffix in (".json.gz", ".json")]
        if any(f.is_file() for f in feeds):
            years.append(year)
            total_size += sum(f.stat().st_size for f in feeds if f.is_file())

    modified_file = local_dir / _MODIFIED_FILE
    recent_file = local_dir / _RECENT_FILE
    if modified_file.exists():
        total_size += modified_file.stat().st_size
    if recent_file.exists():
        total_size += recent_file.stat().st_size

    return {
        "exists": True,
        "dir": str(local_dir),
        "years_available": years,
        "has_modified": modified_file.exists(),
        "has_recent": recent_file.exists(),
        "total_size_mb": round(total_size / 1024 / 1024, 1),
    }
