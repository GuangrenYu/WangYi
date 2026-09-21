"""Local NVD reference content cache.

Stores extracted reference pages under ``poc_kb/ref_cache/<year>/CVE-xxxx.json``
so later runs can reuse them when live extract (Tavily/wayback/builtin) fails or
is skipped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cve_hunter.config import cfg

_CVE_RE = re.compile(r"CVE-(\d{4})-\d+", re.I)


def _cache_root() -> Path:
    root = Path(getattr(cfg, "local_kb_dir", "") or "poc_kb")
    return root / "ref_cache"


def cache_path_for(cve_id: str) -> Path | None:
    m = _CVE_RE.search(cve_id or "")
    if not m:
        return None
    year = m.group(1)
    return _cache_root() / year / f"{cve_id.upper()}.json"


def load_reference_cache(cve_id: str) -> list[dict[str, str]]:
    path = cache_path_for(cve_id)
    if not path or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    items = data.get("references") if isinstance(data, dict) else data
    out: list[dict[str, str]] = []
    if not isinstance(items, list):
        return []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        content = str(item.get("content") or "")
        if not url or not content.strip():
            continue
        out.append(
            {
                "url": url,
                "title": str(item.get("title") or ""),
                "content": content,
            }
        )
    return out


def save_reference_cache(cve_id: str, references: list[dict[str, Any]]) -> Path | None:
    path = cache_path_for(cve_id)
    if not path:
        return None
    cleaned: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in references:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        content = str(item.get("content") or "")
        if not url or not content.strip() or url in seen:
            continue
        seen.add(url)
        cleaned.append(
            {
                "url": url,
                "title": str(item.get("title") or ""),
                "content": content[:8000],
            }
        )
    if not cleaned:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cve_id": cve_id.upper(),
        "references": cleaned,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def merge_reference_contents(
    cached: list[dict[str, str]],
    fetched: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Prefer longer content for the same URL; keep stable order cached-first."""
    by_url: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for item in list(cached) + list(fetched):
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        content = str(item.get("content") or "")
        if not content.strip():
            continue
        if url not in by_url:
            by_url[url] = {
                "url": url,
                "title": str(item.get("title") or ""),
                "content": content,
            }
            order.append(url)
            continue
        if len(content) > len(by_url[url].get("content") or ""):
            by_url[url]["content"] = content
            if item.get("title"):
                by_url[url]["title"] = str(item.get("title") or "")
    return [by_url[url] for url in order]
