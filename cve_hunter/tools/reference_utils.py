"""Reference URL normalization helpers."""

from __future__ import annotations

import re


def normalize_reference_urls(raw_refs: list[str]) -> list[str]:
    """Split malformed concatenated URLs and deduplicate while preserving order."""
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in raw_refs:
        for url in _split_concatenated_urls(str(raw or "")):
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(url)

    return normalized


def _split_concatenated_urls(raw: str) -> list[str]:
    value = raw.strip().strip("<>")
    if not value:
        return []

    parts = re.split(r"(?=https?://)", value)
    urls = []
    for part in parts:
        url = part.strip().strip("<>").rstrip(").,;]")
        if url.startswith(("http://", "https://")):
            urls.append(url)
    return urls
