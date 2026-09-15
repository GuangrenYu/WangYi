"""Shared Tavily transport with a bounded direct fallback for broken proxies."""

import logging
import json
import re

import httpx


def post_tavily(endpoint, *, api_key, payload, proxy=None):
    options = dict(
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=httpx.Timeout(90.0, connect=15.0),
        trust_env=False,
    )
    url = f"https://api.tavily.com/{endpoint}"
    try:
        response = httpx.post(url, proxy=proxy or None, **options)
    except (httpx.ProxyError, httpx.ConnectError, httpx.ConnectTimeout):
        if not proxy:
            raise
        logging.getLogger(__name__).warning("Tavily 代理连接失败，尝试直连")
        response = httpx.post(url, proxy=None, **options)
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # Tavily uses custom status codes (432/433). The response body explains
        # the rejection; httpx's default exception drops that information.
        try:
            body = response.json()
            detail = body.get("detail", body.get("error", body.get("message", body))) if isinstance(body, dict) else body
            detail = detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False)
        except ValueError:
            detail = response.text
        if api_key:
            detail = detail.replace(api_key, "[REDACTED]")
        detail = re.sub(r"tvly-[A-Za-z0-9_-]+", "[REDACTED]", detail)
        detail = " ".join(detail.split())[:1200] or "服务未返回错误详情"
        message = f"Tavily API HTTP {response.status_code} ({endpoint}): {detail}"
        raise httpx.HTTPStatusError(message, request=exc.request, response=response) from None
    return response.json()
