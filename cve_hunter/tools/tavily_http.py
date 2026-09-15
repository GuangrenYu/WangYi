"""Shared Tavily transport with a bounded direct fallback for broken proxies."""

import logging

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
    response.raise_for_status()
    return response.json()
