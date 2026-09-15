from types import SimpleNamespace
from unittest.mock import patch

import httpx

from cve_hunter.tools import web_extract
from cve_hunter.tools.tavily_http import post_tavily
import pytest


def test_tavily_extract_uses_httpx_api(monkeypatch):
    request = httpx.Request("POST", "https://api.tavily.com/extract")
    response = httpx.Response(200, request=request, json={"results": [{"title": "advisory", "raw_content": "GET /p"}]})
    monkeypatch.setattr(web_extract, "cfg", SimpleNamespace(tavily_api_key="key", httpx_proxy=""))
    with patch.object(web_extract.httpx, "post", return_value=response) as post:
        result = web_extract.extract_url_content_tavily("https://example.test/advisory")
    assert result["content"] == "GET /p"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer key"


@pytest.mark.parametrize("endpoint", ["search", "extract"])
def test_broken_proxy_retries_direct(endpoint):
    response = httpx.Response(200, request=httpx.Request("POST", "https://api.tavily.com/" + endpoint), json={"results": []})
    with patch("httpx.post", side_effect=[httpx.ConnectError("proxy refused"), response]) as post:
        assert post_tavily(endpoint, api_key="key", payload={}, proxy="http://127.0.0.1:7890") == {"results": []}
    assert len(post.call_args_list) == 2
    assert post.call_args_list[0].kwargs["proxy"] == "http://127.0.0.1:7890"
    assert post.call_args_list[1].kwargs["proxy"] is None
    assert all(call.kwargs["trust_env"] is False for call in post.call_args_list)


@pytest.mark.parametrize("status", [401, 429])
def test_auth_and_quota_errors_are_not_retried(status):
    response = httpx.Response(status, request=httpx.Request("POST", "https://api.tavily.com/search"))
    with patch("httpx.post", return_value=response) as post, pytest.raises(httpx.HTTPStatusError):
        post_tavily("search", api_key="key", payload={}, proxy="http://127.0.0.1:7890")
    assert post.call_count == 1
