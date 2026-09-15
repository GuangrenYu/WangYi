from types import SimpleNamespace
from unittest.mock import patch

import httpx

from cve_hunter.tools import web_extract


def test_tavily_extract_uses_httpx_api(monkeypatch):
    request = httpx.Request("POST", "https://api.tavily.com/extract")
    response = httpx.Response(200, request=request, json={"results": [{"title": "advisory", "raw_content": "GET /p"}]})
    monkeypatch.setattr(web_extract, "cfg", SimpleNamespace(tavily_api_key="key", httpx_proxy=""))
    with patch.object(web_extract.httpx, "post", return_value=response) as post:
        result = web_extract.extract_url_content_tavily("https://example.test/advisory")
    assert result["content"] == "GET /p"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer key"
