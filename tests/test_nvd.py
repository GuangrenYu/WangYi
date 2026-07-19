from unittest.mock import patch
from types import SimpleNamespace

import httpx

from cve_hunter.tools.nvd import _request_nvd


def test_nvd_request_falls_back_to_direct_when_proxy_is_unreachable():
    request = httpx.Request("GET", "https://services.nvd.nist.gov/")
    response = httpx.Response(200, request=request, json={"vulnerabilities": []})

    with (
        patch(
            "cve_hunter.tools.nvd.cfg",
            SimpleNamespace(httpx_proxy="http://127.0.0.1:7890"),
        ),
        patch(
            "cve_hunter.tools.nvd.httpx.get",
            side_effect=[httpx.ConnectError("refused", request=request), response],
        ) as get,
    ):
        actual = _request_nvd("CVE-2021-44228", {"User-Agent": "test"})

    assert actual is response
    assert get.call_count == 2
    assert get.call_args_list[0].kwargs["proxy"] == "http://127.0.0.1:7890"
    assert get.call_args_list[1].kwargs["proxy"] is None
