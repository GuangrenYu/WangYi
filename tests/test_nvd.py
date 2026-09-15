from unittest.mock import patch
from types import SimpleNamespace

import httpx

from cve_hunter.tools.nvd import _request_nvd
from cve_hunter.tools.nvd_local import parse_nvd_years
import pytest


def test_year_ranges_include_1999_and_deduplicate():
    expected = list(range(1999, 2027))
    assert parse_nvd_years("1999-2026", current_year=2026) == expected
    assert parse_nvd_years("all", current_year=2026) == expected
    assert parse_nvd_years("1999，2000-2002 2001", current_year=2026) == [1999, 2000, 2001, 2002]


@pytest.mark.parametrize("value", ["1998", "2027", "2026-1999", "invalid", ",,,"])
def test_invalid_year_selection(value):
    with pytest.raises(ValueError):
        parse_nvd_years(value, current_year=2026)


def test_web_accepts_full_range_without_downloading():
    from fastapi.testclient import TestClient
    from cve_hunter import web_app
    with patch.dict(web_app.knowledge_jobs, {}, clear=True), patch.object(web_app.manager.executor, "submit") as submit:
        with TestClient(web_app.app) as client:
            response = client.post("/api/knowledge-bases/nvd/update", data={"years": "1999-2026"})
            assert response.status_code == 200
            assert response.json()["years"] == list(range(1999, 2027))
            submit.assert_called_once()
            assert client.post("/api/knowledge-bases/nvd/update", data={"years": "all"}).status_code == 409


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
