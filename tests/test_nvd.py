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


def test_pre_2002_feeds_are_reported_as_officially_unavailable():
    from cve_hunter.tools.nvd_local import download_nvd_feeds
    with patch("cve_hunter.tools.nvd_local._nvd_local_dir") as local_dir, patch("cve_hunter.tools.nvd_local.httpx.Client") as client:
        local_dir.return_value.mkdir = lambda **kwargs: None
        result = download_nvd_feeds(years=[1999, 2000, 2001, 2002], include_modified=False)
        labels = {item["label"] for item in result["errors"]}
        assert {"1999", "2000", "2001"}.issubset(labels)
        client.assert_called_once()


def test_gzip_feed_with_legacy_cve_items_is_read_even_without_gz_suffix(tmp_path):
    import gzip, json
    from dataclasses import replace
    from cve_hunter.tools.nvd import query_nvd
    item = {"cve": {"id": "CVE-2002-0001", "descriptions": [{"lang": "en", "value": "legacy"}]}}
    path = tmp_path / "archive-2002.feed"
    with gzip.open(path, "wb") as stream:
        stream.write(json.dumps({"CVE_Items": [item]}).encode())
    from cve_hunter.tools import nvd_local
    with patch.object(nvd_local, "cfg", replace(nvd_local.cfg, nvd_local_dir=str(tmp_path), cvelist_dir=str(tmp_path / "none"))):
        result = query_nvd("CVE-2002-0001", local_only=True)
    assert result["description"] == "legacy"


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
