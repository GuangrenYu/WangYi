from unittest.mock import patch

import httpx
import pytest

from cve_hunter.evidence import write_repro_bundle


@pytest.mark.parametrize("status,content,success", [
    (200, b"\xd4\xc3\xb2\xa1" + b"\0" * 20, True),
    (200, b'<html>login required</html>', False),
    (404, b'not found', False),
])
def test_remote_capture_download(tmp_path, status, content, success):
    response = httpx.Response(status, content=content,
        request=httpx.Request("GET", "http://192.0.2.1/api/file?filename=capture.pcap"))
    # The response is a context manager in the real streaming call.
    from contextlib import contextmanager
    @contextmanager
    def stream(*args, **kwargs):
        assert kwargs["trust_env"] is False
        yield response

    with patch("cve_hunter.evidence.httpx.stream", side_effect=stream):
        result = write_repro_bundle(tmp_path, cve_id="CVE-2025-0001",
            status="SUCCESS", status_code="检测命中", message="hit",
            success_tier="检测证据", failure_class="无", success_level="ips",
            poc_source="local", poc_raw_http="GET / HTTP/1.1\r\nHost: test\r\n\r\n",
            pcap_file_path="data/pcap/remote-only.pcap",
            executor_result={"pcap_download_url": str(response.request.url)})
    assert (tmp_path / "poc.http").is_file()
    assert (tmp_path / "capture.pcap").exists() == success
    assert not (tmp_path / "capture.pcap.part").exists()
    assert bool(result["errors"]) != success
    assert result["complete"] == success
    if success:
        assert (tmp_path / "capture.pcap").read_bytes() == content
