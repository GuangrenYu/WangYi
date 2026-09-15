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
        headers={"Content-Disposition": 'attachment; filename="CVE-2025-0001_20260915_120000.pcap"'},
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
    destination = tmp_path / "CVE-2025-0001_20260915_120000.pcap"
    assert destination.exists() == success
    assert not list(tmp_path.glob("*.part"))
    assert bool(result["errors"]) != success
    assert result["complete"] == success
    if success:
        assert destination.read_bytes() == content
        assert result["artifacts"]["pcap"] == str(destination)


@pytest.mark.parametrize("header,path,url,expected", [
    ("", r"C:\captures\original_123.pcap", "http://example.test/download", "original_123.pcap"),
    ("", "", "http://example.test/download?filename=original_456.pcap", "original_456.pcap"),
    ("", "", "http://example.test/files/original.pcapng", "original.pcapng"),
    ('attachment; filename="../../original.pcap"', "", "", "original.pcap"),
    ("attachment; filename*=UTF-8''CVE_%E6%B5%8B%E8%AF%95.pcap", "", "", "CVE_测试.pcap"),
    ('attachment; filename="bad:stream.pcap"', "", "", "capture.pcap"),
])
def test_remote_filename(header, path, url, expected):
    from cve_hunter.evidence import _remote_pcap_name
    assert _remote_pcap_name(header, path, url) == expected
