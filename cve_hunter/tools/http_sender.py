"""HTTP 请求发送与 PCAP 抓包模块。

支持两种模式：
1. 调用外部 http2pcap 服务
2. 内置 httpx 发送 + scapy 抓包
"""

from __future__ import annotations

import os
import re
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

from cve_hunter.config import cfg


def send_poc_and_capture(
    *,
    raw_http: str = "",
    target_url: str = "",
    nuclei_yaml: str = "",
) -> dict:
    """发送 PoC 并抓包。

    优先使用 http2pcap 服务；若不可用则使用内置方式。
    """
    if cfg.http2pcap_url:
        if nuclei_yaml:
            return _send_via_http2pcap_nuclei(nuclei_yaml, target_url)
        return _send_via_http2pcap(raw_http)
    return _send_builtin(raw_http, target_url)


def _send_via_http2pcap(raw_http: str) -> dict:
    """通过 http2pcap 服务发送原始 HTTP 请求。"""
    try:
        data = _post_http2pcap(
            "/api/http2pcap",
            json={"raw_http": raw_http, "check_ips": True},
            timeout=60,
        )
        return {
            "success": data.get("success", False),
            "status_code": data.get("status_code", 0),
            "body": data.get("body", ""),
            "pcap_file_path": data.get("pcap_file_path", ""),
            "pcap_download_url": data.get("pcap_download_url", ""),
            "ips_matches": data.get("ips_matches", []),
            "packet_count": data.get("packet_count", 0),
            "error": data.get("error", ""),
            "error_type": data.get("error_type", ""),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _send_via_http2pcap_nuclei(yaml_content: str, target_url: str) -> dict:
    """通过 http2pcap 服务执行 nuclei PoC。"""
    try:
        data = _post_http2pcap(
            "/api/nuclei-poc",
            json={
                "yaml_content": yaml_content,
                "target_url": target_url or f"http://{cfg.target_ip}",
                "check_ips": True,
            },
            timeout=120,
        )
        return {
            "success": data.get("success", False),
            "matched": data.get("matched", False),
            "pcap_file_path": data.get("pcap_file_path", ""),
            "pcap_download_url": data.get("pcap_download_url", ""),
            "ips_matches": data.get("ips_matches", []),
            "packet_count": data.get("packet_count", 0),
            "result_info": data.get("result_info", ""),
            "error": data.get("error", ""),
            "error_type": data.get("error_type", ""),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _post_http2pcap(path: str, *, json: dict, timeout: int) -> dict:
    """调用 http2pcap 服务并返回 JSON 响应。

    http2pcap/IPS 是内网服务，不能受 .env 中用于外部情报源的 HTTP_PROXY 影响。
    """
    url = f"{cfg.http2pcap_url.rstrip('/')}{path}"
    resp = httpx.post(url, json=json, timeout=timeout, trust_env=False)

    try:
        return resp.json()
    except ValueError as exc:
        body = resp.text.replace("\r", "\\r").replace("\n", "\\n")[:500]
        raise RuntimeError(
            f"http2pcap 返回非 JSON 响应: status={resp.status_code}, "
            f"content_type={resp.headers.get('content-type', '')}, body={body}"
        ) from exc


def _send_builtin(raw_http: str, target_url: str = "") -> dict:
    """内置方式：解析 raw HTTP → httpx 发送 → 可选 scapy 抓包。"""
    if not raw_http and not target_url:
        return {"success": False, "error": "缺少 raw_http 或 target_url"}

    parsed = _parse_raw_http(raw_http) if raw_http else None

    if parsed:
        url = parsed["url"]
        method = parsed["method"]
        headers = parsed["headers"]
        body = parsed["body"]
    elif target_url:
        url = target_url
        method = "GET"
        headers = {}
        body = None
    else:
        return {"success": False, "error": "无法解析请求"}

    pcap_path = ""
    capture_thread = None

    # 尝试 scapy 抓包（需要 root 权限）
    host = urlparse(url).hostname or ""
    try:
        pcap_path, capture_thread, stop_event = _start_capture(host)
    except Exception:
        pcap_path = ""
        capture_thread = None
        stop_event = None

    try:
        resp = httpx.request(
            method,
            url,
            headers=headers,
            content=body.encode() if body else None,
            timeout=cfg.request_timeout,
            follow_redirects=False,
            verify=False,
        )
        result = {
            "success": True,
            "status_code": resp.status_code,
            "body": resp.text[:2000],
            "pcap_file_path": pcap_path,
            "ips_matches": [],
            "packet_count": 0,
        }
    except Exception as e:
        result = {"success": False, "error": str(e), "pcap_file_path": pcap_path}

    if stop_event:
        time.sleep(1)
        stop_event.set()
    if capture_thread:
        capture_thread.join(timeout=5)

    return result


def _parse_raw_http(raw_http: str) -> dict | None:
    """将原始 HTTP 报文字符串解析为请求组件。"""
    lines = raw_http.replace("\r\n", "\n").split("\n")
    if not lines:
        return None

    request_line = lines[0].strip()
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return None

    method = parts[0].upper()
    path = parts[1]

    headers = {}
    body = ""
    header_done = False
    body_lines = []

    for line in lines[1:]:
        if header_done:
            body_lines.append(line)
        elif line.strip() == "":
            header_done = True
        else:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()

    body = "\n".join(body_lines).strip()

    host = headers.get("Host", "")
    scheme = "https" if ":443" in host else "http"
    url = f"{scheme}://{host}{path}" if host else path

    return {"method": method, "url": url, "headers": headers, "body": body}


def _start_capture(host: str) -> tuple[str, threading.Thread, threading.Event]:
    """启动 scapy 后台抓包线程。"""
    from scapy.all import sniff, wrpcap

    output_dir = Path(cfg.output_dir) / "pcap"
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = str(output_dir / f"{ts}_{host}.pcap")

    stop_event = threading.Event()
    captured_packets = []

    def _capture():
        try:
            bpf = f"host {host}" if host else ""
            pkts = sniff(
                filter=bpf,
                timeout=cfg.request_timeout + 5,
                stop_filter=lambda _: stop_event.is_set(),
            )
            captured_packets.extend(pkts)
            if captured_packets:
                wrpcap(pcap_path, captured_packets)
        except Exception:
            pass

    t = threading.Thread(target=_capture, daemon=True)
    t.start()
    time.sleep(0.5)
    return pcap_path, t, stop_event
