"""HTTP 请求发送与 PCAP 抓包模块。

支持两种模式：
1. 调用外部 http2pcap 服务
2. 内置 httpx 发送 + scapy 抓包
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

from cve_hunter.config import cfg
from cve_hunter.runtime import effective_target_ip, as_target_url
from cve_hunter.safety import is_local_lab_host


def send_poc_and_capture(
    *,
    raw_http: str = "",
    target_url: str = "",
    nuclei_yaml: str = "",
    cve_id: str = "",
) -> dict:
    """发送 PoC 并抓包。

    优先使用 http2pcap 服务；服务不可达/异常时回退内置 raw socket（本地靶场）。
    """
    if cfg.http2pcap_url:
        if nuclei_yaml:
            result = _send_via_http2pcap_nuclei(nuclei_yaml, target_url, cve_id)
            # nuclei 依赖服务侧执行；不可达时无法可靠回退 nuclei 语义
            if result.get("success") or not _looks_like_http2pcap_unreachable(result):
                return result
            if raw_http:
                fallback = _send_builtin(raw_http, target_url, cve_id)
                fallback["http2pcap_fallback"] = True
                fallback["http2pcap_error"] = result.get("error", "")
                return fallback
            result.setdefault("error_type", "http2pcap_unreachable")
            return result

        result = _send_via_http2pcap(raw_http, cve_id)
        if result.get("success") or not _looks_like_http2pcap_unreachable(result):
            return result
        # 服务挂掉时不要把整个 HTTP 批测打成「发包服务失败」
        fallback = _send_builtin(raw_http, target_url, cve_id)
        fallback["http2pcap_fallback"] = True
        fallback["http2pcap_error"] = result.get("error", "")
        return fallback
    return _send_builtin(raw_http, target_url, cve_id)


def _looks_like_http2pcap_unreachable(result: dict) -> bool:
    """Detect transport-level failure talking to http2pcap service itself."""
    if result.get("success"):
        return False
    err = str(result.get("error") or "").lower()
    markers = (
        "10061",
        "actively refused",
        "connection refused",
        "connecterror",
        "connect timeout",
        "timed out",
        "name or service not known",
        "nodename nor servname",
        "failed to establish a new connection",
        "remote protocol error",
        "server disconnected",
        "http2pcap 返回非 json",
    )
    return any(marker in err for marker in markers)


def _is_local_raw_target(raw_http: str, target_url: str = "") -> bool:
    host_header = _raw_header_value(raw_http.replace("\r\n", "\n"), "Host") if raw_http else ""
    host = _hostname_only(host_header)
    if not host and target_url:
        host = urlparse(target_url if "://" in target_url else f"http://{target_url}").hostname or ""
    return is_local_lab_host(host)


def _hostname_only(host_header: str) -> str:
    host_header = (host_header or "").strip()
    if host_header.startswith("["):
        end = host_header.find("]")
        return host_header[1:end] if end != -1 else host_header.strip("[]")
    if ":" in host_header:
        return host_header.rsplit(":", 1)[0]
    return host_header


def _send_via_http2pcap(raw_http: str, cve_id: str = "") -> dict:
    """通过 http2pcap 服务发送原始 HTTP 请求。"""
    try:
        data = _post_http2pcap(
            "/api/http2pcap",
            json={"raw_http": raw_http, "check_ips": True, "cve_id": cve_id},
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
        return {"success": False, "error": str(e), "error_type": "http2pcap_unreachable"}


def _send_via_http2pcap_nuclei(yaml_content: str, target_url: str, cve_id: str = "") -> dict:
    """通过 http2pcap 服务执行 nuclei PoC。"""
    try:
        data = _post_http2pcap(
            "/api/nuclei-poc",
            json={
                "yaml_content": yaml_content,
                "target_url": target_url or as_target_url(effective_target_ip()),
                "check_ips": True,
                "cve_id": cve_id,
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
        return {"success": False, "error": str(e), "error_type": "http2pcap_unreachable"}


def _post_http2pcap(path: str, *, json: dict, timeout: int) -> dict:
    """调用 http2pcap 服务并返回 JSON 响应。

    http2pcap/IPS 是内网服务，不能受 .env 中用于外部情报源的 HTTP_PROXY 影响。
    """
    url = f"{cfg.http2pcap_url.rstrip('/')}{path}"
    # 连接超时单独缩短，避免服务挂掉时卡满整个 request_timeout
    connect_timeout = min(5.0, float(timeout))
    resp = httpx.post(
        url,
        json=json,
        timeout=httpx.Timeout(timeout, connect=connect_timeout),
        trust_env=False,
    )

    try:
        return resp.json()
    except ValueError as exc:
        body = resp.text.replace("\r", "\\r").replace("\n", "\\n")[:500]
        raise RuntimeError(
            f"http2pcap 返回非 JSON 响应: status={resp.status_code}, "
            f"content_type={resp.headers.get('content-type', '')}, body={body}"
        ) from exc


def _send_builtin(raw_http: str, target_url: str = "", cve_id: str = "") -> dict:
    """内置方式：解析 raw HTTP → httpx 发送 → 可选 scapy 抓包。"""
    if not raw_http and not target_url:
        return {"success": False, "error": "缺少 raw_http 或 target_url"}

    if raw_http:
        return _send_raw_http_socket(raw_http, target_url, cve_id=cve_id)

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


def _send_raw_http_socket(
    raw_http: str,
    target_url: str = "",
    *,
    capture: bool = True,
    cve_id: str = "",
) -> dict:
    """按原始 request-target 直发，避免 httpx 规范化 ../、# 等特殊路径。"""
    request = raw_http.replace("\r\n", "\n").strip()
    if not request:
        return {"success": False, "error": "raw_http 为空"}

    parsed_target = urlparse(target_url) if target_url else None
    host_header = _raw_header_value(request, "Host")
    if not host_header and parsed_target:
        host_header = parsed_target.netloc
        request = _insert_header_after_request_line(request, f"Host: {host_header}")
    if not host_header:
        return {"success": False, "error": "raw_http 缺少 Host 头"}

    scheme = parsed_target.scheme if parsed_target and parsed_target.scheme else ("https" if host_header.endswith(":443") else "http")
    connect_host, connect_port = _host_port(host_header, default_port=443 if scheme == "https" else 80)
    if not connect_host:
        return {"success": False, "error": f"无法解析 Host: {host_header}"}

    request = _ensure_connection_close(request)
    payload = request.replace("\n", "\r\n").encode("iso-8859-1", errors="ignore") + b"\r\n\r\n"

    pcap_path = ""
    capture_process = None
    if capture:
        try:
            pcap_path, capture_process = _start_dumpcap_capture(connect_host, cve_id)
        except Exception:
            pcap_path = ""

    try:
        with socket.create_connection((connect_host, connect_port), timeout=cfg.request_timeout) as sock:
            sock.settimeout(cfg.request_timeout)
            if scheme == "https":
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=connect_host) as tls_sock:
                    tls_sock.sendall(payload)
                    response = _recv_all(tls_sock)
            else:
                sock.sendall(payload)
                response = _recv_all(sock)
        parsed = _parse_http_response(response)
        result = {
            "success": True,
            "status_code": parsed["status_code"],
            "body": parsed["body"][:2000],
            "pcap_file_path": pcap_path,
            "ips_matches": [],
            "packet_count": 0,
        }
    except Exception as e:
        result = {"success": False, "error": str(e), "pcap_file_path": pcap_path}
    finally:
        if capture_process:
            time.sleep(0.8)
            _stop_dumpcap_capture(capture_process)

    if pcap_path:
        result["packet_count"] = _pcap_packet_count(Path(pcap_path))

    return result


def _capture_output_path(host: str, cve_id: str = "", now: datetime | None = None) -> Path:
    now = now or datetime.now()
    output_dir = Path(cfg.pcap_output_dir) / ".pending" / now.strftime("%Y-%m-%d")
    output_dir.mkdir(parents=True, exist_ok=True)
    cve_label = cve_id.strip().upper() if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id.strip(), re.I) else "capture"
    return output_dir / f"{cve_label}.pcap"


def finalize_capture(pcap_file_path: str, *, keep: bool = True) -> str:
    """Promote a pending local capture and retain it by default.

    Destination filename is always normalised to ``CVE-XXXX-XXXXX.pcap`` so that
    database-path captures (whose pending name carries port/timestamp/interface
    suffixes like ``CVE-2012-2122_database_p3622_151341_if1.pcap``) end up with
    the same clean name as HTTP-path captures.  If the destination already exists
    the larger file wins (more data kept).
    """
    if not pcap_file_path:
        return ""
    path = Path(pcap_file_path)
    root = Path(cfg.pcap_output_dir).resolve()
    pending_root = (root / ".pending").resolve()
    resolved = path.resolve()
    if pending_root not in resolved.parents:
        if not keep and (resolved == root or root in resolved.parents):
            path.unlink(missing_ok=True)
        return pcap_file_path if keep else ""
    if not keep:
        path.unlink(missing_ok=True)
        return ""
    relative = resolved.relative_to(pending_root)
    # Normalise: strip port/timestamp/interface suffixes → CVE-XXXX-XXXXX.pcap
    cve_match = re.search(r"CVE-\d{4}-\d{4,}", relative.stem, re.I)
    final_name = f"{cve_match.group(0).upper()}.pcap" if cve_match else relative.name
    final_path = root / relative.parent / final_name
    final_path.parent.mkdir(parents=True, exist_ok=True)
    # Collision: keep the file with more data
    if final_path.exists():
        try:
            existing_size = final_path.stat().st_size
            incoming_size = path.stat().st_size if path.exists() else 0
        except OSError:
            existing_size = incoming_size = 0
        if incoming_size > existing_size:
            path.replace(final_path)
        else:
            path.unlink(missing_ok=True)
    else:
        path.replace(final_path)
    return str(final_path)


def _start_dumpcap_capture(host: str, cve_id: str = "") -> tuple[str, subprocess.Popen]:
    dumpcap = os.getenv("DUMPCAP_PATH") or shutil.which("dumpcap")
    if not dumpcap:
        raise FileNotFoundError("未找到 dumpcap")
    interface = os.getenv("CAPTURE_INTERFACE", r"\Device\NPF_Loopback" if os.name == "nt" else "any")
    output_path = _capture_output_path(host, cve_id)
    process = subprocess.Popen(
        [dumpcap, "-q", "-i", interface, "-F", "pcap", "-w", str(output_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.7)
    if process.poll() is not None:
        error = process.stderr.read().strip() if process.stderr else ""
        raise RuntimeError(error or "dumpcap 未能启动")
    return str(output_path), process


def _stop_dumpcap_capture(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _pcap_packet_count(path: Path) -> int:
    tshark = os.getenv("TSHARK_PATH") or shutil.which("tshark")
    if not tshark or not path.is_file() or path.stat().st_size == 0:
        return 0
    result = subprocess.run(
        [tshark, "-r", str(path), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def _raw_header_value(raw_http: str, name: str) -> str:
    match = re.search(rf"(?im)^{re.escape(name)}\s*:\s*(.+?)\s*$", raw_http)
    return match.group(1).strip() if match else ""


def _insert_header_after_request_line(raw_http: str, header: str) -> str:
    lines = raw_http.split("\n")
    if not lines:
        return raw_http
    return "\n".join([lines[0], header, *lines[1:]])


def _ensure_connection_close(raw_http: str) -> str:
    if re.search(r"(?im)^Connection\s*:", raw_http):
        return re.sub(r"(?im)^Connection\s*:\s*.*$", "Connection: close", raw_http, count=1)
    parts = raw_http.split("\n\n", 1)
    head = f"{parts[0]}\nConnection: close"
    return "\n\n".join([head, parts[1]]) if len(parts) == 2 else head


def _host_port(host_header: str, *, default_port: int) -> tuple[str, int]:
    host_header = host_header.strip()
    if host_header.startswith("["):
        end = host_header.find("]")
        if end != -1:
            host = host_header[1:end]
            rest = host_header[end + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, default_port
            return host, default_port
    if ":" in host_header:
        host, port_text = host_header.rsplit(":", 1)
        try:
            return host.strip(), int(port_text)
        except ValueError:
            return host_header, default_port
    return host_header, default_port


def _recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def _parse_http_response(response: bytes) -> dict:
    text = response.decode("iso-8859-1", errors="ignore")
    head, _, body = text.partition("\r\n\r\n")
    if not body:
        head, _, body = text.partition("\n\n")
    status_line = head.splitlines()[0] if head.splitlines() else ""
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d+)", status_line)
    status_code = int(match.group(1)) if match else 0
    return {"status_code": status_code, "body": body}


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

    output_dir = Path(cfg.pcap_output_dir) / datetime.now().strftime("%Y-%m-%d")
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
