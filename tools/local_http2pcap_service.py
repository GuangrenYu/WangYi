"""Local raw-HTTP sender and packet-capture service for CVE Hunter.

The service intentionally binds to loopback and only sends to local/private
targets. Wireshark's dumpcap performs the capture so Windows Npcap support is
used without coupling packet capture to the request thread.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from cve_hunter.safety import is_local_lab_host
from cve_hunter.tools.http_sender import _hostname_only, _raw_header_value, _send_raw_http_socket


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "data" / "cve" / "pcaps"
DEFAULT_INTERFACE = r"\Device\NPF_Loopback" if os.name == "nt" else "any"
CAPTURE_LOCK = threading.Lock()


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _target_host(raw_http: str, target_url: str = "") -> str:
    host = _hostname_only(_raw_header_value(raw_http.replace("\r\n", "\n"), "Host"))
    if not host and target_url:
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.hostname or ""
    return host


def _safe_capture_name(cve_id: str, host: str) -> str:
    label = cve_id.strip().upper() if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id.strip(), re.I) else "capture"
    return f"{label}.pcap"


def _dated_output_path(output_dir: Path, filename: str, now: datetime | None = None) -> Path:
    test_date = (now or datetime.now()).strftime("%Y-%m-%d")
    return output_dir / test_date / filename


def _find_tool(name: str, explicit: str = "") -> str:
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / f"{name}.exe"
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(f"未找到 {name}，请安装 Wireshark/Npcap 或设置对应环境变量")


class DumpcapCapture:
    def __init__(self, output_path: Path, interface: str, dumpcap_path: str = "") -> None:
        self.output_path = output_path
        self.interface = interface
        self.dumpcap_path = _find_tool("dumpcap", dumpcap_path)
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        command = [self.dumpcap_path, "-q", "-i", self.interface, "-F", "pcap", "-w", str(self.output_path)]
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(0.7)
        if self.process.poll() is not None:
            error = self.process.stderr.read().strip() if self.process.stderr else ""
            raise RuntimeError(error or "dumpcap 未能启动")

    def stop(self) -> None:
        if not self.process or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def _packet_count(path: Path, tshark_path: str = "") -> int:
    if not path.is_file() or path.stat().st_size == 0:
        return 0
    tshark = _find_tool("tshark", tshark_path)
    result = subprocess.run(
        [tshark, "-r", str(path), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return len([line for line in result.stdout.splitlines() if line.strip()])


class LocalHttp2PcapServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], output_dir: Path, interface: str) -> None:
        super().__init__(address, LocalHttp2PcapHandler)
        self.output_dir = output_dir.resolve()
        self.interface = interface
        self.dumpcap_path = os.getenv("DUMPCAP_PATH", "")
        self.tshark_path = os.getenv("TSHARK_PATH", "")


class LocalHttp2PcapHandler(BaseHTTPRequestHandler):
    server: LocalHttp2PcapServer

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def _respond(self, status: int, payload: dict) -> None:
        body = _json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in {"/", "/health", "/api/health"}:
            self._respond(200, {"status": "ok", "interface": self.server.interface, "output_dir": str(self.server.output_dir)})
            return
        if self.path.startswith("/pcap/"):
            relative_path = Path(unquote(self.path.removeprefix("/pcap/")))
            path = (self.server.output_dir / relative_path).resolve()
            if self.server.output_dir not in path.parents or not path.is_file():
                self._respond(404, {"success": False, "error": "PCAP 文件不存在"})
                return
            name = path.name
            content = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        self._respond(404, {"success": False, "error": "接口不存在"})

    def do_POST(self) -> None:
        if self.path != "/api/http2pcap":
            self._respond(501 if self.path == "/api/nuclei-poc" else 404, {"success": False, "error": "本地服务当前仅支持 raw HTTP 发包"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2 * 1024 * 1024:
                raise ValueError("请求体大小无效")
            payload = json.loads(self.rfile.read(length))
            raw_http = str(payload.get("raw_http", ""))
            target_url = str(payload.get("target_url", ""))
            cve_id = str(payload.get("cve_id", ""))
            host = _target_host(raw_http, target_url)
            if not raw_http.strip():
                raise ValueError("缺少 raw_http")
            if not host or not is_local_lab_host(host):
                self._respond(403, {"success": False, "error": f"本地服务拒绝非本地/私网目标: {host or 'unknown'}", "error_type": "policy_blocked"})
                return
            result = self._capture_and_send(raw_http, target_url, cve_id, host)
            self._respond(200, result)
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond(400, {"success": False, "error": str(exc), "error_type": "invalid_request"})
        except Exception as exc:
            self._respond(500, {"success": False, "error": str(exc), "error_type": "capture_failed"})

    def _capture_and_send(self, raw_http: str, target_url: str, cve_id: str, host: str) -> dict:
        output_path = _dated_output_path(self.server.output_dir, _safe_capture_name(cve_id, host))
        capture = DumpcapCapture(output_path, self.server.interface, self.server.dumpcap_path)
        with CAPTURE_LOCK:
            capture.start()
            try:
                result = _send_raw_http_socket(raw_http, target_url, capture=False, cve_id=cve_id)
                time.sleep(0.8)
            finally:
                capture.stop()
        count = _packet_count(output_path, self.server.tshark_path)
        result.update(
            pcap_file_path=str(output_path),
            pcap_download_url=(
                f"http://{self.headers.get('Host', '127.0.0.1')}/pcap/"
                f"{quote(output_path.relative_to(self.server.output_dir).as_posix())}"
            ),
            packet_count=count,
            ips_matches=[],
        )
        if count == 0:
            result.update(success=False, error="抓包完成但未捕获到数据包，请检查 CAPTURE_INTERFACE", error_type="capture_failed")
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="本地 raw HTTP 发包与 PCAP 抓包服务")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机")
    parser.add_argument("--port", type=int, default=3012, help="监听端口")
    parser.add_argument("--interface", default=os.getenv("CAPTURE_INTERFACE", DEFAULT_INTERFACE), help="dumpcap 抓包接口名称或编号")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="PCAP 输出目录")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server = LocalHttp2PcapServer((args.host, args.port), args.output_dir, args.interface)
    print(f"http2pcap listening on http://{args.host}:{args.port}")
    print(f"capture interface: {args.interface}")
    print(f"pcap output: {server.output_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
