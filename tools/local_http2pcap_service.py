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
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import yaml

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


def _pending_output_path(output_dir: Path, filename: str, now: datetime | None = None) -> Path:
    return _dated_output_path(output_dir / ".pending", filename, now)


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


def _nuclei_findings(output: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            findings.append(item)
    return findings


def _run_nuclei_poc(
    yaml_content: str,
    target_url: str,
    *,
    nuclei_path: str = "",
    timeout: int = 90,
) -> dict:
    try:
        template = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise ValueError(f"Nuclei YAML 无效: {exc}") from exc
    if not isinstance(template, dict) or not template.get("http"):
        raise ValueError("本地服务仅执行包含 http 请求的 Nuclei 模板")

    try:
        nuclei = _find_tool("nuclei", nuclei_path)
    except FileNotFoundError as exc:
        # Do not bubble as capture_failed; nuclei is optional tooling for yaml PoCs.
        return {
            "success": False,
            "matched": False,
            "error": str(exc),
            "error_type": "tool_missing",
        }

    # Prefer a project-local temp dir. On this Windows/Docker setup, templates
    # under D:\Docker\tmp are sometimes invisible to nuclei and yield
    # "no templates provided for scan".
    temp_root = ROOT / "output" / ".tmp" / "nuclei"
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cve-hunter-nuclei-", dir=str(temp_root)) as temp_dir:
        template_path = Path(temp_dir) / "poc.yaml"
        template_path.write_text(yaml_content, encoding="utf-8")
        command = [
            nuclei,
            "-u",
            target_url,
            "-t",
            str(template_path.resolve()),
            "-jsonl",
            "-silent",
            "-no-color",
            "-duc",
            "-no-interactsh",
            "-pt",
            "http",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "matched": False,
                "error": f"Nuclei 执行超过 {timeout}s",
                "error_type": "request_failed",
            }

    findings = _nuclei_findings(completed.stdout)
    if completed.returncode != 0:
        error = completed.stderr.strip() or completed.stdout.strip() or f"exit code {completed.returncode}"
        return {
            "success": False,
            "matched": False,
            "error": f"Nuclei 执行失败: {error[:2000]}",
            "error_type": "request_failed",
        }

    first = findings[0] if findings else {}
    response = str(first.get("response") or "")
    return {
        "success": True,
        "matched": bool(findings),
        "status_code": int(first.get("status-code") or 0),
        "body": response[-2000:],
        "result_info": completed.stdout.strip()[:4000],
    }


class LocalHttp2PcapServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], output_dir: Path, interface: str) -> None:
        super().__init__(address, LocalHttp2PcapHandler)
        self.output_dir = output_dir.resolve()
        self.interface = interface
        self.dumpcap_path = os.getenv("DUMPCAP_PATH", "")
        self.tshark_path = os.getenv("TSHARK_PATH", "")
        self.nuclei_path = os.getenv("NUCLEI_PATH", "")
        self.nuclei_timeout = int(os.getenv("NUCLEI_TIMEOUT", "90"))


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
            tools = {}
            for name, explicit in (
                ("dumpcap", self.server.dumpcap_path),
                ("tshark", self.server.tshark_path),
                ("nuclei", self.server.nuclei_path),
            ):
                try:
                    tools[name] = {"available": True, "path": _find_tool(name, explicit)}
                except FileNotFoundError:
                    tools[name] = {"available": False, "path": ""}
            self._respond(
                200,
                {
                    "status": "ok",
                    "interface": self.server.interface,
                    "output_dir": str(self.server.output_dir),
                    "tools": tools,
                },
            )
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
        if self.path not in {"/api/http2pcap", "/api/nuclei-poc"}:
            self._respond(404, {"success": False, "error": "接口不存在"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2 * 1024 * 1024:
                raise ValueError("请求体大小无效")
            payload = json.loads(self.rfile.read(length))
            raw_http = str(payload.get("raw_http", ""))
            yaml_content = str(payload.get("yaml_content", ""))
            target_url = str(payload.get("target_url", ""))
            cve_id = str(payload.get("cve_id", ""))
            host = _target_host(raw_http, target_url)
            if self.path == "/api/http2pcap" and not raw_http.strip():
                raise ValueError("缺少 raw_http")
            if self.path == "/api/nuclei-poc" and (not yaml_content.strip() or not target_url.strip()):
                raise ValueError("缺少 yaml_content 或 target_url")
            if not host or not is_local_lab_host(host):
                self._respond(403, {"success": False, "error": f"本地服务拒绝非本地/私网目标: {host or 'unknown'}", "error_type": "policy_blocked"})
                return
            if self.path == "/api/nuclei-poc":
                result = self._capture_and_run_nuclei(yaml_content, target_url, cve_id, host)
            else:
                result = self._capture_and_send(raw_http, target_url, cve_id, host)
            self._respond(200, result)
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond(400, {"success": False, "error": str(exc), "error_type": "invalid_request"})
        except Exception as exc:
            self._respond(500, {"success": False, "error": str(exc), "error_type": "capture_failed"})

    def _capture_and_send(self, raw_http: str, target_url: str, cve_id: str, host: str) -> dict:
        return self._capture_operation(
            cve_id,
            host,
            lambda: _send_raw_http_socket(raw_http, target_url, capture=False, cve_id=cve_id),
        )

    def _capture_and_run_nuclei(self, yaml_content: str, target_url: str, cve_id: str, host: str) -> dict:
        # Resolve nuclei before starting dumpcap so a missing binary does not
        # look like a packet-capture failure.
        try:
            _find_tool("nuclei", self.server.nuclei_path)
        except FileNotFoundError as exc:
            return {
                "success": False,
                "matched": False,
                "error": str(exc),
                "error_type": "tool_missing",
                "pcap_file_path": "",
                "pcap_download_url": "",
                "packet_count": 0,
                "ips_matches": [],
            }
        return self._capture_operation(
            cve_id,
            host,
            lambda: _run_nuclei_poc(
                yaml_content,
                target_url,
                nuclei_path=self.server.nuclei_path,
                timeout=self.server.nuclei_timeout,
            ),
        )

    def _capture_operation(self, cve_id: str, host: str, operation: Callable[[], dict]) -> dict:
        output_path = _pending_output_path(self.server.output_dir, _safe_capture_name(cve_id, host))
        capture = DumpcapCapture(output_path, self.server.interface, self.server.dumpcap_path)
        with CAPTURE_LOCK:
            output_path.unlink(missing_ok=True)
            try:
                capture.start()
                try:
                    result = operation()
                    time.sleep(0.8)
                finally:
                    capture.stop()
                count = _packet_count(output_path, self.server.tshark_path)
            except Exception:
                output_path.unlink(missing_ok=True)
                raise
        # If the operation itself failed for non-capture reasons (e.g. nuclei
        # runtime error), keep that error_type and do not overwrite with capture_failed.
        operation_failed = not result.get("success", False)
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
            output_path.unlink(missing_ok=True)
            if operation_failed:
                result.update(
                    pcap_file_path="",
                    pcap_download_url="",
                )
            else:
                result.update(
                    success=False,
                    pcap_file_path="",
                    pcap_download_url="",
                    error="抓包完成但未捕获到数据包，请检查 CAPTURE_INTERFACE",
                    error_type="capture_failed",
                )
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="本地 HTTP/Nuclei PoC 发包与 PCAP 抓包服务")
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
