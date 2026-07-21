"""Database / non-HTTP TCP capture helpers (dumpcap).

HTTP 路径已有 http_sender 内的 dumpcap；数据库直连不经过 http2pcap，
因此在执行前后单独包一层 TCP 抓包，产物仍走 PCAP_OUTPUT_DIR/.pending
与 finalize_capture 晋升逻辑。

Windows + Docker Desktop 注意：映射到 127.0.0.1 的容器端口流量不一定出现在
NPF_Loopback 上，可能在 vEthernet (WSL) 等接口。因此默认对多个候选接口
并行抓包，结束后保留包数最多的 pcap。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cve_hunter.config import cfg


@dataclass
class _IfaceCapture:
    interface: str
    pcap_path: str
    process: subprocess.Popen | None = None
    error: str = ""


@dataclass
class TcpCaptureSession:
    """One or more dumpcap sessions covering candidate interfaces."""

    pcap_path: str = ""
    process: subprocess.Popen | None = None  # 兼容旧字段：主进程（若仅一个）
    interface: str = ""
    bpf_filter: str = ""
    enabled: bool = False
    error: str = ""
    _captures: list[_IfaceCapture] = field(default_factory=list, repr=False)

    def stop(self) -> dict[str, Any]:
        time.sleep(1.2)
        best_path = ""
        best_packets = -1
        best_iface = self.interface
        errors: list[str] = []

        captures = list(self._captures)
        if not captures and self.process is not None and self.pcap_path:
            captures = [
                _IfaceCapture(interface=self.interface, pcap_path=self.pcap_path, process=self.process)
            ]

        for item in captures:
            if item.process is not None:
                _stop_process(item.process)
                item.process = None
            path = item.pcap_path
            if not path or not Path(path).is_file():
                if item.error:
                    errors.append(f"{item.interface}: {item.error}")
                continue
            packets = _pcap_packet_count(Path(path))
            size = Path(path).stat().st_size
            if packets > best_packets or (packets == best_packets and size > 24 and not best_path):
                # 清理上一份较差文件
                if best_path and best_path != path:
                    try:
                        Path(best_path).unlink(missing_ok=True)
                    except OSError:
                        pass
                best_path = path
                best_packets = packets
                best_iface = item.interface
            else:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError:
                    pass

        self.process = None
        self.pcap_path = best_path
        self.interface = best_iface or self.interface
        packet_count = max(best_packets, 0) if best_path else 0

        if best_path and Path(best_path).stat().st_size <= 24 and packet_count <= 0:
            self.error = self.error or (
                "抓包文件为空（Docker Desktop 流量可能不在所选网卡；"
                "可设置 CAPTURE_INTERFACE 指向 vEthernet (WSL) 等）"
            )
        if errors and not best_path:
            self.error = self.error or "; ".join(errors[:3])

        return {
            "pcap_file_path": best_path,
            "packet_count": packet_count,
            "capture_interface": self.interface,
            "capture_filter": self.bpf_filter,
            "capture_enabled": self.enabled,
            "capture_error": self.error,
            "capture_interfaces_tried": [c.interface for c in captures],
        }


def db_tcp_capture_enabled() -> bool:
    """Whether database path should attempt TCP capture."""
    raw = os.getenv("DB_TCP_CAPTURE_ENABLED")
    if raw is not None and raw.strip() != "":
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return str(getattr(cfg, "run_mode", "plan_only") or "").lower() == "local_lab"


def start_tcp_capture(
    *,
    host: str = "127.0.0.1",
    port: int | None = None,
    cve_id: str = "",
    protocol: str = "database",
) -> TcpCaptureSession:
    """Start dumpcap on candidate interfaces (parallel) filtered to port."""
    if not db_tcp_capture_enabled():
        return TcpCaptureSession(
            enabled=False,
            error="DB_TCP_CAPTURE_ENABLED=false 或非 local_lab",
        )

    dumpcap = os.getenv("DUMPCAP_PATH") or shutil.which("dumpcap")
    if not dumpcap:
        return TcpCaptureSession(
            enabled=True,
            error="未找到 dumpcap（请安装 Wireshark/Npcap 并加入 PATH）",
        )

    bpf = _build_bpf_filter(host=host, port=port)
    interfaces = _candidate_interfaces(dumpcap)
    if not interfaces:
        return TcpCaptureSession(enabled=True, error="未找到可用抓包网卡", bpf_filter=bpf)

    captures: list[_IfaceCapture] = []
    base = _capture_output_path(cve_id=cve_id, protocol=protocol, port=port)
    for index, interface in enumerate(interfaces):
        path = base
        if index > 0:
            path = base.with_name(f"{base.stem}_if{index}{base.suffix}")
        cmd = [dumpcap, "-q", "-i", interface, "-F", "pcap", "-w", str(path)]
        if bpf:
            cmd.extend(["-f", bpf])
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            captures.append(_IfaceCapture(interface=interface, pcap_path=str(path), process=process))
        except Exception as exc:
            captures.append(
                _IfaceCapture(interface=interface, pcap_path=str(path), process=None, error=str(exc))
            )

    # 等待 dumpcap 就绪；去掉立刻退出的接口
    time.sleep(1.0)
    alive: list[_IfaceCapture] = []
    for item in captures:
        if item.process is None:
            continue
        if item.process.poll() is not None:
            err = item.process.stderr.read().strip() if item.process.stderr else "dumpcap 未能启动"
            item.error = err
            item.process = None
            try:
                Path(item.pcap_path).unlink(missing_ok=True)
            except OSError:
                pass
            continue
        alive.append(item)

    if not alive:
        errors = [f"{c.interface}: {c.error}" for c in captures if c.error]
        return TcpCaptureSession(
            enabled=True,
            bpf_filter=bpf,
            error="; ".join(errors[:4]) or "dumpcap 未能在任何接口上启动",
            _captures=captures,
        )

    primary = alive[0]
    return TcpCaptureSession(
        pcap_path=primary.pcap_path,
        process=primary.process,
        interface=primary.interface,
        bpf_filter=bpf,
        enabled=True,
        error="",
        _captures=alive,
    )


def _build_bpf_filter(*, host: str, port: int | None) -> str:
    parts: list[str] = []
    if port:
        parts.append(f"tcp port {int(port)}")
    host = (host or "").strip()
    if host and host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        parts.append(f"host {host}")
    return " and ".join(parts)


def _candidate_interfaces(dumpcap: str) -> list[str]:
    explicit = (os.getenv("CAPTURE_INTERFACE") or "").strip()
    if explicit:
        return [explicit]

    listed = _list_dumpcap_interfaces(dumpcap)
    if not listed:
        return [r"\Device\NPF_Loopback" if os.name == "nt" else "any"]

    preferred: list[str] = []
    secondary: list[str] = []
    for device, description in listed:
        text = f"{device} {description}".lower()
        if "loopback" in text or device.endswith("NPF_Loopback"):
            preferred.append(device)
        elif any(marker in text for marker in ("wsl", "hyper-v", "vethernet", "docker")):
            preferred.append(device)
        elif any(marker in text for marker in ("以太网", "ethernet", "wlan", "wi-fi", "wifi", "本地连接")):
            secondary.append(device)
        else:
            secondary.append(device)

    ordered = preferred + secondary
    seen: set[str] = set()
    out: list[str] = []
    for item in ordered:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out[:3]


def _list_dumpcap_interfaces(dumpcap: str) -> list[tuple[str, str]]:
    try:
        result = subprocess.run(
            [dumpcap, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except Exception:
        return []
    rows: list[tuple[str, str]] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line or ". " not in line:
            continue
        _, rest = line.split(". ", 1)
        if " (" in rest and rest.endswith(")"):
            device, desc = rest.rsplit(" (", 1)
            rows.append((device.strip(), desc[:-1].strip()))
        else:
            rows.append((rest.strip(), ""))
    return rows


def _capture_output_path(*, cve_id: str, protocol: str, port: int | None) -> Path:
    now = datetime.now()
    output_dir = Path(cfg.pcap_output_dir) / ".pending" / now.strftime("%Y-%m-%d")
    output_dir.mkdir(parents=True, exist_ok=True)
    cve_label = (
        cve_id.strip().upper()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", (cve_id or "").strip(), re.I)
        else "capture"
    )
    port_part = f"p{int(port)}" if port else "p0"
    stamp = now.strftime("%H%M%S")
    return output_dir / f"{cve_label}_{protocol}_{port_part}_{stamp}.pcap"


def _stop_process(process: subprocess.Popen) -> None:
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
    if not path.is_file():
        return 0
    try:
        size = path.stat().st_size
    except OSError:
        return 0
    if size <= 24:
        return 0
    if not tshark:
        return max(1, (size - 24) // 64)
    try:
        result = subprocess.run(
            [tshark, "-r", str(path), "-T", "fields", "-e", "frame.number"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
        return len(lines)
    except Exception:
        return max(1, (size - 24) // 64)
