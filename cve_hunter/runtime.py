"""Per-run options that must remain isolated across concurrent web tasks."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import ipaddress
from urllib.parse import urlsplit
from typing import Iterator

from cve_hunter.config import cfg


_target_ip: ContextVar[str] = ContextVar("cve_hunter_target_ip", default="")
_local_only: ContextVar[bool] = ContextVar("cve_hunter_local_only", default=False)


def is_local_only() -> bool:
    return _local_only.get()


def explicit_target_ip() -> str:
    return _target_ip.get().strip()


def effective_target_ip() -> str:
    return _target_ip.get().strip() or cfg.target_ip


def normalize_target(value: str, *, default_port: int | None = None) -> str:
    """Normalize an IP/host:port or HTTP URL, optionally filling a missing port."""
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("目标必须是 IP 或 IP:端口")

    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("目标端口必须在 1-65535 范围内") from exc
    else:
        host = ""
        port = None
        try:
            ipaddress.ip_address(raw)
            host = raw
        except ValueError:
            parsed = urlsplit(f"//{raw}")
            host = parsed.hostname or ""
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("目标端口必须在 1-65535 范围内") from exc

    if not host:
        raise ValueError("目标必须是 IP 或 IP:端口")
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("目标必须是有效的 IPv4 或 IPv6 地址") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("目标端口必须在 1-65535 范围内")
    if port is None and default_port is not None:
        try:
            candidate_port = int(default_port)
        except (TypeError, ValueError):
            candidate_port = 0
        if 1 <= candidate_port <= 65535:
            port = candidate_port
    return format_target(host, port)


def format_target(host: str, port: int | None = None) -> str:
    """Format an IP and optional port for Host headers and runtime options."""
    text = str(host or "").strip()
    if ":" in text and not text.startswith("["):
        text = f"[{text}]"
    return f"{text}:{port}" if port is not None else text


def _target_has_port(target: str) -> bool:
    raw = str(target or "").strip()
    if raw.startswith(("http://", "https://")):
        return urlsplit(raw).port is not None
    try:
        ipaddress.ip_address(raw)
        return False
    except ValueError:
        try:
            return urlsplit(f"//{raw}").port is not None
        except ValueError:
            return False


def as_target_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    normalized = normalize_target(target)
    if not _target_has_port(normalized):
        configured_port = int(getattr(cfg, "target_port", 0) or 0)
        if 1 <= configured_port <= 65535:
            normalized = format_target(normalized, configured_port)
    return f"http://{normalized}"


@contextmanager
def run_options(*, target_ip: str = "", local_only: bool = False) -> Iterator[None]:
    raw_target = str(target_ip or "").strip()
    # Normalize task-scoped targets once so every downstream executor sees the
    # same host:port, while an explicit port remains authoritative.
    try:
        task_target = normalize_target(raw_target, default_port=getattr(cfg, "target_port", 0)) if raw_target else ""
    except ValueError:
        task_target = raw_target
    token = _target_ip.set(task_target)
    local_token = _local_only.set(local_only)
    try:
        yield
    finally:
        _target_ip.reset(token)
        _local_only.reset(local_token)
