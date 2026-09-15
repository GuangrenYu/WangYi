"""Per-run options that must remain isolated across concurrent web tasks."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
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


def as_target_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    if ":" in target and not target.startswith("["):
        target = f"[{target}]"
    return f"http://{target}"


@contextmanager
def run_options(*, target_ip: str = "", local_only: bool = False) -> Iterator[None]:
    token = _target_ip.set(str(target_ip or "").strip())
    local_token = _local_only.set(local_only)
    try:
        yield
    finally:
        _target_ip.reset(token)
        _local_only.reset(local_token)
