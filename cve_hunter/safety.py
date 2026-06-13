"""Execution policy helpers for CVE verification.

The workflow may generate executable PoC candidates before a human has
confirmed the target scope. This module keeps the final execution decision
small, explicit, and testable.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


RUN_MODE_PLAN_ONLY = "plan_only"
RUN_MODE_LOCAL_LAB = "local_lab"
RUN_MODE_AUTHORIZED_TARGET = "authorized_target"
VALID_RUN_MODES = {
    RUN_MODE_PLAN_ONLY,
    RUN_MODE_LOCAL_LAB,
    RUN_MODE_AUTHORIZED_TARGET,
}


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    run_mode: str
    target_url: str
    target_host: str
    reason: str

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "allowed": self.allowed,
            "run_mode": self.run_mode,
            "target_url": self.target_url,
            "target_host": self.target_host,
            "reason": self.reason,
        }


def normalize_run_mode(value: str) -> str:
    mode = (value or RUN_MODE_PLAN_ONLY).strip().lower()
    return mode if mode in VALID_RUN_MODES else RUN_MODE_PLAN_ONLY


def evaluate_execution_policy(
    target_url: str,
    target_host: str = "",
    *,
    run_mode: str,
    allowlist: list[str] | tuple[str, ...] | None = None,
) -> PolicyDecision:
    mode = normalize_run_mode(run_mode)
    host = _hostname(target_host or target_url)
    target_label = target_host or host or target_url
    allowlist = list(allowlist or [])

    if mode == RUN_MODE_PLAN_ONLY:
        return PolicyDecision(
            allowed=False,
            run_mode=mode,
            target_url=target_url,
            target_host=target_label,
            reason="RUN_MODE=plan_only blocks network execution",
        )

    if mode == RUN_MODE_LOCAL_LAB:
        if is_local_lab_host(host) or is_allowlisted_target(host, target_label, allowlist):
            return PolicyDecision(True, mode, target_url, target_label, "target is local/private or allowlisted")
        return PolicyDecision(
            allowed=False,
            run_mode=mode,
            target_url=target_url,
            target_host=target_label,
            reason=f"RUN_MODE=local_lab only allows local/private targets; got {target_label}",
        )

    if is_allowlisted_target(host, target_label, allowlist):
        return PolicyDecision(True, mode, target_url, target_label, "target matched TARGET_ALLOWLIST")

    return PolicyDecision(
        allowed=False,
        run_mode=mode,
        target_url=target_url,
        target_host=target_label,
        reason=f"RUN_MODE=authorized_target requires TARGET_ALLOWLIST match; got {target_label}",
    )


def is_local_lab_host(host: str) -> bool:
    host = (host or "").strip().strip("[]").lower()
    if not host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private or ip.is_link_local)


def is_allowlisted_target(host: str, target_label: str, allowlist: list[str] | tuple[str, ...]) -> bool:
    host = (host or "").strip().strip("[]").lower()
    target_label = (target_label or "").strip().lower()
    if not host and not target_label:
        return False

    for raw_entry in allowlist:
        entry = str(raw_entry or "").strip()
        if not entry:
            continue
        if entry == "*":
            return True

        normalized_entry = entry.lower()
        entry_host = _hostname(entry)
        if _matches_cidr(host, normalized_entry):
            return True
        if entry_host and _matches_cidr(host, entry_host):
            return True

        candidates = {normalized_entry}
        if entry_host:
            candidates.add(entry_host.lower())
        for candidate in candidates:
            if candidate in {host, target_label}:
                return True
            if fnmatch.fnmatchcase(host, candidate) or fnmatch.fnmatchcase(target_label, candidate):
                return True
    return False


def _matches_cidr(host: str, cidr: str) -> bool:
    if "/" not in cidr:
        return False
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _hostname(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if host:
        return host.strip("[]")
    return value.split("/", 1)[0].split(":", 1)[0].strip("[]")
