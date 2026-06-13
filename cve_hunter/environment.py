"""Structured attack-environment manifest support."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class HealthCheckSpec:
    url: str = ""
    expected_status: int = 200
    timeout_seconds: int = 60


@dataclass
class SafetySpec:
    run_mode: str = "plan_only"
    network_scope: str = "plan_only"
    allowlist: list[str] = field(default_factory=list)


@dataclass
class EnvironmentSpec:
    cve_id: str
    target_url: str = ""
    target_host: str = ""
    source: str = "default_target"
    kind: str = "remote_or_existing_target"
    compose_file: str = ""
    workdir: str = ""
    setup_mode: str = ""
    setup_result: dict[str, Any] = field(default_factory=dict)
    healthcheck: HealthCheckSpec = field(default_factory=HealthCheckSpec)
    preconditions: list[str] = field(default_factory=list)
    evidence_urls: list[str] = field(default_factory=list)
    confidence: float = 0.0
    reason: str = ""
    safety: SafetySpec = field(default_factory=SafetySpec)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_environment_spec(
    *,
    cve_id: str,
    environment: dict[str, Any],
    candidates: list[dict[str, Any]] | None = None,
    run_mode: str,
    allowlist: list[str] | tuple[str, ...] | None = None,
    preconditions: list[str] | None = None,
    evidence_urls: list[str] | None = None,
) -> dict[str, Any]:
    candidates = candidates or []
    selected = candidates[0] if candidates else {}
    target_url = str(environment.get("target_url") or selected.get("target_url") or "")
    target_host = str(environment.get("target_host") or selected.get("target_host") or "")
    compose_file = str(environment.get("compose_file") or selected.get("compose_file") or "")
    setup_result = environment.get("setup_result") if isinstance(environment.get("setup_result"), dict) else {}
    setup_mode = str(environment.get("setup_mode") or ("docker_compose" if compose_file else "not_required"))
    source = str(environment.get("source") or selected.get("source") or "default_target")
    kind = str(environment.get("kind") or selected.get("kind") or "remote_or_existing_target")

    confidence = 0.35
    if source in {"explicit_compose", "vulhub_local"}:
        confidence = 0.75
    if setup_result.get("success"):
        confidence = 0.9

    spec = EnvironmentSpec(
        cve_id=cve_id,
        target_url=target_url,
        target_host=target_host,
        source=source,
        kind=kind,
        compose_file=compose_file,
        workdir=str(environment.get("workdir") or selected.get("workdir") or ""),
        setup_mode=setup_mode,
        setup_result=setup_result,
        healthcheck=HealthCheckSpec(url=target_url),
        preconditions=list(preconditions or []),
        evidence_urls=list(evidence_urls or []),
        confidence=confidence,
        reason=str(environment.get("reason") or selected.get("reason") or ""),
        safety=SafetySpec(
            run_mode=run_mode,
            network_scope=_network_scope(run_mode),
            allowlist=list(allowlist or []),
        ),
    )
    return spec.to_dict()


def write_environment_manifest(spec: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "environment_manifest.json"
    path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _network_scope(run_mode: str) -> str:
    mode = (run_mode or "plan_only").strip().lower()
    if mode == "local_lab":
        return "local_or_private"
    if mode == "authorized_target":
        return "explicit_allowlist"
    return "plan_only"
