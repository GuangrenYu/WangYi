"""Read-only preflight checks for local Docker Compose environments."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cve_hunter.agents import _guess_target_url_from_compose


_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
_CVE_ID_PATTERN = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)
_NON_HTTP_PORTS = {
    22, 25, 110, 143, 389, 445, 873, 1433, 1521, 1883, 2375, 3306,
    5432, 5672, 6379, 9042, 9300, 11211, 27017, 61616,
}


def run_environment_preflight(
    cve_ids: list[str],
    *,
    compose_root: Path,
    input_file: Path,
    output_dir: Path,
    range_start: int,
    range_end: int,
) -> tuple[dict[str, Any], Path, Path]:
    """Inspect Compose definitions without pulling images or starting containers."""
    compose_index = _index_compose_files(compose_root)
    compose_command = _docker_compose_command()
    cached_images = _cached_images()
    records: list[dict[str, Any]] = []

    for index, cve_id in enumerate(cve_ids, start=range_start):
        paths = compose_index.get(cve_id.upper(), [])
        if not paths:
            records.append(_missing_record(index, cve_id))
            continue
        records.append(_inspect_compose(
            index=index,
            cve_id=cve_id,
            compose_file=paths[0],
            alternative_compose_files=paths[1:],
            compose_command=compose_command,
            cached_images=cached_images,
        ))

    port_counts = Counter(
        str(port)
        for record in records
        for port in record.get("published_ports", [])
    )
    conflicting_ports = {port: count for port, count in port_counts.items() if count > 1}
    for record in records:
        record_conflicts = {
            str(port): conflicting_ports[str(port)]
            for port in record.get("published_ports", [])
            if str(port) in conflicting_ports
        }
        record["port_conflicts"] = record_conflicts
        if record_conflicts:
            record["warnings"].append("published_port_conflict")

    summary = _summarize(records, conflicting_ports)
    report = {
        "generated_at": datetime.now().isoformat(),
        "input_file": str(input_file),
        "range_start": range_start,
        "range_end": range_end,
        "compose_root": str(compose_root),
        "cached_image_count": len(cached_images),
        "summary": summary,
        "records": records,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{input_file.stem}_{range_start}_{range_end}"
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(render_preflight_markdown(report), encoding="utf-8")
    return report, json_path, markdown_path


def render_preflight_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Local Environment Preflight",
        "",
        f"Generated: {report['generated_at']}",
        f"Input: `{report['input_file']}`",
        f"Range: {report['range_start']}-{report['range_end']}",
        f"Compose root: `{report['compose_root']}`",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for key in (
        "total",
        "compose_found",
        "config_valid",
        "config_invalid",
        "fully_cached",
        "partially_cached",
        "build_required",
        "no_published_port",
        "multiple_published_ports",
        "static_start_ready",
    ):
        lines.append(f"| `{key}` | {summary[key]} |")

    lines.extend([
        "",
        "## Port Conflicts",
        "",
        "| Published port | Environments |",
        "|---|---:|",
    ])
    for port, count in summary["conflicting_ports"].items():
        lines.append(f"| `{port}` | {count} |")
    if not summary["conflicting_ports"]:
        lines.append("| none | 0 |")

    lines.extend([
        "",
        "## Environments",
        "",
        "| # | CVE | Config | Media | Services | Ports | Check | Static start | Warnings | Compose |",
        "|---:|---|---|---|---:|---|---|---|---|---|",
    ])
    for record in report["records"]:
        config_status = "valid" if record["config_valid"] else "invalid"
        ports = ", ".join(str(port) for port in record["published_ports"]) or "none"
        warnings = ", ".join(record["warnings"]) or "none"
        compose_file = record["compose_file"] or "none"
        lines.append(
            f"| {record['index']} | {record['cve_id']} | {config_status} | "
            f"{record['media_status']} | {record['service_count']} | {ports} | "
            f"{record['suggested_healthcheck']} | {str(record['static_start_ready']).lower()} | "
            f"{warnings} | `{compose_file}` |"
        )
    lines.append("")
    return "\n".join(lines)


def _inspect_compose(
    *,
    index: int,
    cve_id: str,
    compose_file: Path,
    alternative_compose_files: list[Path],
    compose_command: list[str] | None,
    cached_images: set[str],
) -> dict[str, Any]:
    base = _base_record(index, cve_id, compose_file, alternative_compose_files)
    if not compose_command:
        base["error"] = "docker compose command is unavailable"
        base["warnings"].append("docker_compose_unavailable")
        return base

    config, error = _load_effective_compose(compose_file, compose_command)
    if error:
        base["error"] = error
        base["warnings"].append("compose_config_invalid")
        return base

    services_data = config.get("services") if isinstance(config, dict) else None
    services = list(services_data.values()) if isinstance(services_data, dict) else []
    images = sorted({
        str(service.get("image") or "").strip()
        for service in services
        if isinstance(service, dict) and str(service.get("image") or "").strip()
    })
    cached = sorted(image for image in images if image in cached_images)
    builds = sum(1 for service in services if isinstance(service, dict) and service.get("build") is not None)
    ports = _published_ports(services)
    target_url = _guess_target_url_from_compose(compose_file)
    suggested_healthcheck = _suggested_healthcheck(target_url)
    compose_healthchecks = sum(
        1 for service in services
        if isinstance(service, dict) and service.get("healthcheck")
    )

    if builds:
        media_status = "build_required"
    elif images and len(cached) == len(images):
        media_status = "fully_cached"
    elif cached:
        media_status = "partially_cached"
    else:
        media_status = "not_cached"

    warnings: list[str] = []
    if builds:
        warnings.append("build_required")
    if media_status not in {"fully_cached"}:
        warnings.append("images_not_fully_cached")
    if not ports:
        warnings.append("no_published_port")
    if len(ports) > 1:
        warnings.append("multiple_published_ports")

    base.update({
        "config_valid": True,
        "service_count": len(services),
        "images": images,
        "cached_images": cached,
        "all_images_cached": bool(images) and len(cached) == len(images),
        "build_service_count": builds,
        "media_status": media_status,
        "published_ports": ports,
        "target_url": target_url,
        "suggested_healthcheck": suggested_healthcheck,
        "compose_healthcheck_count": compose_healthchecks,
        "static_start_ready": (
            media_status == "fully_cached"
            and bool(target_url)
            and suggested_healthcheck in {"http", "tcp"}
        ),
        "warnings": warnings,
    })
    return base


def _load_effective_compose(
    compose_file: Path,
    compose_command: list[str],
) -> tuple[dict[str, Any], str]:
    try:
        result = subprocess.run(
            [*compose_command, "-f", str(compose_file), "config", "--format", "json"],
            cwd=compose_file.parent,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {}, str(exc)
    if result.returncode != 0:
        return {}, (result.stderr or result.stdout or "compose config failed").strip()
    try:
        return json.loads(result.stdout), ""
    except json.JSONDecodeError as exc:
        return {}, f"compose config returned invalid JSON: {exc}"


def _cached_images() -> set[str]:
    docker = shutil.which("docker")
    if not docker:
        return set()
    try:
        result = subprocess.run(
            [docker, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode != 0:
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _docker_compose_command() -> list[str] | None:
    docker = shutil.which("docker")
    if docker:
        return [docker, "compose"]
    docker_compose = shutil.which("docker-compose")
    return [docker_compose] if docker_compose else None


def _index_compose_files(root: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    if not root.is_dir():
        return index
    for path in root.rglob("*"):
        if not path.is_file() or path.name.lower() not in _COMPOSE_NAMES:
            continue
        cve_id = next(
            (
                match.group(0).upper()
                for part in reversed(path.parts[:-1])
                if (match := _CVE_ID_PATTERN.search(part))
            ),
            "",
        )
        if cve_id:
            index.setdefault(cve_id, []).append(path.resolve())
    return {
        cve_id: sorted(paths, key=lambda item: (len(item.parts), str(item).lower()))
        for cve_id, paths in index.items()
    }


def _published_ports(services: list[Any]) -> list[str]:
    ports: list[str] = []
    for service in services:
        if not isinstance(service, dict):
            continue
        for port in service.get("ports") or []:
            if isinstance(port, dict):
                published = port.get("published") or port.get("host_port")
            else:
                published = None
            if published is not None:
                ports.append(str(published))
    return ports


def _suggested_healthcheck(target_url: str) -> str:
    if not target_url:
        return "none"
    port = urlparse(target_url).port
    return "tcp" if port in _NON_HTTP_PORTS else "http"


def _base_record(
    index: int,
    cve_id: str,
    compose_file: Path,
    alternatives: list[Path],
) -> dict[str, Any]:
    return {
        "index": index,
        "cve_id": cve_id,
        "compose_file": str(compose_file),
        "alternative_compose_files": [str(path) for path in alternatives],
        "config_valid": False,
        "service_count": 0,
        "images": [],
        "cached_images": [],
        "all_images_cached": False,
        "build_service_count": 0,
        "media_status": "unknown",
        "published_ports": [],
        "target_url": "",
        "suggested_healthcheck": "none",
        "compose_healthcheck_count": 0,
        "static_start_ready": False,
        "port_conflicts": {},
        "warnings": [],
        "error": "",
    }


def _missing_record(index: int, cve_id: str) -> dict[str, Any]:
    record = _base_record(index, cve_id, Path(), [])
    record["compose_file"] = ""
    record["warnings"] = ["compose_not_found"]
    record["error"] = "compose file not found"
    return record


def _summarize(records: list[dict[str, Any]], conflicts: dict[str, int]) -> dict[str, Any]:
    return {
        "total": len(records),
        "compose_found": sum(bool(record["compose_file"]) for record in records),
        "config_valid": sum(bool(record["config_valid"]) for record in records),
        "config_invalid": sum(not record["config_valid"] for record in records),
        "fully_cached": sum(record["media_status"] == "fully_cached" for record in records),
        "partially_cached": sum(record["media_status"] == "partially_cached" for record in records),
        "build_required": sum(record["media_status"] == "build_required" for record in records),
        "no_published_port": sum(not record["published_ports"] for record in records),
        "multiple_published_ports": sum(len(record["published_ports"]) > 1 for record in records),
        "static_start_ready": sum(bool(record["static_start_ready"]) for record in records),
        "conflicting_ports": dict(sorted(conflicts.items(), key=lambda item: (-item[1], item[0]))),
    }
