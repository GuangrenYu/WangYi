"""Protocol-agnostic execution_spec helpers.

HTTP 走既有 http_sender；数据库走 database 执行器；其余协议仅保留接口。
"""

from __future__ import annotations

from typing import Any

from cve_hunter.executors.database import execute_database_spec
from cve_hunter.status_codes import PROTOCOL_UNSUPPORTED as STATUS_PROTOCOL_UNSUPPORTED


PROTOCOL_HTTP = "http"
PROTOCOL_DATABASE = "database"
PROTOCOL_TCP = "tcp"
PROTOCOL_KERNEL = "kernel"
PROTOCOL_UNSUPPORTED = "unsupported"


def infer_protocol(
    *,
    is_http_vuln: bool = True,
    vuln_type: str = "",
    description: str = "",
    execution_spec: dict[str, Any] | None = None,
) -> str:
    """Infer coarse protocol family for routing."""
    if execution_spec and execution_spec.get("protocol"):
        return str(execution_spec.get("protocol")).strip().lower() or PROTOCOL_HTTP

    text = f"{vuln_type} {description}".lower()
    db_markers = (
        "sql", "mysql", "mariadb", "postgres", "postgresql", "sqlite",
        "mongodb", "redis", "数据库", "dbms", "jdbc",
    )
    if any(marker in text for marker in db_markers):
        return PROTOCOL_DATABASE

    if any(marker in text for marker in ("kernel", "内核", "syscall", "privilege escalation", "本地提权")):
        return PROTOCOL_KERNEL

    if any(marker in text for marker in ("ssh", "ftp", "smtp", "ldap", "mqtt", "tcp", "udp", "smb")):
        return PROTOCOL_TCP

    if is_http_vuln:
        return PROTOCOL_HTTP
    return PROTOCOL_UNSUPPORTED


def build_execution_spec(
    *,
    protocol: str,
    cve_id: str = "",
    engine: str = "",
    version: str = "",
    target: str = "",
    config: list[str] | None = None,
    schema_sql: list[str] | None = None,
    setup_sql: list[str] | None = None,
    trigger_sql: list[str] | None = None,
    cleanup_sql: list[str] | None = None,
    oracle: dict[str, Any] | None = None,
    action: str = "",
    auth_bypass: dict[str, Any] | None = None,
    sessions: list[dict[str, Any]] | None = None,
    raw_http: str = "",
    nuclei_yaml: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Build a structured execution_spec for executors and archiving."""
    proto = (protocol or PROTOCOL_HTTP).strip().lower()
    spec: dict[str, Any] = {
        "protocol": proto,
        "cve_id": cve_id,
        "target": target,
        "notes": notes,
    }
    if proto == PROTOCOL_DATABASE:
        spec.update(
            {
                "engine": engine or "mysql",
                "version": version,
                "config": list(config or []),
                "schema_sql": list(schema_sql or []),
                "setup_sql": list(setup_sql or []),
                "trigger_sql": list(trigger_sql or []),
                "cleanup_sql": list(cleanup_sql or []),
                "oracle": oracle or {"type": "error_pattern", "expect": ""},
            }
        )
        if action:
            spec["action"] = str(action).strip().lower()
        if auth_bypass:
            spec["auth_bypass"] = dict(auth_bypass)
        if sessions:
            spec["sessions"] = [dict(item) for item in sessions if isinstance(item, dict)]
    elif proto == PROTOCOL_HTTP:
        spec.update({"raw_http": raw_http, "nuclei_yaml": nuclei_yaml})
    else:
        spec["status"] = "interface_only"
    return spec


def execute_spec(
    spec: dict[str, Any],
    environment: dict[str, Any] | None = None,
    *,
    cve_id: str = "",
) -> dict[str, Any]:
    """Dispatch execution_spec to the matching protocol executor."""
    environment = environment or {}
    protocol = str((spec or {}).get("protocol") or PROTOCOL_HTTP).strip().lower()

    if protocol == PROTOCOL_DATABASE:
        return execute_database_spec(spec, environment, cve_id=cve_id or str(spec.get("cve_id") or ""))

    if protocol == PROTOCOL_HTTP:
        # HTTP remains on the legacy candidate path; this is a thin adapter.
        from cve_hunter.tools.http_sender import send_poc_and_capture

        return send_poc_and_capture(
            raw_http=str(spec.get("raw_http") or ""),
            nuclei_yaml=str(spec.get("nuclei_yaml") or ""),
            target_url=str(environment.get("target_url") or spec.get("target") or ""),
            cve_id=cve_id or str(spec.get("cve_id") or ""),
        )

    return {
        "success": False,
        "skipped": True,
        "protocol": protocol,
        "error": f"协议执行器未实现: {protocol}",
        "error_type": "protocol_unsupported",
        "status_code": STATUS_PROTOCOL_UNSUPPORTED,
    }
