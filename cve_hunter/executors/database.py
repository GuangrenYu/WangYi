"""Database execution_spec runner (MySQL/PostgreSQL first).

MVP 目标：
- 按 schema/setup/trigger/cleanup 顺序执行 SQL
- oracle 支持 error_pattern / result_contains / crash / row_count
- 连接失败与执行失败分开归因

未安装 DB 驱动时返回明确错误，不伪装成功。
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

from cve_hunter.status_codes import (
    DB_EXECUTION_FAILED,
    DB_ORACLE_FAILED,
    DB_ORACLE_SUCCESS,
    EXECUTION_POLICY_BLOCKED,
    NO_EXPLOIT_EVIDENCE,
    TARGET_ACCESS_FAILED,
)
from cve_hunter.safety import evaluate_execution_policy
from cve_hunter.config import cfg


def execute_database_spec(
    spec: dict[str, Any],
    environment: dict[str, Any] | None = None,
    *,
    cve_id: str = "",
) -> dict[str, Any]:
    environment = environment or {}
    engine = str(spec.get("engine") or "mysql").strip().lower()
    from cve_hunter.tools.db_spec import resolve_database_target

    raw_target = str(spec.get("target") or "")
    env_target = str(environment.get("target_url") or environment.get("target_host") or "")
    # 若 spec 已是 DSN 则保留账号；环境地址用于覆盖 host/port
    if raw_target.startswith(("mysql://", "postgres://", "postgresql://", "mariadb://")):
        host, port, database, user, password = _parse_db_target(raw_target, engine)
        if env_target and not env_target.startswith(("mysql://", "postgres://", "postgresql://", "mariadb://")):
            target = resolve_database_target(
                engine=engine,
                env_target=env_target,
                user=user,
                password=password,
                database=database,
                port=port,
            )
            host, port, database, user, password = _parse_db_target(target, engine)
        else:
            target = raw_target
    else:
        target = resolve_database_target(
            engine=engine,
            env_target=env_target or raw_target,
            user="postgres" if engine.startswith("postgres") else "root",
            password="postgres" if engine.startswith("postgres") else "",
            database="postgres" if engine.startswith("postgres") else "",
        )
        host, port, database, user, password = _parse_db_target(target, engine)

    policy = evaluate_execution_policy(
        target if "://" in target else f"{engine}://{host}:{port}",
        host,
        run_mode=getattr(cfg, "run_mode", "plan_only"),
        allowlist=getattr(cfg, "target_allowlist", []),
    )
    if not policy.allowed:
        return {
            "success": False,
            "skipped": True,
            "policy_blocked": True,
            "protocol": "database",
            "engine": engine,
            "error": policy.reason,
            "error_type": "policy",
            "status_code": EXECUTION_POLICY_BLOCKED,
        }

    # TCP 刚就绪时 DBMS 可能仍在初始化，短暂重试连接。
    connect: dict[str, Any] = {"success": False, "error": "数据库连接失败"}
    last_error = ""
    for attempt in range(1, 9):
        connect = _connect(engine, host, port, database, user, password)
        if connect.get("success"):
            break
        last_error = str(connect.get("error") or "数据库连接失败")
        time.sleep(min(2 * attempt, 8))
    if not connect.get("success"):
        return {
            "success": False,
            "protocol": "database",
            "engine": engine,
            "target": f"{host}:{port}/{database}",
            "error": last_error or connect.get("error", "数据库连接失败"),
            "error_type": "target",
            "status_code": TARGET_ACCESS_FAILED,
            "phase": "connect",
        }

    conn = connect["connection"]
    cursor = connect["cursor"]
    logs: list[dict[str, Any]] = []
    try:
        for phase in ("schema_sql", "setup_sql", "trigger_sql"):
            for sql in list(spec.get(phase) or []):
                item = _run_sql(cursor, conn, str(sql), phase=phase)
                logs.append(item)
                if not item.get("success") and phase != "trigger_sql":
                    return {
                        "success": False,
                        "protocol": "database",
                        "engine": engine,
                        "target": f"{host}:{port}/{database}",
                        "error": item.get("error", "SQL 执行失败"),
                        "error_type": "db_execution",
                        "status_code": DB_EXECUTION_FAILED,
                        "phase": phase,
                        "logs": logs,
                    }

        trigger_logs = [item for item in logs if item.get("phase") == "trigger_sql"]
        if not trigger_logs and list(spec.get("trigger_sql") or []):
            # all triggers failed
            return {
                "success": False,
                "protocol": "database",
                "engine": engine,
                "target": f"{host}:{port}/{database}",
                "error": logs[-1].get("error") if logs else "触发 SQL 未执行",
                "error_type": "db_execution",
                "status_code": DB_EXECUTION_FAILED,
                "phase": "trigger_sql",
                "logs": logs,
            }

        oracle = _evaluate_db_oracle(spec.get("oracle") or {}, logs)
        result = {
            "success": bool(oracle.get("success")),
            "protocol": "database",
            "engine": engine,
            "target": f"{host}:{port}/{database}",
            "phase": "oracle",
            "logs": logs,
            "oracle": oracle,
            "status_code": oracle.get("status_code") or (
                DB_ORACLE_SUCCESS if oracle.get("success") else DB_ORACLE_FAILED
            ),
            "error": "" if oracle.get("success") else oracle.get("evidence", "数据库验证未命中"),
            "error_type": "" if oracle.get("success") else "db_oracle",
            "body": oracle.get("evidence", ""),
            "request_success": True,
        }
        return result
    finally:
        for phase_sql in list(spec.get("cleanup_sql") or []):
            try:
                _run_sql(cursor, conn, str(phase_sql), phase="cleanup_sql")
            except Exception:
                pass
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _parse_db_target(target: str, engine: str) -> tuple[str, int, str, str, str]:
    default_port = 5432 if engine in {"postgres", "postgresql"} else 3306
    text = (target or "").strip()
    if not text:
        return "127.0.0.1", default_port, "", "root", ""
    if "://" not in text:
        # host:port or host:port/db
        hostport, _, db = text.partition("/")
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else default_port
        return host or "127.0.0.1", port, db, "root", ""
    parsed = urlparse(text)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or default_port
    database = (parsed.path or "").lstrip("/")
    user = parsed.username or "root"
    password = parsed.password or ""
    return host, port, database, user, password


def _connect(engine: str, host: str, port: int, database: str, user: str, password: str) -> dict[str, Any]:
    try:
        if engine in {"postgres", "postgresql"}:
            import psycopg2  # type: ignore

            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=database or "postgres",
                user=user or "postgres",
                password=password or "",
                connect_timeout=max(3, int(getattr(cfg, "request_timeout", 30) or 30)),
            )
            conn.autocommit = True
            return {"success": True, "connection": conn, "cursor": conn.cursor()}

        # default mysql family
        try:
            import pymysql  # type: ignore

            conn = pymysql.connect(
                host=host,
                port=port,
                user=user or "root",
                password=password or "",
                database=database or None,
                connect_timeout=max(3, int(getattr(cfg, "request_timeout", 30) or 30)),
                charset="utf8mb4",
                autocommit=True,
            )
            return {"success": True, "connection": conn, "cursor": conn.cursor()}
        except ImportError:
            import MySQLdb  # type: ignore

            conn = MySQLdb.connect(
                host=host,
                port=port,
                user=user or "root",
                passwd=password or "",
                db=database or None,
                connect_timeout=max(3, int(getattr(cfg, "request_timeout", 30) or 30)),
                charset="utf8mb4",
            )
            conn.autocommit(True)
            return {"success": True, "connection": conn, "cursor": conn.cursor()}
    except ImportError as exc:
        return {
            "success": False,
            "error": f"缺少数据库驱动（MySQL 需 pymysql，PostgreSQL 需 psycopg2）: {exc}",
        }
    except Exception as exc:
        return {"success": False, "error": f"数据库连接失败: {exc}"}


def _run_sql(cursor: Any, conn: Any, sql: str, *, phase: str) -> dict[str, Any]:
    sql = (sql or "").strip()
    if not sql:
        return {"success": True, "phase": phase, "sql": sql, "skipped": True}
    try:
        cursor.execute(sql)
        rows = []
        description = getattr(cursor, "description", None)
        if description:
            try:
                rows = cursor.fetchmany(20)
            except Exception:
                rows = []
        # some drivers need explicit commit
        if hasattr(conn, "commit"):
            try:
                conn.commit()
            except Exception:
                pass
        return {
            "success": True,
            "phase": phase,
            "sql": sql,
            "rowcount": getattr(cursor, "rowcount", -1),
            "rows": [list(row) if not isinstance(row, dict) else row for row in rows],
            "error": "",
        }
    except Exception as exc:
        return {
            "success": False,
            "phase": phase,
            "sql": sql,
            "rowcount": -1,
            "rows": [],
            "error": str(exc),
        }


def _evaluate_db_oracle(oracle: dict[str, Any], logs: list[dict[str, Any]]) -> dict[str, Any]:
    hint_type = str(oracle.get("type") or "error_pattern").strip().lower()
    expect = str(oracle.get("expect") or oracle.get("pattern") or "")
    trigger_logs = [item for item in logs if item.get("phase") == "trigger_sql"]
    all_errors = "\n".join(str(item.get("error") or "") for item in trigger_logs)
    all_rows = []
    for item in trigger_logs:
        all_rows.extend(item.get("rows") or [])

    if hint_type in {"crash", "disconnect"}:
        crashed = any(not item.get("success") and _looks_like_crash(str(item.get("error") or "")) for item in trigger_logs)
        return {
            "evaluated": True,
            "success": crashed,
            "type": hint_type,
            "evidence": all_errors or "无崩溃信号",
            "status_code": DB_ORACLE_SUCCESS if crashed else DB_ORACLE_FAILED,
        }

    if hint_type in {"error_pattern", "regex"}:
        if not expect:
            # 任意触发错误都算弱证据不足
            any_error = any(not item.get("success") for item in trigger_logs)
            return {
                "evaluated": True,
                "success": False,
                "type": hint_type,
                "evidence": all_errors if any_error else "触发 SQL 无错误且未配置期望模式",
                "status_code": NO_EXPLOIT_EVIDENCE if not any_error else DB_ORACLE_FAILED,
            }
        matched = bool(re.search(expect, all_errors, re.I)) if all_errors else False
        return {
            "evaluated": True,
            "success": matched,
            "type": hint_type,
            "evidence": all_errors or "无错误输出",
            "status_code": DB_ORACLE_SUCCESS if matched else DB_ORACLE_FAILED,
        }

    if hint_type in {"result_contains", "response_contains"}:
        blob = "\n".join(str(row) for row in all_rows)
        matched = bool(expect) and expect in blob
        return {
            "evaluated": True,
            "success": matched,
            "type": hint_type,
            "evidence": blob[:1000] or "无结果行",
            "status_code": DB_ORACLE_SUCCESS if matched else DB_ORACLE_FAILED,
        }

    if hint_type in {"row_count", "min_rows"}:
        try:
            minimum = int(oracle.get("min_rows") or expect or 1)
        except (TypeError, ValueError):
            minimum = 1
        total = sum(max(int(item.get("rowcount") or 0), 0) for item in trigger_logs)
        ok = total >= minimum
        return {
            "evaluated": True,
            "success": ok,
            "type": hint_type,
            "evidence": f"rowcount={total}, min_rows={minimum}",
            "status_code": DB_ORACLE_SUCCESS if ok else DB_ORACLE_FAILED,
        }

    return {
        "evaluated": False,
        "success": False,
        "type": hint_type,
        "evidence": f"未实现的数据库 oracle 类型: {hint_type}",
        "status_code": DB_ORACLE_FAILED,
    }


def _looks_like_crash(error: str) -> bool:
    lower = error.lower()
    return any(
        marker in lower
        for marker in (
            "server has gone away",
            "connection reset",
            "lost connection",
            "crashed",
            "segfault",
            "terminated",
            "broken pipe",
        )
    )
