"""Extract database execution_spec from README / PoC text.

优先从 Vulhub README 的 ```sql``` 代码块提取；并尽量从说明文字中识别
engine、默认账号和 oracle 线索。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cve_hunter.executors.base import PROTOCOL_DATABASE, build_execution_spec


# 仅匹配显式 SQL 语言标记，或内容明显是 SQL 的代码块。
_SQL_FENCED = re.compile(
    r"```(?:sql|postgresql|postgres|mysql|plsql|pgsql)\s*\n([\s\S]*?)```",
    re.IGNORECASE,
)
_ANY_FENCED = re.compile(r"```[a-zA-Z0-9_-]*\s*\n([\s\S]*?)```", re.IGNORECASE)
_SQL_START = re.compile(
    r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|COPY|ALTER|WITH|DO|CALL|GRANT|REVOKE)\b",
    re.IGNORECASE,
)
_ENGINE_PATTERNS = (
    ("postgres", re.compile(r"\b(postgresql|postgres|psql)\b", re.I)),
    ("mysql", re.compile(r"\b(mysql|mariadb)\b", re.I)),
)
_USER_PASS = re.compile(
    r"(?:账号|用户|user|username)\s*[/与和:：]?\s*([A-Za-z0-9_.-]+)\s*[/，, ]+\s*(?:密码|password)\s*[/为:：]?\s*([A-Za-z0-9_.@-]+)",
    re.I,
)
_PORT = re.compile(r"端口\s*(\d{2,5})|port\s+(\d{2,5})", re.I)
_ENV_PASSWORD = re.compile(
    r"(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD)\s*[=:：]\s*([^\s\"']+)",
    re.I,
)
_SIMPLE_USER_PASS = re.compile(
    r"(?:账号密码|用户名密码|默认账号密码)\s*(?:为|是|:|：)?\s*([A-Za-z0-9_.-]+)\s*/\s*([A-Za-z0-9_.@-]+)",
    re.I,
)


def resolve_database_target(
    *,
    engine: str,
    env_target: str = "",
    user: str = "",
    password: str = "",
    database: str = "",
    port: int | None = None,
) -> str:
    """把环境推断出的 http://host:port 补成数据库 DSN。"""
    engine_name = (engine or "postgres").strip().lower()
    if engine_name in {"postgresql", "pgsql"}:
        engine_name = "postgres"
    default_port = 5432 if engine_name.startswith("postgres") else 3306
    default_user = user or ("postgres" if engine_name.startswith("postgres") else "root")
    default_password = password if password is not None else ("postgres" if engine_name.startswith("postgres") else "")
    default_db = database or ("postgres" if engine_name.startswith("postgres") else "")

    text = str(env_target or "").strip()
    if text.startswith(("mysql://", "postgres://", "postgresql://", "mariadb://")):
        return text

    host = "127.0.0.1"
    resolved_port = int(port or default_port)
    if text:
        cleaned = text.replace("http://", "").replace("https://", "").replace("tcp://", "")
        cleaned = cleaned.split("/")[0]
        if ":" in cleaned:
            host_part, port_part = cleaned.rsplit(":", 1)
            host = host_part or host
            if port_part.isdigit():
                resolved_port = int(port_part)
        elif cleaned:
            host = cleaned

    auth = default_user
    if default_password:
        auth = f"{default_user}:{default_password}"
    db_part = f"/{default_db}" if default_db else ""
    return f"{engine_name}://{auth}@{host}:{resolved_port}{db_part}"


def extract_sql_statements(text: str) -> list[str]:
    """Extract ordered SQL statements from markdown/text."""
    if not text:
        return []
    statements: list[str] = []
    for match in _SQL_FENCED.finditer(text):
        statements.extend(_split_sql(match.group(1).strip()))
    if not statements:
        # unlabeled fenced blocks that look like SQL (not shell/docker)
        for match in _ANY_FENCED.finditer(text):
            block = match.group(1).strip()
            if not block or re.search(r"\b(docker|compose|curl|wget|bash|npm|pip)\b", block, re.I):
                continue
            if _SQL_START.search(block):
                statements.extend(_split_sql(block))
    if not statements:
        for line in text.splitlines():
            stripped = line.strip().rstrip(";")
            if _SQL_START.match(stripped):
                statements.append(stripped + ("" if stripped.endswith(";") else ";"))
    return _dedupe(statements)


def extract_database_execution_spec(
    text: str,
    *,
    cve_id: str = "",
    target: str = "",
    default_engine: str = "",
) -> dict[str, Any] | None:
    """Build a database execution_spec from documentation text."""
    sqls = extract_sql_statements(text)
    if not sqls:
        return None

    engine = default_engine or _infer_engine(text) or "postgres"
    user, password = _infer_credentials(text, engine)
    port = _infer_port(text, engine)
    schema_sql, setup_sql, trigger_sql, cleanup_sql = _partition_sql(sqls)
    oracle = _infer_oracle(text, trigger_sql)
    dbname = "postgres" if engine.startswith("postgres") else ""

    if not target:
        target = resolve_database_target(
            engine=engine,
            user=user,
            password=password,
            database=dbname,
            port=port,
        )
    else:
        target = resolve_database_target(
            engine=engine,
            env_target=target,
            user=user,
            password=password,
            database=dbname,
            port=port,
        )

    return build_execution_spec(
        protocol=PROTOCOL_DATABASE,
        cve_id=cve_id,
        engine=engine,
        target=target,
        schema_sql=schema_sql,
        setup_sql=setup_sql,
        trigger_sql=trigger_sql,
        cleanup_sql=cleanup_sql,
        oracle=oracle,
        notes="extracted_from_text",
    )


def extract_database_spec_from_paths(
    paths: list[Path],
    *,
    cve_id: str = "",
    target: str = "",
) -> dict[str, Any] | None:
    """Try multiple README/PoC files and return the first usable DB spec."""
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        engine_hint = ""
        lowered = str(path).lower()
        if "postgres" in lowered:
            engine_hint = "postgres"
        elif "mysql" in lowered or "mariadb" in lowered:
            engine_hint = "mysql"
        spec = extract_database_execution_spec(
            text,
            cve_id=cve_id,
            target=target,
            default_engine=engine_hint,
        )
        if spec:
            spec["source_path"] = str(path)
            return spec
    return None


def _split_sql(block: str) -> list[str]:
    cleaned = []
    for line in block.splitlines():
        if line.strip().startswith("--"):
            continue
        cleaned.append(line)
    text = "\n".join(cleaned).strip()
    if not text:
        return []
    parts = re.split(r";\s*\n|;\s*$", text)
    statements = []
    for part in parts:
        sql = part.strip()
        if not sql:
            continue
        if not sql.endswith(";"):
            sql += ";"
        statements.append(sql)
    return statements


def _partition_sql(sqls: list[str]) -> tuple[list[str], list[str], list[str], list[str]]:
    schema_sql: list[str] = []
    setup_sql: list[str] = []
    trigger_sql: list[str] = []
    cleanup_sql: list[str] = []
    for sql in sqls:
        upper = sql.upper()
        if upper.startswith("DROP "):
            cleanup_sql.append(sql)
            # DROP often appears before CREATE in demos; keep as setup prelude too
            if "IF EXISTS" in upper:
                schema_sql.append(sql)
        elif upper.startswith("CREATE "):
            schema_sql.append(sql)
        elif upper.startswith(("INSERT ", "UPDATE ", "ALTER ", "GRANT ", "SET ")):
            setup_sql.append(sql)
        else:
            # COPY/SELECT/DO/CALL etc. treated as trigger
            trigger_sql.append(sql)
    if not trigger_sql and setup_sql:
        trigger_sql = setup_sql[-1:]
        setup_sql = setup_sql[:-1]
    if not trigger_sql and schema_sql:
        # last non-drop statement as trigger fallback
        for sql in reversed(schema_sql):
            if not sql.upper().startswith("DROP "):
                trigger_sql = [sql]
                break
    return schema_sql, setup_sql, trigger_sql, cleanup_sql


def _infer_engine(text: str) -> str:
    for name, pattern in _ENGINE_PATTERNS:
        if pattern.search(text):
            return name
    return ""


def _infer_credentials(text: str, engine: str) -> tuple[str, str]:
    match = _USER_PASS.search(text)
    if match:
        return match.group(1), match.group(2)
    match = _SIMPLE_USER_PASS.search(text)
    if match:
        return match.group(1), match.group(2)
    env_pw = _ENV_PASSWORD.search(text)
    if env_pw:
        if engine.startswith("postgres"):
            return "postgres", env_pw.group(1)
        return "root", env_pw.group(1)
    if engine.startswith("postgres"):
        return "postgres", "postgres"
    return "root", ""


def _infer_port(text: str, engine: str) -> int:
    match = _PORT.search(text)
    if match:
        return int(match.group(1) or match.group(2))
    return 5432 if engine.startswith("postgres") else 3306


def _infer_oracle(text: str, trigger_sql: list[str]) -> dict[str, Any]:
    joined = "\n".join(trigger_sql).upper()
    # COPY ... PROGRAM / command execution often verified by SELECT output markers
    if "FROM PROGRAM" in joined or "COPY " in joined:
        # id command commonly used in vulhub demos
        return {"type": "result_contains", "expect": "uid="}
    if "UPDATEXML" in joined or "EXTRACTVALUE" in joined:
        return {"type": "error_pattern", "expect": "XPATH syntax error"}
    if re.search(r"\b(id|whoami|uname)\b", "\n".join(trigger_sql), re.I):
        return {"type": "result_contains", "expect": "uid="}
    # default: any successful trigger execution is weak; require non-empty rows if SELECT
    if any(sql.upper().lstrip().startswith("SELECT") for sql in trigger_sql):
        return {"type": "row_count", "min_rows": 1}
    return {"type": "error_pattern", "expect": ""}


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = re.sub(r"\s+", " ", item).strip().lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
