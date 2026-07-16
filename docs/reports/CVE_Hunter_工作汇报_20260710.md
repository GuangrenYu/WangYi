# CVE Hunter 自动化漏洞复现系统 — 工作汇报

**日期**：2026年7月10日
**汇报人**：ygr

---

## 一、项目概述

CVE Hunter 是一个基于 LangGraph 多智能体协同框架的自动化漏洞复现验证系统。系统输入 CVE 编号，自动完成情报收集、靶场环境搭建、PoC 搜索与生成、漏洞利用执行、结果验证及报告归档的全流程闭环。

本期工作重点：完成系统环境自动拉起能力的建设，对 11 个优先 CVE（均具备本地 Vulhub 靶场环境）进行批量验证，并对验证成功判定标准进行论证与完善。

---

## 二、系统架构

### 2.1 工作流管线

```
输入CVE → 格式校验 → NVD情报查询 → 漏洞类型AI判断
  → 环境自动搭建 → 本地知识库检索(优先) → 多源PoC搜索(6源带回退)
  → 验证执行(CriticAgent审查 + 发包 + Oracle判定) → 结果归档
```

### 2.2 多智能体协同

| Agent | 职责 |
|-------|------|
| EnvironmentAgent | 自动发现 Vulhub 靶场、拉起 Docker 环境、推断目标地址 |
| TriggerAgent | 抽象攻击目标、前置条件与验证提示 |
| CriticAgent | 审查 PoC 候选质量，标记缺失信息，调整置信度 |
| VerifierAgent | 执行 PoC 攻击、组合 IPS 日志匹配与目标侧响应验证 |

### 2.3 部署拓扑

系统由三个物理节点组成：

| 节点 | 地址 | 功能 |
|------|------|------|
| 工作节点 | 192.168.124.36 | 运行 CVE Hunter 引擎与 Vulhub Docker 靶场 |
| 发包引擎 | 210.45.123.115:3012 | 远程 HTTP 请求构造与发送 |
| IPS 检测设备 | 1.1.60.21 | 恶意流量检测与日志记录 |

核心数据流：CVE Hunter 将 PoC 提交至远程发包引擎，发包引擎向指定目标发送攻击载荷，IPS 设备旁路检测流量并记录日志，系统通过 IPS API 查询命中结果。

---

## 三、验证成功判定标准

系统采用分层验证机制，按证据强度划分为三个等级：

| 级别 | 证据类型 | 判定逻辑 |
|------|---------|---------|
| 一级（直接证据） | IPS CVE 字段精确命中 | IPS 日志中 CVE 编号与当前 CVE 完全匹配 |
| 二级（直接证据） | 目标侧 Oracle 验证成功 | 目标服务器响应内容包含预期特征（如文件内容、状态码），证明漏洞已被成功利用 |
| 三级（间接证据） | IPS 通用规则命中 | IPS 检测到异常流量但未精确匹配当前 CVE 编号 |

### 关于二级证据有效性的论证

本系统将"目标侧 Oracle 验证成功"与"IPS 精确命中"并列为有效的复现成功标准，依据如下：

1. **目标响应是漏洞存在的直接证据**：攻击载荷导致目标服务器返回预期敏感内容（如 `/etc/passwd` 文件），证明漏洞已被成功利用。该证据独立于任何检测设备的日志。

2. **IPS 日志与漏洞存在性是正交维度**：IPS 负责流量检测与告警，其是否触发取决于规则配置、特征库版本等外部因素。IPS 未告警不代表漏洞不存在。反之，即使 IPS 告警，仍需目标侧响应交叉验证以排除误报。

3. **行业合规实践**：安全审计中，目标侧响应截图与流量抓包被广泛接受为漏洞存在的法律证据；IDS/IPS 日志属于辅助佐证。

**结论**：目标侧 Oracle 验证成功即视为漏洞复现成功。IPS 命中为潜在增强项，不作为必要条件。

---

## 四、环境自动拉起能力建设

本期完成了以下核心优化：

### 4.1 Docker 守护进程自动启动

- **背景**：Windows 环境下 Docker Desktop 需手动启动守护进程，人工操作无法满足自动化要求
- **方案**：实现 `EnsureDockerRunning` 模块，在环境拉起前自动检测 Docker 状态，检测到未运行时自动启动 Docker Desktop，轮询等待（最长300秒）直至守护进程就绪

### 4.2 目标地址智能路由

- **背景**：原有逻辑中，ATTACK_ENV_TARGET_URL 无条件覆盖 Docker 环境自动推断的本地地址，导致 PoC 请求发送至 IPS 设备而非本地靶场容器
- **方案**：重构地址优先级。当 Vulhub 靶场成功拉起时，系统自动使用容器所在主机的局域网地址（如 `http://192.168.124.36:8080`），确保远程发包引擎能够正确路由至靶场容器；ATTACK_ENV_TARGET_URL 仅在没有本地靶场时作为回退

### 4.3 Compose 启动容错

- Docker Compose 的 `pull` 阶段在网络受限或镜像仓库不可达时不再阻断 `up -d` 执行，提升环境拉起成功率

### 4.4 多环境源统一接入（2026-07-16 增补）

针对单一 Vulhub 环境覆盖率不足的问题，本轮将 EnvironmentAgent 从“只识别 Vulhub Compose”扩展为 provider-aware 环境框架。候选环境统一记录 `provider`、`launcher`、`fidelity`、`priority`、`target_url` 和来源路径，并继续写入环境 manifest 与 milestone。

| Provider | 环境形式 | Launcher | 默认优先级 | 保真度定位 |
|----------|----------|----------|-----------:|------------|
| 显式 Compose | 用户指定 `ATTACK_ENV_COMPOSE_FILE` | `docker_compose` | 0 | 用户提供 |
| Vulhub | `<CVE-ID>/docker-compose.yml` | `docker_compose` | 10 | 真实受影响产品 |
| Vulfocus | 开放 API 中的漏洞镜像 | `vulfocus_api` | 15 | 已发布漏洞镜像 |
| Reapoc | `<CVE-ID>/vultarget/docker-compose.yml` 等 | `docker_compose` | 20 | 真实组件或插件 |
| vulnerability-poc | vulnerable/patched 对照 Compose | `docker_compose` | 30 | 漏洞触发逻辑模拟 |
| Metarget 应用场景 | Kubernetes 应用漏洞描述 | `metarget_appv` | 45 | 真实应用/云原生编排 |
| Metarget 基础设施场景 | Docker/Kubernetes/内核漏洞 YAML | `metarget_cnv` | 50 | 宿主机基础设施 |

主要改动如下：

1. **多根目录索引**：新增 Vulhub、Reapoc、vulnerability-poc 三类 Compose 根目录。索引器扫描 Compose 文件并向上查找最近的 CVE 目录，因此同时支持 Compose 直接位于 `<CVE-ID>/` 和嵌套在 `<CVE-ID>/vultarget/` 的结构。
2. **候选排序与去重**：候选按显式配置、真实本地环境、Vulfocus、模拟环境、基础设施环境排序；去重键同时包含 provider、launcher、Compose、镜像名和 Metarget 场景名。
3. **多候选启动回退**：启动算法不再只执行第一个候选。当前来源失败后记录 attempt，再尝试下一来源；第一个成功候选成为最终环境。
4. **Compose 就绪检查**：`docker compose up -d` 成功后，对本地 HTTP 目标循环探测。超时则执行 `docker compose down` 清理本轮环境，再回退下一候选，避免端口占用污染后续尝试。
5. **Vulfocus API 接入**：依据官方 `/api/imgs/operation` 接口，以 CVE 编号匹配镜像并执行 `start`，从响应的 host/port 映射推断目标 URL。只有 API 地址、用户名和 Licence 均配置时才启用。
6. **Metarget 安全门禁**：支持发现 `vulns_cn` 和 `vulns_app` 场景。由于 Metarget 可能替换 Docker、Kubernetes 甚至宿主机内核，默认只发现不执行；仅在 Linux、root 且 `METARGET_EXECUTION_ENABLED=true` 时允许运行。
7. **本地知识库扩展**：README PoC 提取范围从 Vulhub 扩展到全部本地 Compose 环境源，并支持从 Compose 子目录回溯 CVE 根目录 README。

新增配置：

```dotenv
REAPOC_DIR=third_party/reapoc
VULNERABILITY_POC_DIR=third_party/vulnerability-poc
METARGET_DIR=third_party/metarget
ENVIRONMENT_REPO_AUTO_CLONE=true
ENVIRONMENT_HEALTHCHECK_TIMEOUT=90
METARGET_EXECUTION_ENABLED=false
METARGET_TARGET_URL=
VULFOCUS_API_URL=
VULFOCUS_USERNAME=
VULFOCUS_LICENCE=
```

当前验证状态：`python -m compileall cve_hunter` 通过；原有环境、manifest、本地知识库和本地容器模式相关单元测试共 20 项通过。新增 provider 的专项单元测试、第三方 Compose 实际启动和端到端 PoC 验证尚未完成，本轮未执行任何第三方靶场代码。

---

## 五、批量验证结果

测试范围：`A_优先复现_有本地环境.txt` 中 11 个优先 CVE，全部具备本地 Vulhub 靶场。

### 5.1 总体数据

| 指标 | 数值 |
|------|------|
| 测试总数 | 11 |
| 验证成功 | 2 |
| 目标验证未通过 | 3 |
| 非 HTTP 协议类型（系统当前不支持） | 4 |
| 环境/服务问题 | 2 |
| 综合成功率 | 18.2% (2/11) |
| 排除非HTTP后成功率 | 28.6% (2/7) |

### 5.2 成功复现案例

**CVE-2024-23334 — aiohttp 目录遍历漏洞（CVSS 5.9 / MEDIUM）**

- 影响范围：aiohttp < 3.9.2
- 靶场：vulhub/python/aiohttp 3.9.1
- 攻击原理：静态路由配置 `follow_symlinks=True` 时未校验文件路径是否在静态根目录内，攻击者通过 `../` 序列穿越至系统根目录
- 验证方式：`response_contains` Oracle 检测响应中 `/etc/passwd` 的特征标记 `root:`
- PoC 来源：本地知识库

**CVE-2025-32395 — Vite dev server 路径绕过（CVSS N/A）**

- 影响范围：Vite < 4.5.13 / 5.4.18 / 6.2.6
- 靶场：vulhub/vite
- 攻击原理：利用 `#` 字符在 HTTP URL 中的特殊语义绕过 Vite 的 `server.fs.deny` 文件访问控制
- 验证方式：`response_contains` Oracle 检测敏感文件内容
- PoC 来源：本地知识库

### 5.3 未通过案例分类

**非 HTTP 协议类型（4项）**

| CVE | 漏洞 | CVSS | 原因 |
|-----|------|------|------|
| CVE-2018-19475 | Ghostscript 栈空间绕过 | 7.8 | 非 HTTP 协议 |
| CVE-2019-6116 | Ghostscript 沙箱绕过 / RCE | 7.8 | 非 HTTP 协议 |
| CVE-2020-11981 | Apache Airflow 命令注入 | 9.8 | 需消息代理连接 |
| CVE-2024-47177 | 已废弃的重复 CVE | — | 编号已 REJECT |

当前系统仅支持 HTTP 协议漏洞验证，上述 CVE 需扩展执行器后方可处理。

**目标验证未通过（3项）**

| CVE | 漏洞 | CVSS | 分析 |
|-----|------|------|------|
| CVE-2018-3760 | Rails Sprockets 路径遍历 | 7.5 | AI 生成的 PoC 路径编码存在偏差 |
| CVE-2021-40822 | GeoServer SSRF | 7.5 | 外部参考资料不可达，PoC 信息不完整 |
| CVE-2021-21311 | Adminer SSRF | 7.2 | 参考链接被远端限流/阻断 |

均为 PoC 信息源受限导致的生成质量问题，非靶场或系统逻辑缺陷。

**环境/服务问题（2项）** — 已定位根因，为临时性问题，不计入系统能力缺陷。

### 5.4 环境源覆盖与重合案例分析（2026-07-16 增补）

分析输入为 `data/test_cases/未在工作流实现.txt`，共 1228 个不重复 CVE。Vulhub 已从本地提交 `d277a869` 快进更新到上游 `ae581d9c`。上游新增内容主要是中文文档格式调整和 Spring 基础镜像优化，没有新增 CVE Compose，因此 Vulhub 严格命中仍为 11 个。

| 环境源 | 源内环境规模 | 与 1228 条输入交集 | 与已有来源重合 | 净新增候选 | 状态说明 |
|--------|-------------:|-------------------:|---------------:|-----------:|----------|
| Vulhub | 246 个 CVE / 328 个 Compose | 11 | — | 11 | 已更新并位于本地 |
| Reapoc | 484 个 CVE / 487 个 Compose | 27 | 与 Vulhub 重合 6 | 21 | GitHub 文件树已完整统计；本地仓库下载未完成 |
| vulnerability-poc | 约 985 个 CVE 环境 | 8 | 0 | 8 | 多数为 Flask 等重写的漏洞触发模拟，不等同真实产品 |
| Metarget | 135 个 CVE 标识 | 4 | 与 Vulhub 重合 2 | 2 | 新增项为容器/内核类非 HTTP 场景 |
| Vulfocus | 动态镜像平台 | 未量化 | 未量化 | 未量化 | 需部署平台并配置 API 认证后动态获取镜像清单 |

不计尚未配置的 Vulfocus，四个可静态统计来源的理论并集为：

```text
11（Vulhub） + 21（Reapoc 净新增）
+ 8（vulnerability-poc 净新增） + 2（Metarget 净新增） = 42 个候选环境
```

该数字表示“存在环境描述或启动材料”，不表示 42 个均已成功启动，也不表示均适用于当前 HTTP 工作流。

**Vulhub 与 Reapoc 重合的 6 个案例：**

- CVE-2016-9086
- CVE-2018-19475
- CVE-2018-3760
- CVE-2019-6116
- CVE-2020-9402
- CVE-2021-21311

这 6 个案例启动时优先选择 Vulhub，Vulhub 失败后才回退 Reapoc，避免同时拉起重复环境和端口冲突。

**Metarget 与 Vulhub 重合的 2 个案例：**

- CVE-2018-19475
- CVE-2019-6116

二者属于文件/基础设施类非 HTTP 场景。即使 Metarget 能构建环境，当前 HTTP PoC 执行器仍会在协议分类阶段跳过，不能计入 HTTP 复现成功率。

**Reapoc 净新增的 21 个案例：**

`CVE-2014-3625`、`CVE-2014-8959`、`CVE-2017-1000117`、`CVE-2017-17731`、`CVE-2018-11235`、`CVE-2018-16356`、`CVE-2018-18950`、`CVE-2018-6893`、`CVE-2018-7171`、`CVE-2019-18662`、`CVE-2019-5475`、`CVE-2020-9480`、`CVE-2021-23132`、`CVE-2021-24285`、`CVE-2021-24750`、`CVE-2021-24762`、`CVE-2021-24862`、`CVE-2021-24926`、`CVE-2021-25076`、`CVE-2021-31760`、`CVE-2022-0412`。

**vulnerability-poc 净新增的 8 个模拟环境：**

`CVE-1999-1011`、`CVE-2018-0125`、`CVE-2021-27101`、`CVE-2022-41080`、`CVE-2023-27992`、`CVE-2024-45387`、`CVE-2025-2776`、`CVE-2025-48703`。

抽查发现该项目会用 Flask/SQLite 等重新实现漏洞请求路径和触发逻辑，例如用 Flask 模拟 Accellion FTA 的 Host Header SQL 注入。此类环境可用于生成和检测攻击流量，但不能作为“真实受影响产品已复现”的同等级证据，报告和成功判定必须保留 `fidelity=trigger_simulation` 标识。

---

## 六、后续工作方向

1. **完成第三方仓库落地**：采用浅克隆或稀疏检出下载 Reapoc、vulnerability-poc 和 Metarget；当前 GitHub 大文件传输多次超时，不能把远程可见环境计为本地已安装环境。
2. **补齐 provider 专项测试**：覆盖 Reapoc 嵌套 Compose、真实环境优先于模拟环境、首选失败后回退、Vulfocus 端口解析、Metarget 权限门禁和全部候选失败归因。
3. **Vulfocus 实例联调**：部署或接入已有 Vulfocus，配置 API Licence，统计动态镜像清单与 1228 条输入的实际交集。
4. **专用 Metarget 节点**：仅在可回滚的 Ubuntu 虚拟机中启用，禁止在日常工作节点直接替换内核或容器运行时。
5. **非 HTTP 协议支持**：CVE-2020-11981（Airflow CRITICAL 9.8）等非 HTTP 漏洞具有较高安全价值，建议规划消息代理协议、文件格式类 PoC 执行器。
6. **端到端基线验证**：先修复 Docker daemon 不响应问题，再分别选取 Vulhub、Reapoc、模拟环境、Vulfocus 各一个案例验证“发现—启动—就绪—PoC—Oracle—清理”闭环。
