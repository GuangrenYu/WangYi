# CVE Hunter 真实软件环境构建现状与改进总结

生成日期：2026-07-17  
最后核实与增补：2026-07-19

适用范围：自有或明确授权的隔离测试环境。本文只总结环境建设和验证工程状态，不包含漏洞利用载荷或面向公网目标的操作说明。

## 一、结论先行

本轮工作的核心进展，是把项目从“发现本地 Compose 并尝试启动”推进到“真实环境候选发现、来源分级、启动、健康检查、归属判断、回收和证据归档”的生命周期框架，并补上官网历史公告检索和网络代理故障回退。

2026-07-19 的核实表明：项目已从“只能发现环境并在失败处停下”推进到“目标清单内真实环境可批量启动、可进入验证、可自动回收”，并已出现目标侧 Oracle 成功与正式 PCAP 归档样本。但批量成功率仍不高，IPS 精确命中与端到端 `CAPTURE_SUCCESS` 仍是下一阶段瓶颈。

截至 2026-07-19 最后核实，最准确的状态是：

| 层级 | 当前结果 | 应如何理解 |
|---|---:|---|
| 本地 Vulhub 环境库 | 246 个唯一 CVE、248 个 CVE Compose 文件 | 已有真实产品/组件的环境定义，不等于均可运行 |
| 当前“未测试且已有本地环境”清单 | 184 个 CVE | 原 197 条已排除 13 条历史成功 PCAP，184 条与本地 Vulhub Compose 精确匹配 |
| 旧 1228 条“未在工作流实现”清单交集 | 11 个 CVE | “11 条”只适用于旧清单交集，不代表本地环境总量 |
| 当前筛出的已缓存介质任务 | 2 个 CVE | 两条 Airflow 任务共享已缓存镜像；步骤 9 后复杂环境可 ready |
| 2026-07-17 自动环境尝试 | 9 条，环境就绪 0 条 | 历史快照：7 条镜像网络，2 条服务就绪超时 |
| 2026-07-19 代理恢复后继续批测 | 6/173 完成，1 条目标侧成功 | 5 条 HTTP 环境 `ready=passed` 且 `cleanup=passed`；1 条 `NOT_HTTP_VULN` |
| 最新状态码分布（6 条） | `TARGET_ORACLE_SUCCESS` 1、`TARGET_ORACLE_FAILED` 3、`NO_EXPLOIT_EVIDENCE` 1、`NOT_HTTP_VULN` 1 | 失败已进入验证层，不再被误标为抓包失败 |
| 官网历史反查 | 25 个唯一 CVE、80 条产品级候选 | 有官方受影响产品证据，但 80 条均未成为本地可用环境 |
| 相关自动化测试（2026-07-19 抽测） | agents/status/http2pcap 相关 52 passed | 环境回收、状态归因、本地抓包服务回归通过 |

因此，项目现在已经能**自动找到真实环境、启动并回收、进入 PoC/Oracle 验证，并给出可审计失败归因**；仍不能宣称 184 条均已端到端成功，也不能把环境 ready 或目标侧 Oracle 单独等同于 IPS 精确命中成功。

## 二、本轮主要改进

### 2.1 增加官网历史公告到环境候选的证据链

新增了真实产品环境候选发现工具，能够从 Oracle、Jenkins、Apache Tomcat 和 Microsoft 官方历史公告中反查指定 CVE，并结构化记录：

- 官方公告来源；
- 受影响产品和版本；
- 环境状态 `environment_status`；
- 部署类型 `deployment_type`；
- 介质状态 `media_status`；
- 本地是否存在产品匹配的 Compose。

这项改进解决了过去“知道 CVE，但不知道对应真实产品、版本和部署条件”的问题。程序还区分 Docker 候选、商业介质人工部署和隔离虚拟机，且只有明确安装包 URL 通过检查时才会标记为介质可获取。

2026-07-17 的历史反查结果为：

| 指标 | 结果 |
|---|---:|
| 输入 CVE | 1228 |
| 命中唯一 CVE | 25 |
| 产品级候选 | 80 |
| Docker 候选 | 1 |
| 商业介质人工部署 | 73 |
| 隔离虚拟机 | 6 |
| 本地已存在环境 | 0 |
| 已确认精确介质 | 0 |
| 来源错误 | 0 |

这 80 条是“有官方证据的建设候选”，不是 80 个已经构建好的环境。

### 2.2 补齐环境生命周期和所有权保护

环境启动前现在会检查 Compose 项目是否已有容器，据此区分：

- 本次工作流新启动的环境；
- 用户或其他任务预先存在的环境。

任务归档时，系统可按启动器执行回收：

- Docker Compose：执行项目回收；
- Vulfocus：调用停止接口；
- Metarget：在显式授权的 Linux 环境执行对应移除命令。

默认 `ENVIRONMENT_AUTO_CLEANUP=true`，但只回收本工作流拥有的环境，不会停止预先存在的靶场。回收结果会写入：

- `result.json` 的 `environment_teardown_result`；
- `environment_manifest.json` 的 `teardown_result`；
- `milestones.environment_cleanup`。

这让“谁启动、是否就绪、是否回收”形成了可审计记录。

2026-07-17 当时的真实运行产物中回收状态多为 `skipped`，原因是环境未进入 ready。2026-07-19 已补齐两项关键缺口并得到运行证据：

1. 健康检查失败或中间 `down` 失败时，仍保留 `started_by_orchestrator` 所有权，最终报告和进程退出时可强制回收；
2. 目标清单批测中已出现多条 `environment_ready=passed` 且 `environment_cleanup=passed`，例如 `CVE-2015-3337` 的 teardown 明确执行了独立 project 的 `down --remove-orphans --volumes`。

### 2.3 提高代理异常时的外部服务可用性

新增 `CVE_HUNTER_DISABLE_PROXY`，可以在本地代理未启动时显式强制直连。NVD 请求也改为：

1. 优先使用已配置代理；
2. 代理连接失败时回退直连；
3. 禁止 HTTP 客户端从系统环境隐式重新拾取错误代理。

LLM 客户端同样显式设置代理并关闭隐式环境代理继承。实际结果显示，19:09 左右的批测仍因本地代理拒绝连接而未通过 NVD；修改后的 19:40 批测已经能够完成 NVD 查询、HTTP 类型判断和 LLM 环境建议，主卡点转移到了目标环境就绪。

需要注意，Docker Desktop 拉取镜像使用自己的代理配置，不受 Python 进程的 `CVE_HUNTER_DISABLE_PROXY` 控制。二者必须分别处理。

### 2.4 多环境来源和失败回退已进入主流程

当前 EnvironmentAgent 可以按优先级发现或规划：

1. 用户显式指定的 Compose；
2. 本地 Vulhub；
3. Vulfocus 镜像；
4. Reapoc；
5. vulnerability-poc；
6. Metarget。

启动一个来源失败后可以继续尝试下一个候选。候选会记录来源、启动器、环境真实性、优先级、目标地址、工作目录和 Compose 文件。

不过，当前机器上只有 `third_party/vulhub` 已落地；Reapoc、vulnerability-poc 和 Metarget 目录均不存在，Vulfocus 也需要单独配置服务和认证。因此“代码支持多来源”与“本机当前有多来源可用”必须分开表述。

### 2.5 环境失败与漏洞验证失败已经分离

环境未就绪时，工作流会记录 `INFRASTRUCTURE_FAILED`，而不是把它误算成 PoC 或漏洞复现失败。最新两条结果中：

- 输入校验通过；
- NVD 数据加载通过；
- HTTP/Web 分类通过；
- 本地 Vulhub 环境命中；
- LLM 环境建议已生成；
- 环境健康检查失败；
- PoC 候选未进入执行；
- `attempt_history` 为空。

这说明现在能够准确回答“失败发生在环境层，而不是验证层”，对后续批量统计和问题归因很重要。

## 三、真实软件环境建设到了哪一步

### 3.1 环境定义层：覆盖已经形成规模

本地 `third_party/vulhub` 当前包含：

- 328 个 Compose 文件；
- 248 个位于 CVE 目录下的 Compose 文件；
- 246 个唯一 CVE。

`未测试_已有本地环境.txt` 最初有 197 条；与历史成功 PCAP 库核对后排除 13 条，当前为 184 条，184 条均能与本地 Vulhub 的 CVE Compose 精确匹配。这意味着环境发现和任务筛选已经可用，但“未测试”必须同时以批测记录和历史 PCAP 为依据。

旧报告中的 11 条也仍然正确，但它表示的是 Vulhub 与 `未在工作流实现.txt` 这 1228 条特定历史任务的交集。两个统计口径不能混用：

```text
本地 Vulhub 总覆盖：246 个唯一 CVE
当前去重后的未测试本地环境清单：184 个 CVE
旧 1228 条未实现清单交集：11 个 CVE
```

### 3.2 镜像介质层：已有部分缓存，但覆盖仍有限

Docker 当前可正常响应，说明 Docker daemon 已经不再是首要阻塞项。当前镜像库存共 16 个标签，其中：

- 12 个为 `vulhub/*` 产品或组件镜像；
- 4 个为 Postgres、Redis 等依赖镜像。

当前专门筛出的“未测试且介质已缓存”清单只有 2 条：

- `CVE-2020-11978`；
- `CVE-2020-17526`。

两条任务都使用本地已有的 `vulhub/airflow:1.10.10`，因此已经越过“镜像无法从 Docker Hub 拉取”的问题，但还没有越过应用初始化和服务就绪问题。

### 3.3 自动启动层：命令链路可执行，目标清单已进入批量就绪

2026-07-17 新生成的 9 份 Docker Compose 环境记录均未达到就绪状态：

- 7 条主要因为 Docker Desktop 无可用 HTTPS 代理，镜像拉取失败；
- 2 条使用已缓存 Airflow 镜像，Compose 已执行，但 `http://127.0.0.1:8080` 在 90 秒内未就绪。

该历史快照说明当时尚未建立批量 ready 基线。2026-07-19 在本机代理 `127.0.0.1:7890` 恢复、Docker 可拉镜像后，对 `未测试_已有本地环境.txt` 启动了 `--continue --local-container` 批测；前 6 条中 5 条 HTTP 环境达到 `environment_ready=passed`，且测完后 `environment_cleanup=passed`，当前仅保留进行中的 CVE 容器。

因此，这一层的阶段结论更新为：

> 自动启动器不仅执行到 Docker，而且已在目标清单内形成“启动后可服务、测完可回收”的批量运行证据；批量成功率与镜像覆盖仍在建设中。

### 3.4 健康检查层：是当前最直接的技术卡点

目前主要使用从 Compose 端口推断出的 HTTP URL 做就绪检查。这个方法适合普通 Web 服务，但存在三类不足：

- Airflow、GitLab 等多服务环境初始化时间可能明显超过统一的 90 秒；
- 首页不一定返回 200，单一 HTTP 判定可能把已启动服务误判为未就绪；
- 数据库、消息协议、UDP、文件处理类环境不能用 HTTP 健康检查判断。

184 条本地环境不能直接等价为 184 条当前 HTTP 工作流都能验收。需要按环境类型配置服务级健康检查、等待条件和初始化步骤。

### 3.5 漏洞验证层：目标清单已进入候选执行与 Oracle

2026-07-17 的两条 Airflow 任务仍停在环境阶段，当时只能评价环境链路。2026-07-19 目标清单继续批测后，验证层已有真实运行证据：

| CVE | 状态码 | 环境 ready | 回收 | 说明 |
|---|---|---|---|---|
| CVE-2014-3704 | `NO_EXPLOIT_EVIDENCE` | passed | passed | 已发包，无当前 CVE IPS/目标侧证据 |
| CVE-2014-6271 | `TARGET_ORACLE_FAILED` | passed | passed | 已执行候选，目标侧 oracle 未命中 |
| CVE-2015-1427 | `TARGET_ORACLE_FAILED` | passed | passed | 同上 |
| CVE-2015-3337 | `TARGET_ORACLE_SUCCESS` | passed | passed | 目标侧 `response_contains` 成功，PCAP 已归档到 `data/cve/pcaps/2026-07-19/CVE-2015-3337.pcap` |
| CVE-2015-5254 | `NOT_HTTP_VULN` | skipped | skipped | 分类阶段退出，未启动环境 |
| CVE-2015-5531 | `TARGET_ORACLE_FAILED` | passed | passed | nuclei 候选已执行，oracle 未命中 |

这说明验证能力已经接到真实本地靶场上。当前主要瓶颈从“环境起不来/抓包被误报”转为“PoC 质量、前置条件补齐、目标侧 oracle 精确性，以及缺少 IPS 精确命中时的成功标准”。

## 四、项目现在能做到什么

### 4.1 当前已实现的能力

- 对单个或批量 CVE 进行输入校验、NVD 查询和 HTTP/Web 分类；
- 从本地环境库中按 CVE 精确发现真实 Compose；
- 发现多种环境来源并按真实性和优先级排序；
- 自动执行 Docker Compose、Vulfocus 或受控 Metarget 启动器；
- 在来源失败时回退到下一个候选；
- 自动推断目标端口并执行基础健康检查；
- 区分环境失败、候选失败、执行失败和漏洞证据失败；
- 记录环境 manifest、Agent 轨迹、milestones、尝试历史和最终结果；
- 默认只允许规划，启用执行后仍受本地/白名单目标策略约束；
- 对本工作流拥有的环境执行自动回收，并保护预先存在的环境；
- 从官方历史公告建立真实产品、受影响版本和部署介质候选清单。

### 4.2 在条件满足时可以做到的能力

当镜像已经缓存或 Docker 网络正常、Compose 本身可运行、初始化条件明确且目标属于 HTTP/Web 类型时，项目可以继续完成：

```text
环境发现 -> 启动 -> 健康检查 -> PoC 候选选择 -> 本地授权验证
-> IPS/目标侧 Oracle 判定 -> PCAP 与结果归档 -> 环境回收
```

这条闭环在代码结构上已经具备，下一阶段需要用一组简单、稳定的真实产品环境形成连续的运行证据。

### 4.3 当前还不能承诺的能力

- 不能从零自动生成任意商业软件或任意 CVE 的真实环境；
- 不能自动获取需要许可、支持合同或登录授权的旧版本安装介质；
- 不能把 246 个 Compose 定义视为 246 个已验证可运行环境；
- 不能自动修复所有失效镜像、架构不兼容、初始化脚本和依赖问题；
- 不能稳定处理登录、CSRF、多阶段浏览器交互和人工初始化；
- 不能用统一 HTTP 健康检查覆盖数据库、消息、文件和内核类漏洞；
- 不能保证多终端并行启动时没有宿主端口冲突；
- 不能在没有明确授权和白名单的情况下对公网目标执行验证；
- 不能把环境启动成功等同于漏洞复现成功。

## 五、当前主要瓶颈

### 5.1 Docker 镜像网络与 Python 网络是两套配置

Python 侧的代理回退已经改进。2026-07-19 核实本机 `127.0.0.1:7890` 代理恢复后，NVD 经代理可达，`docker pull` 也可成功；目标清单批测因此越过了早期“镜像几乎全失败”的阶段。但仍需把 Docker Desktop 代理/镜像缓存作为常设基线，避免代理再次中断后批测回退到介质层失败。

### 5.2 复杂应用需要环境专属初始化和健康检查

Airflow 的最新两条结果证明“镜像存在、Compose 执行成功”仍不足以得到可用服务。需要将数据库初始化、依赖服务状态、日志关键事件和更长启动窗口纳入环境规格，而不是仅检查一个统一 URL。

### 5.3 并行环境缺少端口和项目级隔离

多终端批测会同时启动多个 Compose，而大量环境默认映射到 8080 等常见端口。当前需要为本地环境任务增加端口分配、Compose project 隔离和并发上限，否则即使镜像齐全也可能互相干扰。

### 5.4 真实环境成功回收：已有运行证据，失败路径也已加固

2026-07-17 时缺少 ready 后的真实回收证据。2026-07-19 已核实：

- 目标清单批测中多条 `cleanup=passed`；
- `CVE-2015-3337` 的 `environment_teardown_result` 明确记录独立 project 的 `down --remove-orphans --volumes` 成功；
- 额外修复了失败路径残留：`compose up` 后即使健康检查失败，也会保留所有权；每条 CVE 结束后 `reclaim_owned_compose_projects()` 兜底，进程退出时 `atexit` 再兜底。

当前剩余风险主要是：异常杀进程、Docker daemon 卡死、或人手动启动的同名项目仍需人工清理，而不是“成功路径完全无回收代码”。

### 5.5 环境来源覆盖与本机落地不一致

代码支持 Vulhub、Vulfocus、Reapoc、vulnerability-poc 和 Metarget，但本机目前只有 Vulhub。优先补齐 Reapoc 等来源前，需要先审计其环境真实性、Compose 可维护性和许可条件，避免把模拟触发器误报为真实产品环境。

## 六、建议的下一阶段验收顺序

### 已完成到哪一步

- 第一阶段（3 至 5 条生命周期基线）：步骤 6 已用清单外 4 条完成；步骤 10 已在目标清单内形成 ready + 验证 + 回收证据。
- 第二阶段（Airflow 类多服务）：步骤 9 已通过真实容器复测达到 ready 并回收。
- 第三阶段（批量隔离与继续批测）：已启动 184 条清单的串行 `--continue --local-container` 批测，并采用独立 Compose project；端口冲突仍需在并行扩容前继续约束。
- 第四阶段（扩大真实产品来源）：尚未启动，仍以后续项推进。

### 下一步优先顺序

1. **完成并复盘 184 条继续批测**  
   按 `environment_ready`、`environment_cleaned`、`NO_EXPLOIT_EVIDENCE`、`TARGET_ORACLE_*`、`CAPTURE_SUCCESS`、`INFRASTRUCTURE_FAILED` 分布统计，区分环境问题与 PoC/证据问题。

2. **提升验证命中，而不是继续堆环境启动能力**  
   - 优先修前置条件缺失（登录、form token、路径版本）；  
   - 收紧/增强目标侧 oracle；  
   - 在有 IPS 的拓扑中单独验收 `CAPTURE_SUCCESS`。

3. **镜像缓存与并行隔离**  
   预检结果按“已缓存 / 需拉取 / 端口冲突”分组；并行前必须保留 project 隔离和端口分配上限。

4. **扩大真实产品来源**  
   Vulhub 批测稳定后，再落地 Reapoc 等来源；官网 25 个 CVE 继续作为介质与版本调研池，商业/Microsoft 产品仍走合法介质或隔离虚拟机。

## 七、验收指标建议

后续汇报建议同时报告以下指标，避免只看“发现了多少环境”：

| 指标 | 含义 |
|---|---|
| `compose_discovered` | 找到环境定义 |
| `media_available` | 所需镜像或安装介质可用 |
| `environment_started` | 启动命令成功 |
| `environment_ready` | 服务达到可验证状态 |
| `candidate_executed` | 至少执行一个候选 |
| `oracle_confirmed` | IPS 当前 CVE 命中或目标侧证据成立 |
| `environment_cleaned` | 本次启动环境已回收 |
| `end_to_end_success` | 全链路成功且证据归档完整 |

建议下一阶段的第一个量化目标是：

```text
3 至 5 条真实产品环境连续完成
发现 -> 介质 -> 启动 -> 就绪 -> 验证 -> 归档 -> 回收
```

达到这一目标后，再逐步扩大到 184 条清单，数字才具有工程意义。

## 八、验证依据

本报告依据以下工作区事实生成，并在 2026-07-19 复核：

### 8.1 2026-07-17 基线

- `third_party/vulhub`：246 个唯一 CVE Compose 环境；
- `data/test_cases/未测试_已有本地环境.txt`：184 个唯一 CVE，历史成功 PCAP 交集为 0；
- `data/test_cases/未测试_已有本地环境_已缓存介质.txt`：2 个唯一 CVE；
- `output/vendor_labs/official_lab_candidates.json`：1228 个请求 CVE、25 个命中 CVE、80 条候选、0 条本地存在；
- `output/batch/未测试_已有本地环境_已缓存介质_1_2_20260717_194000.json`：2 条完成、0 条成功；
- `output/CVE-2020-11978/` 和 `output/CVE-2020-17526/`：当时环境就绪失败，未进入候选执行；
- 当时 `pytest -q`：115/118 passed（随步骤递增），1 条第三方弃用预警。

### 8.2 2026-07-19 复核

- 本机代理 `127.0.0.1:7890` 恢复；NVD via proxy 返回 200；`docker pull` 可用；
- `tools/bin/nuclei.exe`（v3.11.0）已安装，`.env` 配置 `NUCLEI_PATH`；
- `local_http2pcap_service` health：`dumpcap/tshark/nuclei` 均 available；
- raw 抓包 smoke：`success=true, packet_count=42`；nuclei smoke：`success=true, matched=true, packet_count=60`；
- 继续批测产物：`output/batch/未测试_已有本地环境_continue_20260719_175408_1_173_20260719_175408.json`
  - completed=6 / planned=173，passed=1；
  - HTTP 环境 ready=5/5，cleanup=5/5；
  - `CVE-2015-3337`：`TARGET_ORACLE_SUCCESS`，PCAP=`data/cve/pcaps/2026-07-19/CVE-2015-3337.pcap`，teardown 成功；
- 相关单测抽查：`tests/test_agents.py`、`tests/test_status_codes.py`、`tests/test_local_http2pcap_service.py` 共 52 passed。

## 九、阶段性判断

项目已经完成了从“漏洞复现工作流”向“带真实环境生命周期管理的漏洞验证工作流”的结构性升级。当前最有价值的能力不是声称自动复现了多少漏洞，而是已经能够把环境候选、真实产品证据、介质状态、启动结果、健康状态、验证证据和回收状态分开记录，并在目标清单上连续运行。

真实软件环境构建目前达到的是：

> **大规模环境材料可发现；代理与镜像链路恢复后，目标清单内环境可批量启动、进入验证并自动回收；已有目标侧 Oracle 成功与正式 PCAP 归档样本。下一步重点从“环境能不能起来”转为“PoC/Oracle 命中率、IPS 精确证据和批量成功率”。**

在此基础上，继续完成 184 条批测并按状态码分类复盘，是当前最可靠的推进路径。

## 十、按步骤改进与验收记录

### 步骤 1：环境预检命令（已完成）

完成时间：2026-07-17

已增加 `--env-preflight` 只读预检模式，按清单范围输出 JSON 和 Markdown，记录 Compose 定义、配置有效性、镜像缓存、构建需求、发布端口、端口冲突和建议健康检查类型。预检不会拉取镜像或启动容器。

本步修正了两项首轮验收问题：测试现在会在临时目录销毁前读取 Markdown；Compose 索引现在能从 `PIL-CVE-2017-8291` 这类带产品前缀的目录名中提取 CVE 编号，同时保留严格的 CVE 数字边界。

同一提取规则也已应用到实际 EnvironmentAgent 的 Compose 候选索引，避免出现“预检报告找到 184 条，但运行时漏掉前缀目录”的口径分裂。

验收结果：

| 验收项 | 结果 |
|---|---:|
| 针对性单元测试 | 3 passed |
| 完整清单扫描 | 184/184 找到 Compose |
| Compose 配置有效 | 183/184 |
| 镜像全缓存 | 2 |
| 静态启动前提满足 | 2 |
| 重复运行 | 连续两次统计一致 |

唯一配置失败为 `CVE-2017-5223`：其 Compose 引用了当前目录中不存在的 `.env` 文件。该问题已被明确记录为 `compose_config_invalid`，没有被误算为 Compose 缺失。

验收产物：

- `output/environment_preflight/未测试_已有本地环境_1_184.json`
- `output/environment_preflight/未测试_已有本地环境_1_184.md`

### 步骤 2：本地容器目标边界（已完成）

完成时间：2026-07-17

本地容器模式现在会在 Compose 候选发现阶段显式应用 `local_only` 约束。Compose 有本地发布端口时仍使用自动推断的 `127.0.0.1` 地址；Compose 无发布端口且 `ATTACK_ENV_TARGET_URL` 或 `TARGET_IP` 指向非本地目标时，候选的 `target_url` 和 `target_host` 保持为空，不会把远程地址带入后续验证链路。

新增单元测试覆盖“无端口 Compose + 远程兜底地址 + `local_container_mode=True`”场景，断言环境候选和最终攻击环境均没有目标地址，状态为 `setup_failed`。

验收结果：`tests/test_agents.py`、`tests/test_local_container_mode.py`、`tests/test_verification.py` 共 27 passed；`git diff --check` 通过。唯一输出为既有 LangGraph 弃用预警，与本步无关。

### 步骤 3：Docker 镜像拉取链路（检查完成，外部阻塞未解除）

检查时间：2026-07-17

Docker Desktop 4.77.0、Engine 29.5.3 和 Compose 5.1.4 均正常在线，本地已有 16 个镜像标签。但公开小镜像 `hello-world:latest` 的实际拉取失败，daemon 错误为访问 `registry-1.docker.io:443` 时按直连处理，Docker Desktop 没有可用 HTTPS 代理，最终 TCP 连接超时。

宿主侧检查结果：

| 检查项 | 结果 |
|---|---|
| WinHTTP 代理 | Direct access |
| Windows 用户代理 | `ProxyEnable=0` |
| 项目 `.env` 代理 | 指向 `127.0.0.1:7890` |
| `127.0.0.1:7890` 监听 | 无监听进程 |
| Docker Desktop 手工代理设置 | 未配置 |
| Registry mirror | 未配置 |
| `docker pull hello-world:latest` | 失败，Docker Hub 443 直连超时 |

本步骤未盲目写入一个不可用的全局代理，也未配置未经审计的第三方镜像站。当前阻塞位于项目工作区之外，需要恢复本机代理服务并在 Docker Desktop 中配置其 HTTPS 地址，或提供组织内部可信 Registry mirror；完成后应以 `docker pull hello-world:latest` 成功作为拉取链路验收。后续步骤仅使用已有缓存镜像选择试点，避免把网络失败误记为环境实现失败。

在外部网络仍阻塞的条件下，启动器已采用 `docker compose pull --policy missing`：本地已有镜像会明确跳过 Registry 请求，缺失镜像才尝试拉取。使用缓存的 `vulhub/vite:6.2.5` 实测返回 `Skipped Image is already present locally`，为后续离线试点消除了无意义的拉取等待；这不改变“缺失镜像仍无法下载”的外部阻塞结论。

### 步骤 4：环境类型感知的就绪检查（已完成）

完成时间：2026-07-17

Docker Compose 环境启动后的就绪判断已改为以下优先级：

1. Compose 声明了启用的 `healthcheck` 时，轮询 `docker compose ps --all --format json`，要求相应服务进入 `healthy`；
2. 没有 Compose healthcheck 时，Redis、PostgreSQL、MySQL、SSH、SMTP、LDAP、MQTT 等已知非 HTTP 端口使用 TCP 建连检查；
3. 其他本地目标使用 HTTP 检查，收到任意 HTTP 响应即视为服务已可达，不把非 200 状态误判为未启动；
4. 没有可检查的本地目标时明确记录 `type=none`，不伪造 HTTP 检查结果。

`setup_result.healthcheck` 现在记录 `compose`、`tcp`、`http` 或 `none` 类型、目标或服务列表，以及类型化失败原因。Compose 状态解析同时兼容 JSON 数组和逐行 JSON 输出。

验收结果：新增 Compose healthcheck 优先、TCP 端口路由和 Compose 状态解析测试；环境相关测试共 27 passed，Python 编译检查和 `git diff --check` 通过。唯一输出为既有 LangGraph 弃用预警。

后续 Airflow 真实复测发现 Windows 下 Docker CLI 的 UTF-8 JSON 被 Python 按系统 GBK 解码，导致健康轮询出现 `UnicodeDecodeError` 并误超时。命令执行器已显式改为 UTF-8 且使用替换式容错解码，避免状态输出中的非 GBK 字符破坏健康检查；该问题修正后重新执行真实复测，结果记录在步骤 7。

复测还发现通用命令归档的 2000 字符截断会破坏多服务 Compose 的完整 JSON。健康状态轮询现已单独保留完整结构化输出，其他普通命令仍维持长度上限；失败结果同时记录每个受检服务的最终 `service_health`，不再只给出笼统超时。

### 步骤 5：独立 Compose 项目与可靠回收（已完成）

完成时间：2026-07-17

每次 Docker Compose 启动现在都会生成独立的 `cvehunter-<环境>-<随机后缀>` project name，并将其写入 `setup_result.project_name`。`ps`、`pull`、`up`、健康状态轮询和 `down` 全部显式携带同一个 `-p <project_name>`，不再依赖 Compose 目录名推导出的共享默认项目。

所有权与回收规则如下：

- 启动前若独立 project name 下已经存在容器，立即拒绝接管，不再执行 `pull/up`；
- `up` 失败或健康检查超时时，立即对本次项目执行 `down --remove-orphans --volumes`，并归档 `cleanup_result`；
- 正常工作流结束时，从 `setup_result` 读取原 project name 执行相同回收；
- 旧记录或异常结果缺少 project name 时，拒绝对默认项目执行危险回收；
- 只有本工作流成功启动且明确拥有的环境会进入自动回收。

验收结果：新增独立项目启动、既有项目拒绝接管、启动失败即时清理测试，并更新正常结束回收测试；环境和报告相关测试共 38 passed，Python 编译检查和 `git diff --check` 通过。唯一输出为既有 LangGraph 弃用预警。

### 步骤 6：4 条低复杂度真实环境试点（已完成）

完成时间：2026-07-17

184 条待测清单中只有两条 Airflow 环境满足“镜像全缓存”，两者均为 7 服务复杂环境，不符合低复杂度基线要求。因此本步从本机已有缓存镜像中选择 4 个单容器真实产品环境，串行验收“独立项目 -> 启动 -> 就绪 -> 回收 -> 残留检查”。

| CVE | 产品环境 | 目标 | 就绪类型 | 启动/就绪 | 回收 | 残留容器 | 耗时 |
|---|---|---|---|---|---|---:|---:|
| CVE-2025-32395 | Vite 6.2.5 | `127.0.0.1:5173` | HTTP | 成功 | 成功 | 0 | 4.7s |
| CVE-2021-21311 | Adminer 4.7.8 | `127.0.0.1:8080` | HTTP | 成功 | 成功 | 0 | 5.0s |
| CVE-2018-3760 | Rails 5.0.7 | `127.0.0.1:3000` | HTTP | 成功 | 成功 | 0 | 6.5s |
| CVE-2021-40822 | GeoServer 2.19.1 | `127.0.0.1:8080` | HTTP | 成功 | 成功 | 0 | 18.1s |

4/4 环境均使用 `cvehunter-*` 独立 project name，缓存镜像通过 `pull --policy missing` 跳过 Registry，请求就绪后由 `teardown_environment` 执行 `down --remove-orphans --volumes`。每条回收后均按 `com.docker.compose.project` 标签复查，未发现残留容器。

本步建立了真实 Docker 环境生命周期基线，但没有执行 PoC 候选、IPS/目标侧 Oracle 或完整报告图，因此不能计为漏洞端到端复现成功；且这 4 条不属于当前 184 条待测清单，不能用于宣称该清单已有 4 条运行成功。

### 步骤 7：20/50/184 扩量门槛判断（已完成，本轮不扩量）

判断时间：2026-07-17

低复杂度环境基线达到 4/4 启动、就绪和回收成功，但目标清单的介质与复杂环境门槛没有同时满足：

| 门槛 | 当前证据 | 结论 |
|---|---|---|
| 184 条静态发现 | 184/184 找到 Compose，183 条配置有效 | 通过 |
| 首批 20 条介质 | 目标清单仅 2/184 镜像全缓存 | 不通过 |
| 缺失镜像拉取 | `docker pull hello-world:latest` 直连超时 | 不通过 |
| 低复杂度环境生命周期 | 4/4 启动、HTTP 就绪、回收、0 残留 | 通过，但样本不在 184 条待测清单 |
| 目标清单复杂环境 | 最终有效 Airflow 复测 0/1 ready | 不通过 |
| 完整验证图 | 本轮试点未执行候选、Oracle 和完整归档 | 不通过 |

`CVE-2020-11978` 的最终有效复测使用完整 UTF-8 Compose JSON，90 秒末状态为：Postgres `healthy`、Redis `healthy`、Flower `healthy`、Airflow Worker `unhealthy`，Webserver 和 Scheduler 的 `Health` 字段为空。失败项目执行 `down --remove-orphans --volumes` 成功，项目残留容器为 0。`CVE-2020-17526` 与其使用相同的 7 服务结构和缓存镜像；在发现解码问题前的运行不计入最终健康结论，门槛已由第一条有效复测否决，因此没有再次消耗 90 秒重复同质结果。

本轮决定：**不扩大到 20 条，也不进入 50 或 184 条运行批次。** 这是按门槛停止，不是把未运行项记为失败。当前 Docker 运行容器数、`cvehunter-*` 残留容器数和项目卷数均为 0。

恢复扩量的进入条件：

1. 恢复 Docker HTTPS 代理或可信内部 Registry mirror，并以 `docker pull hello-world:latest` 成功验收；
2. 预检中至少 20 条目标任务达到介质可用，且按端口分组后可串行或隔离运行；
3. 至少 3 条目标清单环境完成 ready、候选进入、归档和回收，不再只使用清单外基线；
4. Airflow 类环境先解决 Worker 不健康及 Webserver/Scheduler 无健康值问题，或明确环境专属初始化与超时规格；
5. 20 条批次达到 `environment_ready >= 80%`、`environment_cleaned = 100%`、跨项目干扰为 0，才进入 50 条；50 条维持相同门槛并完成失败分类复核后，才进入 184 条。

最终代码验收：`pytest -q` 为 115 passed、1 条第三方 LangGraph 弃用预警；Python 编译检查和 `git diff --check` 通过。

### 步骤 8：历史成功项溯源与永久防重（已完成）

完成时间：2026-07-17

原 197 条清单的生成口径不是“历史 PCAP 中未成功”，而是 2026-07-17 19:08 时从 246 个本地 Vulhub CVE 中排除当时已有批测记录的 49 条。生成过程没有读取 `data/cve/pcaps/漏洞类`，因此“未测试”命名不准确。

历史库当前包含 2524 个 PCAP 文件、1425 个唯一 CVE。原 197 条与其交集为 13 条，已从待测清单删除：

`CVE-2016-4977`、`CVE-2019-9053`、`CVE-2020-1957`、`CVE-2021-28073`、`CVE-2023-25157`、`CVE-2023-25826`、`CVE-2023-38646`、`CVE-2023-41892`、`CVE-2023-49070`、`CVE-2024-1561`、`CVE-2024-39907`、`CVE-2025-2945`、`CVE-2025-3248`。

去重后清单为 184 条，与历史成功 PCAP 的交集为 0。重新预检结果为 184/184 找到 Compose、183/184 配置有效、2 条镜像全缓存；唯一配置失败仍为 `CVE-2017-5223` 缺少 `.env`。

为防止以后重新生成清单时再次混入已做项，批量入口现在在执行前统一排除：

- `data/cve/pcaps/漏洞类` 中按文件名识别的历史成功 CVE；
- `output/batch` 中 `status=SUCCESS` 或 `passed=true` 的成功 CVE。

`--continue` 同时改为按 CVE 编号匹配本清单已有结果，不再只按可能因删行而错位的序号匹配。直接 `--batch` 仍保留原文件绝对序号，跳过成功项不会导致结果编号变化。

最终防重验收：当前 184 条与 1425 个历史成功 PCAP CVE、461 个批测成功 CVE 的并集交集均为 0；`pytest -q` 为 115 passed，`git diff --check` 通过。

### 步骤 9：通用初始化服务生命周期与目标服务健康过滤（已完成）

完成时间：2026-07-18

步骤 7 的 Airflow 复测暴露了多服务环境的两个通用问题：一次性数据库初始化服务与主服务并发启动导致竞态；健康检查把与漏洞入口无关的服务（如 Worker、Flower）纳入阻断条件，使已可用的 Web 入口被误判为未就绪。本步在不硬编码 Airflow 特例的前提下补齐通用生命周期。

改进要点：

1. **初始化服务先行**。以通用服务名模式 `(^|[-_])(init|initialize|migrate|migration|setup|bootstrap)([-_]|$)` 识别一次性初始化服务，先单独 `up -d` 并轮询到 `exited/0`，再启动其余主服务；识别不到初始化服务时保持原有单次 `up -d` 行为。
2. **初始化失败即停**。任一初始化服务以非零码退出或超时，立即对独立项目执行 `down --remove-orphans --volumes` 回收，并归档 `initialization` 与 `cleanup_result`，不再启动主服务，也不进入健康检查。
3. **目标服务健康过滤**。健康检查按目标 URL 端口映射到具体 Compose 服务后，只要求命中该端口的服务达到 `healthy`；其余服务的健康状态仍完整记录在 `observed_services` / `service_health`，但不作为阻断条件。无法映射到具体服务时，回退到原有的全 healthcheck 服务判定，再退到目标 URL 的 HTTP/TCP 检查。

这三条共同把“初始化竞态”和“非入口服务不健康”从误报的环境失败中分离出来。对 CVE-2020-11978 的 Airflow 环境，`airflow-init` 现在会先完成数据库初始化，Webserver（宿主 8080）作为漏洞入口单独判定就绪，Worker/Flower 状态仅作记录，不再阻断 ready。

验收结果：新增“初始化先行且主服务排除初始化服务”“初始化失败先回收再拒绝启动主服务”“健康检查只要求目标服务但完整观测其余服务”三条针对性测试；`tests/test_agents.py` 26 passed，完整套件 `pytest -q` 为 118 passed、1 条既有 LangGraph 弃用预警；`py_compile` 与 `git diff --check` 通过。

本步为纯生命周期编排修复，均以单元测试验证真实命令序列（`up -d <init>` -> 轮询 -> `up -d <main>` -> 目标服务健康过滤 -> 失败即 `down`），不涉及 PoC 载荷、外网目标或漏洞利用；真实容器复测仍限定为本地、单次、无害的就绪验证，并在结束后强制回收独立 Compose 项目、网络与卷。

真实容器复测（2026-07-18，`scripts/retest_cve_2020_11978.py`，独立项目 `cvehunter-airflowdiag-0718b`）结果如下，与步骤 7 的 0/1 ready 形成对照：

| 检查项 | 步骤 7（修复前） | 步骤 9（修复后） |
|---|---|---|
| `airflow-init` | 未单独先行 | `exited/0`，主服务启动前完成 |
| 目标就绪判定 | 全服务健康，被 Worker 阻断 | 仅 `airflow-webserver`(8080) `healthy` 即 ready |
| Webserver | 无健康值/未判定就绪 | `healthy` |
| Scheduler / Worker | 阻断 ready | `starting`，仅记录不阻断 |
| 环境就绪 | 失败（`INFRASTRUCTURE_FAILED`） | 成功（`healthcheck.success=true`） |
| 回收与残留 | 项目残留 0 | `teardown.success=true`，容器/网络/卷残留 0 |

复测只发起就绪健康检查，未执行 PoC 候选、Oracle 判定或漏洞利用，因此这条结果证明的是“Airflow 类多服务环境现在可稳定达到 ready 并被回收”，仍不等同于漏洞端到端复现成功；且该环境属于步骤 7 目标清单内的已缓存介质任务，可作为“目标清单复杂环境达到 ready”门槛的第一条真实证据。

### 步骤 10：失败路径强制回收、抓包/nuclei 链路修复与目标清单继续批测（已完成并持续运行）

完成时间：2026-07-19

#### 10.1 问题核实

对 `未测试_已有本地环境.txt` 的历史批测与 2026-07-19 试跑进行交叉核实时，确认了三类会直接拉低“环境/抓包成功率”观感的问题：

1. **容器残留**：`compose up` 后若健康检查失败，中间 `cleanup` 不成功时，因 `setup_result.success=False`，最终 `teardown_environment` 会跳过；汇总失败候选时还曾丢掉 `started_by_orchestrator`。结果是容器可能残留到下一条任务。
2. **代理与镜像**：早期批测时 `127.0.0.1:7890` 不可用，Docker Hub 拉取失败导致大量 `INFRASTRUCTURE_FAILED`。同日晚些时候代理恢复后，NVD 与 `docker pull` 均可用。
3. **抓包状态误标**：
   - 本机无 nuclei 时，nuclei 候选失败被 `error_type=capture_failed` 记成 `PCAP_CAPTURE_FAILED`；
   - 部分 raw HTTP 缺 `Host` 或仅有 `{{TARGET_HOST}}` 未替换，被本地服务拒绝为 `unknown`；
   - 中间一次 nuclei/抓包失败会以更高优先级覆盖前面“已成功发包但无利用证据”的最终状态。

#### 10.2 代码与配置改进

| 改动点 | 文件/位置 | 作用 |
|---|---|---|
| 所有权登记与失败路径保留 | `cve_hunter/agents.py` | `compose up` 后立即 `register_owned_compose_project`；失败结果仍可带 `started_by_orchestrator=True` |
| 候选失败汇总保留所有权元数据 | `_start_environment_candidates` | 不再只保留 error 字符串，避免最终 teardown 误 skip |
| 每 CVE 强制回收 + atexit | `main.run_cve` / `reclaim_owned_compose_projects` | 报告 teardown 之外的安全网；进程退出再兜底 |
| Host 注入 | `cve_hunter/verification.py` `_prepare_raw_http` | 替换 `{{TARGET_HOST}}`，缺 Host 时自动补环境目标 |
| 状态归因修正 | `cve_hunter/status_codes.py` | 缺 nuclei / policy_blocked 不再误标为 PCAP 抓包失败 |
| 中间失败不覆盖已发包结果 | `cve_hunter/graph.py` | 已有 `request_success` 时，临时 infra 错误不抬升最终状态 |
| nuclei 安装与服务 | `tools/bin/nuclei.exe` + `NUCLEI_PATH` | health 显示 nuclei available |
| nuclei 模板目录 | `tools/local_http2pcap_service.py` | 模板写入 `output/.tmp/nuclei`，避免 Docker 临时目录导致 `no templates provided` |
| 缺 nuclei 先返回 tool_missing | 同上 | 不启动 dumpcap，避免误报 capture_failed |

#### 10.3 服务与批测验收

本地抓包服务 smoke（2026-07-19）：

| 接口 | 结果 |
|---|---|
| `GET /api/health` | dumpcap/tshark/nuclei 均 available |
| `POST /api/http2pcap` | `success=true`，约 42 packets |
| `POST /api/nuclei-poc` | `success=true, matched=true`，约 60 packets |

目标清单继续批测（代理开启、本地容器模式、串行）：

```text
python -u main.py --continue --file 未测试_已有本地环境.txt --local-container --terminals 1
```

快照产物：`output/batch/未测试_已有本地环境_continue_20260719_175408_1_173_20260719_175408.json`

| 指标 | 结果 |
|---:|
| 计划/完成 | 173 / 6（跳过历史已有完成记录后的剩余集合） |
| passed | 1 |
| HTTP 环境 ready | 5/5 |
| cleanup passed | 5/5 |
| `TARGET_ORACLE_SUCCESS` | 1（CVE-2015-3337） |
| 正式 PCAP 归档 | `data/cve/pcaps/2026-07-19/CVE-2015-3337.pcap` |
| 成功路径 teardown | `environment_teardown_result.success=true`，独立 project down 成功 |

与修复前对比：

| 时期 | 代表性状态 | 含义 |
|---|---|---|
| 2026-07-17 早批 | `NVD_REQUEST_FAILED` / 镜像拉取失败 | 代理与介质阻塞 |
| 2026-07-19 修复前试跑 | `PCAP_CAPTURE_FAILED` 居多 | 抓包/nuclei/状态归因误伤 |
| 2026-07-19 修复后继续批 | `NO_EXPLOIT_EVIDENCE` / `TARGET_ORACLE_*` | 环境与发包已通，进入真实验证归因 |

#### 10.4 单元测试与边界

- 新增/更新：失败 setup 仍可 teardown、owned project reclaim、缺 nuclei/空抓包/policy 状态归因、Host 注入；
- 抽测：`tests/test_agents.py` + `tests/test_status_codes.py` + `tests/test_local_http2pcap_service.py` 共 52 passed；
- 明确边界：
  - `TARGET_ORACLE_SUCCESS` 证明目标侧利用证据成立，不等于 IPS 字段精确命中的 `CAPTURE_SUCCESS`；
  - 批测仍在后台继续，6/173 只是核实写入时的快照，不是终态；
  - 无 IPS 环境下，大量任务会合理停在 `NO_EXPLOIT_EVIDENCE` 或 `TARGET_ORACLE_FAILED`，这是验证标准问题，不是环境启动失败。

#### 10.5 对本报告前序门槛的影响

| 步骤 7 门槛 | 2026-07-19 状态 |
|---|---|
| 缺失镜像拉取 | 代理恢复后 `docker pull` 可用，阻塞解除 |
| 目标清单复杂/真实环境 ready | 清单内多条 ready，不再只有清单外 4 条基线 |
| 成功回收运行证据 | 已有多条 cleanup=passed 与 teardown 命令记录 |
| 完整验证图 | 已进入候选执行/Oracle/PCAP；IPS 精确成功仍待扩量 |

因此，步骤 7 当时“不扩量”的判断在当时证据下正确；2026-07-19 起已满足“可对 184 条做受控继续批测”的工程条件，并已实际启动。扩量目标从“证明链路存在”转为“统计 ready/cleanup/oracle/capture 分布并提升 PoC 命中”。
