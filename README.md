# CVE Hunter

基于 LangGraph 的 CVE 漏洞自动复现工具，实现"情报获取 → PoC 构造 → 流量验证 → 结果归档"的标准化闭环。

## 架构概述

本项目使用 **LangGraph** 编排工作流，复现了原 n8n 方案的完整 CVE HTTP 漏洞复现链路：

```
输入CVE → NVD查询 → AI类型判断 → 多源PoC搜索(带回退) → HTTP验证 → PCAP抓包 → 归档
```

### 工作流节点

| 节点 | 功能 |
|------|------|
| `validate_input` | 验证 CVE 编号格式 |
| `query_nvd` | 查询 NVD 官方 API 获取漏洞信息与 References |
| `vuln_type_check` | AI 判断是否为 HTTP/Web 漏洞 |
| `reference_analysis` | 提取 NVD References 链接中的网页内容 |
| `poc_from_refs` | 基于 References 内容由 AI 生成 PoC |
| `nuclei_search` | 搜索 nuclei-templates 官方 PoC 库 |
| `exploitdb_search` | 搜索 Exploit-DB |
| `imfht_search` | 搜索 imfht 漏洞库 |
| `web_search` | Tavily/DuckDuckGo 联网搜索 + AI 构造 PoC |
| `verify_poc` | 发送 HTTP 请求验证 PoC |
| `generate_report` | 生成分析报告并归档所有产物 |

### PoC 搜索回退优先级

```
NVD References → Nuclei → Exploit-DB → imfht → 联网搜索+AI构造
```

任一阶段验证成功（IPS 命中）即结束；全部失败则标记为复现失败。

## 快速开始

### 1. 环境准备

```bash
conda activate cve_hunter
pip install -r requirements.txt
```

### 2. 配置

复制 `.env.example` 为 `.env` 并填写：

```bash
cp .env.example .env
```

**必填项：**
- `LLM_API_KEY` — 大模型 API Key（支持 DeepSeek、OpenAI 兼容接口）
- `LLM_BASE_URL` — API 地址（默认 DeepSeek，也可用 `https://jeniya.top/v1` 等中转）
- `LLM_MODEL` — 模型名称（如 `deepseek-chat`、`gpt-4o`）

**网络代理（国内服务器必配）：**
- `HTTP_PROXY` / `HTTPS_PROXY` — 所有外部请求（NVD、GitHub、搜索等）均走此代理

**可选项：**
- `NVD_API_KEY` — 提升 NVD API 查询配额
- `TAVILY_API_KEY` — Tavily 搜索（不填则用 DuckDuckGo 备用）
- `HTTP2PCAP_URL` — 外部 http2pcap 服务地址
- `IPS_API_URL` — 防火墙/IPS 检测接口地址（http2pcap 服务启用 `check_ips` 时使用）
- `WAYBACK_URL` — 外部 wayback-cve 服务地址
- `TARGET_IP` — PoC 验证目标 IP

### 3. 运行

```bash
# 命令行模式
python main.py CVE-2021-44228

# 批量测试模式（从 test 目录选择 txt 文件和测试范围）
python main.py --batch

# 非交互批量测试：测试 fhq-http.txt 中第 1 到第 20 个 CVE
python main.py --batch --file fhq-http.txt --start 1 --end 20

# 多开 VS Code 集成终端批量测试：把第 1 到第 100 个 CVE 拆成 5 个终端执行
python main.py --batch --file fhq-http.txt --start 1 --end 100 --terminals 5

# 分类筛选：只做 HTTP/非 HTTP 判断，输出 fhq-http_h.txt 和 fhq-http_f.txt
python main.py --classify --file fhq-http.txt

# 统计 output/batch 下已有 JSON 测试记录
python main.py --stats

# 二次核验 output/batch 中 HTTP 类型未通过记录，并覆盖原 JSON 结果
python main.py --retry-http-failed

# 正确数据核验：重跑历史通过记录，清理旧版本把通用 IPS 命中误判为当前 CVE 成功的结果
python main.py --retry-http-failed --retry-mode passed

# 指定状态码核验：只重跑 status_code 匹配的记录，多个状态码可逗号分隔
python main.py --retry-mode status --status-code AI_REPRODUCTION_FAILED,POC_NOT_FOUND

# 多开 VS Code 集成终端二次核验：筛选第 2001 到第 5000 个原始序号，拆成 5 个终端执行
python main.py --retry-http-failed --start 2001 --end 5000 --terminals 5

# 交互模式
python main.py
```

批量测试会按 `test/*.txt` 中出现的 CVE 编号顺序执行，范围为 1-based 闭区间。批量模式会隐藏单条任务内部的查询、AI 生成和发包过程日志，只在每个 CVE 完成后显示最终结果、进度和正确率；明细会在每条结束后实时写入 `output/batch/`。

批量测试支持 `--terminals/-t` 自动拆分范围，并通过 VS Code Tasks 在集成终端中并行运行；交互模式下选择测试范围后也会询问启动终端数量，默认 1 个。多终端启动会自动写入 `output/vscode/cve_hunter_launch.code-workspace` 并打开一个 VS Code 自动任务工作区。

分类筛选同样支持 `--start` / `--end`，但只调用 NVD 查询和 AI HTTP/Web 类型判断，不执行 PoC 检索、发包或抓包。

统计模式只读取 `output/batch/*.json`，展示每个 JSON 的完成数、HTTP/非 HTTP 数、总正确率，以及排除非 HTTP 后的正确率。

二次核验默认处理已完成 JSON 中的 HTTP 失败记录，排除 `NOT_HTTP_VULN` 和 `PARAMETER_ERROR`。可用 `--retry-mode passed` 核验历史通过记录，或 `--retry-mode all` 同时核验失败与历史通过记录。核验完成后会把该条明细直接覆盖回原 JSON，并重新计算 JSON 顶层的 `passed` 数。
也可用 `--retry-mode status --status-code <状态码>` 按指定 `status_code` 精确筛选后重跑；`--status-code` 支持多次传入或用逗号分隔，且不额外判断历史 `passed` 值。

## 输出产物

每次复现的产物保存在 `output/<CVE-ID>/` 目录下：

| 文件 | 说明 |
|------|------|
| `result.json` | 结构化复现结果 |
| `report.md` | AI 生成的分析报告 |
| `poc.http` | 原始 HTTP 请求 PoC |
| `poc.yaml` | Nuclei YAML 模板（如有） |

PCAP 文件保存在 `output/pcap/` 目录下。

## 返回状态码

| status | code | 说明 |
|--------|------|------|
| SUCCESS | CAPTURE_SUCCESS | PoC 验证成功，IPS 日志 CVE 字段匹配当前 CVE |
| FAILURE | PARAMETER_ERROR | CVE 编号格式错误 |
| FAILURE | NOT_HTTP_VULN | 非 HTTP 类漏洞 |
| FAILURE | NVD_NOT_FOUND | NVD 中未找到该 CVE |
| FAILURE | NVD_RATE_LIMITED | NVD API 限流或配额限制 |
| FAILURE | NVD_REQUEST_FAILED | NVD API 请求失败 |
| FAILURE | API_QUOTA_EXHAUSTED | 外部 API 余额或额度耗尽 |
| FAILURE | API_AUTH_FAILED | 外部 API 鉴权失败 |
| FAILURE | API_RATE_LIMITED | 外部 API 限流 |
| FAILURE | API_REQUEST_FAILED | 外部 API 请求失败 |
| FAILURE | URL_ACCESS_FAILED | 参考链接或网页访问失败 |
| FAILURE | WEB_SEARCH_FAILED | 联网搜索失败 |
| FAILURE | POC_SOURCE_ACCESS_FAILED | PoC 来源站点访问失败 |
| FAILURE | POC_NOT_FOUND | 未找到可用 PoC |
| FAILURE | HTTP2PCAP_SERVICE_FAILED | http2pcap 服务调用失败 |
| FAILURE | TARGET_ACCESS_FAILED | 目标网址访问失败 |
| FAILURE | HTTP_REQUEST_FAILED | PoC HTTP 请求发送失败 |
| FAILURE | PCAP_CAPTURE_FAILED | PCAP 抓包失败 |
| FAILURE | IPS_GENERIC_MATCH_ONLY | 只检测到通用/非当前 CVE IPS 命中 |
| FAILURE | AI_REPRODUCTION_FAILED | 所有源均已尝试，未能命中当前 CVE 的 IPS 规则 |
| FAILURE | BATCH_EXCEPTION | 批量任务执行异常 |

## 项目结构

```
.
├── main.py                        # CLI 入口
├── requirements.txt               # Python 依赖
├── .env.example                   # 环境变量模板
├── cve_hunter/
│   ├── config.py                  # 全局配置
│   ├── state.py                   # LangGraph 状态定义
│   ├── graph.py                   # LangGraph 工作流编排
│   ├── llm.py                     # LLM 调用封装（支持降级）
│   ├── prompts/
│   │   └── templates.py           # Prompt 模板
│   └── tools/
│       ├── nvd.py                 # NVD API 查询
│       ├── poc_sources.py         # PoC 多源检索
│       ├── web_extract.py         # 网页内容提取
│       ├── web_search.py          # 联网搜索
│       └── http_sender.py         # HTTP 发送 + PCAP 抓包
└── output/                        # 输出目录（运行时生成）
```

## 依赖的外部服务（可选）

- **http2pcap**：HTTP 请求发送 + PCAP 抓包 + IPS 检测服务。不配置时使用内置 httpx + scapy。
- **防火墙/IPS API**：http2pcap 服务使用 `IPS_API_URL` 查询命中结果，接口形如 `http://<host>:3013/api/cve-match`。
- **wayback-cve**：网页内容提取服务。不配置时使用内置 httpx + trafilatura。

## 与原 n8n 工作流的对应关系

| n8n 模块 | LangGraph 节点 |
|----------|----------------|
| 自动化输入 CVE 编号 | `validate_input` |
| IPS 特征预检 | `verify_poc` (IPS check) |
| AI 判断是否 HTTP 漏洞 | `vuln_type_check` |
| 获取 NVD 通报信息 | `query_nvd` + `reference_analysis` |
| AI 基于 References 生成 PoC | `poc_from_refs` |
| 检索 nuclei/exploit-db/imfht | `nuclei_search` / `exploitdb_search` / `imfht_search` |
| Bing/Tavily 联网搜索 | `web_search` |
| 自动发包抓包 | `verify_poc` |
| 归档 PoC/PCAP/结果 | `generate_report` |
