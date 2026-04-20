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

**可选项：**
- `NVD_API_KEY` — 提升 NVD API 查询配额
- `TAVILY_API_KEY` — Tavily 搜索（不填则用 DuckDuckGo 备用）
- `HTTP2PCAP_URL` — 外部 http2pcap 服务地址
- `WAYBACK_URL` — 外部 wayback-cve 服务地址
- `TARGET_IP` — PoC 验证目标 IP

### 3. 运行

```bash
# 命令行模式
python main.py CVE-2021-44228

# 交互模式
python main.py
```

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
| SUCCESS | CAPTURE_SUCCESS | PoC 验证成功，IPS 命中 |
| FAILURE | AI_REPRODUCTION_FAILED | 所有源均已尝试，未能命中 IPS |
| FAILURE | PARAMETER_ERROR | CVE 编号格式错误 |
| FAILURE | NOT_HTTP_VULN | 非 HTTP 类漏洞 |

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
