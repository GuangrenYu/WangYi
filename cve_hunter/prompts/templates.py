"""LLM Prompt 模板。"""

VULN_TYPE_CHECK = """\
你是一位网络安全专家。请根据以下 CVE 漏洞信息，判断该漏洞是否属于 HTTP/Web 网络交互漏洞。

CVE 编号: {cve_id}
漏洞描述: {description}
CVSS 评分: {cvss_score} ({cvss_severity})
受影响产品: {affected_products}

请严格按以下 JSON 格式回答（不要输出其他内容）：
{{"is_http_vuln": true/false, "vuln_type": "漏洞类型简述", "reason": "判断理由"}}
"""

POC_GENERATION_FROM_REFS = """\
你是一位网络安全专家，擅长编写漏洞 PoC。

## 漏洞信息
- CVE 编号: {cve_id}
- 描述: {description}
- CVSS: {cvss_score} ({cvss_severity})
- 受影响产品: {affected_products}
- 漏洞类型: {vuln_type}

## 参考链接内容
{reference_contents}

## 任务
根据以上信息，生成一个可以直接发送的 HTTP 原始请求（Raw HTTP Request）作为 PoC。
请直接输出原始 HTTP 请求报文，格式如下：

```http
METHOD /path HTTP/1.1
Host: {{{{TARGET_HOST}}}}
...其他头部...

请求体（如有）
```

要求：
1. Host 使用 {{{{TARGET_HOST}}}} 占位符
2. 尽量利用参考链接中提取到的利用路径、参数、payload
3. 如果有多个可能的 PoC，每个用 --- 分隔
4. 只输出 HTTP 报文，不要输出解释
"""

POC_GENERATION_FROM_SEARCH = """\
你是一位网络安全专家，擅长编写漏洞 PoC。

## 漏洞信息
- CVE 编号: {cve_id}
- 描述: {description}
- CVSS: {cvss_score} ({cvss_severity})
- 受影响产品: {affected_products}
- 漏洞类型: {vuln_type}

## 搜索结果
{search_results}

## 任务
根据以上搜索到的信息，生成一个可以直接发送的 HTTP 原始请求（Raw HTTP Request）作为 PoC。
请直接输出原始 HTTP 请求报文，格式如下：

```http
METHOD /path HTTP/1.1
Host: {{{{TARGET_HOST}}}}
...其他头部...

请求体（如有）
```

要求：
1. Host 使用 {{{{TARGET_HOST}}}} 占位符
2. 尽量利用搜索结果中找到的利用路径、参数、payload
3. 如果有多个可能的 PoC，每个用 --- 分隔
4. 只输出 HTTP 报文，不要输出解释
"""

ANALYSIS_REPORT = """\
你是一位网络安全分析师。请根据以下漏洞复现过程的信息，生成一份简洁的分析报告。

## 漏洞信息
- CVE 编号: {cve_id}
- 描述: {description}
- CVSS: {cvss_score} ({cvss_severity})
- 受影响产品: {affected_products}
- 漏洞类型: {vuln_type}

## 复现过程
- PoC 来源: {poc_source}
- 已尝试阶段: {phases_tried}
- 最终状态: {status}
- 状态码: {status_code}
- 错误信息: {error_messages}

## 验证结果
- HTTP 状态码: {http_status_code}
- IPS 命中: {ips_matched}
- PCAP 文件: {pcap_file_path}

请输出 Markdown 格式的分析报告，包括：
1. 漏洞概述
2. 复现过程总结
3. PoC 详情（如有）
4. 验证结果
5. 建议
"""
