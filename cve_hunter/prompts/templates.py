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
根据以上信息，生成 1-3 个可以直接发送的 HTTP PoC 候选。
请严格只输出 JSON，不要输出 Markdown、代码块或解释文本。

JSON 格式：
{{
  "candidates": [
    {{
      "method": "GET",
      "path": "/path",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }},
      "body": "",
      "evidence_url": "支持该 PoC 的参考链接 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个请求可能触发该 CVE"
    }}
  ]
}}

要求：
1. Host 必须使用 {{{{TARGET_HOST}}}} 占位符
2. method/path/headers/body 必须能由程序渲染成 Raw HTTP Request
3. 优先使用参考链接中明确出现的利用路径、参数、header、payload
4. 证据不足时降低 confidence，不要编造不存在的产品路径
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
根据以上搜索到的信息，生成 1-3 个可以直接发送的 HTTP PoC 候选。
请严格只输出 JSON，不要输出 Markdown、代码块或解释文本。

JSON 格式：
{{
  "candidates": [
    {{
      "method": "GET",
      "path": "/path",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }},
      "body": "",
      "evidence_url": "支持该 PoC 的搜索结果 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个请求可能触发该 CVE"
    }}
  ]
}}

要求：
1. Host 必须使用 {{{{TARGET_HOST}}}} 占位符
2. method/path/headers/body 必须能由程序渲染成 Raw HTTP Request
3. 优先使用搜索结果中明确出现的利用路径、参数、header、payload
4. 证据不足时降低 confidence，不要编造不存在的产品路径
"""

POC_REFLECTION_AFTER_VERIFY = """\
你是一位网络安全专家，负责在 PoC 验证失败后做有限修正。

## 漏洞信息
- CVE 编号: {cve_id}
- 描述: {description}
- 受影响产品: {affected_products}
- 漏洞类型: {vuln_type}

## 当前失败候选
{current_candidate}

## 验证反馈
- HTTP 状态码: {http_status_code}
- 响应片段:
{http_response_body}
- 当前 CVE IPS 命中: {ips_matched}
- 通用/非当前 CVE IPS 命中: {generic_ips_matched}
- IPS 命中统计: {ips_match_summary}

## 最近尝试轨迹
{attempt_history}

## 任务
基于失败反馈，生成 0-2 个当前 PoC 的小变体候选。
请严格只输出 JSON，不要输出 Markdown、代码块或解释文本。

JSON 格式：
{{
  "candidates": [
    {{
      "method": "GET",
      "path": "/path",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }},
      "body": "",
      "evidence_url": "沿用或补充支持该变体的 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个变体可能修正上一次失败"
    }}
  ]
}}

限制：
1. 只能调整 path、query/body 参数、header、method、Content-Type、URL 编码形式
2. 不要更换产品、CVE、漏洞链或编造全新利用路径
3. 如果失败原因无法通过小改动修正，输出 {{"candidates": []}}
4. Host 必须使用 {{{{TARGET_HOST}}}} 占位符
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
- 当前 CVE IPS 命中: {ips_matched}
- 通用/非当前 CVE IPS 命中: {generic_ips_matched}
- IPS 命中统计: {ips_match_summary}
- PCAP 文件: {pcap_file_path}

请输出 Markdown 格式的分析报告，包括：
1. 漏洞概述
2. 复现过程总结
3. PoC 详情（如有）
4. 验证结果
5. 建议
"""
