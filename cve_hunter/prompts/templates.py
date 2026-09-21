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

## 触发模型（规则预分析结果，供生成时参考；不得据此编造路径）
{trigger_context}

## 参考链接内容
{reference_contents}

## 任务
根据以上信息，生成 0-3 个可以直接发送的 HTTP PoC 候选。

从参考链接内容中寻找明确的利用证据，按优先级逐字提取：
1. curl 命令（如 `curl -X POST http://host/path --data '...'`）
2. 原始 HTTP 请求示例（`GET /path HTTP/1.1` 或 `POST /path HTTP/1.1`）
3. exploit 代码里的 URL 拼接或请求库调用（requests.get/post、urllib、fetch、axios 等）

只从这些证据里逐字提取 method/path/参数/header/payload。如果参考内容为空、或只有漏洞原理描述、没有具体请求细节，返回空数组，严禁用 CVE 编号或产品名去猜测路径。
请严格只输出 JSON，不要输出 Markdown、代码块或解释文本。

JSON 格式：
{{
  "candidates": [
    {{
      "method": "GET",
      "path": "/path1",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }},
      "body": "",
      "evidence_url": "支持该 PoC 的参考链接 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个请求可能触发该 CVE"
    }},
    {{
      "method": "POST",
      "path": "/path2",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded"
      }},
      "body": "param=value",
      "evidence_url": "支持该 PoC 的参考链接 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个请求可能触发该 CVE"
    }}
  ]
}}

要求：
1. Host 必须使用 {{{{TARGET_HOST}}}} 占位符
2. method/path/headers/body 必须能由程序渲染成 Raw HTTP Request
3. 候选的 path/参数/header/payload 必须能在参考内容中找到明确出处，逐字引用，不得改写或猜测
4. 证据不足时直接返回 {{"candidates":[]}}，不要降低 confidence 硬凑一个模糊请求
5. 候选数量不固定（0-3 个）：证据支撑几个就输出几个；没有具体利用细节就输出空数组，绝不为凑数编造路径
"""

POC_GENERATION_FROM_SEARCH = """\
你是一位网络安全专家，擅长编写漏洞 PoC。

## 漏洞信息
- CVE 编号: {cve_id}
- 描述: {description}
- CVSS: {cvss_score} ({cvss_severity})
- 受影响产品: {affected_products}
- 漏洞类型: {vuln_type}

## 触发模型（规则预分析结果，供生成时参考；不得据此编造路径）
{trigger_context}

## 搜索结果
{search_results}

## 任务
根据以上搜索到的信息，生成 0-3 个可以直接发送的 HTTP PoC 候选。

从搜索结果中寻找明确的利用证据，按优先级逐字提取：
1. curl 命令（如 `curl -X POST http://host/path --data '...'`）
2. 原始 HTTP 请求示例（`GET /path HTTP/1.1` 或 `POST /path HTTP/1.1`）
3. exploit 代码里的 URL 拼接或请求库调用（requests.get/post、urllib、fetch、axios 等）
4. nuclei 模板中的 requests/http 段

只从这些证据里逐字提取 method/path/参数/header/payload。如果搜索结果只有漏洞原理描述、没有具体请求细节，返回空数组，严禁用 CVE 编号或产品名去猜测路径。
请严格只输出 JSON，不要输出 Markdown、代码块或解释文本。

JSON 格式：
{{
  "candidates": [
    {{
      "method": "GET",
      "path": "/path1",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*"
      }},
      "body": "",
      "evidence_url": "支持该 PoC 的搜索结果 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个请求可能触发该 CVE"
    }},
    {{
      "method": "POST",
      "path": "/path2",
      "headers": {{
        "Host": "{{{{TARGET_HOST}}}}",
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded"
      }},
      "body": "param=value",
      "evidence_url": "支持该 PoC 的搜索结果 URL，没有则为空字符串",
      "confidence": 0.0,
      "reason": "为什么这个请求可能触发该 CVE"
    }}
  ]
}}

要求：
1. Host 必须使用 {{{{TARGET_HOST}}}} 占位符
2. method/path/headers/body 必须能由程序渲染成 Raw HTTP Request
3. 候选的 path/参数/header/payload 必须能在搜索结果中找到明确出处，逐字引用，不得改写或猜测
4. 证据不足时直接返回 {{"candidates":[]}}，不要降低 confidence 硬凑一个模糊请求
5. 候选数量不固定（0-3 个）：证据支撑几个就输出几个；没有具体利用细节就输出空数组，绝不为凑数编造路径
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
- PoC 候选数量: {poc_candidate_count}
- PoC 候选摘要: {poc_candidate_summary}
- 当前/最后选中 PoC 预览: {poc_preview}
- 已尝试阶段: {phases_tried}
- 执行策略: RUN_MODE={run_mode}, TARGET_ALLOWLIST={target_allowlist}
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

约束：
- 如果 PoC 候选数量大于 0，不要写“未获取到任何可用 PoC”；应说明“已生成候选，但未完成执行验证”。
- RUN_MODE=plan_only 只阻止真实发包/验证，不阻止情报搜索或 PoC 生成。
- 本工具有效运行模式只有 plan_only、local_lab、authorized_target；不要建议 full_run。
- 如果状态码是 EXECUTION_POLICY_BLOCKED，失败主因是执行策略阻止，不要归因为 PoC 来源访问失败。
"""
