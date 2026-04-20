"""LangGraph 工作流核心编排。

实现 CVE HTTP 漏洞复现的完整工作流：
  输入CVE → 获取NVD信息 → 适用性判断 → 多源PoC搜索(带回退) → 验证 → 归档
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from langgraph.graph import StateGraph, END

from cve_hunter.config import cfg
from cve_hunter.state import CVEState
from cve_hunter.llm import invoke_llm
from cve_hunter.prompts.templates import (
    VULN_TYPE_CHECK,
    POC_GENERATION_FROM_REFS,
    POC_GENERATION_FROM_SEARCH,
    ANALYSIS_REPORT,
)
from cve_hunter.tools.nvd import query_nvd
from cve_hunter.tools.web_extract import extract_url_content
from cve_hunter.tools.poc_sources import search_nuclei, search_exploitdb, search_imfht
from cve_hunter.tools.web_search import search_web
from cve_hunter.tools.http_sender import send_poc_and_capture

from rich.console import Console

console = Console()


# ═══════════════════════════════════════════════════════════
# 节点函数
# ═══════════════════════════════════════════════════════════


def node_validate_input(state: CVEState) -> dict:
    """验证输入的 CVE 编号格式。"""
    console.print(f"[bold cyan]▶ 验证输入[/] {state.cve_id}")
    cve_id = state.cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return {
            "status": "FAILURE",
            "status_code": "PARAMETER_ERROR",
            "message": f"CVE 编号格式错误: {state.cve_id}",
        }
    return {"cve_id": cve_id, "current_phase": "nvd_query"}


def node_query_nvd(state: CVEState) -> dict:
    """查询 NVD 获取 CVE 详细信息。"""
    console.print(f"[bold cyan]▶ 查询 NVD[/] {state.cve_id}")
    try:
        info = query_nvd(state.cve_id)
        if "error" in info:
            return {
                "error_messages": state.error_messages + [info["error"]],
                "nvd_description": "",
                "current_phase": "vuln_type_check",
            }
        console.print(f"  [green]✓[/] CVSS={info['cvss_score']} refs={len(info['references'])}")
        return {
            "nvd_description": info["description"],
            "nvd_references": info["references"],
            "affected_products": info["affected_products"],
            "cvss_score": info["cvss_score"],
            "cvss_severity": info["cvss_severity"],
            "current_phase": "vuln_type_check",
        }
    except Exception as e:
        console.print(f"  [red]✗ NVD 查询失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"NVD 查询失败: {e}"],
            "current_phase": "vuln_type_check",
        }


def node_vuln_type_check(state: CVEState) -> dict:
    """AI 判断漏洞是否属于 HTTP/Web 类型。"""
    console.print("[bold cyan]▶ AI 漏洞类型判断[/]")

    if not state.nvd_description:
        console.print("  [yellow]⚠ 无 NVD 描述，默认为 HTTP 漏洞继续处理[/]")
        return {"is_http_vuln": True, "vuln_type": "未知", "current_phase": "reference_analysis"}

    prompt = VULN_TYPE_CHECK.format(
        cve_id=state.cve_id,
        description=state.nvd_description,
        cvss_score=state.cvss_score,
        cvss_severity=state.cvss_severity,
        affected_products=", ".join(state.affected_products[:5]),
    )

    try:
        result = invoke_llm(prompt)
        cleaned = re.sub(r"```json\s*|\s*```", "", result).strip()
        data = json.loads(cleaned)
        is_http = data.get("is_http_vuln", True)
        vuln_type = data.get("vuln_type", "未知")
        console.print(f"  [green]✓[/] is_http={is_http} type={vuln_type}")
        return {
            "is_http_vuln": is_http,
            "vuln_type": vuln_type,
            "current_phase": "reference_analysis",
        }
    except Exception as e:
        console.print(f"  [yellow]⚠ AI 判断解析失败，默认继续:[/] {e}")
        return {"is_http_vuln": True, "vuln_type": "未知", "current_phase": "reference_analysis"}


def node_reference_analysis(state: CVEState) -> dict:
    """提取 NVD References 中的网页内容并分析。"""
    console.print(f"[bold cyan]▶ 分析 References[/] ({len(state.nvd_references)} 个链接)")
    if not state.nvd_references:
        return {"current_phase": "poc_from_refs", "phases_tried": state.phases_tried + ["reference_analysis"]}

    contents = []
    for i, url in enumerate(state.nvd_references[:8]):
        console.print(f"  [{i+1}] {url[:80]}...")
        result = extract_url_content(url)
        if result.get("content"):
            contents.append({"url": url, "title": result.get("title", ""), "content": result["content"][:3000]})

    console.print(f"  [green]✓[/] 成功提取 {len(contents)} 个页面内容")
    return {
        "reference_contents": contents,
        "current_phase": "poc_from_refs",
        "phases_tried": state.phases_tried + ["reference_analysis"],
    }


def node_poc_from_refs(state: CVEState) -> dict:
    """基于 References 内容让 AI 生成 PoC。"""
    console.print("[bold cyan]▶ 基于 References 生成 PoC[/]")

    if not state.reference_contents:
        console.print("  [yellow]⚠ 无 Reference 内容，跳过[/]")
        return {"current_phase": "nuclei_search", "phases_tried": state.phases_tried + ["poc_from_refs"]}

    ref_text = ""
    for ref in state.reference_contents:
        ref_text += f"\n### {ref['title']} ({ref['url']})\n{ref['content'][:2000]}\n"

    prompt = POC_GENERATION_FROM_REFS.format(
        cve_id=state.cve_id,
        description=state.nvd_description,
        cvss_score=state.cvss_score,
        cvss_severity=state.cvss_severity,
        affected_products=", ".join(state.affected_products[:5]),
        vuln_type=state.vuln_type,
        reference_contents=ref_text[:8000],
    )

    try:
        result = invoke_llm(prompt)
        pocs = _extract_http_requests(result, state.cve_id)
        if pocs:
            console.print(f"  [green]✓[/] AI 生成了 {len(pocs)} 个 PoC")
            return {
                "poc_raw_http": pocs[0],
                "poc_payloads": pocs,
                "poc_source": "reference",
                "current_phase": "verify_poc",
                "phases_tried": state.phases_tried + ["poc_from_refs"],
            }
    except Exception as e:
        console.print(f"  [red]✗ AI 生成失败:[/] {e}")

    return {"current_phase": "nuclei_search", "phases_tried": state.phases_tried + ["poc_from_refs"]}


def node_nuclei_search(state: CVEState) -> dict:
    """在 nuclei-templates 搜索官方 PoC。"""
    console.print("[bold cyan]▶ 搜索 Nuclei 官方 PoC 库[/]")
    try:
        result = search_nuclei(state.cve_id)
        if result.get("found"):
            console.print(f"  [green]✓[/] 找到 nuclei 模板: {result.get('name', '')}")
            return {
                "poc_nuclei_yaml": result["yaml_content"],
                "poc_source": "nuclei",
                "current_phase": "verify_poc",
                "phases_tried": state.phases_tried + ["nuclei_search"],
            }
        console.print("  [yellow]⚠ nuclei 库中未找到[/]")
    except Exception as e:
        console.print(f"  [red]✗ 搜索失败:[/] {e}")

    return {"current_phase": "exploitdb_search", "phases_tried": state.phases_tried + ["nuclei_search"]}


def node_exploitdb_search(state: CVEState) -> dict:
    """在 Exploit-DB 搜索 PoC。"""
    console.print("[bold cyan]▶ 搜索 Exploit-DB[/]")
    try:
        result = search_exploitdb(state.cve_id)
        if result.get("found"):
            records = result.get("results", [])
            console.print(f"  [green]✓[/] 找到 {len(records)} 个 exploit")
            # 提取 exploit 内容
            for rec in records[:2]:
                content = extract_url_content(rec["url"])
                if content.get("content"):
                    pocs = _extract_http_requests(content["content"], state.cve_id)
                    if pocs:
                        return {
                            "poc_raw_http": pocs[0],
                            "poc_payloads": pocs,
                            "poc_source": "exploit-db",
                            "current_phase": "verify_poc",
                            "phases_tried": state.phases_tried + ["exploitdb_search"],
                        }
        console.print("  [yellow]⚠ Exploit-DB 中未找到可用 PoC[/]")
    except Exception as e:
        console.print(f"  [red]✗ 搜索失败:[/] {e}")

    return {"current_phase": "imfht_search", "phases_tried": state.phases_tried + ["exploitdb_search"]}


def node_imfht_search(state: CVEState) -> dict:
    """在 imfht 漏洞库搜索。"""
    console.print("[bold cyan]▶ 搜索 imfht 漏洞库[/]")
    try:
        result = search_imfht(state.cve_id)
        if result.get("found"):
            console.print("  [green]✓[/] imfht 找到漏洞信息")
            pocs = _extract_http_requests(result.get("content", ""), state.cve_id)
            if pocs:
                return {
                    "poc_raw_http": pocs[0],
                    "poc_payloads": pocs,
                    "poc_source": "imfht",
                    "current_phase": "verify_poc",
                    "phases_tried": state.phases_tried + ["imfht_search"],
                }
        console.print("  [yellow]⚠ imfht 中未找到可用 PoC[/]")
    except Exception as e:
        console.print(f"  [red]✗ 搜索失败:[/] {e}")

    return {"current_phase": "web_search", "phases_tried": state.phases_tried + ["imfht_search"]}


def node_web_search(state: CVEState) -> dict:
    """联网搜索并由 AI 生成 PoC。"""
    console.print("[bold cyan]▶ 联网搜索 + AI 构造 PoC[/]")

    queries = [
        f"{state.cve_id} PoC exploit HTTP",
        f"{state.cve_id} vulnerability exploit payload",
    ]

    all_results = []
    for q in queries:
        results = search_web(q, max_results=5)
        all_results.extend(results)

    if not all_results:
        console.print("  [yellow]⚠ 搜索无结果[/]")
        return {"current_phase": "generate_report", "phases_tried": state.phases_tried + ["web_search"]}

    console.print(f"  搜索到 {len(all_results)} 条结果")

    # 提取高价值页面内容
    search_text = ""
    for r in all_results[:5]:
        if r.get("content"):
            search_text += f"\n### {r['title']} ({r['url']})\n{r['content'][:2000]}\n"
        elif r.get("url"):
            page = extract_url_content(r["url"])
            if page.get("content"):
                search_text += f"\n### {page['title']} ({r['url']})\n{page['content'][:2000]}\n"

    prompt = POC_GENERATION_FROM_SEARCH.format(
        cve_id=state.cve_id,
        description=state.nvd_description,
        cvss_score=state.cvss_score,
        cvss_severity=state.cvss_severity,
        affected_products=", ".join(state.affected_products[:5]),
        vuln_type=state.vuln_type,
        search_results=search_text[:8000],
    )

    try:
        result = invoke_llm(prompt)
        pocs = _extract_http_requests(result, state.cve_id)
        if pocs:
            console.print(f"  [green]✓[/] AI 基于搜索结果生成了 {len(pocs)} 个 PoC")
            return {
                "poc_raw_http": pocs[0],
                "poc_payloads": pocs,
                "poc_source": "search",
                "current_phase": "verify_poc",
                "phases_tried": state.phases_tried + ["web_search"],
            }
    except Exception as e:
        console.print(f"  [red]✗ AI 生成失败:[/] {e}")

    return {"current_phase": "generate_report", "phases_tried": state.phases_tried + ["web_search"]}


def node_verify_poc(state: CVEState) -> dict:
    """发送 PoC 并验证。"""
    console.print(f"[bold cyan]▶ 验证 PoC[/] (来源: {state.poc_source})")

    target = cfg.target_ip

    if state.poc_source == "nuclei" and state.poc_nuclei_yaml:
        console.print("  使用 Nuclei YAML 模板验证...")
        result = send_poc_and_capture(
            nuclei_yaml=state.poc_nuclei_yaml,
            target_url=f"http://{target}",
        )
    elif state.poc_raw_http:
        # 原始 HTTP 请求验证
        raw = state.poc_raw_http.replace("{{TARGET_HOST}}", target)
        console.print(f"  发送 HTTP 请求到 {target}...")
        result = send_poc_and_capture(raw_http=raw)
    else:
        return {"current_phase": _next_phase_after_verify(state)}

    success = result.get("success", False)
    ips_matches = result.get("ips_matches", [])
    ips_matched = len(ips_matches) > 0

    updates = {
        "http_status_code": result.get("status_code", 0),
        "http_response_body": result.get("body", "")[:2000],
        "pcap_file_path": result.get("pcap_file_path", ""),
        "ips_matched": ips_matched,
        "ips_match_details": ips_matches,
    }

    if ips_matched:
        console.print(f"  [bold green]✓ IPS 命中![/] {len(ips_matches)} 条匹配")
        updates["status"] = "SUCCESS"
        updates["status_code"] = "CAPTURE_SUCCESS"
        updates["message"] = "PoC 验证成功，IPS 命中"
        updates["current_phase"] = "archive"
    elif success:
        console.print(f"  [yellow]请求成功但 IPS 未命中[/] (HTTP {result.get('status_code', '?')})")
        updates["current_phase"] = _next_phase_after_verify(state)
    else:
        console.print(f"  [red]✗ 请求失败:[/] {result.get('error', '未知错误')}")
        updates["error_messages"] = state.error_messages + [result.get("error", "")]
        updates["current_phase"] = _next_phase_after_verify(state)

    return updates


def node_archive(state: CVEState) -> dict:
    """IPS 命中成功后的快速归档，直接进入报告生成。"""
    console.print("[bold cyan]▶ IPS 命中，进入归档[/]")
    return {"current_phase": "generate_report"}


def node_generate_report(state: CVEState) -> dict:
    """生成最终分析报告并归档所有产物。"""
    console.print("[bold cyan]▶ 生成分析报告[/]")

    if state.status != "SUCCESS":
        final_status = "FAILURE"
        if not state.is_http_vuln:
            final_code = "NOT_HTTP_VULN"
            final_msg = "漏洞非 HTTP 类型，工作流不支持"
        elif state.status_code == "PARAMETER_ERROR":
            final_code = "PARAMETER_ERROR"
            final_msg = state.message
        else:
            final_code = "AI_REPRODUCTION_FAILED"
            final_msg = "所有 PoC 源均已尝试，未能命中 IPS"
    else:
        final_status = state.status
        final_code = state.status_code
        final_msg = state.message

    prompt = ANALYSIS_REPORT.format(
        cve_id=state.cve_id,
        description=state.nvd_description or "无",
        cvss_score=state.cvss_score,
        cvss_severity=state.cvss_severity or "无",
        affected_products=", ".join(state.affected_products[:5]) or "无",
        vuln_type=state.vuln_type or "未知",
        poc_source=state.poc_source or "无",
        phases_tried=", ".join(state.phases_tried) or "无",
        status=final_status,
        status_code=final_code,
        error_messages="; ".join(state.error_messages[-3:]) or "无",
        http_status_code=state.http_status_code or "无",
        ips_matched=state.ips_matched,
        pcap_file_path=state.pcap_file_path or "无",
    )

    try:
        report = invoke_llm(prompt)
    except Exception as e:
        report = f"# {state.cve_id} 复现报告\n\n生成报告失败: {e}\n\n状态: {final_status}"

    # 归档所有产物
    output_dir = Path(cfg.output_dir) / state.cve_id
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "report.md", "w", encoding="utf-8") as f:
        f.write(report)

    report_data = {
        "cve_id": state.cve_id,
        "status": final_status,
        "status_code": final_code,
        "message": final_msg,
        "nvd_description": state.nvd_description,
        "cvss_score": state.cvss_score,
        "cvss_severity": state.cvss_severity,
        "vuln_type": state.vuln_type,
        "poc_source": state.poc_source,
        "poc_raw_http": state.poc_raw_http,
        "phases_tried": state.phases_tried,
        "ips_matched": state.ips_matched,
        "pcap_file_path": state.pcap_file_path,
        "timestamp": datetime.now().isoformat(),
    }
    with open(output_dir / "result.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    if state.poc_raw_http:
        with open(output_dir / "poc.http", "w", encoding="utf-8") as f:
            f.write(state.poc_raw_http)

    if state.poc_nuclei_yaml:
        with open(output_dir / "poc.yaml", "w", encoding="utf-8") as f:
            f.write(state.poc_nuclei_yaml)

    console.print(f"  [green]✓[/] 报告与产物已保存到 {output_dir}")
    return {
        "analysis_report": report,
        "status": final_status,
        "status_code": final_code,
        "message": final_msg,
        "current_phase": "done",
    }


# ═══════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════


def _extract_http_requests(text: str, cve_id: str) -> list[str]:
    """从 LLM 输出或网页文本中提取 HTTP 请求。"""
    requests = []

    # 提取 ```http ... ``` 代码块
    pattern = r"```(?:http)?\s*\n((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+.*?)```"
    for m in re.finditer(pattern, text, re.DOTALL | re.IGNORECASE):
        req = m.group(1).strip()
        if req and "HTTP/" in req:
            requests.append(req)

    # 直接匹配原始 HTTP 请求格式
    if not requests:
        pattern2 = r"((?:GET|POST|PUT|DELETE|PATCH)\s+/\S*\s+HTTP/[\d.]+\r?\n(?:[^\n]+\r?\n)*\r?\n(?:.*)?)"
        for m in re.finditer(pattern2, text, re.DOTALL):
            req = m.group(1).strip()
            if len(req) > 30:
                requests.append(req)

    return requests


def _next_phase_after_verify(state: CVEState) -> str:
    """验证失败后确定下一个阶段。"""
    phase_order = [
        "poc_from_refs", "nuclei_search", "exploitdb_search",
        "imfht_search", "web_search",
    ]

    tried = set(state.phases_tried)
    for phase in phase_order:
        if phase not in tried:
            return phase

    return "generate_report"


# ═══════════════════════════════════════════════════════════
# 路由函数
# ═══════════════════════════════════════════════════════════


def route_after_validate(state: CVEState) -> str:
    if state.status == "FAILURE" and state.status_code == "PARAMETER_ERROR":
        return "generate_report"
    return "query_nvd"


def route_after_type_check(state: CVEState) -> str:
    if not state.is_http_vuln:
        return "generate_report"
    return "reference_analysis"


def route_after_phase(state: CVEState) -> str:
    """通用路由：根据 current_phase 决定下一个节点。"""
    phase = state.current_phase
    phase_map = {
        "nvd_query": "query_nvd",
        "vuln_type_check": "vuln_type_check",
        "reference_analysis": "reference_analysis",
        "poc_from_refs": "poc_from_refs",
        "nuclei_search": "nuclei_search",
        "exploitdb_search": "exploitdb_search",
        "imfht_search": "imfht_search",
        "web_search": "web_search",
        "verify_poc": "verify_poc",
        "archive": "archive",
        "generate_report": "generate_report",
        "done": END,
    }
    return phase_map.get(phase, "generate_report")


# ═══════════════════════════════════════════════════════════
# 构建 Graph
# ═══════════════════════════════════════════════════════════


def build_graph() -> StateGraph:
    """构建并编译 LangGraph 工作流。"""

    workflow = StateGraph(CVEState)

    # 添加节点
    workflow.add_node("validate_input", node_validate_input)
    workflow.add_node("query_nvd", node_query_nvd)
    workflow.add_node("vuln_type_check", node_vuln_type_check)
    workflow.add_node("reference_analysis", node_reference_analysis)
    workflow.add_node("poc_from_refs", node_poc_from_refs)
    workflow.add_node("nuclei_search", node_nuclei_search)
    workflow.add_node("exploitdb_search", node_exploitdb_search)
    workflow.add_node("imfht_search", node_imfht_search)
    workflow.add_node("web_search", node_web_search)
    workflow.add_node("verify_poc", node_verify_poc)
    workflow.add_node("archive", node_archive)
    workflow.add_node("generate_report", node_generate_report)

    # 设置入口
    workflow.set_entry_point("validate_input")

    # 添加边
    workflow.add_conditional_edges("validate_input", route_after_validate)
    workflow.add_edge("query_nvd", "vuln_type_check")
    workflow.add_conditional_edges("vuln_type_check", route_after_type_check)
    workflow.add_edge("reference_analysis", "poc_from_refs")

    # PoC 搜索链和验证的路由
    for node in ["poc_from_refs", "nuclei_search", "exploitdb_search",
                  "imfht_search", "web_search", "verify_poc", "archive"]:
        workflow.add_conditional_edges(node, route_after_phase)

    workflow.add_edge("generate_report", END)

    return workflow.compile()
