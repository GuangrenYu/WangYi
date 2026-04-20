#!/usr/bin/env python3
"""CVE Hunter —— 基于 LangGraph 的 CVE 漏洞自动复现工具。

用法:
    python main.py CVE-2023-1234
    python main.py                 # 交互模式
"""

from __future__ import annotations

import sys
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from cve_hunter.config import cfg
from cve_hunter.state import CVEState
from cve_hunter.graph import build_graph

console = Console()


def run_cve(cve_id: str) -> CVEState:
    """执行一次 CVE 复现流程。"""
    console.print(Panel(
        f"[bold white]CVE Hunter[/bold white]\n"
        f"目标: [bold yellow]{cve_id}[/bold yellow]\n"
        f"模型: {cfg.llm_model} @ {cfg.llm_base_url}\n"
        f"目标IP: {cfg.target_ip}",
        title="🔍 漏洞复现工作流",
        border_style="cyan",
    ))

    graph = build_graph()
    initial_state = CVEState(cve_id=cve_id)

    final_state = graph.invoke(initial_state)

    # 输出结果摘要
    console.print()
    status_color = "green" if final_state["status"] == "SUCCESS" else "red"
    console.print(Panel(
        f"状态: [{status_color}]{final_state['status']}[/{status_color}]\n"
        f"状态码: {final_state.get('status_code', 'N/A')}\n"
        f"消息: {final_state.get('message', 'N/A')}\n"
        f"PoC来源: {final_state.get('poc_source', '无')}\n"
        f"IPS命中: {final_state.get('ips_matched', False)}\n"
        f"PCAP: {final_state.get('pcap_file_path', '无')}\n"
        f"已尝试阶段: {', '.join(final_state.get('phases_tried', []))}",
        title="📋 复现结果",
        border_style=status_color,
    ))

    # 显示报告
    report = final_state.get("analysis_report", "")
    if report:
        console.print()
        console.print(Panel(Markdown(report), title="📝 分析报告", border_style="blue"))

    # 显示 PoC
    poc = final_state.get("poc_raw_http", "")
    if poc:
        console.print()
        console.print(Panel(poc, title="💉 PoC (Raw HTTP)", border_style="yellow"))

    nuclei_yaml = final_state.get("poc_nuclei_yaml", "")
    if nuclei_yaml:
        console.print()
        console.print(Panel(nuclei_yaml[:3000], title="💉 PoC (Nuclei YAML)", border_style="yellow"))

    return final_state


def main():
    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
    else:
        console.print("[bold cyan]CVE Hunter[/bold cyan] - 基于 LangGraph 的漏洞自动复现")
        console.print("输入 CVE 编号开始复现，输入 quit 退出\n")
        while True:
            try:
                cve_id = console.input("[bold green]CVE>[/bold green] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n再见！")
                break
            if not cve_id or cve_id.lower() in ("quit", "exit", "q"):
                console.print("再见！")
                break
            run_cve(cve_id)
            console.print()
        return

    run_cve(cve_id)


if __name__ == "__main__":
    main()
