#!/usr/bin/env python3
"""CVE Hunter —— 基于 LangGraph 的 CVE 漏洞自动复现工具。

用法:
    python main.py CVE-2023-1234
    python main.py --batch
    python main.py --batch --file fhq-http.txt --start 1 --end 20
    python main.py --batch --file fhq-http.txt --start 1 --end 100 --terminals 5
    python main.py --classify --file fhq-http.txt
    python main.py --stats
    python main.py --retry-http-failed
    python main.py --retry-mode status --status-code AI_REPRODUCTION_FAILED
    python main.py                 # 交互模式
"""

from __future__ import annotations

import argparse
import os
import sys
import json
import re
import shutil
import subprocess
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter, sleep, time

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table

from cve_hunter.config import cfg
from cve_hunter.status_codes import (
    BATCH_EXCEPTION,
    CAPTURE_SUCCESS,
    NOT_HTTP_VULN,
    PARAMETER_ERROR,
    STATUS_DESCRIPTIONS,
)

console = Console()
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
TEST_DIR = Path("test")
BATCH_DIR = Path(cfg.output_dir) / "batch"
VSCODE_TASK_DIR = Path(cfg.output_dir) / "vscode"


@dataclass
class BatchResult:
    index: int
    cve_id: str
    passed: bool
    status: str
    status_code: str
    message: str
    poc_source: str
    pcap_file_path: str
    elapsed_seconds: float
    ips_matched: bool = False
    generic_ips_matched: bool = False
    ips_match_count: int = 0
    cve_ips_match_count: int = 0
    generic_ips_match_count: int = 0


@dataclass
class ClassifyResult:
    index: int
    cve_id: str
    is_http_vuln: bool
    vuln_type: str
    error: str
    elapsed_seconds: float


@dataclass
class RetryTarget:
    path: Path
    index: int
    cve_id: str


@contextmanager
def quiet_workflow_output():
    """批量模式下隐藏工作流内部查询、生成和发包日志。"""
    import cve_hunter.graph as graph_module

    old_graph_quiet = getattr(graph_module.console, "quiet", False)
    graph_module.console.quiet = True
    try:
        with open(os.devnull, "w", encoding="utf-8") as devnull:
            with redirect_stdout(devnull), redirect_stderr(devnull):
                yield
    finally:
        graph_module.console.quiet = old_graph_quiet


def run_cve(cve_id: str, *, show_details: bool = True) -> CVEState:
    """执行一次 CVE 复现流程。"""
    from cve_hunter.graph import build_graph
    from cve_hunter.state import CVEState

    if show_details:
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
    if show_details:
        console.print()
        status_color = "green" if final_state["status"] == "SUCCESS" else "red"
        console.print(Panel(
            f"状态: [{status_color}]{final_state['status']}[/{status_color}]\n"
            f"状态码: {final_state.get('status_code', 'N/A')}\n"
            f"消息: {final_state.get('message', 'N/A')}\n"
            f"PoC来源: {final_state.get('poc_source', '无')}\n"
            f"当前CVE IPS命中: {final_state.get('ips_matched', False)}\n"
            f"通用IPS命中: {final_state.get('generic_ips_matched', False)}\n"
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


def list_test_files() -> list[Path]:
    """列出 test 目录下的 txt 测试文件。"""
    if not TEST_DIR.exists():
        return []
    return sorted(path for path in TEST_DIR.glob("*.txt") if path.is_file())


def resolve_test_file(file_name: str | None) -> Path:
    """根据输入解析测试文件路径，支持 test 下文件名或完整路径。"""
    if not file_name:
        return choose_test_file()

    candidates = [Path(file_name), TEST_DIR / file_name]
    if not file_name.lower().endswith(".txt"):
        candidates.append(TEST_DIR / f"{file_name}.txt")

    for path in candidates:
        if path.is_file():
            return path

    available = ", ".join(path.name for path in list_test_files()) or "无"
    raise FileNotFoundError(f"未找到测试文件: {file_name}；test 目录可用文件: {available}")


def choose_test_file() -> Path:
    """交互式选择 test 目录下的 txt 文件。"""
    files = list_test_files()
    if not files:
        raise FileNotFoundError("test 目录下没有可用的 .txt 文件")

    table = Table(title="可用测试文件")
    table.add_column("序号", justify="right")
    table.add_column("文件")
    table.add_column("大小")
    for i, path in enumerate(files, start=1):
        table.add_row(str(i), path.name, f"{path.stat().st_size} bytes")
    console.print(table)

    while True:
        value = console.input("[bold green]选择测试文件序号>[/bold green] ").strip()
        try:
            index = int(value)
        except ValueError:
            console.print("[red]请输入数字序号[/red]")
            continue
        if 1 <= index <= len(files):
            return files[index - 1]
        console.print(f"[red]序号超出范围: 1-{len(files)}[/red]")


def load_cve_ids(path: Path) -> list[str]:
    """从 txt 文件中按出现顺序提取 CVE 编号。"""
    cve_ids: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = CVE_PATTERN.search(line)
        if not match:
            continue
        cve_ids.append(match.group(0).upper())
    return cve_ids


def choose_range(total: int, start: int | None, end: int | None) -> tuple[int, int]:
    """选择 1-based 闭区间测试范围。"""
    if total <= 0:
        raise ValueError("测试文件中没有 CVE 编号")

    if start is None:
        raw = console.input(f"[bold green]起始序号(1-{total}, 默认 1)>[/bold green] ").strip()
        start = int(raw) if raw else 1
    if end is None:
        raw = console.input(f"[bold green]结束序号({start}-{total}, 默认 {total})>[/bold green] ").strip()
        end = int(raw) if raw else total

    if start < 1 or end < 1 or start > total or end > total or start > end:
        raise ValueError(f"范围无效: start={start}, end={end}，有效范围为 1-{total}")

    return start, end


def choose_terminal_count(total: int, terminal_count: int | None, *, prompt: bool) -> int:
    """选择本次任务要拆分启动的终端数量。"""
    if total <= 0:
        return 1

    if terminal_count is None and prompt:
        raw = console.input(f"[bold green]启动终端数量(1-{total}, 默认 1)>[/bold green] ").strip()
        terminal_count = int(raw) if raw else 1
    elif terminal_count is None:
        terminal_count = 1

    if terminal_count < 1:
        raise ValueError(f"终端数量无效: {terminal_count}")

    return min(terminal_count, total)


def split_contiguous_range(start: int, end: int, parts: int) -> list[tuple[int, int]]:
    """把闭区间按数量尽量均匀切分成多个闭区间。"""
    total = end - start + 1
    parts = min(parts, total)
    base_size, remainder = divmod(total, parts)

    ranges: list[tuple[int, int]] = []
    current = start
    for i in range(parts):
        size = base_size + (1 if i < remainder else 0)
        chunk_start = current
        chunk_end = current + size - 1
        ranges.append((chunk_start, chunk_end))
        current = chunk_end + 1
    return ranges


def find_vscode_cli() -> str:
    """查找 VS Code CLI。"""
    code_cli = shutil.which("code.cmd") or shutil.which("code")
    if code_cli:
        return code_cli

    candidates = [
        Path(r"F:\Microsoft VS Code\bin\code.cmd"),
        Path(r"C:\Users\86191\AppData\Local\Programs\Microsoft VS Code\bin\code.cmd"),
        Path(r"C:\Program Files\Microsoft VS Code\bin\code.cmd"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise RuntimeError("未找到 VS Code CLI：请确认 code 命令可用，或在 VS Code 中安装 Shell Command")


def make_vscode_task(label: str, command_args: list[str], *, auto_run: bool = True) -> dict:
    """生成一个在 VS Code 集成终端里运行的任务。"""
    task = {
        "label": label,
        "type": "process",
        "command": command_args[0],
        "args": command_args[1:],
        "options": {"cwd": str(Path.cwd())},
        "presentation": {
            "echo": True,
            "reveal": "always",
            "focus": False,
            "panel": "dedicated",
            "clear": False,
        },
        "problemMatcher": [],
    }
    if auto_run:
        task["runOptions"] = {"runOn": "folderOpen"}
    return task


def cleanup_legacy_vscode_tasks() -> None:
    """清理旧版本写入 .vscode/tasks.json 的 CVE Hunter 任务。"""
    tasks_path = Path(".vscode") / "tasks.json"
    if not tasks_path.exists():
        return

    try:
        data = json.loads(tasks_path.read_text(encoding="utf-8"))
        existing_tasks = data.get("tasks", [])
        if not isinstance(existing_tasks, list):
            return
    except Exception:
        return

    kept_tasks = [
        task for task in existing_tasks
        if not str(task.get("label", "")).startswith("CVE Hunter: ")
    ]
    if len(kept_tasks) == len(existing_tasks):
        return

    if kept_tasks:
        data["tasks"] = kept_tasks
        tasks_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        tasks_path.unlink()


def launch_vscode_task_group(group_label: str, tasks: list[dict]) -> None:
    """写入临时 VS Code 工作区，并用自动任务打开集成终端。"""
    cleanup_legacy_vscode_tasks()
    VSCODE_TASK_DIR.mkdir(parents=True, exist_ok=True)

    compound_task = {
        "label": group_label,
        "dependsOn": [task["label"] for task in tasks],
        "dependsOrder": "parallel",
        "group": {"kind": "build", "isDefault": True},
        "problemMatcher": [],
    }
    workspace_path = VSCODE_TASK_DIR / "cve_hunter_launch.code-workspace"
    workspace_data = {
        "folders": [{"path": str(Path.cwd())}],
        "settings": {
            "task.allowAutomaticTasks": "on",
        },
        "tasks": {
            "version": "2.0.0",
            "tasks": tasks + [compound_task],
        },
    }
    workspace_path.write_text(json.dumps(workspace_data, ensure_ascii=False, indent=2), encoding="utf-8")

    subprocess.Popen([
        find_vscode_cli(),
        "--new-window",
        str(workspace_path.resolve()),
    ])
    console.print(f"[green]已写入并打开 VS Code 自动任务工作区:[/green] {workspace_path}")
    console.print("[yellow]如果 VS Code 因安全策略没有自动运行任务，请在新窗口按 Ctrl+Shift+B 运行默认任务。[/yellow]")


def launch_batch_terminals(test_file: Path, ranges: list[tuple[int, int]]) -> None:
    """按范围在 VS Code 集成终端执行批量测试。"""
    script = str(Path(__file__).resolve())
    tasks: list[dict] = []
    for i, (chunk_start, chunk_end) in enumerate(ranges, start=1):
        label = f"CVE Hunter: Batch {chunk_start}-{chunk_end}"
        command_args = [
            sys.executable,
            script,
            "--batch",
            "--file",
            str(test_file),
            "--start",
            str(chunk_start),
            "--end",
            str(chunk_end),
        ]
        tasks.append(make_vscode_task(label, command_args))
        console.print(f"[green]已准备 VS Code 终端任务 {i}/{len(ranges)}:[/green] {chunk_start}-{chunk_end}")
    launch_vscode_task_group(f"CVE Hunter: Batch All ({len(ranges)} terminals)", tasks)


def execute_cve_as_batch_result(index: int, cve_id: str) -> BatchResult:
    """按批量结果格式执行并封装一次 CVE 复现。"""
    case_started = perf_counter()
    try:
        with quiet_workflow_output():
            final_state = run_cve(cve_id, show_details=False)
        ips_summary = final_state.get("ips_match_summary", {}) or {}
        ips_matched = bool(final_state.get("ips_matched", False))
        generic_ips_matched = bool(final_state.get("generic_ips_matched", False))
        passed = final_state.get("status") == "SUCCESS" and ips_matched
        status = final_state.get("status", "FAILURE")
        status_code = final_state.get("status_code", "")
        message = final_state.get("message", "")
        poc_source = final_state.get("poc_source", "") or "无"
        pcap_file_path = final_state.get("pcap_file_path", "") or "无"
        ips_match_count = int(ips_summary.get("total_count") or 0)
        cve_ips_match_count = int(ips_summary.get("cve_match_count") or 0)
        generic_ips_match_count = int(ips_summary.get("generic_match_count") or 0)
    except Exception as exc:
        passed = False
        status = "FAILURE"
        status_code = BATCH_EXCEPTION
        message = str(exc)
        poc_source = "无"
        pcap_file_path = "无"
        ips_matched = False
        generic_ips_matched = False
        ips_match_count = 0
        cve_ips_match_count = 0
        generic_ips_match_count = 0

    return BatchResult(
        index=index,
        cve_id=cve_id,
        passed=passed,
        status=status,
        status_code=status_code,
        message=message,
        poc_source=poc_source,
        pcap_file_path=pcap_file_path,
        elapsed_seconds=perf_counter() - case_started,
        ips_matched=ips_matched,
        generic_ips_matched=generic_ips_matched,
        ips_match_count=ips_match_count,
        cve_ips_match_count=cve_ips_match_count,
        generic_ips_match_count=generic_ips_match_count,
    )


def run_batch(
    file_name: str | None = None,
    start: int | None = None,
    end: int | None = None,
    terminal_count: int | None = None,
) -> list[BatchResult]:
    """按测试文件中的 CVE 编号批量执行复现流程。"""
    should_prompt_terminals = terminal_count is None and (file_name is None or start is None or end is None)
    test_file = resolve_test_file(file_name)
    cve_ids = load_cve_ids(test_file)
    start_index, end_index = choose_range(len(cve_ids), start, end)
    selected = cve_ids[start_index - 1:end_index]
    total = len(selected)
    selected_terminals = choose_terminal_count(total, terminal_count, prompt=should_prompt_terminals)

    if selected_terminals > 1:
        ranges = split_contiguous_range(start_index, end_index, selected_terminals)
        console.print(Panel(
            f"测试文件: [bold yellow]{test_file}[/bold yellow]\n"
            f"总范围: 第 {start_index} 到第 {end_index} 个，共 {total} 个\n"
            f"启动 VS Code 集成终端: {len(ranges)} 个",
            title="批量测试多终端启动",
            border_style="cyan",
        ))
        launch_batch_terminals(test_file, ranges)
        return []

    console.print(Panel(
        f"测试文件: [bold yellow]{test_file}[/bold yellow]\n"
        f"文件 CVE 总数: {len(cve_ids)}\n"
        f"本次范围: 第 {start_index} 到第 {end_index} 个，共 {total} 个\n"
        f"目标IP: {cfg.target_ip}",
        title="批量测试",
        border_style="cyan",
    ))

    results: list[BatchResult] = []
    passed_count = 0
    batch_started = perf_counter()
    output_path = create_batch_results_path(test_file, start_index, end_index)
    write_batch_results(output_path, test_file, start_index, end_index, total, results)

    for offset, cve_id in enumerate(selected, start=1):
        absolute_index = start_index + offset - 1
        result = execute_cve_as_batch_result(absolute_index, cve_id)
        if result.passed:
            passed_count += 1

        results.append(result)
        write_batch_results(output_path, test_file, start_index, end_index, total, results)

        tested_count = len(results)
        accuracy = passed_count / tested_count if tested_count else 0
        color = "green" if result.passed else "red"
        console.print(
            f"[{color}]{'正确' if result.passed else '错误'}[/{color}] "
            f"[{tested_count}/{total}] #{absolute_index} {cve_id} | "
            f"状态: {result.status}/{result.status_code or 'N/A'} | "
            f"PoC来源: {result.poc_source} | 用时: {result.elapsed_seconds:.1f}s | "
            f"正确率: {passed_count}/{tested_count} ({accuracy:.2%})"
        )

    total_elapsed = perf_counter() - batch_started
    print_batch_summary(results, total_elapsed)
    console.print(f"[green]批量测试明细已保存:[/green] {output_path}")
    return results


def run_classify(file_name: str | None = None, start: int | None = None, end: int | None = None) -> list[ClassifyResult]:
    """快速筛选 HTTP/Web 与非 HTTP CVE，并写出 *_h.txt / *_f.txt。"""
    from cve_hunter.classifier import VulnTypeResult, classify_http_vuln

    test_file = resolve_test_file(file_name)
    cve_ids = load_cve_ids(test_file)
    start_index, end_index = choose_range(len(cve_ids), start, end)
    selected = cve_ids[start_index - 1:end_index]
    total = len(selected)

    console.print(Panel(
        f"输入文件: [bold yellow]{test_file}[/bold yellow]\n"
        f"文件 CVE 总数: {len(cve_ids)}\n"
        f"筛选范围: 第 {start_index} 到第 {end_index} 个，共 {total} 个\n"
        "执行内容: 仅 NVD 查询 + AI HTTP/Web 类型判断，不跑 PoC、不发包",
        title="分类筛选",
        border_style="cyan",
    ))

    results: list[ClassifyResult] = []
    http_ids: list[str] = []
    non_http_ids: list[str] = []
    started = perf_counter()

    for offset, cve_id in enumerate(selected, start=1):
        absolute_index = start_index + offset - 1
        case_started = perf_counter()
        console.rule(f"[bold cyan]{offset}/{total}[/bold cyan] #{absolute_index} {cve_id}")

        try:
            classified = classify_http_vuln(cve_id)
        except Exception as exc:
            classified = VulnTypeResult(
                cve_id=cve_id,
                is_http_vuln=True,
                vuln_type="未知",
                error=f"分类异常，按现有工作流默认归为 HTTP/Web: {exc}",
            )

        elapsed = perf_counter() - case_started
        if classified.is_http_vuln:
            http_ids.append(classified.cve_id)
            label = "HTTP"
            color = "green"
        else:
            non_http_ids.append(classified.cve_id)
            label = "非HTTP"
            color = "yellow"

        results.append(ClassifyResult(
            index=absolute_index,
            cve_id=classified.cve_id,
            is_http_vuln=classified.is_http_vuln,
            vuln_type=classified.vuln_type,
            error=classified.error,
            elapsed_seconds=elapsed,
        ))

        console.print(
            f"[{color}]{label}[/{color}] {classified.cve_id} | "
            f"类型: {classified.vuln_type or '未知'} | 用时: {elapsed:.1f}s | "
            f"进度: {offset}/{total} | HTTP: {len(http_ids)} | 非HTTP: {len(non_http_ids)}"
        )
        if classified.error:
            console.print(f"[yellow]  {classified.error}[/yellow]")

    http_path, non_http_path = save_classify_results(test_file, http_ids, non_http_ids)
    elapsed_total = perf_counter() - started
    print_classify_summary(results, http_path, non_http_path, elapsed_total)
    return results


def save_classify_results(test_file: Path, http_ids: list[str], non_http_ids: list[str]) -> tuple[Path, Path]:
    """按原文件名生成 *_h.txt 和 *_f.txt。"""
    http_path = test_file.with_name(f"{test_file.stem}_h{test_file.suffix}")
    non_http_path = test_file.with_name(f"{test_file.stem}_f{test_file.suffix}")

    http_path.write_text("\n".join(http_ids) + ("\n" if http_ids else ""), encoding="utf-8")
    non_http_path.write_text("\n".join(non_http_ids) + ("\n" if non_http_ids else ""), encoding="utf-8")
    return http_path, non_http_path


def print_classify_summary(
    results: list[ClassifyResult],
    http_path: Path,
    non_http_path: Path,
    elapsed_seconds: float,
) -> None:
    total = len(results)
    http_count = sum(1 for item in results if item.is_http_vuln)
    non_http_count = total - http_count

    table = Table(title="分类筛选汇总")
    table.add_column("总数", justify="right")
    table.add_column("HTTP", justify="right")
    table.add_column("非HTTP", justify="right")
    table.add_column("HTTP占比", justify="right")
    table.add_column("总用时", justify="right")
    ratio = http_count / total if total else 0
    table.add_row(str(total), str(http_count), str(non_http_count), f"{ratio:.2%}", f"{elapsed_seconds:.1f}s")
    console.print(table)
    console.print(f"[green]HTTP 结果:[/green] {http_path}")
    console.print(f"[green]非 HTTP 结果:[/green] {non_http_path}")


def create_batch_results_path(test_file: Path, start: int, end: int) -> Path:
    """创建本次批量测试的结果文件路径。"""
    output_dir = Path(cfg.output_dir) / "batch"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return output_dir / f"{test_file.stem}_{start}_{end}_{timestamp}.json"


def write_batch_results(
    output_path: Path,
    test_file: Path,
    start: int,
    end: int,
    planned_total: int,
    results: list[BatchResult],
) -> None:
    """实时保存批量测试明细。"""
    data = {
        "test_file": str(test_file),
        "start": start,
        "end": end,
        "planned_total": planned_total,
        "completed": len(results),
        "passed": sum(1 for item in results if item.passed),
        "results": [item.__dict__ for item in results],
    }
    output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def print_batch_summary(results: list[BatchResult], elapsed_seconds: float) -> None:
    """打印批量测试汇总。"""
    total = len(results)
    passed = sum(1 for item in results if item.passed)
    accuracy = passed / total if total else 0

    table = Table(title="批量测试汇总")
    table.add_column("总数", justify="right")
    table.add_column("正确", justify="right")
    table.add_column("错误", justify="right")
    table.add_column("正确率", justify="right")
    table.add_column("总用时", justify="right")
    table.add_row(str(total), str(passed), str(total - passed), f"{accuracy:.2%}", f"{elapsed_seconds:.1f}s")
    console.print(table)

    failed = [item for item in results if not item.passed]
    if failed:
        failed_table = Table(title="未通过明细")
        failed_table.add_column("序号", justify="right")
        failed_table.add_column("CVE")
        failed_table.add_column("状态")
        failed_table.add_column("消息")
        for item in failed[:20]:
            failed_table.add_row(str(item.index), item.cve_id, f"{item.status}/{item.status_code}", item.message[:80])
        console.print(failed_table)
        if len(failed) > 20:
            console.print(f"[yellow]仅显示前 20 条未通过记录，共 {len(failed)} 条。完整结果已写入 output/batch。[/yellow]")


def is_non_http_result(result: dict) -> bool:
    """根据批量结果状态码判断是否为非 HTTP 漏洞。"""
    return str(result.get("status_code", "")).upper() == NOT_HTTP_VULN


def is_retry_http_failed_result(result: dict) -> bool:
    """二次核验处理 HTTP 类型失败结果。"""
    status_code = str(result.get("status_code", "")).upper()
    return (
        not result.get("passed")
        and status_code not in {NOT_HTTP_VULN, PARAMETER_ERROR}
        and status_code != ""
    )


def is_retry_passed_result(result: dict) -> bool:
    """正确数据核验处理历史通过记录，用于清理旧的 IPS 泛化误判。"""
    return bool(result.get("passed")) and str(result.get("status_code", "")).upper() == CAPTURE_SUCCESS


def parse_retry_status_codes(values: list[str] | None) -> set[str]:
    """解析状态码筛选参数，支持多次传参、逗号/空白分隔。"""
    codes: set[str] = set()
    for value in values or []:
        for part in re.split(r"[\s,，]+", value):
            code = part.strip().upper()
            if code:
                codes.add(code)
    return codes


def validate_retry_status_codes(codes: set[str]) -> None:
    """对未知状态码给出提示，但允许兼容历史 JSON 中的自定义状态码。"""
    unknown = sorted(code for code in codes if code not in STATUS_DESCRIPTIONS)
    if unknown:
        console.print(
            "[yellow]提示: 以下状态码不在当前内置列表中，将按原样匹配历史记录:[/yellow] "
            + ", ".join(unknown)
        )


def is_retry_status_code_result(result: dict, retry_status_codes: set[str] | None) -> bool:
    """指定状态码核验：只按 status_code 精确筛选，不额外判断 passed。"""
    if not retry_status_codes:
        return False
    return str(result.get("status_code", "")).upper() in retry_status_codes


def is_retry_target_result(result: dict, retry_mode: str, retry_status_codes: set[str] | None = None) -> bool:
    """根据 retry 模式判断一条批量结果是否需要重跑。"""
    if retry_mode == "failed":
        return is_retry_http_failed_result(result)
    if retry_mode == "passed":
        return is_retry_passed_result(result)
    if retry_mode == "all":
        return is_retry_http_failed_result(result) or is_retry_passed_result(result)
    if retry_mode == "status":
        return is_retry_status_code_result(result, retry_status_codes)
    raise ValueError(f"未知 retry 模式: {retry_mode}")


def retry_mode_description(retry_mode: str, retry_status_codes: set[str] | None = None) -> str:
    if retry_mode == "status":
        codes = ", ".join(sorted(retry_status_codes or [])) or "未指定"
        return f"指定状态码核验: status_code in [{codes}]"
    descriptions = {
        "failed": "失败数据核验: HTTP 失败记录，排除 NOT_HTTP_VULN/PARAMETER_ERROR",
        "passed": "正确数据核验: status_code == CAPTURE_SUCCESS 且 passed == true",
        "all": "失败+正确数据核验: HTTP 失败记录或 CAPTURE_SUCCESS",
    }
    return descriptions.get(retry_mode, retry_mode)


def load_batch_record(path: Path) -> dict:
    """读取一份 output/batch JSON 记录。"""
    return json.loads(path.read_text(encoding="utf-8"))


def save_batch_record(path: Path, data: dict) -> None:
    """保存一份 output/batch JSON 记录。"""
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


@contextmanager
def batch_record_lock(path: Path):
    """用锁文件保护二次核验进程之间的 JSON 回写。"""
    lock_path = path.with_suffix(path.suffix + ".lock")
    started = perf_counter()
    fd: int | None = None

    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, f"{os.getpid()} {datetime.now().isoformat()}".encode("utf-8"))
            break
        except FileExistsError:
            try:
                if lock_path.exists() and time() - lock_path.stat().st_mtime > 600:
                    lock_path.unlink()
                    continue
            except OSError:
                pass
            if perf_counter() - started > 120:
                raise TimeoutError(f"等待锁文件超时: {lock_path}")
            sleep(0.2)

    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def result_matches(result: dict, index: int, cve_id: str) -> bool:
    """判断 JSON 明细是否对应同一条测试记录。"""
    try:
        result_index = int(result.get("index"))
    except (TypeError, ValueError):
        return False
    return result_index == index and str(result.get("cve_id", "")).upper() == cve_id.upper()


def is_completed_batch_record(data: dict, results: list) -> bool:
    """判断批量 JSON 是否已完成，避免和普通批量任务同时写同一文件。"""
    try:
        planned_total = int(data.get("planned_total") or 0)
    except (TypeError, ValueError):
        planned_total = 0
    if planned_total <= 0:
        return True
    return len(results) >= planned_total


def collect_retry_targets(
    retry_mode: str = "failed",
    retry_status_codes: set[str] | None = None,
) -> tuple[list[RetryTarget], list[tuple[Path, str]], list[Path]]:
    """按 retry 模式收集 output/batch 中已完成 JSON 的待核验记录。"""
    files = sorted(BATCH_DIR.glob("*.json")) if BATCH_DIR.exists() else []
    targets: list[RetryTarget] = []
    skipped_files: list[tuple[Path, str]] = []
    unfinished_files: list[Path] = []

    for path in files:
        try:
            data = load_batch_record(path)
            results = data.get("results", [])
            if not isinstance(results, list):
                raise ValueError("results 字段不是列表")
        except Exception as exc:
            skipped_files.append((path, str(exc)))
            continue

        if not is_completed_batch_record(data, results):
            unfinished_files.append(path)
            continue

        for result in results:
            if not is_retry_target_result(result, retry_mode, retry_status_codes):
                continue
            try:
                index = int(result.get("index"))
            except (TypeError, ValueError):
                continue
            cve_id = str(result.get("cve_id", "")).upper()
            if cve_id:
                targets.append(RetryTarget(path=path, index=index, cve_id=cve_id))

    targets.sort(key=lambda item: (item.index, item.path.name, item.cve_id))
    return targets, skipped_files, unfinished_files


def choose_retry_range(targets: list[RetryTarget], start: int | None, end: int | None) -> tuple[int, int]:
    """为二次核验选择原始测试序号范围。"""
    min_index = min(item.index for item in targets)
    max_index = max(item.index for item in targets)

    if start is None:
        raw = console.input(f"[bold green]二次核验起始序号({min_index}-{max_index}, 默认 {min_index})>[/bold green] ").strip()
        start = int(raw) if raw else min_index
    if end is None:
        raw = console.input(f"[bold green]二次核验结束序号({start}-{max_index}, 默认 {max_index})>[/bold green] ").strip()
        end = int(raw) if raw else max_index

    if start < 1 or end < 1 or start > end:
        raise ValueError(f"范围无效: start={start}, end={end}，可参考范围为 {min_index}-{max_index}")

    return start, end


def launch_retry_terminals(
    start: int,
    end: int,
    terminal_count: int,
    retry_mode: str,
    retry_status_codes: set[str] | None = None,
) -> None:
    """在 VS Code 集成终端执行二次核验，按目标列表分片避免重复处理。"""
    script = str(Path(__file__).resolve())
    tasks: list[dict] = []
    for shard in range(terminal_count):
        label = f"CVE Hunter: Retry {shard + 1}-{terminal_count}"
        command_args = [
            sys.executable,
            script,
            "--retry-http-failed",
            "--start",
            str(start),
            "--end",
            str(end),
            "--retry-mode",
            retry_mode,
            "--retry-shard",
            str(shard),
            "--retry-shards",
            str(terminal_count),
        ]
        if retry_mode == "status":
            command_args.extend(["--status-code", ",".join(sorted(retry_status_codes or []))])
        tasks.append(make_vscode_task(label, command_args))
        console.print(f"[green]已准备二次核验 VS Code 终端任务 {shard + 1}/{terminal_count}[/green]")
    launch_vscode_task_group(f"CVE Hunter: Retry All ({terminal_count} terminals)", tasks)


def update_retry_result(
    target: RetryTarget,
    result: BatchResult,
    retry_mode: str,
    retry_status_codes: set[str] | None = None,
) -> str:
    """把二次核验结果覆盖回原 JSON 中对应记录。"""
    with batch_record_lock(target.path):
        data = load_batch_record(target.path)
        results = data.get("results", [])
        if not isinstance(results, list):
            return "跳过: results 字段不是列表"

        for position, current in enumerate(results):
            if not result_matches(current, target.index, target.cve_id):
                continue
            if not is_retry_target_result(current, retry_mode, retry_status_codes):
                return f"跳过: 原记录状态已变为 {current.get('status_code', 'N/A')}"

            results[position] = result.__dict__
            data["results"] = results
            data["completed"] = len(results)
            data["passed"] = sum(1 for item in results if item.get("passed"))
            save_batch_record(target.path, data)
            return "已覆盖"

    return "跳过: 未找到原记录"


def run_retry_http_failed(
    start: int | None = None,
    end: int | None = None,
    terminal_count: int | None = None,
    retry_shard: int | None = None,
    retry_shards: int | None = None,
    retry_mode: str = "failed",
    retry_status_codes: set[str] | None = None,
) -> list[BatchResult]:
    """重跑 output/batch 中指定模式的记录并覆盖原结果。"""
    retry_status_codes = set(retry_status_codes or [])
    targets, skipped_files, unfinished_files = collect_retry_targets(retry_mode, retry_status_codes)
    if not targets:
        console.print(f"[yellow]未找到可二次核验的记录:[/yellow] {BATCH_DIR} ({retry_mode_description(retry_mode, retry_status_codes)})")
        return []

    prompt_for_range = start is None or end is None
    start_index, end_index = choose_retry_range(targets, start, end)
    selected = [item for item in targets if start_index <= item.index <= end_index]
    if not selected:
        console.print(f"[yellow]范围 {start_index}-{end_index} 内没有待二次核验记录[/yellow]")
        return []

    if retry_shards is not None:
        if retry_shard is None or retry_shards < 1 or retry_shard < 0 or retry_shard >= retry_shards:
            raise ValueError(f"分片参数无效: retry_shard={retry_shard}, retry_shards={retry_shards}")
        selected = [item for offset, item in enumerate(selected) if offset % retry_shards == retry_shard]
        if not selected:
            console.print(f"[yellow]当前二次核验分片无任务:[/yellow] {retry_shard + 1}/{retry_shards}")
            return []
    else:
        selected_terminals = choose_terminal_count(
            len(selected),
            terminal_count,
            prompt=terminal_count is None and prompt_for_range,
        )
        if selected_terminals > 1:
            console.print(Panel(
                f"目录: [bold yellow]{BATCH_DIR}[/bold yellow]\n"
                f"范围: {start_index}-{end_index}\n"
                f"待二次核验: {len(selected)} 条\n"
                f"启动 VS Code 集成终端: {selected_terminals} 个",
                title="二次核验多终端启动",
                border_style="cyan",
            ))
            launch_retry_terminals(start_index, end_index, selected_terminals, retry_mode, retry_status_codes)
            return []

    console.print(Panel(
        f"目录: [bold yellow]{BATCH_DIR}[/bold yellow]\n"
        f"范围: {start_index}-{end_index}\n"
        f"待二次核验: {len(selected)} 条\n"
        f"筛选条件: {retry_mode_description(retry_mode, retry_status_codes)}",
        title="二次核验",
        border_style="cyan",
    ))

    results: list[BatchResult] = []
    passed_count = 0
    started = perf_counter()

    for offset, target in enumerate(selected, start=1):
        result = execute_cve_as_batch_result(target.index, target.cve_id)
        write_status = update_retry_result(target, result, retry_mode, retry_status_codes)
        results.append(result)
        if result.passed:
            passed_count += 1

        color = "green" if result.passed else "red"
        console.print(
            f"[{color}]{'正确' if result.passed else '错误'}[/{color}] "
            f"[{offset}/{len(selected)}] {target.path.name} #{target.index} {target.cve_id} | "
            f"状态: {result.status}/{result.status_code or 'N/A'} | "
            f"PoC来源: {result.poc_source} | 用时: {result.elapsed_seconds:.1f}s | "
            f"{write_status}"
        )

    elapsed = perf_counter() - started
    accuracy = passed_count / len(results) if results else 0
    console.print(
        f"[bold]二次核验完成:[/bold] {len(results)} 条，正确 {passed_count} 条，"
        f"本轮正确率 {accuracy:.2%}，用时 {elapsed:.1f}s"
    )

    if unfinished_files:
        console.print(f"[yellow]跳过未完成 JSON 文件 {len(unfinished_files)} 个；等普通批量任务完成后可再次运行。[/yellow]")
    if skipped_files:
        console.print(f"[yellow]跳过异常 JSON 文件 {len(skipped_files)} 个。[/yellow]")

    return results


def run_batch_stats() -> None:
    """统计 output/batch 下已有 JSON 批量测试记录。"""
    files = sorted(BATCH_DIR.glob("*.json")) if BATCH_DIR.exists() else []
    if not files:
        console.print(f"[yellow]未找到批量测试记录:[/yellow] {BATCH_DIR}")
        return

    total_records = 0
    total_passed = 0
    total_http_passed = 0
    total_http = 0
    total_non_http = 0
    skipped_files: list[tuple[Path, str]] = []

    console.print(Panel(
        f"目录: [bold yellow]{BATCH_DIR}[/bold yellow]\n"
        f"JSON 文件数: {len(files)}\n"
        "HTTP正确率 = 排除 status_code 为 NOT_HTTP_VULN 的记录后计算",
        title="批量测试记录统计",
        border_style="cyan",
    ))

    for path in files:
        try:
            data = load_batch_record(path)
            results = data.get("results", [])
            if not isinstance(results, list):
                raise ValueError("results 字段不是列表")
        except Exception as exc:
            skipped_files.append((path, str(exc)))
            continue

        completed = len(results)
        passed = sum(1 for item in results if item.get("passed"))
        non_http = sum(1 for item in results if is_non_http_result(item))
        http = completed - non_http
        http_passed = sum(1 for item in results if item.get("passed") and not is_non_http_result(item))
        accuracy = passed / completed if completed else 0
        http_accuracy = http_passed / http if http else 0

        total_records += completed
        total_passed += passed
        total_http_passed += http_passed
        total_http += http
        total_non_http += non_http

        start = data.get("start", "?")
        end = data.get("end", "?")
        http_accuracy_text = f"{http_accuracy:.2%}" if http else "N/A"
        console.print(
            f"[cyan]{path.name}[/cyan] | "
            f"范围: {start}-{end} | "
            f"完成: {completed} | "
            f"HTTP: {http} | 非HTTP: {non_http} | "
            f"正确: {passed} | "
            f"总正确率: {accuracy:.2%} | "
            f"HTTP正确率: {http_accuracy_text}"
        )

    total_accuracy = total_passed / total_records if total_records else 0
    http_accuracy_total = total_http_passed / total_http if total_http else 0

    summary = Table(title="总计")
    summary.add_column("JSON文件", justify="right")
    summary.add_column("有效文件", justify="right")
    summary.add_column("测试记录", justify="right")
    summary.add_column("HTTP", justify="right")
    summary.add_column("非HTTP", justify="right")
    summary.add_column("正确", justify="right")
    summary.add_column("总正确率", justify="right")
    summary.add_column("HTTP正确率", justify="right")
    summary.add_row(
        str(len(files)),
        str(len(files) - len(skipped_files)),
        str(total_records),
        str(total_http),
        str(total_non_http),
        str(total_passed),
        f"{total_accuracy:.2%}",
        f"{http_accuracy_total:.2%}" if total_http else "N/A",
    )
    console.print(summary)
    total_http_accuracy_text = f"{http_accuracy_total:.2%}" if total_http else "N/A"
    console.print(
        f"[bold]总计:[/bold] JSON文件 {len(files)} 个，有效文件 {len(files) - len(skipped_files)} 个，"
        f"测试记录 {total_records} 条，HTTP {total_http} 条，非HTTP {total_non_http} 条，"
        f"正确 {total_passed} 条，总正确率 {total_accuracy:.2%}，"
        f"排除非HTTP正确率 {total_http_accuracy_text}"
    )

    if skipped_files:
        skipped = Table(title="跳过的 JSON 文件")
        skipped.add_column("文件")
        skipped.add_column("原因")
        for path, reason in skipped_files:
            skipped.add_row(path.name, reason[:120])
        console.print(skipped)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE Hunter 漏洞复现工具")
    parser.add_argument("cve_id", nargs="?", help="单个 CVE 编号；批量/分类模式下也可作为测试文件名")
    parser.add_argument("--batch", "-b", action="store_true", help="从 test 目录 txt 文件中批量测试 CVE")
    parser.add_argument("--classify", action="store_true", help="快速分类 test txt 中的 HTTP/非 HTTP CVE，并输出 *_h.txt/*_f.txt")
    parser.add_argument("--stats", action="store_true", help="统计 output/batch 下已有 JSON 批量测试记录")
    parser.add_argument("--retry-http-failed", "--retry", action="store_true", help="重跑 output/batch 中 HTTP 失败记录并覆盖原结果")
    parser.add_argument("--retry-mode", choices=("failed", "passed", "all", "status"), default="failed", help="二次核验范围: failed=失败记录, passed=历史通过记录, all=两类都核验, status=按状态码筛选")
    parser.add_argument("--retry-passed", action="store_true", help="等同于 --retry --retry-mode passed，用于正确数据核验")
    parser.add_argument("--status-code", "--status-codes", "--retry-status-code", dest="status_codes", action="append", help="按指定 status_code 重跑；可多次使用或用逗号分隔，如 AI_REPRODUCTION_FAILED,POC_NOT_FOUND")
    parser.add_argument("--file", "-f", help="批量测试文件名或路径，默认交互选择 test/*.txt")
    parser.add_argument("--start", type=int, help="批量测试起始序号，1-based，包含")
    parser.add_argument("--end", type=int, help="批量测试结束序号，1-based，包含")
    parser.add_argument("--terminals", "-t", type=int, help="批量测试/二次核验时自动拆分启动的终端数")
    parser.add_argument("--retry-shard", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--retry-shards", type=int, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def interactive_loop() -> None:
    console.print("[bold cyan]CVE Hunter[/bold cyan] - 基于 LangGraph 的漏洞自动复现")
    console.print("输入 CVE 编号开始复现；输入 batch 进入批量测试；输入 retry 二次核验失败记录；输入 retry-passed 核验历史通过记录；输入 retry-status 按状态码核验；输入 classify 进入分类筛选；输入 stats 查看批量统计；输入 quit 退出\n")
    while True:
        try:
            cve_id = console.input("[bold green]CVE>[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n再见！")
            break
        if not cve_id or cve_id.lower() in ("quit", "exit", "q"):
            console.print("再见！")
            break
        if cve_id.lower() in ("batch", "b"):
            run_batch()
            console.print()
            continue
        if cve_id.lower() in ("classify", "filter", "c"):
            run_classify()
            console.print()
            continue
        if cve_id.lower() in ("stats", "stat", "summary", "s"):
            run_batch_stats()
            console.print()
            continue
        if cve_id.lower() in ("retry", "retry-http", "retry-http-failed", "r"):
            run_retry_http_failed()
            console.print()
            continue
        if cve_id.lower() in ("retry-passed", "retry-success", "retry-correct", "rp"):
            run_retry_http_failed(retry_mode="passed")
            console.print()
            continue
        if cve_id.lower() in ("retry-status", "retry-code", "rs"):
            raw_codes = console.input("[bold green]状态码(逗号分隔)>[/bold green] ").strip()
            retry_status_codes = parse_retry_status_codes([raw_codes])
            if not retry_status_codes:
                console.print("[red]未输入有效状态码[/red]")
                console.print()
                continue
            validate_retry_status_codes(retry_status_codes)
            run_retry_http_failed(retry_mode="status", retry_status_codes=retry_status_codes)
            console.print()
            continue
        run_cve(cve_id)
        console.print()


def main():
    args = parse_args(sys.argv[1:])
    retry_status_codes = parse_retry_status_codes(args.status_codes)
    if args.retry_passed and retry_status_codes:
        raise SystemExit("--retry-passed 不能和 --status-code 同时使用")
    if retry_status_codes:
        if args.retry_mode not in ("failed", "status"):
            raise SystemExit("--status-code 不能和 --retry-mode passed/all 同时使用")
        args.retry_mode = "status"

    if args.retry_passed:
        args.retry_http_failed = True
        args.retry_mode = "passed"
    elif args.retry_mode == "status":
        args.retry_http_failed = True
        if not retry_status_codes:
            raise SystemExit("--retry-mode status 需要指定 --status-code")
        validate_retry_status_codes(retry_status_codes)
    elif args.retry_mode != "failed":
        args.retry_http_failed = True

    if (args.retry_shard is not None or args.retry_shards is not None) and not args.retry_http_failed:
        raise SystemExit("--retry-shard/--retry-shards 只能和 --retry-http-failed 一起使用")

    selected_modes = sum(1 for enabled in (args.batch, args.classify, args.stats, args.retry_http_failed) if enabled)
    if selected_modes > 1:
        raise SystemExit("--batch、--classify、--stats 和 --retry-http-failed 不能同时使用")

    if args.batch:
        batch_file = args.file or args.cve_id
        run_batch(batch_file, args.start, args.end, args.terminals)
        return

    if args.classify:
        if args.terminals is not None:
            raise SystemExit("--terminals 只能和 --batch 或 --retry-http-failed 一起使用")
        classify_file = args.file or args.cve_id
        run_classify(classify_file, args.start, args.end)
        return

    if args.stats:
        if args.cve_id or args.file or args.start is not None or args.end is not None or args.terminals is not None:
            raise SystemExit("--stats 不需要 CVE、--file、--start、--end 或 --terminals")
        run_batch_stats()
        return

    if args.retry_http_failed:
        if args.cve_id or args.file:
            raise SystemExit("--retry 不需要 CVE 或 --file")
        run_retry_http_failed(
            args.start,
            args.end,
            args.terminals,
            args.retry_shard,
            args.retry_shards,
            args.retry_mode,
            retry_status_codes,
        )
        return

    if args.file or args.start is not None or args.end is not None or args.terminals is not None:
        raise SystemExit("--file/--start/--end/--terminals 只能和对应启动项一起使用")

    if args.cve_id:
        run_cve(args.cve_id)
    else:
        interactive_loop()


if __name__ == "__main__":
    main()
