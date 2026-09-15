"""LangGraph 工作流核心编排。

实现 CVE HTTP 漏洞复现的完整工作流：
  输入CVE → 获取NVD信息 → 适用性判断 → 本地KB搜索(优先) → 多源PoC搜索(带回退) → 验证 → 归档 → 保存到本地KB

PoC 获取优先级（由高到低）：
  1. 本地知识库 custom/（自验证保存的 PoC）
  2. 本地知识库 trickest-cve/（外部 PoC 目录，含 GitHub 仓库链接）
  3. NVD References + AI 生成
  4. Nuclei 官方模板库
  5. Exploit-DB
  6. imfht 漏洞库
  7. 联网搜索 + AI 生成
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from functools import lru_cache

from langgraph.graph import StateGraph, END

from cve_hunter.classifier import classify_http_vuln_from_info
from cve_hunter.config import cfg
from cve_hunter.runtime import effective_target_ip
from cve_hunter.environment import build_environment_spec, write_environment_manifest
from cve_hunter.state import CVEState
from cve_hunter.llm import invoke_llm
from cve_hunter.agents import (
    append_agent_trace,
    run_critic_agent,
    run_environment_agent,
    run_trigger_agent,
    teardown_environment,
)
from cve_hunter.poc_parser import extract_http_requests, parse_poc_candidates_json
from cve_hunter.prompts.templates import (
    POC_GENERATION_FROM_REFS,
    POC_GENERATION_FROM_SEARCH,
)
from cve_hunter.tools.nvd import query_nvd
from cve_hunter.tools.web_extract import extract_url_content, extract_url_content_tavily
from cve_hunter.tools.poc_sources import search_nuclei, search_exploitdb, search_imfht
from cve_hunter.tools.local_kb import search_local_kb, save_to_local_kb
from cve_hunter.tools.web_search import search_web
from cve_hunter.verification import evaluate_success, execute_candidate
from cve_hunter.tools.http_sender import finalize_capture
from cve_hunter.evidence import (
    FAILURE_CLASS_NONE,
    build_version_evidence,
    classify_failure,
    derive_success_tier,
    write_repro_bundle,
)
from cve_hunter.status_codes import (
    AI_REPRODUCTION_FAILED,
    CAPTURE_SUCCESS,
    EXECUTION_POLICY_BLOCKED,
    HTTP2PCAP_SERVICE_FAILED,
    HTTP_REQUEST_FAILED,
    INFRASTRUCTURE_FAILED,
    IPS_GENERIC_MATCH_ONLY,
    NOT_HTTP_VULN,
    PARAMETER_ERROR,
    PCAP_CAPTURE_FAILED,
    POC_NOT_FOUND,
    PROTOCOL_UNSUPPORTED,
    classify_error,
    make_status_update,
    status_description,
)
from cve_hunter.executors.base import (
    PROTOCOL_DATABASE,
    PROTOCOL_HTTP,
    infer_protocol,
)

from rich.console import Console

console = Console()


def _state_output_root(state: CVEState) -> Path:
    """Resolve a run-specific artifact root without changing CLI defaults."""
    configured = str(getattr(state, "output_dir", "") or "").strip()
    root = Path(configured) if configured else Path(cfg.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _mark_milestone_map(
    milestones: dict,
    name: str,
    status: str,
    *,
    message: str = "",
    data: dict | None = None,
) -> dict:
    updated = deepcopy(milestones or {})
    previous = updated.get(name, {})
    updated[name] = {
        "status": status,
        "message": message,
        "data": data or {},
        "count": int(previous.get("count") or 0) + 1 if isinstance(previous, dict) else 1,
        "timestamp": datetime.now().isoformat(),
    }
    return updated


def _milestone_update(
    state: CVEState,
    name: str,
    status: str,
    *,
    message: str = "",
    data: dict | None = None,
) -> dict:
    return {"milestones": _mark_milestone_map(state.milestones, name, status, message=message, data=data)}


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
            "status_code": PARAMETER_ERROR,
            "message": f"CVE 编号格式错误: {state.cve_id}",
            **_milestone_update(
                state,
                "input_validated",
                "failed",
                message="CVE 编号格式错误",
                data={"input": state.cve_id},
            ),
        }
    return {
        "cve_id": cve_id,
        "current_phase": "nvd_query",
        **_milestone_update(state, "input_validated", "passed", data={"cve_id": cve_id}),
    }


def node_query_nvd(state: CVEState) -> dict:
    """查询 NVD 获取 CVE 详细信息。"""
    console.print(f"[bold cyan]▶ 查询 NVD[/] {state.cve_id}")
    try:
        info = query_nvd(state.cve_id, local_only=state.local_only)
        if "error" in info:
            hint = classify_error(info["error"], source="nvd")
            return {
                "error_messages": state.error_messages + [info["error"]],
                "nvd_description": "",
                "nvd_source": info.get("nvd_source", ""),
                **make_status_update(state.status_code, hint.code, hint.message),
                "current_phase": "vuln_type_check",
                **_milestone_update(
                    state,
                    "nvd_loaded",
                    "failed",
                    message=hint.message,
                    data={"status_code": hint.code},
                ),
            }
        console.print(f"  [green]✓[/] CVSS={info['cvss_score']} refs={len(info['references'])}")
        return {
            "nvd_description": info["description"],
            "nvd_source": info.get("nvd_source", ""),
            "nvd_references": info["references"],
            "affected_products": info["affected_products"],
            "cvss_score": info["cvss_score"],
            "cvss_severity": info["cvss_severity"],
            "nvd_metadata": info.get("metadata", {}),
            "current_phase": "vuln_type_check",
            **_milestone_update(
                state,
                "nvd_loaded",
                "passed",
                data={
                    "cvss_score": info["cvss_score"],
                    "cvss_severity": info["cvss_severity"],
                    "reference_count": len(info["references"]),
                },
            ),
        }
    except Exception as e:
        hint = classify_error(e, source="nvd")
        console.print(f"  [red]✗ NVD 查询失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"NVD 查询失败: {e}"],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "vuln_type_check",
            **_milestone_update(
                state,
                "nvd_loaded",
                "failed",
                message=hint.message,
                data={"status_code": hint.code},
            ),
        }


def node_vuln_type_check(state: CVEState) -> dict:
    """AI 判断漏洞是否属于 HTTP/Web 类型。"""
    console.print("[bold cyan]▶ AI 漏洞类型判断[/]")

    if state.local_only:
        protocol = infer_protocol(
            is_http_vuln=True,
            description=state.nvd_description,
        )
        is_http = protocol == PROTOCOL_HTTP
        return {
            "is_http_vuln": is_http,
            "vuln_type": "本地规则",
            "protocol": protocol,
            "current_phase": "environment_agent",
            **_milestone_update(
                state,
                "http_classified",
                "passed",
                message="严格本地模式：使用本地规则分类",
                data={"is_http_vuln": is_http, "vuln_type": "本地规则", "protocol": protocol},
            ),
        }

    if not state.nvd_description:
        console.print("  [yellow]⚠ 无 NVD 描述，默认为 HTTP 漏洞继续处理[/]")
        return {
            "is_http_vuln": True,
            "vuln_type": "未知",
            "protocol": PROTOCOL_HTTP,
            "current_phase": "environment_agent",
            **_milestone_update(
                state,
                "http_classified",
                "passed",
                message="无 NVD 描述，按 HTTP/Web 继续",
                data={"is_http_vuln": True, "vuln_type": "未知", "protocol": PROTOCOL_HTTP},
            ),
        }

    result = classify_http_vuln_from_info(
        cve_id=state.cve_id,
        description=state.nvd_description,
        references=state.nvd_references,
        affected_products=state.affected_products,
        cvss_score=state.cvss_score,
        cvss_severity=state.cvss_severity,
    )
    protocol = infer_protocol(
        is_http_vuln=result.is_http_vuln,
        vuln_type=result.vuln_type,
        description=state.nvd_description,
    )
    if result.error:
        console.print(f"  [yellow]⚠ {result.error}[/]")
        updates = {
            "is_http_vuln": result.is_http_vuln,
            "vuln_type": result.vuln_type,
            "protocol": protocol,
            "current_phase": "reference_analysis" if result.is_http_vuln or protocol == PROTOCOL_DATABASE else "generate_report",
            "error_messages": state.error_messages + [result.error],
        }
        if not result.is_http_vuln and protocol != PROTOCOL_DATABASE:
            updates.update(make_status_update(state.status_code, PROTOCOL_UNSUPPORTED, status_description(PROTOCOL_UNSUPPORTED)))
        console.print(f"  [green]✓[/] is_http={result.is_http_vuln} type={result.vuln_type} protocol={protocol}")
        updates["milestones"] = _mark_milestone_map(
            state.milestones,
            "http_classified",
            "failed" if "AI 判断" in result.error else "passed",
            message=result.error,
            data={"is_http_vuln": result.is_http_vuln, "vuln_type": result.vuln_type, "protocol": protocol},
        )
        return updates
    console.print(f"  [green]✓[/] is_http={result.is_http_vuln} type={result.vuln_type} protocol={protocol}")
    phase = "environment_agent"
    updates = {
        "is_http_vuln": result.is_http_vuln,
        "vuln_type": result.vuln_type,
        "protocol": protocol,
        "current_phase": phase,
        **_milestone_update(
            state,
            "http_classified",
            "passed",
            data={"is_http_vuln": result.is_http_vuln, "vuln_type": result.vuln_type, "protocol": protocol},
        ),
    }
    if not result.is_http_vuln and protocol != PROTOCOL_DATABASE:
        updates.update(make_status_update(state.status_code, PROTOCOL_UNSUPPORTED, status_description(PROTOCOL_UNSUPPORTED)))
        updates["current_phase"] = "generate_report"
    return updates


def node_environment_agent(state: CVEState) -> dict:
    """EnvironmentAgent：规划并按配置自动搭建攻击环境。"""
    console.print("[bold cyan]▶ EnvironmentAgent 攻击环境规划[/]")
    result = run_environment_agent(state)
    trace = result["trace"]
    env = result["attack_environment"]
    environment_spec = build_environment_spec(
        cve_id=state.cve_id,
        environment=env,
        candidates=result["environment_candidates"],
        run_mode=getattr(cfg, "run_mode", "plan_only"),
        allowlist=getattr(cfg, "target_allowlist", []),
        evidence_urls=state.nvd_references[:8],
    )
    manifest_path = ""
    manifest_error = ""
    try:
        manifest_path = str(write_environment_manifest(environment_spec, _state_output_root(state) / state.cve_id))
    except Exception as exc:
        manifest_error = f"环境 manifest 写入失败: {exc}"

    milestone_status = "failed" if trace.get("status") in {"setup_failed", "not_found"} else "passed"
    milestone_message = trace.get("summary", "")
    milestones = _mark_milestone_map(
        state.milestones,
        "environment_planned",
        milestone_status,
        message=milestone_message,
        data={
            "source": env.get("source", ""),
            "provider": env.get("provider", ""),
            "launcher": env.get("launcher", ""),
            "target_url": env.get("target_url", ""),
            "candidate_count": len(result["environment_candidates"]),
            "manifest_path": manifest_path,
        },
    )
    setup_result = env.get("setup_result") if isinstance(env.get("setup_result"), dict) else {}
    if setup_result:
        milestones = _mark_milestone_map(
            milestones,
            "environment_ready",
            "passed" if setup_result.get("success") else "failed",
            message=setup_result.get("error", "") or "environment setup completed",
            data={"setup_result": setup_result},
        )
    else:
        milestones = _mark_milestone_map(
            milestones,
            "environment_ready",
            "skipped",
            message=env.get("setup_mode", "") or "environment setup not required",
            data={"setup_mode": env.get("setup_mode", "")},
        )

    updates = {
        "environment_candidates": result["environment_candidates"],
        "attack_environment": env,
        "environment_spec": environment_spec,
        "environment_manifest_path": manifest_path,
        "environment_setup_result": env.get("setup_result", {}),
        "agent_trace": append_agent_trace(state, **trace),
        "current_phase": "local_kb_search",
        "milestones": milestones,
    }
    errors = list(result.get("errors") or [])
    if manifest_error:
        errors.append(manifest_error)
    if errors:
        updates["error_messages"] = state.error_messages + errors
        if cfg.auto_env_enabled or state.local_container_mode:
            updates.update(make_status_update(state.status_code, INFRASTRUCTURE_FAILED, errors[0]))
        if state.local_container_mode:
            updates["current_phase"] = "generate_report"
    setup_result = env.get("setup_result") if isinstance(env.get("setup_result"), dict) else {}
    if env.get("setup_mode") == "disabled":
        console.print(f"  [dim]环境启动已禁用 (AUTO_ENV_ENABLED=false)[/]")
    elif setup_result.get("success"):
        console.print(f"  [green]✓[/] 攻击环境已启动")
    elif setup_result:
        console.print(f"  [red]✗[/] 攻击环境启动失败: {setup_result.get('error', '未知错误')}")
    else:
        console.print(f"  [dim]环境候选已记录，未实际启动[/]")
    console.print(f"  [green]✓[/] target={env.get('target_url', '')} source={env.get('source', '')}")
    return updates


def node_local_kb_search(state: CVEState) -> dict:
    """在本地知识库中搜索 PoC（最高优先级，优先于远程源）。"""
    console.print("[bold cyan]▶ 搜索本地知识库[/]")
    try:
        result = _search_uploaded_files(state.cve_id, state.uploaded_files)
        if not result.get("found"):
            result = search_local_kb(state.cve_id)
        if result.get("found"):
            source_label = result["source"]
            console.print(f"  [green]✓ 本地知识库命中[/] (来源: {source_label})")

            updates: dict = {
                "phases_tried": state.phases_tried + ["local_kb_search"],
                "local_knowledge_context": str(result.get("content") or result.get("raw_http") or result.get("yaml_content") or "")[:12000],
            }

            if result.get("raw_http"):
                console.print("  [green]✓ 提取到 HTTP PoC[/]")
                updates.update(_candidate_update(
                    state,
                    _raw_http_candidates(
                        [result["raw_http"]],
                        source=source_label,
                        evidence_url=result.get("kb_path", ""),
                        confidence=0.95 if source_label == "local_kb_custom" else 0.75,
                        reason="本地知识库命中",
                        validation_hint=result.get("validation_hint"),
                    ),
                    fallback_phase="reference_analysis",
                ))
                return updates

            if result.get("execution_spec"):
                console.print("  [green]✓ 提取到数据库 execution_spec[/]")
                from cve_hunter.tools.db_spec import resolve_database_target
                from urllib.parse import urlparse

                spec = dict(result["execution_spec"])
                engine = str(spec.get("engine") or "postgres")
                env_target = (state.attack_environment or {}).get("target_url") or (
                    state.attack_environment or {}
                ).get("target_host") or ""
                # 从已抽取 DSN 取账号库名，再用环境 host:port 覆盖地址
                existing = str(spec.get("target") or "")
                user, password, database = "postgres", "postgres", "postgres"
                if engine.startswith("mysql"):
                    user, password, database = "root", "", ""
                if "://" in existing:
                    parsed = urlparse(existing)
                    user = parsed.username or user
                    password = parsed.password if parsed.password is not None else password
                    database = (parsed.path or "").lstrip("/") or database
                if env_target:
                    spec["target"] = resolve_database_target(
                        engine=engine,
                        env_target=str(env_target),
                        user=user,
                        password=password or "",
                        database=database,
                    )
                    # 多会话同样覆盖 host/port，保留各会话自身账号
                    sessions = list(spec.get("sessions") or [])
                    if sessions:
                        rewritten_sessions = []
                        for session in sessions:
                            if not isinstance(session, dict):
                                continue
                            item = dict(session)
                            item["target"] = resolve_database_target(
                                engine=engine,
                                env_target=str(env_target),
                                user=str(item.get("user") or user),
                                password=str(item.get("password") if item.get("password") is not None else password),
                                database=str(item.get("database") or database),
                            )
                            rewritten_sessions.append(item)
                        spec["sessions"] = rewritten_sessions
                candidate = {
                    "kind": "execution_spec",
                    "source": source_label,
                    "execution_spec": spec,
                    "evidence_url": result.get("kb_path", ""),
                    "confidence": 0.9,
                    "reason": "本地知识库 SQL 场景命中",
                    "validation_hint": dict(spec.get("oracle") or {}),
                }
                updates["execution_spec"] = spec
                updates["protocol"] = "database"
                updates.update(_candidate_update(
                    state,
                    [candidate],
                    fallback_phase="reference_analysis",
                ))
                return updates

            if result.get("yaml_content"):
                updates.update(_candidate_update(
                    state,
                    [_nuclei_candidate(
                        result["yaml_content"],
                        source=source_label,
                        evidence_url=result.get("kb_path", ""),
                        confidence=0.9,
                        reason="本地知识库命中",
                    )],
                    fallback_phase="reference_analysis",
                ))
                return updates

            # trickest-cve 命中但未提取到 HTTP/SQL PoC
            if _local_container_skip_remote(state):
                console.print("  [yellow]⚠ 本地 KB 无可用 HTTP/SQL PoC，local-container 模式跳过远程搜索[/]")
                updates.update(
                    make_status_update(state.status_code, POC_NOT_FOUND, status_description(POC_NOT_FOUND))
                )
                updates["current_phase"] = "poc_from_nvd" if state.local_only else "generate_report"
                return updates
            console.print("  [yellow]⚠ 本地 KB 无可用 HTTP/SQL PoC，继续远程搜索[/]")
            updates["current_phase"] = "poc_from_nvd" if state.local_only else "reference_analysis"
            return updates

        if result.get("error"):
            console.print(f"  [yellow]⚠ {result.get('error')}[/]")

        console.print("  [dim]本地知识库未命中[/]")
    except Exception as e:
        console.print(f"  [yellow]⚠ 本地知识库搜索异常: {e}[/]")

    if _local_container_skip_remote(state):
        console.print("  [yellow]⚠ local-container 模式：无本地 PoC，跳过远程搜索[/]")
        return {
            "phases_tried": state.phases_tried + ["local_kb_search"],
            "current_phase": "poc_from_nvd" if state.local_only else "generate_report",
            **make_status_update(state.status_code, POC_NOT_FOUND, status_description(POC_NOT_FOUND)),
        }

    return {
        "phases_tried": state.phases_tried + ["local_kb_search"],
        "current_phase": "poc_from_nvd" if state.local_only else "reference_analysis",
    }


def node_poc_from_nvd(state: CVEState) -> dict:
    """Generate a candidate from local intelligence without fetching references."""
    import re

    requests = []
    # Bound extraction to explicit code blocks to avoid treating prose as a body.
    for block in re.findall(r"```(?:http|text|raw)?\s*\n(.*?)```", state.nvd_description, re.S | re.I):
        requests.extend(extract_http_requests(block))
    updates = {"phases_tried": state.phases_tried + ["poc_from_nvd"]}
    prompt = f"""Generate a conservative PoC candidate for {state.cve_id} using ONLY this local CVE data.
Use explicit paths, parameters, payloads, or reproduction steps present in the data. Do not use references or invent endpoints.
If no executable evidence exists, return {{\"candidates\":[]}}.
Return JSON with candidates containing raw_http only when grounded in supplied data.
LOCAL DATA:\n{state.nvd_description}\n{state.local_knowledge_context}\n{json.dumps(state.nvd_metadata, ensure_ascii=False)[:6000]}\nProducts: {', '.join(state.affected_products[:10])}"""
    try:
        generated = _llm_poc_candidates(invoke_llm(prompt), source="local_llm",
            evidence_url=f"local-nvd:{state.cve_id}", confidence=0.55,
            reason="仅基于本地 NVD/cvelist 上下文生成")
        requests.extend(c.get("raw_http", "") for c in generated if c.get("raw_http"))
    except Exception as exc:
        updates["error_messages"] = state.error_messages + [f"本地上下文 PoC 生成失败: {exc}"]
    if requests:
        updates.update(_candidate_update(
            state, _raw_http_candidates(requests, source="local_nvd",
                evidence_url=f"local-nvd:{state.cve_id}", confidence=0.6,
                reason="本地 NVD 描述中的明确 HTTP 请求，尚未验证"),
            fallback_phase="generate_report",
        ))
    else:
        if state.allow_reference_links and state.nvd_references:
            updates["current_phase"] = "reference_analysis"
            return updates
        updates.update({"current_phase": "generate_report", **make_status_update(
            state.status_code, POC_NOT_FOUND,
            "本地知识库无可用 PoC；NVD 描述、CVSS 和版本信息不足以构造明确请求，未联网补全",
        )})
    return updates


def _search_uploaded_files(cve_id: str, paths: list[str]) -> dict:
    """Use PoC files supplied by the browser before the shared KB.

    Uploads remain outside the repository KB. Raw HTTP and Nuclei YAML are
    recognized directly; scripts/prose are still retained on disk for review.
    """
    needle = str(cve_id or "").upper()
    for raw_path in paths or []:
        path = Path(str(raw_path))
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        haystack = f"{path.name}\n{text}".upper()
        if needle and needle not in haystack:
            continue
        requests = extract_http_requests(text)
        if requests:
            return {
                "found": True,
                "source": "uploaded_file",
                "raw_http": requests[0],
                "kb_path": str(path),
                "validation_hint": {"type": "status_code"},
            }
        suffix = path.suffix.lower()
        if suffix in {".yaml", ".yml"} and ("http:" in text.lower() or "id:" in text.lower()):
            return {"found": True, "source": "uploaded_file", "yaml_content": text, "kb_path": str(path)}
        candidates = parse_poc_candidates_json(text)
        if candidates:
            return {
                "found": True,
                "source": "uploaded_file",
                "raw_http": candidates[0].get("raw_http", ""),
                "kb_path": str(path),
                "validation_hint": {"type": "status_code"},
            }
    return {"found": False}


def node_reference_analysis(state: CVEState) -> dict:
    """提取 NVD References 中的网页内容并分析。"""
    console.print(f"[bold cyan]▶ 分析 References[/] ({len(state.nvd_references)} 个链接)")
    if not state.nvd_references:
        return {"current_phase": "trigger_agent", "phases_tried": state.phases_tried + ["reference_analysis"]}

    contents = []
    errors = []
    # References are independent network requests.  A small bounded pool cuts
    # wall time substantially while avoiding an unbounded burst to external sites.
    from concurrent.futures import ThreadPoolExecutor
    urls = list(state.nvd_references[:8])
    for i, url in enumerate(urls):
        console.print(f"  [{i+1}] {url[:80]}...")
    extractor = extract_url_content_tavily if state.allow_reference_links else extract_url_content
    with ThreadPoolExecutor(max_workers=min(4, len(urls))) as pool:
        results = list(pool.map(extractor, urls))
    for url, result in zip(urls, results):
        if result.get("content"):
            contents.append({"url": url, "title": result.get("title", ""), "content": result["content"][:3000]})
        elif result.get("error"):
            errors.append(f"{url}: {result.get('error')}")

    console.print(f"  [green]✓[/] 成功提取 {len(contents)} 个页面内容")
    updates = {
        "reference_contents": contents,
        "current_phase": "trigger_agent",
        "phases_tried": state.phases_tried + ["reference_analysis"],
    }
    if errors:
        updates["error_messages"] = state.error_messages + errors[:3]
        if not contents:
            hint = classify_error(errors[0], source="reference")
            updates.update(make_status_update(state.status_code, hint.code, hint.message))
    return updates


def node_poc_from_refs(state: CVEState) -> dict:
    """基于 References 内容让 AI 生成 PoC。"""
    console.print("[bold cyan]▶ 基于 References 生成 PoC[/]")

    if not state.reference_contents:
        if state.nvd_references and "reference_analysis" not in set(state.phases_tried):
            console.print("  [yellow]⚠ 尚未分析 References，先提取网页内容[/]")
            return {"current_phase": "reference_analysis"}
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
        candidates = _llm_poc_candidates(
            result,
            source="reference",
            evidence_url=",".join(ref["url"] for ref in state.reference_contents[:3]),
            confidence=0.65,
            reason="基于 NVD References 内容由 AI 生成",
        )
        if candidates:
            console.print(f"  [green]✓[/] AI 生成了 {len(candidates)} 个 PoC 候选")
            return {
                **_candidate_update(
                    state,
                    candidates,
                    fallback_phase="nuclei_search",
                ),
                "phases_tried": state.phases_tried + ["poc_from_refs"],
            }
    except Exception as e:
        hint = classify_error(e, source="llm")
        console.print(f"  [red]✗ AI 生成失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"AI 生成 PoC 失败: {e}"],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "nuclei_search",
            "phases_tried": state.phases_tried + ["poc_from_refs"],
        }

    return {"current_phase": "nuclei_search", "phases_tried": state.phases_tried + ["poc_from_refs"]}


def node_nuclei_search(state: CVEState) -> dict:
    """在 nuclei-templates 搜索官方 PoC。"""
    console.print("[bold cyan]▶ 搜索 Nuclei 官方 PoC 库[/]")
    try:
        result = search_nuclei(state.cve_id)
        if result.get("found"):
            console.print(f"  [green]✓[/] 找到 nuclei 模板: {result.get('name', '')}")
            return {
                **_candidate_update(
                    state,
                    [_nuclei_candidate(
                        result["yaml_content"],
                        source="nuclei",
                        evidence_url=result.get("url", ""),
                        confidence=0.85,
                        reason=result.get("name", "nuclei 官方模板"),
                    )],
                    fallback_phase="exploitdb_search",
                ),
                "phases_tried": state.phases_tried + ["nuclei_search"],
            }
        if result.get("error"):
            hint = classify_error(result.get("error"), source="nuclei")
            return {
                "error_messages": state.error_messages + [f"nuclei 搜索失败: {result.get('error')}"],
                **make_status_update(state.status_code, hint.code, hint.message),
                "current_phase": "exploitdb_search",
                "phases_tried": state.phases_tried + ["nuclei_search"],
            }
        console.print("  [yellow]⚠ nuclei 库中未找到[/]")
    except Exception as e:
        hint = classify_error(e, source="nuclei")
        console.print(f"  [red]✗ 搜索失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"nuclei 搜索失败: {e}"],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "exploitdb_search",
            "phases_tried": state.phases_tried + ["nuclei_search"],
        }

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
            extract_errors = []
            candidates = []
            from concurrent.futures import ThreadPoolExecutor
            records_to_fetch = records[:2]
            if records_to_fetch:
                with ThreadPoolExecutor(max_workers=min(2, len(records_to_fetch))) as pool:
                    fetched = list(pool.map(lambda rec: extract_url_content(rec["url"]), records_to_fetch))
            else:
                fetched = []
            for rec, content in zip(records_to_fetch, fetched):
                if content.get("content"):
                    pocs = _extract_http_requests(content["content"], state.cve_id)
                    if pocs:
                        candidates.extend(_raw_http_candidates(
                            pocs,
                            source="exploit-db",
                            evidence_url=rec["url"],
                            confidence=0.7,
                            reason=rec.get("title", "Exploit-DB 结果"),
                        ))
                elif content.get("error"):
                    extract_errors.append(f"{rec['url']}: {content.get('error')}")
            if candidates:
                console.print(f"  [green]✓[/] 提取到 {len(candidates)} 个 HTTP PoC 候选")
                return {
                    **_candidate_update(state, candidates, fallback_phase="imfht_search"),
                    "phases_tried": state.phases_tried + ["exploitdb_search"],
                }
            if extract_errors:
                hint = classify_error(extract_errors[0], source="reference")
                return {
                    "error_messages": state.error_messages + extract_errors[:2],
                    **make_status_update(state.status_code, hint.code, hint.message),
                    "current_phase": "imfht_search",
                    "phases_tried": state.phases_tried + ["exploitdb_search"],
                }
        if result.get("error"):
            hint = classify_error(result.get("error"), source="exploit-db")
            return {
                "error_messages": state.error_messages + [f"Exploit-DB 搜索失败: {result.get('error')}"],
                **make_status_update(state.status_code, hint.code, hint.message),
                "current_phase": "imfht_search",
                "phases_tried": state.phases_tried + ["exploitdb_search"],
            }
        console.print("  [yellow]⚠ Exploit-DB 中未找到可用 PoC[/]")
    except Exception as e:
        hint = classify_error(e, source="exploit-db")
        console.print(f"  [red]✗ 搜索失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"Exploit-DB 搜索失败: {e}"],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "imfht_search",
            "phases_tried": state.phases_tried + ["exploitdb_search"],
        }

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
                    **_candidate_update(
                        state,
                        _raw_http_candidates(
                            pocs,
                            source="imfht",
                            evidence_url=result.get("url", ""),
                            confidence=0.6,
                            reason="imfht 页面提取",
                        ),
                        fallback_phase="web_search",
                    ),
                    "phases_tried": state.phases_tried + ["imfht_search"],
                }
        if result.get("error"):
            hint = classify_error(result.get("error"), source="imfht")
            return {
                "error_messages": state.error_messages + [f"imfht 搜索失败: {result.get('error')}"],
                **make_status_update(state.status_code, hint.code, hint.message),
                "current_phase": "web_search",
                "phases_tried": state.phases_tried + ["imfht_search"],
            }
        console.print("  [yellow]⚠ imfht 中未找到可用 PoC[/]")
    except Exception as e:
        hint = classify_error(e, source="imfht")
        console.print(f"  [red]✗ 搜索失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"imfht 搜索失败: {e}"],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "web_search",
            "phases_tried": state.phases_tried + ["imfht_search"],
        }

    return {"current_phase": "web_search", "phases_tried": state.phases_tried + ["imfht_search"]}


def node_web_search(state: CVEState) -> dict:
    """联网搜索并由 AI 生成 PoC。"""
    console.print("[bold cyan]▶ 联网搜索 + AI 构造 PoC[/]")

    queries = [
        f"{state.cve_id} PoC exploit HTTP",
        f"{state.cve_id} vulnerability exploit payload",
    ]

    from concurrent.futures import ThreadPoolExecutor
    all_results = []
    search_errors = []
    with ThreadPoolExecutor(max_workers=len(queries)) as pool:
        query_results = list(pool.map(lambda q: search_web(q, max_results=5), queries))
    for results in query_results:
        for item in results:
            if item.get("title") == "搜索错误":
                search_errors.append(item.get("content", "搜索错误"))
        all_results.extend(results)

    # Both queries commonly return the same URLs; remove duplicates before
    # fetching page bodies and sending context to the LLM.
    deduped_results = []
    seen_urls = set()
    for item in all_results:
        if item.get("title") == "搜索错误":
            deduped_results.append(item)
            continue
        url = str(item.get("url") or "").strip()
        key = url or (item.get("title"), item.get("content", ""))
        if key in seen_urls:
            continue
        seen_urls.add(key)
        deduped_results.append(item)
    all_results = deduped_results

    if not all_results:
        console.print("  [yellow]⚠ 搜索无结果[/]")
        return {
            **make_status_update(state.status_code, POC_NOT_FOUND, status_description(POC_NOT_FOUND)),
            "current_phase": "generate_report",
            "phases_tried": state.phases_tried + ["web_search"],
        }

    if search_errors and len(search_errors) == len(all_results):
        hint = classify_error(search_errors[0], source="web_search")
        console.print(f"  [red]✗ 联网搜索失败:[/] {search_errors[0]}")
        return {
            "error_messages": state.error_messages + search_errors[:2],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "generate_report",
            "phases_tried": state.phases_tried + ["web_search"],
        }

    console.print(f"  搜索到 {len(all_results)} 条结果")

    # 提取高价值页面内容
    search_text = ""
    extract_errors = []
    extract_targets = [r for r in all_results[:5] if r.get("title") != "搜索错误" and not r.get("content") and r.get("url")]
    extracted = {}
    if extract_targets:
        with ThreadPoolExecutor(max_workers=min(4, len(extract_targets))) as pool:
            extracted = {id(item): result for item, result in zip(extract_targets, pool.map(lambda item: extract_url_content(item["url"]), extract_targets))}
    for r in all_results[:5]:
        if r.get("title") == "搜索错误":
            continue
        if r.get("content"):
            search_text += f"\n### {r['title']} ({r['url']})\n{r['content'][:2000]}\n"
        elif r.get("url"):
            page = extracted.get(id(r), {})
            if page.get("content"):
                search_text += f"\n### {page['title']} ({r['url']})\n{page['content'][:2000]}\n"
            elif page.get("error"):
                extract_errors.append(f"{r['url']}: {page.get('error')}")

    if not search_text and extract_errors:
        hint = classify_error(extract_errors[0], source="reference")
        return {
            "error_messages": state.error_messages + extract_errors[:3],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "generate_report",
            "phases_tried": state.phases_tried + ["web_search"],
        }

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
        candidates = _llm_poc_candidates(
            result,
            source="search",
            confidence=0.45,
            reason="基于联网搜索结果由 AI 生成",
        )
        if candidates:
            console.print(f"  [green]✓[/] AI 基于搜索结果生成了 {len(candidates)} 个 PoC 候选")
            return {
                **_candidate_update(
                    state,
                    candidates,
                    fallback_phase="generate_report",
                ),
                "phases_tried": state.phases_tried + ["web_search"],
            }
    except Exception as e:
        hint = classify_error(e, source="llm")
        console.print(f"  [red]✗ AI 生成失败:[/] {e}")
        return {
            "error_messages": state.error_messages + [f"AI 基于搜索结果生成 PoC 失败: {e}"],
            **make_status_update(state.status_code, hint.code, hint.message),
            "current_phase": "generate_report",
            "phases_tried": state.phases_tried + ["web_search"],
        }

    return {
        **make_status_update(state.status_code, POC_NOT_FOUND, status_description(POC_NOT_FOUND)),
        "current_phase": "generate_report",
        "phases_tried": state.phases_tried + ["web_search"],
    }


def node_verify_poc(state: CVEState) -> dict:
    """发送 PoC 并验证。"""
    console.print(f"[bold cyan]▶ 验证 PoC[/] (来源: {state.poc_source})")

    candidate = _current_candidate(state)
    critic = run_critic_agent(state, candidate)
    candidate = critic["candidate"]
    agent_trace = append_agent_trace(state, **critic["trace"])
    candidate_update = _replace_current_candidate_update(state, candidate)
    review = critic["review"]
    milestones = _mark_milestone_map(
        state.milestones,
        "candidate_reviewed",
        "passed" if review.get("accepted") else "failed",
        message="候选审查完成",
        data={
            "candidate_index": state.current_candidate_index,
            "source": candidate.get("source", ""),
            "flags": review.get("flags", []),
            "confidence_after": review.get("confidence_after", candidate.get("confidence", 0.0)),
        },
    )

    if (
        not candidate.get("raw_http")
        and not candidate.get("nuclei_yaml")
        and not candidate.get("request_steps")
        and not candidate.get("execution_spec")
    ):
        milestones = _mark_milestone_map(
            milestones,
            "request_executed",
            "skipped",
            message="候选缺少可执行 payload",
            data={"candidate_index": state.current_candidate_index},
        )
        return {
            "candidate_reviews": state.candidate_reviews + [critic["review"]],
            "agent_trace": agent_trace,
            **candidate_update,
            "milestones": milestones,
            **make_status_update(state.status_code, POC_NOT_FOUND, status_description(POC_NOT_FOUND)),
            **_next_attempt_or_phase_update(state),
        }

    environment = state.attack_environment or {}
    target = environment.get("target_host") or effective_target_ip()
    console.print(f"  准备验证候选，目标 {target}...")
    max_requests = int(getattr(cfg, "max_requests_per_cve", 20) or 0)
    if state.local_container_mode:
        local_cap = int(getattr(cfg, "local_container_max_requests_per_cve", 6) or 6)
        max_requests = min(max_requests, local_cap) if max_requests > 0 else local_cap
    if max_requests > 0 and len(state.attempt_history) >= max_requests:
        result = {
            "success": False,
            "skipped": True,
            "policy_blocked": True,
            "error": f"MAX_REQUESTS_PER_CVE={max_requests} budget exhausted",
            "error_type": "policy",
            "executor": "policy_guard",
            "target_url": environment.get("target_url", ""),
            "target_host": target,
            "ips_matches": [],
        }
    else:
        result = execute_candidate(candidate, environment, cve_id=state.cve_id)
    oracle = evaluate_success(state=state, candidate=candidate, result=result, environment=environment)

    success = result.get("success", False)
    ips_summary = oracle["ips_summary"]
    ips_classification = oracle["ips_classification"]
    ips_matched = oracle["ips_matched"]
    generic_ips_matched = oracle["generic_ips_matched"]
    target_oracle = oracle["target_oracle"]
    # A capture is traffic evidence even when the oracle/IPS condition misses.
    # Keep every capture produced by a request so failed validations remain
    # inspectable and can be used to improve matching rules later.
    result["pcap_file_path"] = finalize_capture(result.get("pcap_file_path", ""))
    request_status = "skipped" if result.get("policy_blocked") or result.get("skipped") else ("passed" if success else "failed")
    milestones = _mark_milestone_map(
        milestones,
        "request_executed",
        request_status,
        message=result.get("error", "") if request_status != "passed" else "request executed",
        data={
            "candidate_index": state.current_candidate_index,
            "executor": result.get("executor", ""),
            "target_url": result.get("target_url", ""),
            "target_host": result.get("target_host", ""),
            "http_status_code": result.get("status_code", 0),
        },
    )
    milestones = _mark_milestone_map(
        milestones,
        "oracle_evaluated",
        "passed",
        message=oracle["message"],
        data={"outcome": oracle["outcome"], "success_level": oracle["success_level"]},
    )
    confirm_status = "passed" if ips_matched else ("skipped" if result.get("policy_blocked") else "failed")
    milestones = _mark_milestone_map(
        milestones,
        "cve_confirmed",
        confirm_status,
        message=oracle["message"],
        data={"outcome": oracle["outcome"], "success_level": oracle["success_level"]},
    )

    updates = {
        "candidate_reviews": state.candidate_reviews + [critic["review"]],
        "agent_trace": _append_agent_event(
            agent_trace,
            agent="VerifierAgent",
            action="execute_and_evaluate",
            status=oracle["outcome"],
            summary=oracle["message"],
            data={
                "executor": result.get("executor", ""),
                "success_level": oracle["success_level"],
                "target_oracle": target_oracle,
            },
        ),
        **candidate_update,
        "http_status_code": result.get("status_code", 0),
        "http_response_body": result.get("body", "")[:2000],
        "pcap_file_path": result.get("pcap_file_path", ""),
        "ips_matched": ips_matched,
        "generic_ips_matched": generic_ips_matched,
        "ips_match_details": ips_classification["all_matches"],
        "cve_ips_match_details": ips_classification["cve_matches"],
        "generic_ips_match_details": ips_classification["generic_matches"],
        "ips_match_summary": ips_summary,
        "executor_result": result,
        "oracle_result": oracle,
        "target_oracle_success": bool(target_oracle.get("success", False)),
        "target_oracle_type": target_oracle.get("type", ""),
        "target_oracle_details": target_oracle,
        "success_level": oracle["success_level"],
        "milestones": milestones,
    }

    if ips_matched:
        console.print(
            f"  [bold green]✓ 当前 CVE IPS 命中![/] "
            f"{ips_summary['cve_match_count']}/{ips_summary['total_count']} 条匹配"
        )
        updates["status"] = "SUCCESS"
        updates["status_code"] = CAPTURE_SUCCESS
        updates["message"] = "PoC 验证成功，IPS CVE 字段匹配当前 CVE"
        updates["current_phase"] = "archive"
        updates["attempt_history"] = _append_attempt_history(
            state, result, ips_summary, ips_matched, generic_ips_matched, oracle["outcome"],
            oracle_result=oracle, candidate=candidate,
        )
    elif target_oracle.get("success"):
        console.print(
            f"  [bold green]✓ 目标侧 oracle 验证成功[/] "
            f"type={target_oracle.get('type', 'unknown')}"
        )
        updates["status"] = "SUCCESS"
        updates["status_code"] = oracle["status_code"]
        updates["message"] = "目标侧 oracle 验证成功，漏洞复现有效"
        updates["current_phase"] = "archive"
        updates["attempt_history"] = _append_attempt_history(
            state, result, ips_summary, ips_matched, generic_ips_matched, oracle["outcome"],
            oracle_result=oracle, candidate=candidate,
        )
    elif generic_ips_matched:
        console.print(
            f"  [yellow]IPS 有通用/非当前 CVE 命中[/] "
            f"{ips_summary['generic_match_count']} 条，但 CVE 字段未匹配 {state.cve_id}，不计为成功"
        )
        updates["message"] = "检测到通用 IPS 命中，但未匹配当前 CVE，不作为成功验证依据"
        updates.update(make_status_update(state.status_code, IPS_GENERIC_MATCH_ONLY, status_description(IPS_GENERIC_MATCH_ONLY)))
        if not success and result.get("error"):
            updates["error_messages"] = state.error_messages + [result.get("error", "")]
        updates["attempt_history"] = _append_attempt_history(
            state, result, ips_summary, ips_matched, generic_ips_matched, oracle["outcome"],
            oracle_result=oracle, candidate=candidate,
        )
        updates.update(_next_attempt_or_phase_update(state))
    elif success:
        console.print(
            f"  [yellow]请求成功但没有利用成功证据[/] "
            f"(HTTP {result.get('status_code', '?')}, oracle={target_oracle.get('type', 'none')})"
        )
        updates.update(make_status_update(state.status_code, oracle["status_code"], oracle["message"]))
        updates["attempt_history"] = _append_attempt_history(
            state, result, ips_summary, ips_matched, generic_ips_matched, oracle["outcome"],
            oracle_result=oracle, candidate=candidate,
        )
        updates.update(_next_attempt_or_phase_update(state))
    else:
        verify_source = "policy" if result.get("policy_blocked") else ("http2pcap" if cfg.http2pcap_url else "target")
        hint = classify_error(result.get("error", "未知错误"), source=verify_source, error_type=result.get("error_type", ""))
        console.print(f"  [red]✗ 请求失败:[/] {result.get('error', '未知错误')}")
        updates["error_messages"] = state.error_messages + [result.get("error", "")]
        # A single nuclei/tool failure must not erase earlier successful HTTP
        # attempts that only lacked exploit evidence. Keep the more informative
        # "request completed" status in that case.
        prior_request_success = any(
            bool(item.get("request_success")) for item in state.attempt_history
        ) or bool(success)
        transient_infra_codes = {
            HTTP2PCAP_SERVICE_FAILED,
            PCAP_CAPTURE_FAILED,
            HTTP_REQUEST_FAILED,
        }
        if not (prior_request_success and hint.code in transient_infra_codes):
            updates.update(make_status_update(state.status_code, hint.code, hint.message))
        updates["attempt_history"] = _append_attempt_history(
            state, result, ips_summary, ips_matched, generic_ips_matched, oracle["outcome"],
            oracle_result=oracle, candidate=candidate,
        )
        updates.update(_next_attempt_or_phase_update(state))

    return updates


def node_trigger_agent(state: CVEState) -> dict:
    """TriggerAgent：抽象漏洞触发逻辑和默认验证 hint。"""
    console.print("[bold cyan]▶ TriggerAgent 抽象触发逻辑[/]")
    result = run_trigger_agent(state)
    trigger = result["trigger_candidates"][0] if result["trigger_candidates"] else {}
    console.print(
        f"  [green]✓[/] objective={trigger.get('attack_objective', 'unknown')} "
        f"oracle={trigger.get('validation_hint', {}).get('type', 'none')}"
    )
    return {
        "trigger_candidates": result["trigger_candidates"],
        "validation_hints": result["validation_hints"],
        "agent_trace": append_agent_trace(state, **result["trace"]),
        "current_phase": "poc_from_refs",
        **_milestone_update(
            state,
            "trigger_modeled",
            "passed" if result["trigger_candidates"] else "failed",
            message=result["trace"].get("summary", ""),
            data={
                "candidate_count": len(result["trigger_candidates"]),
                "attack_objective": trigger.get("attack_objective", ""),
                "validation_hint": trigger.get("validation_hint", {}),
            },
        ),
    }


def node_archive(state: CVEState) -> dict:
    """验证成功后的快速归档。"""
    console.print("[bold cyan]▶ 当前 CVE IPS 命中，进入归档[/]")
    return {"current_phase": "save_to_local_kb"}


def node_save_to_local_kb(state: CVEState) -> dict:
    """验证成功后将 PoC 保存到本地知识库 custom/ 目录。"""
    console.print("[bold cyan]▶ 保存 PoC 到本地知识库[/]")

    if state.status_code != CAPTURE_SUCCESS:
        console.print("  [dim]未获得验证成功证据，不写入 custom 知识库[/]")
        return {"current_phase": "generate_report"}

    if state.poc_raw_http or state.poc_nuclei_yaml:
        metadata = {
            "status": state.status,
            "poc_source": state.poc_source,
            "cvss_score": state.cvss_score,
            "cvss_severity": state.cvss_severity,
            "vuln_type": state.vuln_type,
            "nvd_description": state.nvd_description,
            "references": state.nvd_references,
            "timestamp": datetime.now().isoformat(),
        }
        path = save_to_local_kb(
            state.cve_id,
            poc_raw_http=state.poc_raw_http,
            poc_nuclei_yaml=state.poc_nuclei_yaml,
            metadata=metadata,
        )
        if path:
            console.print(f"  [green]✓[/] 已保存到 {path}")
        else:
            console.print("  [yellow]⚠ 保存失败[/]")
    else:
        console.print("  [dim]无 PoC 可保存[/]")

    return {"current_phase": "generate_report"}


def node_generate_report(state: CVEState) -> dict:
    """生成最终分析报告并归档所有产物。"""
    console.print("[bold cyan]▶ 生成分析报告[/]")

    if state.status != "SUCCESS":
        final_status = "FAILURE"
        if not state.is_http_vuln and getattr(state, "protocol", "") != PROTOCOL_DATABASE:
            final_code = state.status_code or PROTOCOL_UNSUPPORTED
            final_msg = state.message or status_description(final_code)
        elif state.status_code == PARAMETER_ERROR:
            final_code = PARAMETER_ERROR
            final_msg = state.message
        elif state.generic_ips_matched:
            final_code = IPS_GENERIC_MATCH_ONLY
            final_msg = "检测到通用 IPS 命中，但日志 CVE 字段未匹配当前 CVE"
        elif _execution_policy_blocked(state):
            final_code = EXECUTION_POLICY_BLOCKED
            final_msg = state.oracle_result.get("message") or state.executor_result.get("error") or status_description(EXECUTION_POLICY_BLOCKED)
        elif state.status_code:
            final_code = state.status_code
            final_msg = state.message or status_description(final_code)
        else:
            final_code = AI_REPRODUCTION_FAILED
            final_msg = status_description(AI_REPRODUCTION_FAILED)
    else:
        final_status = state.status
        final_code = state.status_code
        final_msg = state.message

    final_msg = _augment_final_message(state, final_status, final_msg)

    teardown_result = teardown_environment(state.attack_environment)
    attack_environment = deepcopy(state.attack_environment)
    attack_environment["teardown_result"] = teardown_result
    environment_spec = deepcopy(state.environment_spec)
    if environment_spec:
        environment_spec["teardown_result"] = teardown_result
        try:
            write_environment_manifest(environment_spec, _state_output_root(state) / state.cve_id)
        except Exception as exc:
            teardown_result = {
                **teardown_result,
                "manifest_error": f"环境 manifest 更新失败: {exc}",
            }
            attack_environment["teardown_result"] = teardown_result
            environment_spec["teardown_result"] = teardown_result

    cleanup_status = "skipped" if teardown_result.get("skipped") else (
        "passed" if teardown_result.get("success") else "failed"
    )
    milestones = _mark_milestone_map(
        state.milestones,
        "environment_cleanup",
        cleanup_status,
        message=teardown_result.get("error") or teardown_result.get("reason") or "environment cleanup completed",
        data={"teardown_result": teardown_result},
    )

    failure_class = classify_failure(final_code) if final_status != "SUCCESS" else FAILURE_CLASS_NONE
    # First pass tier without bundle completeness.
    success_tier = derive_success_tier(
        status_code=final_code,
        success_level=state.success_level,
        milestones=milestones,
        attempt_history=state.attempt_history,
        ips_matched=state.ips_matched,
        target_oracle_success=state.target_oracle_success,
        repro_bundle_complete=False,
        cleanup_status=cleanup_status,
    )

    # Archiving is deterministic. Analysis/report LLM calls belong to an
    # explicit analysis phase and must not run while persisting results.
    report = ""

    # 归档所有产物
    output_dir = _state_output_root(state) / state.cve_id
    output_dir.mkdir(parents=True, exist_ok=True)

    version_evidence = build_version_evidence(
        cve_id=state.cve_id,
        nvd_description=state.nvd_description or "",
        attack_environment=attack_environment,
        execution_spec=getattr(state, "execution_spec", {}) or {},
        executor_result=state.executor_result,
        oracle_result=state.oracle_result,
    )
    repro_bundle = write_repro_bundle(
        output_dir,
        cve_id=state.cve_id,
        status=final_status,
        status_code=final_code,
        message=final_msg,
        success_tier=success_tier,
        failure_class=failure_class,
        success_level=state.success_level,
        poc_source=state.poc_source,
        poc_raw_http=state.poc_raw_http,
        poc_nuclei_yaml=state.poc_nuclei_yaml,
        pcap_file_path=state.pcap_file_path,
        attack_environment=attack_environment,
        environment_spec=environment_spec,
        environment_teardown_result=teardown_result,
        oracle_result=state.oracle_result,
        executor_result=state.executor_result,
        milestones=milestones,
        attempt_history=state.attempt_history,
        execution_spec=getattr(state, "execution_spec", {}) or {},
        request_steps=(
            (_current_candidate(state) or {}).get("request_steps")
            if isinstance((_current_candidate(state) or {}).get("request_steps"), list)
            else None
        ),
        version_evidence=version_evidence,
    )
    # Promote to L4 when bundle is complete after L2/L3 evidence.
    success_tier = derive_success_tier(
        status_code=final_code,
        success_level=state.success_level,
        milestones=milestones,
        attempt_history=state.attempt_history,
        ips_matched=state.ips_matched,
        target_oracle_success=state.target_oracle_success,
        repro_bundle_complete=bool(repro_bundle.get("complete")),
        cleanup_status=cleanup_status,
    )
    repro_bundle["success_tier"] = success_tier
    report_data = {
        "cve_id": state.cve_id,
        "status": final_status,
        "status_code": final_code,
        "message": final_msg,
        "nvd_description": state.nvd_description,
        "nvd_source": state.nvd_source,
        "nvd_metadata": state.nvd_metadata,
        "local_only": state.local_only,
        "target_ip": state.target_ip,
        "cvss_score": state.cvss_score,
        "cvss_severity": state.cvss_severity,
        "vuln_type": state.vuln_type,
        "poc_source": state.poc_source,
        "poc_raw_http": state.poc_raw_http,
        "poc_candidates": [_candidate_history_view(candidate) for candidate in state.poc_candidates],
        "current_candidate_index": state.current_candidate_index,
        "attempt_history": state.attempt_history,
        "agent_trace": state.agent_trace,
        "environment_candidates": state.environment_candidates,
        "attack_environment": attack_environment,
        "environment_spec": environment_spec,
        "environment_manifest_path": state.environment_manifest_path,
        "environment_setup_result": state.environment_setup_result,
        "environment_teardown_result": teardown_result,
        "trigger_candidates": state.trigger_candidates,
        "validation_hints": state.validation_hints,
        "candidate_reviews": state.candidate_reviews,
        "milestones": milestones,
        "executor_result": state.executor_result,
        "oracle_result": state.oracle_result,
        "target_oracle_success": state.target_oracle_success,
        "target_oracle_type": state.target_oracle_type,
        "target_oracle_details": state.target_oracle_details,
        "success_level": state.success_level,
        "success_tier": success_tier,
        "failure_class": failure_class,
        "protocol": getattr(state, "protocol", "") or ("http" if state.is_http_vuln else "unsupported"),
        "execution_spec": getattr(state, "execution_spec", {}) or {},
        "version_evidence": version_evidence,
        "repro_bundle_path": repro_bundle.get("path", ""),
        "repro_bundle_complete": bool(repro_bundle.get("complete")),
        "repro_bundle": repro_bundle,
        "phases_tried": state.phases_tried,
        "ips_matched": state.ips_matched,
        "generic_ips_matched": state.generic_ips_matched,
        "ips_match_summary": state.ips_match_summary,
        "ips_match_details": state.ips_match_details,
        "cve_ips_match_details": state.cve_ips_match_details,
        "generic_ips_match_details": state.generic_ips_match_details,
        "pcap_file_path": state.pcap_file_path,
        "timestamp": datetime.now().isoformat(),
    }
    with open(output_dir / "result.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    console.print(f"  [green]✓[/] 报告与产物已保存到 {output_dir}")
    if repro_bundle.get("path"):
        console.print(
            f"  [green]✓[/] repro bundle: {repro_bundle['path']} "
            f"(tier={success_tier}, class={failure_class}, complete={repro_bundle.get('complete')})"
        )
    return {
        "analysis_report": report,
        "status": final_status,
        "status_code": final_code,
        "message": final_msg,
        "attack_environment": attack_environment,
        "environment_spec": environment_spec,
        "environment_teardown_result": teardown_result,
        "milestones": milestones,
        "success_tier": success_tier,
        "failure_class": failure_class,
        "repro_bundle_path": repro_bundle.get("path", ""),
        "repro_bundle_complete": bool(repro_bundle.get("complete")),
        "current_phase": "done",
    }


# ═══════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════


def _raw_http_candidates(
    pocs: list[str],
    *,
    source: str,
    evidence_url: str = "",
    confidence: float = 0.5,
    reason: str = "",
    validation_hint: dict | None = None,
) -> list[dict]:
    """把提取到的 Raw HTTP PoC 标准化为候选记录。"""
    candidates = []
    for poc in pocs:
        raw_http = poc.strip()
        if not raw_http:
            continue
        hint = validation_hint if isinstance(validation_hint, dict) and validation_hint else _infer_raw_http_validation_hint(raw_http)
        candidates.append({
            "kind": "raw_http",
            "source": source,
            "raw_http": raw_http,
            "nuclei_yaml": "",
            "evidence_url": evidence_url,
            "confidence": confidence,
            "reason": reason,
            "validation_hint": hint,
        })
    return candidates


def _infer_raw_http_validation_hint(raw_http: str) -> dict:
    text = raw_http.lower()
    if any(marker in text for marker in (
        "/etc/passwd",
        "etc/passwd",
        "../",
        "..%2f",
        "%2e%2e",
        "..../",          # Gradio CVE-2023-51449 style: ....//
        "boot.ini",
        "win.ini",
    )):
        return {
            "type": "response_contains",
            "markers": ["root:", "root:x:", "[boot loader]", "[extensions]", "localhost"],
            "case_sensitive": False,
        }
    # Gradio /file= route: any path access is a traversal context
    if "/file=" in text:
        return {
            "type": "response_contains",
            "markers": ["root:", "root:x:", "[boot loader]", "[extensions]", "localhost"],
            "case_sensitive": False,
        }
    return {}


def _nuclei_candidate(
    yaml_content: str,
    *,
    source: str,
    evidence_url: str = "",
    confidence: float = 0.5,
    reason: str = "",
) -> dict:
    """把 Nuclei YAML 标准化为候选记录。"""
    return {
        "kind": "nuclei_yaml",
        "source": source,
        "raw_http": "",
        "nuclei_yaml": yaml_content.strip(),
        "evidence_url": evidence_url,
        "confidence": confidence,
        "reason": reason,
    }


def _candidate_update(state: CVEState, candidates: list[dict], *, fallback_phase: str = "") -> dict:
    """追加候选并选择第一个新增候选作为当前验证对象。"""
    unique_candidates = _dedupe_new_candidates(state.poc_candidates, candidates)
    if not unique_candidates:
        updates = _milestone_update(
            state,
            "candidate_collected",
            "skipped",
            message="未收集到新的可执行候选",
            data={"incoming_count": len(candidates), "existing_count": len(state.poc_candidates)},
        )
        if fallback_phase:
            updates["current_phase"] = fallback_phase
        return updates

    max_candidates = int(getattr(cfg, "max_candidates_per_cve", 50) or 0)
    if max_candidates > 0:
        remaining = max_candidates - len(state.poc_candidates)
        if remaining <= 0:
            updates = _milestone_update(
                state,
                "candidate_collected",
                "skipped",
                message=f"候选数量已达到 MAX_CANDIDATES_PER_CVE={max_candidates}",
                data={"max_candidates": max_candidates},
            )
            if fallback_phase:
                updates["current_phase"] = fallback_phase
            return updates
        unique_candidates = unique_candidates[:remaining]

    all_candidates = state.poc_candidates + unique_candidates
    selected_index = len(state.poc_candidates)
    raw_payloads = [candidate["raw_http"] for candidate in unique_candidates if candidate.get("raw_http")]

    return {
        "poc_candidates": all_candidates,
        "poc_payloads": state.poc_payloads + raw_payloads,
        "current_phase": "verify_poc",
        **_milestone_update(
            state,
            "candidate_collected",
            "passed",
            data={
                "added_count": len(unique_candidates),
                "total_count": len(all_candidates),
                "sources": sorted({str(candidate.get("source", "")) for candidate in unique_candidates}),
            },
        ),
        **_select_candidate_update(all_candidates[selected_index], selected_index),
    }


def _dedupe_new_candidates(existing_candidates: list[dict], candidates: list[dict]) -> list[dict]:
    seen = {_candidate_key(candidate) for candidate in existing_candidates}
    unique = []
    for candidate in candidates:
        key = _candidate_key(candidate)
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _augment_final_message(state: CVEState, final_status: str, message: str) -> str:
    """Add concise workflow context to the terminal failure message."""
    if final_status == "SUCCESS":
        return message

    clauses = [message or status_description(state.status_code)]
    if not state.poc_candidates and not state.poc_raw_http and not state.poc_nuclei_yaml:
        clauses.append("未生成 PoC 候选")

    if state.error_messages:
        recent = "; ".join(state.error_messages[-2:])
        if recent and recent not in clauses[0]:
            clauses.append(f"最近错误: {recent}")

    return "；".join(clause for clause in clauses if clause)


def _execution_policy_blocked(state: CVEState) -> bool:
    if state.oracle_result.get("status_code") == EXECUTION_POLICY_BLOCKED:
        return True
    if state.executor_result.get("policy_blocked"):
        return True
    if state.attempt_history and all(item.get("outcome") == "execution_policy_blocked" for item in state.attempt_history):
        return True
    return False


def _poc_candidate_summary(state: CVEState) -> str:
    if not state.poc_candidates:
        return "无"

    summary: dict[str, dict[str, int]] = {}
    for candidate in state.poc_candidates:
        source = candidate.get("source", "unknown")
        kind = candidate.get("kind", "unknown")
        source_summary = summary.setdefault(source, {"total": 0})
        source_summary["total"] += 1
        source_summary[kind] = source_summary.get(kind, 0) + 1
    return json.dumps(summary, ensure_ascii=False)


def _poc_preview(state: CVEState) -> str:
    if state.poc_raw_http:
        return state.poc_raw_http[:2000]
    if state.poc_nuclei_yaml:
        return state.poc_nuclei_yaml[:2000]
    candidate = _current_candidate(state)
    if candidate:
        return (candidate.get("raw_http") or candidate.get("nuclei_yaml") or "")[:2000] or "无"
    return "无"


def _candidate_key(candidate: dict) -> str:
    kind = candidate.get("kind", "")
    body = candidate.get("raw_http") or candidate.get("nuclei_yaml") or ""
    if not body and isinstance(candidate.get("execution_spec"), dict):
        spec = candidate["execution_spec"]
        body = json.dumps(
            {
                "protocol": spec.get("protocol", ""),
                "engine": spec.get("engine", ""),
                "trigger_sql": spec.get("trigger_sql", []),
                "oracle": spec.get("oracle", {}),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    if not kind or not body:
        return ""
    return f"{kind}:{body.strip()}"


def _replace_current_candidate_update(state: CVEState, candidate: dict) -> dict:
    """Replace the currently selected candidate after CriticAgent enrichment."""
    if not state.poc_candidates or not (0 <= state.current_candidate_index < len(state.poc_candidates)):
        return {
            "poc_source": candidate.get("source", state.poc_source),
            "poc_raw_http": candidate.get("raw_http", state.poc_raw_http),
            "poc_nuclei_yaml": candidate.get("nuclei_yaml", state.poc_nuclei_yaml),
        }

    candidates = list(state.poc_candidates)
    candidates[state.current_candidate_index] = candidate
    return {
        "poc_candidates": candidates,
        "poc_source": candidate.get("source", state.poc_source),
        "poc_raw_http": candidate.get("raw_http", ""),
        "poc_nuclei_yaml": candidate.get("nuclei_yaml", ""),
    }


def _select_candidate_update(candidate: dict, index: int) -> dict:
    updates = {
        "current_candidate_index": index,
        "poc_source": candidate.get("source", ""),
        "poc_raw_http": candidate.get("raw_http", ""),
        "poc_nuclei_yaml": candidate.get("nuclei_yaml", ""),
    }
    if isinstance(candidate.get("execution_spec"), dict):
        updates["execution_spec"] = candidate["execution_spec"]
        protocol = str(candidate["execution_spec"].get("protocol") or "")
        if protocol:
            updates["protocol"] = protocol
    return updates


def _next_attempt_or_phase_update(state: CVEState) -> dict:
    """验证失败后优先切换到候选池里的下一个 PoC。"""
    next_index = state.current_candidate_index + 1
    if next_index < len(state.poc_candidates):
        candidate = state.poc_candidates[next_index]
        console.print(
            f"  [cyan]-> 尝试下一个 PoC 候选[/] "
            f"{next_index + 1}/{len(state.poc_candidates)} (来源: {candidate.get('source', 'unknown')})"
        )
        return {
            "current_phase": "verify_poc",
            **_select_candidate_update(candidate, next_index),
        }

    return {"current_phase": _next_phase_after_verify(state)}


def _append_attempt_history(
    state: CVEState,
    result: dict,
    ips_summary: dict,
    ips_matched: bool,
    generic_ips_matched: bool,
    outcome: str,
    *,
    oracle_result: dict | None = None,
    candidate: dict | None = None,
) -> list[dict]:
    oracle_result = oracle_result or {}
    target_oracle = oracle_result.get("target_oracle", {})
    cand = candidate or _current_candidate(state)
    if cand.get("execution_spec"):
        kind = "execution_spec"
    elif state.poc_nuclei_yaml and not state.poc_raw_http:
        kind = "nuclei_yaml"
    else:
        kind = cand.get("kind") or "raw_http"
    return state.attempt_history + [{
        "attempt": len(state.attempt_history) + 1,
        "candidate_index": state.current_candidate_index if state.poc_candidates else None,
        "source": state.poc_source,
        "kind": kind,
        "outcome": outcome,
        # 数据库等非 HTTP 执行：success 表示 oracle 命中；request_success 表示已触发执行
        "request_success": bool(result.get("request_success", result.get("success", False))),
        "http_status_code": result.get("status_code", 0),
        "ips_matched": ips_matched,
        "generic_ips_matched": generic_ips_matched,
        "target_oracle_success": bool(target_oracle.get("success", False)),
        "target_oracle_type": target_oracle.get("type", ""),
        "target_oracle": deepcopy(target_oracle),
        "success_level": oracle_result.get("success_level", ""),
        "ips_match_summary": deepcopy(ips_summary),
        "pcap_file_path": result.get("pcap_file_path", ""),
        "error": result.get("error", ""),
        "error_type": result.get("error_type", ""),
        "executor": result.get("executor", ""),
        "target_url": result.get("target_url", ""),
        "target_host": result.get("target_host", ""),
        "candidate": _candidate_history_view(candidate or _current_candidate(state)),
        "timestamp": datetime.now().isoformat(),
    }]


def _current_candidate(state: CVEState) -> dict:
    if 0 <= state.current_candidate_index < len(state.poc_candidates):
        return state.poc_candidates[state.current_candidate_index]
    return {
        "kind": "nuclei_yaml" if state.poc_nuclei_yaml and not state.poc_raw_http else "raw_http",
        "source": state.poc_source,
        "raw_http": state.poc_raw_http,
        "nuclei_yaml": state.poc_nuclei_yaml,
        "evidence_url": "",
        "confidence": 0.0,
        "reason": "legacy state",
    }


def _candidate_history_view(candidate: dict) -> dict:
    """生成适合写入 result.json 的候选摘要，避免 YAML 体积过大。"""
    view = {
        "kind": candidate.get("kind", ""),
        "source": candidate.get("source", ""),
        "trigger_id": candidate.get("trigger_id", ""),
        "attack_objective": candidate.get("attack_objective", ""),
        "validation_hint": candidate.get("validation_hint", {}),
        "preconditions": candidate.get("preconditions", []),
        "evidence_url": candidate.get("evidence_url", ""),
        "confidence": candidate.get("confidence", 0.0),
        "reason": candidate.get("reason", ""),
        "raw_http": candidate.get("raw_http", ""),
        "nuclei_yaml_preview": candidate.get("nuclei_yaml", "")[:2000],
    }
    if isinstance(candidate.get("execution_spec"), dict):
        view["execution_spec"] = candidate["execution_spec"]
    return view


def _llm_poc_candidates(
    text: str,
    *,
    source: str,
    evidence_url: str = "",
    confidence: float = 0.5,
    reason: str = "",
) -> list[dict]:
    """Parse LLM output as JSON first, then fall back to legacy Raw HTTP."""
    parsed_candidates = parse_poc_candidates_json(text)
    if parsed_candidates:
        candidates = []
        for candidate in parsed_candidates:
            raw_http = candidate.get("raw_http", "").strip()
            if not raw_http:
                continue
            candidates.append({
                "kind": "raw_http",
                "source": source,
                "raw_http": raw_http,
                "nuclei_yaml": "",
                "evidence_url": candidate.get("evidence_url") or evidence_url,
                "confidence": candidate.get("confidence", confidence),
                "reason": candidate.get("reason") or reason,
            })
        return candidates

    return _raw_http_candidates(
        _extract_http_requests(text, ""),
        source=source,
        evidence_url=evidence_url,
        confidence=confidence,
        reason=reason,
    )


def _extract_http_requests(text: str, cve_id: str) -> list[str]:
    """从 LLM 输出或网页文本中提取 HTTP 请求。"""
    return extract_http_requests(text)


def _local_container_skip_remote(state: CVEState) -> bool:
    """local-container 批测默认禁止远程搜索/外链抽取（可用配置打开）。"""
    if state.local_only:
        return True
    if not state.local_container_mode:
        return False
    return not bool(getattr(cfg, "local_container_allow_remote_search", False))


def _has_local_kb_candidates(state: CVEState) -> bool:
    local_sources = {
        "local_kb_custom",
        "local_kb_vulhub",
        "local_kb_vulhub_sql",
        "local_kb_pcap",
        "local_kb_trickest",
        "local_kb_trickest_sql",
    }
    for candidate in state.poc_candidates or []:
        source = str(candidate.get("source") or "")
        if source in local_sources or source.startswith("local_kb"):
            return True
    return False


def _next_phase_after_verify(state: CVEState) -> str:
    """验证失败后确定下一个阶段。"""
    if state.local_only and not state.allow_reference_links:
        return "generate_report"
    if state.local_only and state.allow_reference_links:
        return "reference_analysis"
    # local-container：已有本地候选则不再远程发散；无本地候选时仅允许本地 nuclei
    if _local_container_skip_remote(state):
        if _has_local_kb_candidates(state):
            console.print("  [dim]local-container：本地候选已用尽，跳过远程搜索[/]")
            return "generate_report"
        phase_order = ["local_kb_search", "nuclei_search"]
    else:
        phase_order = [
            "local_kb_search", "reference_analysis", "poc_from_refs", "nuclei_search",
            "exploitdb_search", "imfht_search", "web_search",
        ]

    tried = set(state.phases_tried)
    for phase in phase_order:
        if phase not in tried:
            return phase

    return "generate_report"


def _append_agent_event(
    trace: list[dict],
    *,
    agent: str,
    action: str,
    status: str,
    summary: str,
    data: dict | None = None,
) -> list[dict]:
    return trace + [{
        "agent": agent,
        "action": action,
        "status": status,
        "summary": summary,
        "data": data or {},
        "timestamp": datetime.now().isoformat(),
    }]


# ═══════════════════════════════════════════════════════════
# 路由函数
# ═══════════════════════════════════════════════════════════


def route_after_validate(state: CVEState) -> str:
    if state.status == "FAILURE" and state.status_code == PARAMETER_ERROR:
        return "generate_report"
    return "query_nvd"


def route_after_type_check(state: CVEState) -> str:
    if getattr(state, "stop_after", "") == "analysis":
        return "generate_report"
    if state.local_only:
        return "environment_agent"
    # HTTP 与数据库可继续；其余非 HTTP 仅保留接口，直接归档。
    if state.is_http_vuln or getattr(state, "protocol", "") == PROTOCOL_DATABASE:
        return "environment_agent"
    return "generate_report"


def route_after_environment(state: CVEState) -> str:
    """Respect local-mode environment failures instead of continuing PoC discovery."""
    if state.current_phase == "generate_report":
        return "generate_report"
    if getattr(state, "stop_after", "") == "environment":
        return "generate_report"
    return "local_kb_search"


def route_after_local_kb(state: CVEState) -> str:
    """本地 KB 搜索后路由：找到 PoC 则直接验证，否则继续常规流程。"""
    if state.current_phase == "poc_from_nvd":
        return "poc_from_nvd"
    if state.current_phase == "verify_poc":
        if state.stop_after == "poc":
            return "generate_report"
        return "verify_poc"
    if state.current_phase == "generate_report":
        return "generate_report"
    # 数据库候选即使 phase 字段异常，只要已有 execution_spec 也直接验证
    if getattr(state, "protocol", "") == PROTOCOL_DATABASE and (
        getattr(state, "execution_spec", None)
        or any(isinstance(c.get("execution_spec"), dict) for c in (state.poc_candidates or []))
    ):
        return "verify_poc"
    # local-container 且跳过远程：无候选则直接归档，不进入 reference/web_search
    if _local_container_skip_remote(state):
        if state.poc_candidates:
            return "verify_poc"
        return "generate_report"
    return "reference_analysis"


def route_after_phase(state: CVEState) -> str:
    """通用路由：根据 current_phase 决定下一个节点。"""
    phase = state.current_phase
    # PoC-only runs stop as soon as the discovery chain produced a candidate;
    # if a source had no candidate, the normal fallback search continues.
    if getattr(state, "stop_after", "") == "poc" and phase == "verify_poc":
        return "generate_report"
    phase_map = {
        "nvd_query": "query_nvd",
        "vuln_type_check": "vuln_type_check",
        "environment_agent": "environment_agent",
        "local_kb_search": "local_kb_search",
        "reference_analysis": "reference_analysis",
        "trigger_agent": "trigger_agent",
        "poc_from_refs": "poc_from_refs",
        "poc_from_nvd": "poc_from_nvd",
        "nuclei_search": "nuclei_search",
        "exploitdb_search": "exploitdb_search",
        "imfht_search": "imfht_search",
        "web_search": "web_search",
        "verify_poc": "verify_poc",
        "archive": "archive",
        "save_to_local_kb": "save_to_local_kb",
        "generate_report": "generate_report",
        "done": END,
    }
    return phase_map.get(phase, "generate_report")


# ═══════════════════════════════════════════════════════════
# 构建 Graph
# ═══════════════════════════════════════════════════════════


@lru_cache(maxsize=1)
def build_graph() -> StateGraph:
    """构建并编译 LangGraph 工作流。"""

    workflow = StateGraph(CVEState)

    # 添加节点
    workflow.add_node("validate_input", node_validate_input)
    workflow.add_node("query_nvd", node_query_nvd)
    workflow.add_node("vuln_type_check", node_vuln_type_check)
    workflow.add_node("environment_agent", node_environment_agent)
    workflow.add_node("local_kb_search", node_local_kb_search)
    workflow.add_node("poc_from_nvd", node_poc_from_nvd)
    workflow.add_conditional_edges("poc_from_nvd", route_after_phase)
    workflow.add_node("reference_analysis", node_reference_analysis)
    workflow.add_node("trigger_agent", node_trigger_agent)
    workflow.add_node("poc_from_refs", node_poc_from_refs)
    workflow.add_node("nuclei_search", node_nuclei_search)
    workflow.add_node("exploitdb_search", node_exploitdb_search)
    workflow.add_node("imfht_search", node_imfht_search)
    workflow.add_node("web_search", node_web_search)
    workflow.add_node("verify_poc", node_verify_poc)
    workflow.add_node("archive", node_archive)
    workflow.add_node("save_to_local_kb", node_save_to_local_kb)
    workflow.add_node("generate_report", node_generate_report)

    # 设置入口
    workflow.set_entry_point("validate_input")

    # 添加边
    workflow.add_conditional_edges("validate_input", route_after_validate)
    workflow.add_edge("query_nvd", "vuln_type_check")
    workflow.add_conditional_edges("vuln_type_check", route_after_type_check)
    workflow.add_conditional_edges("environment_agent", route_after_environment)
    workflow.add_conditional_edges("local_kb_search", route_after_local_kb)
    workflow.add_edge("reference_analysis", "trigger_agent")
    workflow.add_edge("trigger_agent", "poc_from_refs")

    # PoC 搜索链和验证的路由
    for node in ["poc_from_refs", "nuclei_search", "exploitdb_search",
                  "imfht_search", "web_search", "verify_poc",
                  "archive", "save_to_local_kb"]:
        workflow.add_conditional_edges(node, route_after_phase)

    workflow.add_edge("generate_report", END)

    return workflow.compile()
