"""Multi-agent role definitions and helper implementations.

Agent 职责速览：
- EnvironmentAgent：负责攻击环境规划/可选搭建。它查找显式 compose、vulhub
  compose，产出 target_url/target_host/compose_file；默认不启动 Docker，只有
  AUTO_ENV_ENABLED=true 时才执行 docker compose。它不生成 PoC、不判定成功。
- TriggerAgent：负责把 CVE 描述、漏洞类型和产品信息抽象成 trigger_logic、
  attack_objective、preconditions、variable_slots、validation_hint。它不发包。
- CriticAgent：负责审查当前 PoC 候选是否可执行，并补充 trigger_id、
  attack_objective、validation_hint、preconditions，降低缺证据/格式异常候选的
  置信度。它不搜索情报、不发包、不生成新 PoC。
- ReporterAgent：当前由 graph.py 的 node_generate_report 承担，负责归档
  agent_trace、attempt_history、oracle_result 和最终报告。

AGENT_LLM_ENABLED=true 时，EnvironmentAgent/TriggerAgent/CriticAgent 会优先
调用 .env 中配置的大模型；AGENT_LLM_MODEL 留空时复用 LLM_MODEL，例如当前
deepseek-v4-pro。LLM 调用失败时会自动退回确定性规则，保持主链路可运行。
"""

from __future__ import annotations

import atexit
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
import uuid
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
import httpx

from cve_hunter.config import cfg
from cve_hunter.llm import invoke_llm
from cve_hunter.state import CVEState


_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
_CVE_PART_PATTERN = re.compile(
    r"(?<![A-Z0-9])CVE[-_]([0-9]{4})[-_]([0-9]{4,7})(?![0-9])",
    re.IGNORECASE,
)
_TCP_TARGET_PORTS = {
    22, 25, 110, 143, 389, 445, 873, 1433, 1521, 1883, 2375, 3306,
    5432, 5672, 6379, 9042, 9300, 11211, 27017, 61616,
}
_COMPOSE_INIT_SERVICE_PATTERN = re.compile(
    r"(^|[-_])(init|initialize|migrate|migration|setup|bootstrap)([-_]|$)",
    re.IGNORECASE,
)
_compose_index_cache: dict[str, dict[str, list[Path]]] = {}
_vulfocus_image_cache: dict[tuple[str, str], list[dict[str, Any]]] = {}
# Compose projects created by this process that still need reclaim.
# project_name -> absolute compose file path.
_owned_compose_projects: dict[str, str] = {}
_atexit_reclaim_registered = False


def _register_atexit_reclaim() -> None:
    """Register process-exit reclaim once so killed batches still release containers."""
    global _atexit_reclaim_registered
    if _atexit_reclaim_registered:
        return
    atexit.register(reclaim_owned_compose_projects)
    _atexit_reclaim_registered = True


def append_agent_trace(
    state: CVEState,
    *,
    agent: str,
    action: str,
    status: str,
    summary: str,
    data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Append a compact, auditable agent event to state.agent_trace."""
    return state.agent_trace + [{
        "agent": agent,
        "action": action,
        "status": status,
        "summary": summary,
        "data": data or {},
        "timestamp": datetime.now().isoformat(),
    }]


def run_environment_agent(state: CVEState) -> dict[str, Any]:
    """Plan and optionally start a local attack environment.

    默认只规划。启用自动环境或本地容器模式后，按候选优先级尝试对应
    launcher，并在一个来源启动失败时回退到下一个来源。
    """
    local_container_mode = state.local_container_mode
    bootstrap_errors: list[str] = []
    if local_container_mode:
        bootstrap = _ensure_environment_repositories()
        bootstrap_errors = list(bootstrap.get("errors") or [])

    candidates = _discover_environment_candidates(
        state.cve_id,
        local_only=local_container_mode,
    )
    environment = _default_environment()
    environment["local_container_mode"] = local_container_mode
    status = "planned"
    summary = "使用默认目标地址，未发现可自动搭建环境"
    errors: list[str] = []

    if candidates:
        _select_environment_candidate(environment, candidates[0])
        summary = f"发现攻击环境候选: {environment.get('source', 'unknown')}"

    if (cfg.auto_env_enabled or local_container_mode) and candidates:
        selected, run_result = _start_environment_candidates(candidates)
        if selected:
            _select_environment_candidate(environment, selected)
        if run_result.get("target_url"):
            environment["target_url"] = run_result["target_url"]
            environment["target_host"] = _target_host_from_url(run_result["target_url"])
        environment["setup_result"] = run_result
        if run_result["success"]:
            status = "started"
            summary = (
                f"已通过 {environment.get('provider', environment.get('source', 'unknown'))} "
                f"启动攻击环境: {environment.get('target_url', '')}"
            )
        else:
            status = "setup_failed"
            errors.append(run_result.get("error", "攻击环境启动失败"))
            summary = errors[-1]
            if not local_container_mode:
                fallback_url = _default_target_url()
                environment["target_url"] = fallback_url
                environment["target_host"] = _target_host_from_url(fallback_url)
    elif (cfg.auto_env_enabled or local_container_mode) and not candidates:
        status = "not_found"
        detail = f"所有已接入环境源均未匹配到 {state.cve_id}，已跳过"
        if bootstrap_errors:
            detail = f"{detail}；" + "；".join(bootstrap_errors)
        errors.append(detail)
        summary = errors[-1]
        if local_container_mode:
            environment["target_url"] = ""
            environment["target_host"] = ""
    elif not cfg.auto_env_enabled:
        environment["setup_mode"] = "disabled"

    llm_plan = {}
    llm_error = ""
    if getattr(cfg, "agent_llm_enabled", False) and not (local_container_mode and not candidates):
        try:
            llm_plan = _run_environment_agent_llm(state, candidates, environment)
            environment["llm_plan"] = llm_plan
            if status == "planned":
                status = "llm_planned"
            summary = f"{summary}；LLM 环境建议已生成"
        except Exception as exc:
            llm_error = str(exc)
            environment["llm_error"] = llm_error

    return {
        "environment_candidates": candidates,
        "attack_environment": environment,
        "errors": errors,
        "trace": {
            "agent": "EnvironmentAgent",
            "action": "plan_attack_environment",
            "status": status,
            "summary": summary,
            "data": {
                "auto_env_enabled": cfg.auto_env_enabled,
                "local_container_mode": local_container_mode,
                "candidate_count": len(candidates),
                "target_url": environment.get("target_url", ""),
                "llm_enabled": getattr(cfg, "agent_llm_enabled", False),
                "llm_model": _agent_llm_model() if getattr(cfg, "agent_llm_enabled", False) else "",
                "llm_plan": llm_plan,
                "llm_error": llm_error,
            },
        },
    }


def run_trigger_agent(state: CVEState) -> dict[str, Any]:
    """Extract a coarse trigger model and default validation hint."""
    llm_error = ""
    if getattr(cfg, "agent_llm_enabled", False):
        try:
            return _run_trigger_agent_llm(state)
        except Exception as exc:
            llm_error = str(exc)

    text = " ".join([
        state.cve_id,
        state.nvd_description,
        state.vuln_type,
        " ".join(state.affected_products[:5]),
    ]).lower()
    objective = _infer_attack_objective(text)
    validation_hint = _default_validation_hint(objective)
    trigger = {
        "trigger_id": f"{state.cve_id.lower()}-trigger-1",
        "cve_id": state.cve_id,
        "vuln_type": state.vuln_type or "未知",
        "attack_objective": objective,
        "trigger_logic": _trigger_logic_summary(objective),
        "preconditions": _infer_preconditions(text),
        "variable_slots": _variable_slots_for_objective(objective),
        "validation_hint": validation_hint,
        "evidence_urls": state.nvd_references[:5],
        "confidence": 0.45 if objective == "traffic_detection" else 0.6,
        "reason": "基于 CVE 描述、漏洞类型和受影响产品的轻量触发逻辑抽象",
    }
    return {
        "trigger_candidates": [trigger],
        "validation_hints": [validation_hint],
        "trace": {
            "agent": "TriggerAgent",
            "action": "extract_trigger_logic",
            "status": "rule_fallback_after_llm_error" if llm_error else "completed",
            "summary": f"推断攻击目标: {objective}",
            "data": {
                "attack_objective": objective,
                "validation_hint": validation_hint,
                "llm_enabled": getattr(cfg, "agent_llm_enabled", False),
                "llm_model": _agent_llm_model() if getattr(cfg, "agent_llm_enabled", False) else "",
                "llm_error": llm_error,
            },
        },
    }


def run_critic_agent(state: CVEState, candidate: dict[str, Any]) -> dict[str, Any]:
    """Review and enrich the current PoC candidate before execution."""
    enriched = deepcopy(candidate)
    flags: list[str] = []
    score_delta = 0.0

    trigger = state.trigger_candidates[0] if state.trigger_candidates else {}
    if trigger:
        enriched.setdefault("trigger_id", trigger.get("trigger_id", ""))
        enriched.setdefault("attack_objective", trigger.get("attack_objective", "traffic_detection"))
        enriched.setdefault("preconditions", trigger.get("preconditions", []))
        enriched.setdefault("validation_hint", trigger.get("validation_hint", {}))

    raw_http = enriched.get("raw_http", "")
    nuclei_yaml = enriched.get("nuclei_yaml", "")
    execution_spec = enriched.get("execution_spec") if isinstance(enriched.get("execution_spec"), dict) else {}
    if raw_http:
        if "{{TARGET_HOST}}" not in raw_http and "Host:" not in raw_http:
            flags.append("raw_http_missing_host")
            score_delta -= 0.1
        if not re.match(r"(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/", raw_http.strip()):
            flags.append("raw_http_request_line_unusual")
            score_delta -= 0.15
    elif nuclei_yaml:
        enriched.setdefault("validation_hint", {"type": "nuclei_match"})
    elif execution_spec.get("protocol") == "database" and (
        execution_spec.get("trigger_sql") or execution_spec.get("schema_sql") or execution_spec.get("setup_sql")
    ):
        enriched.setdefault("validation_hint", execution_spec.get("oracle") or {"type": "error_pattern"})
        if not enriched.get("attack_objective"):
            enriched["attack_objective"] = "database_exploit"
    elif execution_spec.get("protocol"):
        # 非 HTTP 接口候选：有协议但未必可执行
        if not (execution_spec.get("trigger_sql") or execution_spec.get("raw_http")):
            flags.append("candidate_has_no_executable_payload")
            score_delta -= 0.3
    else:
        flags.append("candidate_has_no_executable_payload")
        score_delta -= 0.3

    if not enriched.get("evidence_url") and enriched.get("source") in {"reference", "search"}:
        flags.append("evidence_url_missing")
        score_delta -= 0.1

    confidence = _coerce_float(enriched.get("confidence"), 0.5)
    enriched["confidence"] = max(0.0, min(1.0, confidence + score_delta))
    review = {
        "candidate_index": state.current_candidate_index if state.poc_candidates else None,
        "source": enriched.get("source", ""),
        "accepted": "candidate_has_no_executable_payload" not in flags,
        "flags": flags,
        "confidence_before": confidence,
        "confidence_after": enriched["confidence"],
        "attack_objective": enriched.get("attack_objective", ""),
        "validation_hint": enriched.get("validation_hint", {}),
        "timestamp": datetime.now().isoformat(),
    }
    llm_error = ""
    if getattr(cfg, "agent_llm_enabled", False):
        try:
            llm_review = _run_critic_agent_llm(state, enriched, review)
            enriched, review = _merge_llm_critic_review(enriched, review, llm_review)
        except Exception as exc:
            llm_error = str(exc)
            review["llm_error"] = llm_error

    return {
        "candidate": enriched,
        "review": review,
        "trace": {
            "agent": "CriticAgent",
            "action": "review_candidate",
            "status": _critic_trace_status(review, llm_error),
            "summary": f"候选审查完成，flags={len(flags)}",
            "data": review,
        },
    }


def _run_environment_agent_llm(
    state: CVEState,
    candidates: list[dict[str, Any]],
    environment: dict[str, Any],
) -> dict[str, Any]:
    prompt = f"""\
你是 CVE 自动复现系统的 EnvironmentAgent。请基于当前 CVE 信息和已发现的本地环境候选，
判断后续攻击环境搭建策略。不要输出 Markdown，只输出 JSON。

## CVE
- 编号: {state.cve_id}
- 描述: {state.nvd_description or "无"}
- 漏洞类型: {state.vuln_type or "未知"}
- 受影响产品: {", ".join(state.affected_products[:8]) or "无"}
- References: {json.dumps(state.nvd_references[:8], ensure_ascii=False)}

## 已发现环境候选
{json.dumps(candidates, ensure_ascii=False, indent=2)}

## 当前环境
{json.dumps(environment, ensure_ascii=False, indent=2)}

请输出：
{{
  "recommended_strategy": "use_existing_target|use_local_vulhub|search_github_poc|search_docker_image|manual_required",
  "target_url_guess": "如果可推断则填写，否则空字符串",
  "search_queries": ["后续可用于搜索环境/镜像/PoC仓库的查询"],
  "docker_hints": ["可能的镜像、compose、vulhub路径或启动注意事项"],
  "preconditions": ["需要认证、插件、版本、初始化数据等前置条件"],
  "risk": "low|medium|high",
  "reason": "简要说明"
}}
"""
    return _load_json_object(_invoke_agent_llm(prompt))


def _run_trigger_agent_llm(state: CVEState) -> dict[str, Any]:
    prompt = f"""\
你是 CVE 自动复现系统的 TriggerAgent。请从漏洞描述、产品和引用信息中抽象漏洞触发逻辑。
不要输出 Markdown，只输出 JSON。证据不足时降低 confidence，不能编造路径或产品。

## CVE
- 编号: {state.cve_id}
- 描述: {state.nvd_description or "无"}
- 漏洞类型: {state.vuln_type or "未知"}
- CVSS: {state.cvss_score} {state.cvss_severity}
- 受影响产品: {", ".join(state.affected_products[:8]) or "无"}
- References: {json.dumps(state.nvd_references[:8], ensure_ascii=False)}
- 已提取 reference 摘要: {json.dumps(state.reference_contents[:4], ensure_ascii=False)[:6000]}

请输出：
{{
  "trigger": {{
    "attack_objective": "command_execution|file_read|database_access|outbound_callback|browser_script_execution|state_change|auth_bypass|denial_of_service|traffic_detection",
    "trigger_logic": "漏洞如何被触发的抽象说明",
    "preconditions": ["认证、CSRF、插件启用、版本路径等前置条件"],
    "variable_slots": ["base_url", "path", "method", "headers", "payload"],
    "validation_hint": {{
      "type": "ips|response_contains|callback|timing|nuclei_match|tool_suggested|auth_state",
      "markers": [],
      "tool": "",
      "callback_url": ""
    }},
    "confidence": 0.0,
    "reason": "依据哪些信息做出判断"
  }}
}}
"""
    data = _load_json_object(_invoke_agent_llm(prompt))
    raw_trigger = data.get("trigger") or _first_dict(data.get("trigger_candidates")) or data
    text = " ".join([state.cve_id, state.nvd_description, state.vuln_type]).lower()
    objective = str(raw_trigger.get("attack_objective") or _infer_attack_objective(text))
    validation_hint = raw_trigger.get("validation_hint")
    if not isinstance(validation_hint, dict) or not validation_hint.get("type"):
        validation_hint = _default_validation_hint(objective)
    trigger = {
        "trigger_id": f"{state.cve_id.lower()}-trigger-1",
        "cve_id": state.cve_id,
        "vuln_type": state.vuln_type or "未知",
        "attack_objective": objective,
        "trigger_logic": str(raw_trigger.get("trigger_logic") or _trigger_logic_summary(objective)),
        "preconditions": _string_list(raw_trigger.get("preconditions")),
        "variable_slots": _string_list(raw_trigger.get("variable_slots")) or _variable_slots_for_objective(objective),
        "validation_hint": validation_hint,
        "evidence_urls": state.nvd_references[:5],
        "confidence": _coerce_float(raw_trigger.get("confidence"), 0.6),
        "reason": str(raw_trigger.get("reason") or "LLM 抽象触发逻辑"),
    }
    return {
        "trigger_candidates": [trigger],
        "validation_hints": [validation_hint],
        "trace": {
            "agent": "TriggerAgent",
            "action": "extract_trigger_logic",
            "status": "llm_completed",
            "summary": f"LLM 推断攻击目标: {objective}",
            "data": {
                "attack_objective": objective,
                "validation_hint": validation_hint,
                "llm_enabled": True,
                "llm_model": _agent_llm_model(),
            },
        },
    }


def _run_critic_agent_llm(
    state: CVEState,
    candidate: dict[str, Any],
    rule_review: dict[str, Any],
) -> dict[str, Any]:
    current_trigger = state.trigger_candidates[0] if state.trigger_candidates else {}
    prompt = f"""\
你是 CVE 自动复现系统的 CriticAgent。请审查当前 PoC 候选是否与 CVE、触发逻辑和证据一致。
不要输出 Markdown，只输出 JSON。你不能生成新 PoC，只能审查、补充 validation_hint 和调整置信度。

## CVE
- 编号: {state.cve_id}
- 描述: {state.nvd_description or "无"}
- 漏洞类型: {state.vuln_type or "未知"}
- 受影响产品: {", ".join(state.affected_products[:8]) or "无"}

## Trigger
{json.dumps(current_trigger, ensure_ascii=False, indent=2)}

## Candidate
{json.dumps(_compact_candidate(candidate), ensure_ascii=False, indent=2)}

## 规则审查结果
{json.dumps(rule_review, ensure_ascii=False, indent=2)}

请输出：
{{
  "accepted": true,
  "flags": ["evidence_url_missing|product_mismatch|path_hallucination|precondition_missing|raw_http_format_issue|low_confidence"],
  "confidence_after": 0.0,
  "attack_objective": "沿用或修正后的攻击目标",
  "validation_hint": {{"type": "ips"}},
  "preconditions": ["需要补充的前置条件"],
  "reason": "简要审查理由"
}}
"""
    return _load_json_object(_invoke_agent_llm(prompt))


def _merge_llm_critic_review(
    candidate: dict[str, Any],
    review: dict[str, Any],
    llm_review: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    enriched = deepcopy(candidate)
    merged_review = deepcopy(review)
    llm_flags = _string_list(llm_review.get("flags"))
    merged_flags = list(dict.fromkeys([*merged_review.get("flags", []), *llm_flags]))
    merged_review["flags"] = merged_flags
    if "accepted" in llm_review:
        merged_review["accepted"] = bool(llm_review.get("accepted"))
    if llm_review.get("attack_objective"):
        enriched["attack_objective"] = str(llm_review["attack_objective"])
        merged_review["attack_objective"] = enriched["attack_objective"]
    if isinstance(llm_review.get("validation_hint"), dict) and llm_review["validation_hint"].get("type"):
        enriched["validation_hint"] = llm_review["validation_hint"]
        merged_review["validation_hint"] = enriched["validation_hint"]
    if llm_review.get("preconditions") is not None:
        preconditions = _string_list(llm_review.get("preconditions"))
        if preconditions:
            enriched["preconditions"] = preconditions
    confidence = _coerce_float(llm_review.get("confidence_after"), _coerce_float(enriched.get("confidence"), 0.5))
    enriched["confidence"] = max(0.0, min(1.0, confidence))
    merged_review["confidence_after"] = enriched["confidence"]
    merged_review["llm_review"] = llm_review
    merged_review["llm_model"] = _agent_llm_model()
    return enriched, merged_review


def _discover_environment_candidates(
    cve_id: str,
    *,
    local_only: bool = False,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    explicit = Path(cfg.attack_env_compose_file).expanduser() if cfg.attack_env_compose_file else None
    if explicit and explicit.is_file():
        candidates.append(_compose_candidate(
            explicit,
            source="explicit_compose",
            provider="explicit",
            fidelity="user_supplied",
            priority=0,
            reason="ATTACK_ENV_COMPOSE_FILE 指定",
            local_only=local_only,
        ))

    for spec in _configured_compose_roots():
        root = Path(spec["path"]).expanduser()
        for compose_file in _compose_files_for_cve(root, cve_id):
            candidates.append(_compose_candidate(
                compose_file,
                source=spec["source"],
                provider=spec["provider"],
                fidelity=spec["fidelity"],
                priority=spec["priority"],
                reason=spec["reason"],
                local_only=local_only,
            ))

    candidates.extend(_discover_vulfocus_candidates(cve_id))
    candidates.extend(_discover_metarget_candidates(cve_id))
    return sorted(_dedupe_candidates(candidates), key=_environment_candidate_sort_key)


def _configured_compose_roots() -> list[dict[str, Any]]:
    specs = [
        {
            "path": getattr(cfg, "vulhub_dir", "third_party/vulhub"),
            "source": "vulhub_local",
            "provider": "vulhub",
            "fidelity": "real_product",
            "priority": 10,
            "reason": "本地 Vulhub 命中",
        },
        {
            "path": getattr(cfg, "reapoc_dir", ""),
            "source": "reapoc_local",
            "provider": "reapoc",
            "fidelity": "real_product",
            "priority": 20,
            "reason": "本地 Reapoc 命中",
        },
        {
            "path": getattr(cfg, "vulnerability_poc_dir", ""),
            "source": "vulnerability_poc_local",
            "provider": "vulnerability_poc",
            "fidelity": "trigger_simulation",
            "priority": 30,
            "reason": "本地 vulnerability-poc 模拟环境命中",
        },
    ]
    return [spec for spec in specs if str(spec["path"] or "").strip()]


def _compose_files_for_cve(root: Path, cve_id: str) -> list[Path]:
    if not root.is_dir():
        return []
    return _compose_index_for_root(root).get(_normalize_cve_id(cve_id), [])


def _compose_index_for_root(root: Path) -> dict[str, list[Path]]:
    key = str(root.resolve())
    cached = _compose_index_cache.get(key)
    if cached is not None:
        return cached

    index: dict[str, list[Path]] = {}
    try:
        paths = root.rglob("*")
        for path in paths:
            if not path.is_file() or path.name.lower() not in _COMPOSE_NAMES:
                continue
            relative_parts = path.relative_to(root).parts[:-1]
            cve_id = next(
                (
                    _normalize_cve_id(part)
                    for part in reversed(relative_parts)
                    if _CVE_PART_PATTERN.search(part)
                ),
                "",
            )
            if cve_id:
                index.setdefault(cve_id, []).append(path.resolve())
    except OSError:
        index = {}

    _compose_index_cache[key] = {
        cve_id: sorted(set(paths), key=lambda item: (len(item.parts), str(item).lower()))
        for cve_id, paths in index.items()
    }
    return _compose_index_cache[key]


def _is_cve_id(value: str) -> bool:
    return _CVE_PART_PATTERN.fullmatch(value.strip()) is not None


def _normalize_cve_id(value: str) -> str:
    match = _CVE_PART_PATTERN.search(value.strip())
    if not match:
        return value.strip().upper().replace("_", "-")
    return f"CVE-{match.group(1)}-{match.group(2)}"


def _environment_candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, str, str]:
    return (
        int(candidate.get("priority", 100)),
        str(candidate.get("provider", "")),
        str(candidate.get("compose_file") or candidate.get("image_name") or candidate.get("scenario_name") or ""),
    )


def _ensure_environment_repositories() -> dict[str, Any]:
    if not getattr(cfg, "environment_repo_auto_clone", True):
        return {"success": True, "results": [], "errors": []}

    results = [_ensure_vulhub_repository()]
    for name, path, url in (
        ("Reapoc", getattr(cfg, "reapoc_dir", ""), "https://github.com/cckuailong/reapoc.git"),
        (
            "vulnerability-poc",
            getattr(cfg, "vulnerability_poc_dir", ""),
            "https://github.com/fankh/vulnerability-poc.git",
        ),
        ("Metarget", getattr(cfg, "metarget_dir", ""), "https://github.com/Metarget/metarget.git"),
    ):
        if path:
            results.append(_ensure_git_repository(name, Path(path).expanduser(), url))
    errors = [str(item.get("error")) for item in results if not item.get("success") and item.get("error")]
    return {"success": not errors, "results": results, "errors": errors}


def _ensure_vulhub_repository() -> dict[str, Any]:
    """Download Vulhub once when local mode needs it and it is not present."""
    return _ensure_git_repository(
        "Vulhub",
        Path(cfg.vulhub_dir).expanduser(),
        "https://github.com/vulhub/vulhub.git",
    )


def _ensure_git_repository(name: str, root: Path, url: str) -> dict[str, Any]:
    if root.is_dir():
        return {"success": True, "downloaded": False, "path": str(root), "provider": name}

    git = shutil.which("git")
    if not git:
        return {"success": False, "error": "未找到 git，无法自动下载 Vulhub"}

    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [git, "-c", "http.version=HTTP/1.1", "clone", "--depth", "1", url, str(root)],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except Exception as exc:
        return {"success": False, "error": f"{name} 自动下载失败: {exc}", "provider": name}
    if proc.returncode != 0:
        error = proc.stderr.strip() or proc.stdout.strip() or f"git clone 返回 {proc.returncode}"
        return {"success": False, "error": f"{name} 自动下载失败: {error}", "provider": name}
    _compose_index_cache.pop(str(root.resolve()), None)
    return {"success": True, "downloaded": True, "path": str(root), "provider": name}


def _compose_candidate(
    path: Path,
    *,
    source: str,
    reason: str,
    provider: str = "compose",
    fidelity: str = "unknown",
    priority: int = 100,
    local_only: bool = False,
) -> dict[str, Any]:
    path = path.resolve()
    # compose 自动推断的地址优先（本地 Docker）；ATTACK_ENV_TARGET_URL 仅作回退
    target_url = _guess_target_url_from_compose(path) or cfg.attack_env_target_url
    target_url = target_url or _default_target_url()
    if local_only and not _is_local_target_url(target_url):
        target_url = ""
    return {
        "source": source,
        "provider": provider,
        "launcher": "docker_compose",
        "fidelity": fidelity,
        "priority": priority,
        "kind": "docker_compose",
        "compose_file": str(path),
        "workdir": str(path.parent),
        "target_url": target_url,
        "target_host": _target_host_from_url(target_url) if target_url else "",
        "reason": reason,
    }


def _discover_vulfocus_candidates(cve_id: str) -> list[dict[str, Any]]:
    api_url = str(getattr(cfg, "vulfocus_api_url", "") or "").strip()
    username = str(getattr(cfg, "vulfocus_username", "") or "").strip()
    licence = str(getattr(cfg, "vulfocus_licence", "") or "").strip()
    if not (api_url and username and licence):
        return []

    normalized = _normalize_cve_id(cve_id)
    candidates = []
    for image in _load_vulfocus_images(api_url, username, licence):
        text = " ".join(str(image.get(key) or "") for key in ("image_name", "image_vul_name", "image_desc"))
        if normalized not in {_normalize_cve_id(match.group(0)) for match in _CVE_PART_PATTERN.finditer(text)}:
            continue
        image_name = str(image.get("image_name") or "").strip()
        if not image_name:
            continue
        candidates.append({
            "source": "vulfocus_api",
            "provider": "vulfocus",
            "launcher": "vulfocus_api",
            "fidelity": "published_image",
            "priority": 15,
            "kind": "vulfocus_image",
            "image_name": image_name,
            "target_url": "",
            "target_host": "",
            "workdir": "",
            "reason": f"Vulfocus 镜像命中: {image_name}",
        })
    return candidates


def _load_vulfocus_images(api_url: str, username: str, licence: str) -> list[dict[str, Any]]:
    key = (api_url.rstrip("/"), username)
    if key in _vulfocus_image_cache:
        return _vulfocus_image_cache[key]

    endpoint = f"{api_url.rstrip('/')}/api/imgs/operation"
    try:
        with httpx.Client(
            timeout=getattr(cfg, "request_timeout", 30),
            proxy=getattr(cfg, "httpx_proxy", None),
        ) as client:
            response = client.get(endpoint, params={"username": username, "licence": licence})
            response.raise_for_status()
            payload = response.json()
        images = payload.get("data") if str(payload.get("status")) == "200" else []
        result = [item for item in images or [] if isinstance(item, dict)]
    except Exception:
        result = []
    _vulfocus_image_cache[key] = result
    return result


def _discover_metarget_candidates(cve_id: str) -> list[dict[str, Any]]:
    root_value = str(getattr(cfg, "metarget_dir", "") or "").strip()
    if not root_value:
        return []
    root = Path(root_value).expanduser()
    if not root.is_dir():
        return []

    normalized = _normalize_cve_id(cve_id)
    slug = normalized.lower()
    candidates = []
    for manifest in sorted(root.glob(f"vulns_cn/**/{slug}.yaml")):
        candidates.append(_metarget_candidate(root, manifest, normalized, "metarget_cnv", slug, 50))

    for manifest in sorted(root.glob("vulns_app/**/desc.yaml")):
        if normalized not in {_normalize_cve_id(part) for part in manifest.parts if _is_cve_id(part)}:
            continue
        try:
            data = yaml.safe_load(manifest.read_text(encoding="utf-8", errors="ignore")) or {}
        except Exception:
            data = {}
        scenario_name = str(data.get("name") or slug)
        candidates.append(_metarget_candidate(
            root,
            manifest,
            normalized,
            "metarget_appv",
            scenario_name,
            45,
        ))
    return candidates


def _metarget_candidate(
    root: Path,
    manifest: Path,
    cve_id: str,
    launcher: str,
    scenario_name: str,
    priority: int,
) -> dict[str, Any]:
    target_url = str(getattr(cfg, "metarget_target_url", "") or "").strip()
    return {
        "source": "metarget_local",
        "provider": "metarget",
        "launcher": launcher,
        "fidelity": "infrastructure" if launcher == "metarget_cnv" else "real_product",
        "priority": priority,
        "kind": "metarget_scenario",
        "scenario_name": scenario_name,
        "manifest_file": str(manifest.resolve()),
        "workdir": str(root.resolve()),
        "target_url": target_url,
        "target_host": _target_host_from_url(target_url) if target_url else "",
        "reason": f"Metarget {launcher.removeprefix('metarget_')} 场景命中 {cve_id}",
    }


def _select_environment_candidate(environment: dict[str, Any], candidate: dict[str, Any]) -> None:
    environment.update(candidate)
    target_url = str(environment.get("target_url") or "")
    environment["target_host"] = _target_host_from_url(target_url) if target_url else ""
    environment["setup_mode"] = str(candidate.get("launcher") or "not_required")


def _start_environment_candidates(
    candidates: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    attempts = []
    last_owned_result: dict[str, Any] | None = None
    last_owned_candidate: dict[str, Any] | None = None
    for candidate in candidates:
        result = _start_environment_candidate(candidate)
        attempt = {
            "provider": candidate.get("provider", ""),
            "source": candidate.get("source", ""),
            "launcher": candidate.get("launcher", ""),
            "success": bool(result.get("success")),
            "error": str(result.get("error") or ""),
            "project_name": result.get("project_name", ""),
            "started_by_orchestrator": bool(result.get("started_by_orchestrator")),
            "cleanup_result": result.get("cleanup_result"),
        }
        attempts.append(attempt)
        if result.get("success"):
            return candidate, {**result, "attempts": attempts}
        # Preserve ownership metadata from residual failed starts so final
        # teardown can reclaim containers when intermediate cleanup failed.
        if result.get("started_by_orchestrator"):
            last_owned_result = result
            last_owned_candidate = candidate

    errors = [attempt["error"] for attempt in attempts if attempt["error"]]
    failure: dict[str, Any] = {
        "success": False,
        "error": "；".join(dict.fromkeys(errors)) or "所有环境候选启动失败",
        "attempts": attempts,
    }
    if last_owned_result:
        failure["started_by_orchestrator"] = True
        failure["project_name"] = last_owned_result.get("project_name", "")
        if last_owned_result.get("cleanup_result") is not None:
            failure["cleanup_result"] = last_owned_result.get("cleanup_result")
        if last_owned_result.get("commands") is not None:
            failure["commands"] = last_owned_result.get("commands")
        if last_owned_result.get("healthcheck") is not None:
            failure["healthcheck"] = last_owned_result.get("healthcheck")
        if last_owned_result.get("initialization") is not None:
            failure["initialization"] = last_owned_result.get("initialization")
    return (last_owned_candidate or (candidates[0] if candidates else None)), failure


def _start_environment_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    launcher = str(candidate.get("launcher") or "docker_compose")
    if launcher == "docker_compose":
        return _start_compose_environment(candidate)
    if launcher in {"metarget_cnv", "metarget_appv"}:
        return _start_metarget_environment(candidate)
    if launcher == "vulfocus_api":
        return _start_vulfocus_environment(candidate)
    return {"success": False, "error": f"不支持的环境启动器: {launcher}"}


def _start_metarget_environment(candidate: dict[str, Any]) -> dict[str, Any]:
    if not getattr(cfg, "metarget_execution_enabled", False):
        return {"success": False, "error": "Metarget 执行未授权，请设置 METARGET_EXECUTION_ENABLED=true"}
    if platform.system() != "Linux":
        return {"success": False, "error": "Metarget 只能在专用 Linux/Ubuntu 靶机上执行"}
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return {"success": False, "error": "Metarget 需要 root 权限"}

    root = Path(str(candidate.get("workdir") or ""))
    executable = root / "metarget"
    if not executable.is_file():
        return {"success": False, "error": f"Metarget 启动器不存在: {executable}"}

    scenario_name = str(candidate.get("scenario_name") or "")
    if candidate.get("launcher") == "metarget_appv":
        command = [str(executable), "appv", "install", scenario_name, "--external", "--verbose"]
    else:
        command = [str(executable), "cnv", "install", scenario_name, "--verbose"]
    result = _run_environment_command(command, cwd=root, timeout=3600)
    if result["returncode"] != 0:
        return {"success": False, "error": result["stderr"] or result["stdout"], "commands": [result]}
    return {
        "success": True,
        "started_by_orchestrator": True,
        "commands": [result],
        "target_url": str(candidate.get("target_url") or ""),
    }


def _start_vulfocus_environment(candidate: dict[str, Any]) -> dict[str, Any]:
    api_url = str(getattr(cfg, "vulfocus_api_url", "") or "").strip()
    username = str(getattr(cfg, "vulfocus_username", "") or "").strip()
    licence = str(getattr(cfg, "vulfocus_licence", "") or "").strip()
    if not (api_url and username and licence):
        return {"success": False, "error": "Vulfocus API 地址或认证信息未配置"}

    endpoint = f"{api_url.rstrip('/')}/api/imgs/operation"
    try:
        with httpx.Client(
            timeout=max(getattr(cfg, "request_timeout", 30), 30),
            proxy=getattr(cfg, "httpx_proxy", None),
        ) as client:
            response = client.post(endpoint, data={
                "username": username,
                "licence": licence,
                "image_name": candidate.get("image_name", ""),
                "requisition": "start",
            })
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        return {"success": False, "error": f"Vulfocus API 调用失败: {exc}"}
    if str(payload.get("status")) != "200" or not isinstance(payload.get("data"), dict):
        return {"success": False, "error": f"Vulfocus 启动失败: {payload.get('msg', '未知错误')}"}

    target_url = _target_url_from_vulfocus(payload["data"], api_url)
    if not target_url:
        return {"success": False, "error": "Vulfocus 已启动镜像，但响应中没有可用端口"}
    return {
        "success": True,
        "started_by_orchestrator": True,
        "target_url": target_url,
        "api_response": payload,
    }


def _target_url_from_vulfocus(data: dict[str, Any], api_url: str) -> str:
    try:
        ports = json.loads(data.get("port") or "{}")
    except (TypeError, ValueError):
        ports = {}
    if not isinstance(ports, dict) or not ports:
        return ""

    ranked = []
    for order, (container_port, published_port) in enumerate(ports.items()):
        port_spec = f"{published_port}:{container_port}"
        ranked.append((_compose_port_score("web", port_spec), order, str(container_port), str(published_port)))
    _, _, container_port, published_port = sorted(ranked)[0]
    host = urlparse(api_url if "://" in api_url else f"http://{api_url}").hostname or "127.0.0.1"
    scheme = "https" if container_port in {"443", "8443", "9443"} else "http"
    return f"{scheme}://{host}:{published_port}"


def _run_environment_command(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    output_limit: int | None = 2000,
) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if output_limit is not None:
            stdout = stdout[-output_limit:]
            stderr = stderr[-output_limit:]
        return {
            "cmd": command,
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }
    except Exception as exc:
        return {"cmd": command, "returncode": -1, "stdout": "", "stderr": str(exc)}


def _ensure_docker_running(timeout: int = 300) -> tuple[bool, str]:
    """确保 Docker 守护进程在运行。Windows 上自动启动 Docker Desktop。

    Returns:
        (ok, message) — ok=True 表示 docker daemon 已就绪。
    """
    if _docker_daemon_alive():
        return True, "Docker 守护进程已在运行"

    system = platform.system()
    if system != "Windows":
        return False, "Docker 守护进程未运行，请手动启动 Docker"

    # Windows: 尝试启动 Docker Desktop
    docker_exe = _find_docker_desktop_executable()

    if not docker_exe:
        return False, "未找到 Docker Desktop 安装路径，请手动启动 Docker"

    try:
        subprocess.Popen(
            [str(docker_exe)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        return False, f"启动 Docker Desktop 失败: {exc}"

    # 轮询等待 docker daemon 就绪
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _docker_daemon_alive():
            return True, "Docker Desktop 已自动启动并就绪"
        time.sleep(5)

    return False, f"Docker Desktop 已启动但在 {timeout}s 内未就绪"


def _find_docker_desktop_executable() -> Path | None:
    """查找默认目录或 docker CLI 所属安装目录中的 Docker Desktop。"""
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Docker" / "Docker Desktop.exe",
    ]
    docker_cli = shutil.which("docker")
    if docker_cli:
        cli_path = Path(docker_cli).resolve()
        candidates.extend(parent / "Docker Desktop.exe" for parent in cli_path.parents)

    return next((path for path in candidates if path.is_file()), None)


def _docker_daemon_alive() -> bool:
    """通过执行 docker info 检查 docker daemon 是否可用。"""
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        result = subprocess.run(
            [docker, "info"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False


def _start_compose_environment(candidate: dict[str, Any]) -> dict[str, Any]:
    compose_file = candidate.get("compose_file", "")
    if not compose_file:
        return {"success": False, "error": "环境候选缺少 compose_file"}

    # 确保 Docker 守护进程运行
    docker_ok, docker_msg = _ensure_docker_running()
    if not docker_ok:
        return {"success": False, "error": docker_msg}

    command = _docker_compose_command()
    if not command:
        return {"success": False, "error": "未找到 docker compose 或 docker-compose 命令"}

    compose_path = Path(compose_file)
    if not compose_path.is_file():
        return {"success": False, "error": f"compose 文件不存在: {compose_file}"}

    # 宿主机端口被占用时写临时 compose，改映到空闲端口（如本机 mysqld 占用 3306）
    compose_path, port_remap, remapped_target_url = _compose_with_free_host_ports(compose_path)
    if remapped_target_url:
        candidate = dict(candidate)
        candidate["target_url"] = remapped_target_url
        candidate["target_host"] = _target_host_from_url(remapped_target_url)
        candidate["port_remap"] = port_remap

    # Windows 检出的 init.sh 可能是 CRLF，entrypoint 会直接失败
    _normalize_compose_shell_scripts(compose_path.parent)

    project_name = str(candidate.get("compose_project_name") or _new_compose_project_name(compose_path))
    compose_args = [*command, "-p", project_name, "-f", str(compose_path)]

    ownership_check = _run_environment_command(
        [*compose_args, "ps", "--all", "-q"],
        cwd=compose_path.parent,
        timeout=60,
    )
    if ownership_check["returncode"] != 0:
        return {
            "success": False,
            "error": ownership_check["stderr"] or ownership_check["stdout"],
            "project_name": project_name,
            "commands": [ownership_check],
        }
    if ownership_check["stdout"].strip():
        return {
            "success": False,
            "error": f"独立 Compose 项目已存在容器，拒绝接管: {project_name}",
            "project_name": project_name,
            "preexisting_environment": True,
            "commands": [ownership_check],
        }

    outputs = [ownership_check]
    owned = False

    def _failed_result(
        error: str,
        *,
        initialization: dict[str, Any] | None = None,
        healthcheck: dict[str, Any] | None = None,
        cleanup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "success": False,
            "error": error,
            "project_name": project_name,
            "commands": outputs,
            # Keep ownership when containers may still exist so final report
            # teardown / reclaim_owned_compose_projects() can force release.
            "started_by_orchestrator": owned and not bool((cleanup or {}).get("success")),
            "preexisting_environment": False,
        }
        if initialization is not None:
            payload["initialization"] = initialization
        if healthcheck is not None:
            payload["healthcheck"] = healthcheck
        if cleanup is not None:
            payload["cleanup_result"] = cleanup
        return payload

    # 已缓存镜像不访问 registry；缺失镜像仍尝试拉取，失败不阻断后续诊断。
    pull_result = _run_environment_command(
        [*compose_args, "pull", "--policy", "missing"],
        cwd=compose_path.parent,
        timeout=600,
    )
    outputs.append(pull_result)

    health_timeout = getattr(cfg, "environment_healthcheck_timeout", 90)
    init_services = _compose_init_services(compose_path)
    initialization: dict[str, Any] | None = None
    if init_services:
        init_up = _run_environment_command(
            [*compose_args, "up", "-d", *init_services],
            cwd=compose_path.parent,
            timeout=600,
        )
        outputs.append(init_up)
        # Even a failed `up` may create partial networks/containers for this
        # project name; claim ownership so reclaim always runs.
        register_owned_compose_project(project_name, compose_path)
        owned = True
        if init_up["returncode"] != 0:
            cleanup = _cleanup_compose_project(command, compose_path, project_name)
            outputs.append(cleanup)
            return _failed_result(
                init_up["stderr"] or init_up["stdout"],
                cleanup=cleanup,
            )
        initialization = _wait_for_compose_init(
            command,
            compose_path,
            project_name,
            init_services,
            health_timeout,
        )
        if not initialization["success"]:
            cleanup = _cleanup_compose_project(command, compose_path, project_name)
            outputs.append(cleanup)
            return _failed_result(
                initialization["error"],
                initialization=initialization,
                cleanup=cleanup,
            )

    all_services = _compose_service_names(compose_path)
    main_services = [service for service in all_services if service not in init_services]
    if main_services or not init_services:
        main_up_command = [*compose_args, "up", "-d"]
        if init_services:
            main_up_command.extend(main_services)
        up_result = _run_environment_command(
            main_up_command,
            cwd=compose_path.parent,
            timeout=600,
        )
        outputs.append(up_result)
        register_owned_compose_project(project_name, compose_path)
        owned = True
        if up_result["returncode"] != 0:
            cleanup = _cleanup_compose_project(command, compose_path, project_name)
            outputs.append(cleanup)
            return _failed_result(
                up_result["stderr"] or up_result["stdout"],
                initialization=initialization,
                cleanup=cleanup,
            )

    target_url = str(candidate.get("target_url") or "")
    compose_healthchecks = _compose_healthcheck_services(compose_path)
    target_services = _compose_target_services(compose_path, target_url)
    required_healthchecks = compose_healthchecks
    if target_services:
        required_healthchecks = [
            service for service in compose_healthchecks if service in target_services
        ]
    healthcheck = _environment_healthcheck(
        command=command,
        compose_path=compose_path,
        project_name=project_name,
        compose_services=required_healthchecks,
        observed_compose_services=compose_healthchecks,
        target_url=target_url,
        timeout=health_timeout,
    )
    if not healthcheck["success"]:
        cleanup = _cleanup_compose_project(command, compose_path, project_name)
        outputs.append(cleanup)
        return _failed_result(
            healthcheck["error"],
            initialization=initialization,
            healthcheck=healthcheck,
            cleanup=cleanup,
        )

    result = {
        "success": True,
        "started_by_orchestrator": True,
        "preexisting_environment": False,
        "project_name": project_name,
        "commands": outputs,
        "target_url": target_url,
        "initialization": initialization,
        "healthcheck": healthcheck,
    }
    if port_remap:
        result["port_remap"] = port_remap
        result["compose_file"] = str(compose_path)
    return result


def register_owned_compose_project(project_name: str, compose_file: str | Path) -> None:
    """Track a Compose project created by this process for forced reclaim."""
    name = str(project_name or "").strip()
    path = str(compose_file or "").strip()
    if name and path:
        _owned_compose_projects[name] = str(Path(path))
        _register_atexit_reclaim()


def unregister_owned_compose_project(project_name: str) -> None:
    """Drop ownership tracking after a successful reclaim."""
    _owned_compose_projects.pop(str(project_name or "").strip(), None)


def list_owned_compose_projects() -> dict[str, str]:
    """Return a copy of Compose projects still owned by this process."""
    return dict(_owned_compose_projects)


def reclaim_owned_compose_projects() -> list[dict[str, Any]]:
    """Force-stop every Compose project still owned by this process.

    Used as a final safety net after each CVE run so healthcheck failures,
    partial ups, or unexpected exceptions cannot leave containers behind.
    """
    results: list[dict[str, Any]] = []
    if not _owned_compose_projects:
        return results

    command = _docker_compose_command()
    for project_name, compose_file in list(_owned_compose_projects.items()):
        compose_path = Path(compose_file)
        if not command:
            results.append({
                "success": False,
                "project_name": project_name,
                "compose_file": compose_file,
                "error": "未找到 docker compose 或 docker-compose 命令",
            })
            continue
        if not compose_path.is_file():
            unregister_owned_compose_project(project_name)
            results.append({
                "success": True,
                "project_name": project_name,
                "compose_file": compose_file,
                "skipped": True,
                "reason": "compose file missing; ownership cleared",
            })
            continue
        output = _cleanup_compose_project(command, compose_path, project_name)
        results.append({
            "success": bool(output.get("success")),
            "project_name": project_name,
            "compose_file": compose_file,
            "error": output.get("error", ""),
            "commands": [output],
        })
    return results


def teardown_environment(environment: dict[str, Any]) -> dict[str, Any]:
    """Stop an environment that this workflow started and still owns.

    Ownership is tracked with started_by_orchestrator. A failed healthcheck can
    still leave containers running when intermediate cleanup fails; those
    residual projects keep started_by_orchestrator=True so final report teardown
    and reclaim_owned_compose_projects() can release them.
    """
    setup_result = environment.get("setup_result")
    if not isinstance(setup_result, dict):
        return _skipped_teardown("environment has no setup result")
    if not setup_result.get("started_by_orchestrator"):
        return _skipped_teardown("environment is not owned by this workflow")
    if not getattr(cfg, "environment_auto_cleanup", True):
        return _skipped_teardown("ENVIRONMENT_AUTO_CLEANUP=false")

    launcher = str(environment.get("launcher") or environment.get("setup_mode") or "")
    if launcher == "docker_compose":
        result = _teardown_compose_environment(environment)
    elif launcher == "vulfocus_api":
        # Only fully successful Vulfocus starts are owned today.
        if not setup_result.get("success"):
            return _skipped_teardown("environment was not started successfully")
        result = _teardown_vulfocus_environment(environment)
    elif launcher in {"metarget_cnv", "metarget_appv"}:
        if not setup_result.get("success"):
            return _skipped_teardown("environment was not started successfully")
        result = _teardown_metarget_environment(environment)
    else:
        result = {"success": False, "error": f"不支持的环境回收器: {launcher or 'unknown'}"}
    return {**result, "skipped": False, "launcher": launcher}


def _skipped_teardown(reason: str) -> dict[str, Any]:
    return {"success": True, "skipped": True, "reason": reason}


def _teardown_compose_environment(environment: dict[str, Any]) -> dict[str, Any]:
    compose_file = str(environment.get("compose_file") or "")
    if not compose_file:
        return {"success": False, "error": "环境缺少 compose_file，无法回收"}
    compose_path = Path(compose_file)
    if not compose_path.is_file():
        return {"success": False, "error": f"compose 文件不存在: {compose_file}"}
    command = _docker_compose_command()
    if not command:
        return {"success": False, "error": "未找到 docker compose 或 docker-compose 命令"}

    setup_result = environment.get("setup_result")
    project_name = str(setup_result.get("project_name") or "") if isinstance(setup_result, dict) else ""
    if not project_name:
        return {"success": False, "error": "环境缺少独立 Compose project name，拒绝回收默认项目"}

    images_before = _compose_image_refs(compose_path)
    output = _cleanup_compose_project(command, compose_path, project_name)
    if output["returncode"] != 0:
        return {
            "success": False,
            "error": output["stderr"] or output["stdout"],
            "commands": [output],
        }

    image_cleanup: dict[str, Any] = {"skipped": True, "removed": [], "kept": [], "errors": []}
    if getattr(cfg, "environment_remove_images_after_run", True):
        image_cleanup = remove_compose_images(
            images_before,
            preserve_db=bool(getattr(cfg, "environment_preserve_db_images", True)),
            project_name=project_name,
        )
        # 删除结果写入 teardown，由调用方日志展示，避免 agents 依赖 rich console
    return {
        "success": True,
        "project_name": project_name,
        "commands": [output],
        "image_cleanup": image_cleanup,
    }


def _compose_image_refs(compose_path: Path) -> list[str]:
    """Read image references from a compose file."""
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return []
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return []
    images: list[str] = []
    for service in services.values():
        if isinstance(service, dict) and service.get("image"):
            images.append(str(service["image"]).strip())
    return images


_DB_IMAGE_MARKERS = (
    "mysql",
    "mariadb",
    "postgres",
    "redis",
    "mongo",
    "h2database",
    "h2",
)


def remove_compose_images(
    images: list[str],
    *,
    preserve_db: bool = True,
    project_name: str = "",
) -> dict[str, Any]:
    """Delete images used by a finished CVE environment to free disk.

    Also removes dangling/project-built images matching the compose project name.
    """
    removed: list[str] = []
    kept: list[str] = []
    errors: list[str] = []
    for image in images:
        if not image:
            continue
        lower = image.lower()
        if preserve_db and any(marker in lower for marker in _DB_IMAGE_MARKERS):
            kept.append(image)
            continue
        result = _run_environment_command(
            ["docker", "rmi", "-f", image], cwd=Path("."), timeout=120
        )
        err = (result.get("stderr") or result.get("stdout") or "").strip()
        # docker rmi -f on missing image can still return 0; treat "No such image" as not removed
        if result.get("returncode") == 0 and "no such image" not in err.lower():
            removed.append(image)
        else:
            errors.append(f"{image}: {err[:160] or 'rmi failed'}")
            kept.append(image)

    # Project-local build tags like cvehunter-cve-xxxx-...
    if project_name:
        list_out = _run_environment_command(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            cwd=Path("."),
            timeout=60,
        )
        for line in (list_out.get("stdout") or "").splitlines():
            tag = line.strip()
            if not tag or tag == "<none>:<none>":
                continue
            if project_name.lower() in tag.lower() or (
                tag.lower().startswith("cvehunter-") and any(
                    part and part in tag.lower()
                    for part in project_name.lower().split("-")
                    if len(part) >= 8
                )
            ):
                if preserve_db and any(marker in tag.lower() for marker in _DB_IMAGE_MARKERS):
                    kept.append(tag)
                    continue
                result = _run_environment_command(
                    ["docker", "rmi", "-f", tag], cwd=Path("."), timeout=120
                )
                if result.get("returncode") == 0:
                    removed.append(tag)
                else:
                    errors.append(tag)

    # dangling layers
    _run_environment_command(
        ["docker", "image", "prune", "-f"], cwd=Path("."), timeout=120
    )

    return {
        "skipped": False,
        "removed": sorted(set(removed)),
        "kept": sorted(set(kept)),
        "errors": errors[:20],
    }


def _new_compose_project_name(compose_path: Path) -> str:
    label = re.sub(r"[^a-z0-9_-]+", "-", compose_path.parent.name.lower()).strip("-_")
    label = label[:32] or "environment"
    return f"cvehunter-{label}-{uuid.uuid4().hex[:8]}"


def _cleanup_compose_project(
    command: list[str],
    compose_path: Path,
    project_name: str,
) -> dict[str, Any]:
    result = _run_environment_command(
        [
            *command,
            "-p",
            project_name,
            "-f",
            str(compose_path),
            "down",
            "--remove-orphans",
            "--volumes",
        ],
        cwd=compose_path.parent,
        timeout=300,
    )
    success = result["returncode"] == 0
    if success:
        unregister_owned_compose_project(project_name)
    return {
        **result,
        "success": success,
        "error": "" if success else (result["stderr"] or result["stdout"]),
    }


def _teardown_vulfocus_environment(environment: dict[str, Any]) -> dict[str, Any]:
    api_url = str(getattr(cfg, "vulfocus_api_url", "") or "").strip()
    username = str(getattr(cfg, "vulfocus_username", "") or "").strip()
    licence = str(getattr(cfg, "vulfocus_licence", "") or "").strip()
    image_name = str(environment.get("image_name") or "").strip()
    if not (api_url and username and licence and image_name):
        return {"success": False, "error": "Vulfocus API 地址、认证信息或镜像名缺失"}

    endpoint = f"{api_url.rstrip('/')}/api/imgs/operation"
    try:
        with httpx.Client(
            timeout=max(getattr(cfg, "request_timeout", 30), 30),
            proxy=getattr(cfg, "httpx_proxy", None),
        ) as client:
            response = client.post(endpoint, data={
                "username": username,
                "licence": licence,
                "image_name": image_name,
                "requisition": "stop",
            })
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        return {"success": False, "error": f"Vulfocus API 调用失败: {exc}"}
    if str(payload.get("status")) != "200":
        return {"success": False, "error": f"Vulfocus 停止失败: {payload.get('msg', '未知错误')}"}
    return {"success": True, "api_response": payload}


def _teardown_metarget_environment(environment: dict[str, Any]) -> dict[str, Any]:
    if not getattr(cfg, "metarget_execution_enabled", False):
        return {"success": False, "error": "Metarget 执行未授权，无法自动回收"}
    if platform.system() != "Linux":
        return {"success": False, "error": "Metarget 只能在专用 Linux/Ubuntu 靶机上回收"}
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return {"success": False, "error": "Metarget 回收需要 root 权限"}

    root = Path(str(environment.get("workdir") or ""))
    executable = root / "metarget"
    if not executable.is_file():
        return {"success": False, "error": f"Metarget 启动器不存在: {executable}"}
    scenario_name = str(environment.get("scenario_name") or "")
    subcommand = "appv" if environment.get("launcher") == "metarget_appv" else "cnv"
    output = _run_environment_command(
        [str(executable), subcommand, "remove", scenario_name, "--verbose"],
        cwd=root,
        timeout=3600,
    )
    if output["returncode"] != 0:
        return {
            "success": False,
            "error": output["stderr"] or output["stdout"],
            "commands": [output],
        }
    return {"success": True, "commands": [output]}


def _is_local_target_url(url: str) -> bool:
    host = (urlparse(url if "://" in url else f"http://{url}").hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1", "host.docker.internal"}


def _wait_for_http_target(url: str, timeout: int) -> bool:
    deadline = time.monotonic() + max(timeout, 0)
    while time.monotonic() <= deadline:
        try:
            with httpx.Client(timeout=3, follow_redirects=False, trust_env=False) as client:
                client.get(url)
            return True
        except Exception:
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    return False


def _wait_for_tcp_target(url: str, timeout: int) -> bool:
    parsed = urlparse(url if "://" in url else f"tcp://{url}")
    host = parsed.hostname or ""
    port = parsed.port
    if not host or port is None:
        return False
    deadline = time.monotonic() + max(timeout, 0)
    while time.monotonic() <= deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    return False


def _compose_service_definitions(compose_path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return {}
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return {}
    return {
        str(name): service
        for name, service in services.items()
        if isinstance(service, dict)
    }


def _compose_service_names(compose_path: Path) -> list[str]:
    return list(_compose_service_definitions(compose_path))


def _compose_init_services(compose_path: Path) -> list[str]:
    return [
        name
        for name in _compose_service_definitions(compose_path)
        if _COMPOSE_INIT_SERVICE_PATTERN.search(name)
    ]


def _compose_healthcheck_services(compose_path: Path) -> list[str]:
    result = []
    for name, service in _compose_service_definitions(compose_path).items():
        healthcheck = service.get("healthcheck")
        if healthcheck and not (isinstance(healthcheck, dict) and healthcheck.get("disable")):
            result.append(name)
    return result


def _compose_target_services(compose_path: Path, target_url: str) -> list[str]:
    if not target_url:
        return []
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    try:
        target_port = parsed.port
    except ValueError:
        return []
    if target_port is None:
        target_port = 443 if parsed.scheme.lower() == "https" else 80

    result = []
    for name, service in _compose_service_definitions(compose_path).items():
        if any(_published_port(port) == str(target_port) for port in service.get("ports") or []):
            result.append(name)
    return result


def _environment_healthcheck(
    *,
    command: list[str],
    compose_path: Path,
    project_name: str,
    compose_services: list[str],
    observed_compose_services: list[str],
    target_url: str,
    timeout: int,
) -> dict[str, Any]:
    if compose_services:
        compose_result = _wait_for_compose_health(
            command,
            compose_path,
            project_name,
            compose_services,
            timeout,
            observed_services=observed_compose_services,
        )
        success = compose_result["success"]
        service_health = compose_result["service_health"]
        status_summary = ", ".join(
            f"{service}={service_health.get(service, 'missing')}"
            for service in compose_services
        )
        return {
            "success": success,
            "type": "compose",
            "services": compose_services,
            "observed_services": observed_compose_services,
            "service_health": service_health,
            "status_error": compose_result.get("status_error", ""),
            "error": "" if success else (
                f"compose 已启动，但服务健康检查在 {timeout}s 内未通过: "
                f"{status_summary}"
            ),
        }

    if not target_url or not _is_local_target_url(target_url):
        return {"success": True, "type": "none", "target": target_url, "error": ""}

    check_type = _target_healthcheck_type(target_url)
    if check_type == "tcp":
        success = _wait_for_tcp_target(target_url, timeout)
    else:
        success = _wait_for_http_target(target_url, timeout)
    return {
        "success": success,
        "type": check_type,
        "target": target_url,
        "error": "" if success else (
            f"compose 已启动，但 {check_type.upper()} 目标 {target_url} "
            f"在 {timeout}s 内未就绪"
        ),
    }


def _target_healthcheck_type(target_url: str) -> str:
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    scheme = parsed.scheme.lower()
    if scheme in {"tcp", "mysql", "postgres", "postgresql", "mariadb", "mongodb", "redis"}:
        return "tcp"
    if parsed.port in _TCP_TARGET_PORTS or parsed.port in {5433, 3307, 27018}:
        return "tcp"
    return "http"


def _wait_for_compose_init(
    command: list[str],
    compose_path: Path,
    project_name: str,
    services: list[str],
    timeout: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(timeout, 0)
    last_status: dict[str, dict[str, Any]] = {}
    last_error = ""
    while time.monotonic() <= deadline:
        result = _run_environment_command(
            [
                *command,
                "-p",
                project_name,
                "-f",
                str(compose_path),
                "ps",
                "--all",
                "--format",
                "json",
            ],
            cwd=compose_path.parent,
            timeout=30,
            output_limit=None,
        )
        if result["returncode"] == 0:
            last_status = _compose_service_status(result.get("stdout", ""))
            last_error = ""
        else:
            last_error = result.get("stderr") or result.get("stdout") or "compose ps failed"

        failed = [
            service
            for service in services
            if last_status.get(service, {}).get("state") in {"dead", "exited"}
            and last_status.get(service, {}).get("exit_code") != 0
        ]
        if failed:
            summary = ", ".join(
                f"{service}=exit:{last_status[service].get('exit_code')}"
                for service in failed
            )
            return {
                "success": False,
                "services": services,
                "service_status": last_status,
                "status_error": last_error,
                "error": f"Compose 初始化服务执行失败: {summary}",
            }
        if services and all(
            last_status.get(service, {}).get("state") in {"dead", "exited"}
            and last_status.get(service, {}).get("exit_code") == 0
            for service in services
        ):
            return {
                "success": True,
                "services": services,
                "service_status": last_status,
                "status_error": "",
                "error": "",
            }
        if time.monotonic() >= deadline:
            break
        time.sleep(2)

    summary = ", ".join(
        f"{service}={last_status.get(service, {}).get('state', 'missing')}"
        for service in services
    )
    return {
        "success": False,
        "services": services,
        "service_status": last_status,
        "status_error": last_error,
        "error": f"Compose 初始化服务在 {timeout}s 内未完成: {summary}",
    }


def _wait_for_compose_health(
    command: list[str],
    compose_path: Path,
    project_name: str,
    services: list[str],
    timeout: int,
    observed_services: list[str] | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(timeout, 0)
    expected = set(services)
    observed = list(dict.fromkeys([*(observed_services or []), *services]))
    last_health: dict[str, str] = {}
    last_error = ""
    while time.monotonic() <= deadline:
        result = _run_environment_command(
            [
                *command,
                "-p",
                project_name,
                "-f",
                str(compose_path),
                "ps",
                "--all",
                "--format",
                "json",
            ],
            cwd=compose_path.parent,
            timeout=30,
            output_limit=None,
        )
        if result["returncode"] == 0:
            last_health = _compose_service_health(result.get("stdout", ""))
            last_error = ""
        else:
            last_error = result.get("stderr") or result.get("stdout") or "compose ps failed"
        if expected and all(last_health.get(service) == "healthy" for service in expected):
            return {
                "success": True,
                "service_health": {
                    service: last_health.get(service, "missing") for service in observed
                },
                "status_error": "",
            }
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    return {
        "success": False,
        "service_health": {
            service: last_health.get(service, "missing") for service in observed
        },
        "status_error": last_error,
    }


def _compose_service_health(output: str) -> dict[str, str]:
    result = {}
    for record in _compose_ps_records(output):
        service = str(record.get("Service") or record.get("service") or "")
        if not service:
            continue
        health = str(record.get("Health") or record.get("health") or "").lower()
        state = str(record.get("State") or record.get("state") or "").lower()
        result[service] = health or (f"state:{state}" if state else "none")
    return result


def _compose_service_status(output: str) -> dict[str, dict[str, Any]]:
    result = {}
    for record in _compose_ps_records(output):
        service = str(record.get("Service") or record.get("service") or "")
        if not service:
            continue
        state = str(record.get("State") or record.get("state") or "").lower()
        exit_code_value = record.get("ExitCode")
        if exit_code_value is None:
            exit_code_value = record.get("exit_code")
        try:
            exit_code = int(exit_code_value)
        except (TypeError, ValueError):
            exit_code = None
        result[service] = {"state": state, "exit_code": exit_code}
    return result


def _compose_ps_records(output: str) -> list[dict[str, Any]]:
    if not output.strip():
        return []
    try:
        payload = json.loads(output)
        records = payload if isinstance(payload, list) else [payload]
    except json.JSONDecodeError:
        records = []
        for line in output.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return [record for record in records if isinstance(record, dict)]


def _docker_compose_command() -> list[str] | None:
    docker = shutil.which("docker")
    if docker:
        return [docker, "compose"]
    docker_compose = shutil.which("docker-compose")
    if docker_compose:
        return [docker_compose]
    return None


def _guess_target_url_from_compose(path: Path) -> str:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return ""

    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        return ""

    candidates = []
    order = 0
    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        for port in service.get("ports") or []:
            published = _published_port(port)
            if published:
                candidates.append((
                    _compose_port_score(str(service_name), port),
                    order,
                    published,
                ))
                order += 1
    if candidates:
        best = sorted(candidates)[0]
        _, _, published = best
        # 数据库类服务用 tcp://，避免对 5432/3306 做 HTTP 健康检查。
        scheme = "tcp" if best[0] >= 40 else "http"
        # best[0] is score; high score means redis/postgres/mysql-like.
        # Recompute scheme from published/target port for robustness.
        try:
            published_int = int(str(published))
        except (TypeError, ValueError):
            published_int = -1
        if published_int in _TCP_TARGET_PORTS or published_int in {5433, 3307, 27018}:
            scheme = "tcp"
        return f"{scheme}://127.0.0.1:{published}"
    return ""


def _normalize_compose_shell_scripts(directory: Path) -> list[str]:
    """把 compose 目录内 .sh 的 CRLF 转为 LF，避免容器 entrypoint 报 $'\\r'。"""
    fixed: list[str] = []
    root = Path(directory)
    if not root.is_dir():
        return fixed
    for path in root.rglob("*.sh"):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\r\n" not in data and not data.endswith(b"\r"):
            continue
        try:
            path.write_bytes(data.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
            fixed.append(str(path))
        except OSError:
            continue
    return fixed


def _is_host_port_free(port: int) -> bool:
    """Check whether a TCP host port can be bound on 0.0.0.0."""
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return False
    if port_i <= 0 or port_i > 65535:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port_i))
            return True
        except OSError:
            return False


def _allocate_free_host_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _rewrite_compose_port_mapping(port: Any, new_host: str) -> Any:
    """Rewrite only the host/published side of a compose port mapping."""
    if isinstance(port, int):
        return f"{new_host}:{port}"
    if isinstance(port, str):
        text = port.strip()
        proto = ""
        if "/" in text:
            text, proto = text.rsplit("/", 1)
            proto = f"/{proto}"
        parts = text.split(":")
        if len(parts) == 1:
            return f"{new_host}:{parts[0]}{proto}"
        if len(parts) == 2:
            # host:container or ip:container — replace host side
            return f"{new_host}:{parts[1]}{proto}"
        if len(parts) == 3:
            # ip:host:container
            return f"{parts[0]}:{new_host}:{parts[2]}{proto}"
        return f"{new_host}:{parts[-1]}{proto}"
    if isinstance(port, dict):
        rewritten = dict(port)
        rewritten["published"] = int(new_host) if str(new_host).isdigit() else new_host
        return rewritten
    return port


def _compose_with_free_host_ports(compose_path: Path) -> tuple[Path, dict[str, str], str]:
    """若 compose 声明的宿主机端口已被占用，写临时 compose 并改映到空闲端口。

    Returns:
        (compose_path_to_use, old_host_port -> new_host_port, remapped_target_url or "")
    """
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        return compose_path, {}, ""
    if not isinstance(data, dict):
        return compose_path, {}, ""
    services = data.get("services")
    if not isinstance(services, dict):
        return compose_path, {}, ""

    port_remap: dict[str, str] = {}
    changed = False
    for service in services.values():
        if not isinstance(service, dict):
            continue
        ports = service.get("ports")
        if not isinstance(ports, list) or not ports:
            continue
        new_ports: list[Any] = []
        for port in ports:
            published = _published_port(port)
            if not published or not str(published).isdigit():
                new_ports.append(port)
                continue
            if _is_host_port_free(int(published)):
                new_ports.append(port)
                continue
            # 已占用：分配空闲端口（同 old 只 remap 一次，保持一致）
            if published in port_remap:
                new_host = port_remap[published]
            else:
                new_host = str(_allocate_free_host_port())
                port_remap[published] = new_host
            new_ports.append(_rewrite_compose_port_mapping(port, new_host))
            changed = True
        if changed:
            service["ports"] = new_ports

    if not changed:
        return compose_path, {}, ""

    # 写到 compose 同目录，便于相对 volume 路径仍有效
    temp_name = f".cvehunter-ports-{uuid.uuid4().hex[:8]}.yml"
    temp_path = compose_path.parent / temp_name
    # 基于原文件结构 dump；去掉已废弃 version 以免警告
    data.pop("version", None)
    temp_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    remapped_target = _guess_target_url_from_compose(temp_path)
    return temp_path, port_remap, remapped_target


def _compose_port_score(service_name: str, port: Any) -> int:
    name = service_name.lower()
    target_port = _target_port(port)
    published = _published_port(port)
    score = 0

    if any(marker in name for marker in (
        "web", "http", "server", "frontend", "app", "adminer", "gitlab",
        "geoserver", "aiohttp", "vite", "rails",
    )):
        score -= 50
    if any(marker in name for marker in ("redis", "postgres", "mysql", "mariadb", "db", "database", "mongo", "zookeeper", "kafka")):
        score += 50

    if target_port in {"80", "8080", "8000", "3000", "5000", "5005", "5173", "5555", "9000"}:
        score -= 20
    if published in {"80", "8080", "8000", "3000", "5000", "5005", "5173", "5555", "9000"}:
        score -= 10
    if target_port in {"22", "5432", "6379", "3306", "1521", "27017", "9200", "9300"}:
        score += 40
    if str(port).lower().endswith("/udp"):
        score += 20
    return score


def _published_port(port: Any) -> str:
    if isinstance(port, int):
        return str(port)
    if isinstance(port, str):
        parts = port.split(":")
        if len(parts) == 1:
            return parts[0].split("/")[0]
        return parts[-2].split("/")[0]
    if isinstance(port, dict):
        value = port.get("published") or port.get("host_port")
        return str(value) if value else ""
    return ""


def _target_port(port: Any) -> str:
    if isinstance(port, int):
        return str(port)
    if isinstance(port, str):
        return port.split(":")[-1].split("/")[0]
    if isinstance(port, dict):
        value = port.get("target") or port.get("container_port") or port.get("published") or port.get("host_port")
        return str(value) if value else ""
    return ""


def _default_environment() -> dict[str, Any]:
    target_url = _default_target_url()
    return {
        "source": "default_target",
        "kind": "remote_or_existing_target",
        "target_url": target_url,
        "target_host": _target_host_from_url(target_url),
        "setup_mode": "not_required",
        "reason": "使用 TARGET_IP 或默认 127.0.0.1",
    }


def _default_target_url() -> str:
    if cfg.attack_env_target_url:
        return cfg.attack_env_target_url
    if cfg.target_ip.startswith(("http://", "https://")):
        return cfg.target_ip
    return f"http://{cfg.target_ip}"


def _target_host_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc or parsed.path or cfg.target_ip


def _infer_attack_objective(text: str) -> str:
    if any(marker in text for marker in ("ssrf", "server-side request forgery", "server side request forgery", "服务端请求伪造")):
        return "outbound_callback"
    if any(marker in text for marker in ("rce", "remote code", "command injection", "execute arbitrary", "code execution", "命令执行", "代码执行", "远程执行")):
        return "command_execution"
    if any(marker in text for marker in ("sql injection", "sqli", "database", "sql注入", "sql 注入", "数据库")):
        return "database_access"
    if any(marker in text for marker in (
        "path traversal", "directory traversal", "file read", "arbitrary file",
        "路径遍历", "目录遍历", "任意文件", "文件读取", "信息泄露", "信息泄漏",
    )):
        return "file_read"
    if any(marker in text for marker in ("xss", "cross-site scripting", "cross site scripting", "跨站脚本")):
        return "browser_script_execution"
    if any(marker in text for marker in ("csrf", "cross-site request forgery", "cross site request forgery", "跨站请求伪造")):
        return "state_change"
    if any(marker in text for marker in ("auth bypass", "authentication bypass", "unauthorized", "privilege escalation", "认证绕过", "未授权", "权限提升")):
        return "auth_bypass"
    if any(marker in text for marker in ("denial of service", "redos", "dos", "resource exhaustion", "拒绝服务", "资源耗尽")):
        return "denial_of_service"
    return "traffic_detection"


def _default_validation_hint(objective: str) -> dict[str, Any]:
    callback_url = getattr(cfg, "callback_url", "")
    if objective in {"outbound_callback", "command_execution"} and callback_url:
        return {"type": "callback", "callback_url": callback_url}
    if objective == "file_read":
        return {"type": "response_contains", "markers": ["root:", "[boot loader]", "localhost"], "case_sensitive": False}
    if objective == "database_access":
        return {"type": "tool_suggested", "tool": "sqlmap"}
    if objective == "browser_script_execution":
        return {"type": "tool_suggested", "tool": "playwright"}
    if objective == "denial_of_service":
        return {"type": "timing", "min_elapsed_ms": 5000}
    if objective == "auth_bypass":
        return {"type": "auth_state"}
    return {"type": "ips"}


def _trigger_logic_summary(objective: str) -> str:
    summaries = {
        "outbound_callback": "触发目标向受控 callback 地址发起请求",
        "command_execution": "通过目标入口注入命令或代码并观察命令执行证据",
        "database_access": "通过输入注入访问或修改数据库状态",
        "file_read": "通过路径或文件参数读取越权文件内容",
        "browser_script_execution": "在受控浏览器上下文中执行注入脚本",
        "state_change": "借助受害会话触发非预期状态变化",
        "auth_bypass": "绕过认证或提升到更高权限状态",
        "denial_of_service": "构造输入导致目标服务异常延迟或不可用",
        "traffic_detection": "发送 CVE 相关攻击流量并依赖 IPS/外部检测验证",
    }
    return summaries.get(objective, summaries["traffic_detection"])


def _infer_preconditions(text: str) -> list[str]:
    preconditions = []
    if any(marker in text for marker in ("authenticated", "login", "administrator", "admin", "privileges required")):
        preconditions.append("可能需要认证或管理员会话")
    if "csrf" in text:
        preconditions.append("可能需要 CSRF token 或受害会话")
    if any(marker in text for marker in ("plugin", "extension", "module")):
        preconditions.append("目标需要启用对应插件/模块")
    return preconditions


def _variable_slots_for_objective(objective: str) -> list[str]:
    common = ["base_url", "path", "method", "headers"]
    slots = {
        "outbound_callback": common + ["callback_url", "payload_encoding"],
        "command_execution": common + ["command", "callback_url", "payload_encoding"],
        "database_access": common + ["parameter", "sql_payload", "content_type"],
        "file_read": common + ["file_parameter", "file_path", "payload_encoding"],
        "browser_script_execution": common + ["script_payload", "browser_state"],
        "state_change": common + ["csrf_token", "cookie", "state_parameter"],
        "auth_bypass": common + ["cookie", "role", "session_state"],
        "denial_of_service": common + ["payload_size", "timeout_threshold"],
    }
    return slots.get(objective, common + ["payload"])


def _dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for candidate in candidates:
        key = json.dumps({
            "kind": candidate.get("kind"),
            "provider": candidate.get("provider"),
            "launcher": candidate.get("launcher"),
            "compose_file": candidate.get("compose_file"),
            "image_name": candidate.get("image_name"),
            "scenario_name": candidate.get("scenario_name"),
            "target_url": candidate.get("target_url"),
        }, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _agent_llm_model() -> str:
    return getattr(cfg, "effective_agent_llm_model", None) or getattr(cfg, "llm_model", "")


def _invoke_agent_llm(prompt: str) -> str:
    return invoke_llm(
        prompt,
        model=_agent_llm_model(),
        temperature=0.1,
        max_tokens=2048,
    )


def _load_json_object(text: str) -> dict[str, Any]:
    for block in re.findall(r"```(?:json)?\s*\n(.*?)```", text, flags=re.DOTALL | re.IGNORECASE):
        try:
            value = json.loads(block.strip())
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return {"items": value}
    raise ValueError("LLM 未返回可解析 JSON 对象")


def _first_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return item
    if isinstance(value, dict):
        return value
    return {}


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _compact_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    compact = deepcopy(candidate)
    if compact.get("nuclei_yaml"):
        compact["nuclei_yaml"] = compact["nuclei_yaml"][:2000]
    if compact.get("raw_http"):
        compact["raw_http"] = compact["raw_http"][:3000]
    return compact


def _critic_trace_status(review: dict[str, Any], llm_error: str = "") -> str:
    if llm_error:
        return "rule_fallback_after_llm_error"
    if review.get("llm_review"):
        return "llm_accepted" if review.get("accepted") else "llm_rejected"
    return "accepted" if review.get("accepted") else "rejected"


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
