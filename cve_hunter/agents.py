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
- ReflectionAgent：当前仍在 graph.py 的 node_reflect_after_verify 中实现，负责
  根据失败反馈生成少量小变体。后续可迁移到本模块并改为枚举化动作输出。
- ReporterAgent：当前由 graph.py 的 node_generate_report 承担，负责归档
  agent_trace、attempt_history、oracle_result 和最终报告。

AGENT_LLM_ENABLED=true 时，EnvironmentAgent/TriggerAgent/CriticAgent 会优先
调用 .env 中配置的大模型；AGENT_LLM_MODEL 留空时复用 LLM_MODEL，例如当前
deepseek-v4-pro。LLM 调用失败时会自动退回确定性规则，保持主链路可运行。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from cve_hunter.config import cfg
from cve_hunter.llm import invoke_llm
from cve_hunter.state import CVEState


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

    默认只规划，不执行 Docker。设置 AUTO_ENV_ENABLED=true 后：
    - 若 ATTACK_ENV_COMPOSE_FILE 指向 compose 文件，则执行该文件。
    - 否则在 VULHUB_DIR 下查找 **/<CVE-ID>/docker-compose.y*ml 并执行。
    """
    candidates = _discover_environment_candidates(state.cve_id)
    environment = _default_environment()
    status = "planned"
    summary = "使用默认目标地址，未发现可自动搭建环境"
    errors: list[str] = []

    if candidates:
        environment.update(candidates[0])
        environment["target_url"] = cfg.attack_env_target_url or environment.get("target_url") or _default_target_url()
        environment["target_host"] = _target_host_from_url(environment["target_url"])
        summary = f"发现攻击环境候选: {environment.get('source', 'unknown')}"

    if cfg.auto_env_enabled and candidates:
        run_result = _start_compose_environment(candidates[0])
        environment["setup_result"] = run_result
        if run_result["success"]:
            status = "started"
            summary = f"已启动攻击环境: {environment.get('target_url', '')}"
        else:
            status = "setup_failed"
            errors.append(run_result.get("error", "攻击环境启动失败"))
            summary = errors[-1]
    elif cfg.auto_env_enabled and not candidates:
        status = "not_found"
        errors.append("未找到可自动搭建的 docker-compose 环境")
        summary = errors[-1]
    elif not cfg.auto_env_enabled:
        environment["setup_mode"] = "disabled"

    llm_plan = {}
    llm_error = ""
    if getattr(cfg, "agent_llm_enabled", False):
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
    if raw_http:
        if "{{TARGET_HOST}}" not in raw_http and "Host:" not in raw_http:
            flags.append("raw_http_missing_host")
            score_delta -= 0.1
        if not re.match(r"(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/", raw_http.strip()):
            flags.append("raw_http_request_line_unusual")
            score_delta -= 0.15
    elif nuclei_yaml:
        enriched.setdefault("validation_hint", {"type": "nuclei_match"})
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


def _discover_environment_candidates(cve_id: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    explicit = Path(cfg.attack_env_compose_file).expanduser() if cfg.attack_env_compose_file else None
    if explicit and explicit.is_file():
        candidates.append(_compose_candidate(explicit, source="explicit_compose", reason="ATTACK_ENV_COMPOSE_FILE 指定"))

    vulhub_root = Path(cfg.vulhub_dir).expanduser()
    if vulhub_root.is_dir():
        pattern = cve_id.upper()
        compose_files = []
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            compose_files.extend(vulhub_root.glob(f"**/{pattern}/{name}"))
            compose_files.extend(vulhub_root.glob(f"**/{pattern.lower()}/{name}"))
        for compose_file in sorted(set(compose_files)):
            candidates.append(_compose_candidate(compose_file, source="vulhub_local", reason="本地 vulhub 命中"))

    return _dedupe_candidates(candidates)


def _compose_candidate(path: Path, *, source: str, reason: str) -> dict[str, Any]:
    path = path.resolve()
    target_url = cfg.attack_env_target_url or _guess_target_url_from_compose(path)
    return {
        "source": source,
        "kind": "docker_compose",
        "compose_file": str(path),
        "workdir": str(path.parent),
        "target_url": target_url or _default_target_url(),
        "target_host": _target_host_from_url(target_url or _default_target_url()),
        "reason": reason,
    }


def _start_compose_environment(candidate: dict[str, Any]) -> dict[str, Any]:
    compose_file = candidate.get("compose_file", "")
    if not compose_file:
        return {"success": False, "error": "环境候选缺少 compose_file"}

    command = _docker_compose_command()
    if not command:
        return {"success": False, "error": "未找到 docker compose 或 docker-compose 命令"}

    compose_path = Path(compose_file)
    if not compose_path.is_file():
        return {"success": False, "error": f"compose 文件不存在: {compose_file}"}

    commands = [
        [*command, "-f", str(compose_path), "pull"],
        [*command, "-f", str(compose_path), "up", "-d"],
    ]
    outputs = []
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(compose_path.parent),
                text=True,
                capture_output=True,
                timeout=600,
                check=False,
            )
        except Exception as exc:
            return {"success": False, "error": str(exc), "commands": outputs}
        outputs.append({
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
        })
        if proc.returncode != 0:
            return {"success": False, "error": proc.stderr.strip() or proc.stdout.strip(), "commands": outputs}

    return {"success": True, "commands": outputs}


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
        _, _, published = sorted(candidates)[0]
        return f"http://127.0.0.1:{published}"
    return ""


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
            "compose_file": candidate.get("compose_file"),
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
