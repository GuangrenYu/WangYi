"""VerifierAgent execution and success-judgment interfaces.

VerifierAgent 在当前代码中拆成两个可替换接口：
- RequestExecutor：只负责执行候选 PoC。当前兼容 raw_http、nuclei_yaml 和
  request_steps，并复用现有 http2pcap / 内置 httpx 发包链路。后续接
  Playwright、sqlmap、ZAP、Burp 或 callback executor 时，只改这里。
- SuccessOracle：只负责判定执行结果。它组合 IPS 当前 CVE 命中、通用 IPS
  命中和目标侧 oracle，输出 success_level、status_code、target_oracle 等
  结构化证据。CAPTURE_SUCCESS 仍只表示 IPS 当前 CVE 字段命中。

边界：VerifierAgent 不搜索情报、不生成 PoC、不做候选合理性审查；这些分别由
IntelAgent/PoCAgent/CriticAgent/ReflectionAgent 负责。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from cve_hunter.config import cfg
from cve_hunter.runtime import effective_target_ip, explicit_target_ip, as_target_url
from cve_hunter.ips_match import classify_ips_matches, summarize_ips_classification
from cve_hunter.state import CVEState
from cve_hunter.status_codes import (
    CAPTURE_SUCCESS,
    DB_ORACLE_SUCCESS,
    EXECUTION_POLICY_BLOCKED,
    IPS_GENERIC_MATCH_ONLY,
    NO_EXPLOIT_EVIDENCE,
    PROTOCOL_UNSUPPORTED,
    TARGET_ORACLE_FAILED,
    TARGET_ORACLE_SUCCESS,
    status_description,
)
from cve_hunter.safety import evaluate_execution_policy
from cve_hunter.tools.http_sender import send_poc_and_capture
from cve_hunter.executors.base import PROTOCOL_DATABASE, PROTOCOL_HTTP, execute_spec


@dataclass
class RequestExecutor:
    """Execution interface for PoC candidates.

    当前默认执行器仍使用现有 http2pcap/builtin 链路。后续接 Playwright、
    sqlmap、ZAP、Burp 或自定义 callback 时，只需新增 executor 实现。
    """

    name: str = "default_http_executor"

    def execute(
        self,
        candidate: dict[str, Any],
        environment: dict[str, Any] | None = None,
        *,
        cve_id: str = "",
    ) -> dict[str, Any]:
        environment = environment or {}
        if environment.get("local_container_mode") and not environment.get("target_url"):
            return _with_executor_metadata(
                {
                    "success": False,
                    "skipped": True,
                    "policy_blocked": True,
                    "error": "本地模式未匹配到可执行环境，已跳过",
                    "error_type": "infrastructure",
                    "ips_matches": [],
                },
                self.name,
                "",
                "",
                step_results=[],
            )
        target_url = environment.get("target_url") or _default_target_url()
        target_host = environment.get("target_host") or _target_host_from_url(target_url)
        policy = evaluate_execution_policy(
            target_url,
            target_host,
            run_mode=getattr(cfg, "run_mode", "plan_only"),
            allowlist=getattr(cfg, "target_allowlist", []),
        )
        if not policy.allowed:
            return _with_executor_metadata(
                {
                    "success": False,
                    "skipped": True,
                    "policy_blocked": True,
                    "error": policy.reason,
                    "error_type": "policy",
                    "policy": policy.to_dict(),
                    "ips_matches": [],
                },
                self.name,
                target_url,
                target_host,
                step_results=[],
            )

        # 数据库 / 非 HTTP 结构化执行规格优先
        execution_spec = candidate.get("execution_spec")
        if isinstance(execution_spec, dict) and execution_spec.get("protocol"):
            protocol = str(execution_spec.get("protocol") or "").strip().lower()
            if protocol == PROTOCOL_DATABASE:
                result = execute_spec(execution_spec, environment, cve_id=cve_id)
                # 将 request_success 统一为“触发阶段已执行”
                if result.get("phase") in {"oracle", "trigger_sql"} or result.get("logs"):
                    result.setdefault("request_success", True)
                return _with_executor_metadata(
                    result,
                    self.name,
                    target_url,
                    target_host,
                    step_results=list(result.get("logs") or []),
                )
            if protocol not in {PROTOCOL_HTTP, ""}:
                result = execute_spec(execution_spec, environment, cve_id=cve_id)
                result.setdefault("status_code", PROTOCOL_UNSUPPORTED)
                return _with_executor_metadata(result, self.name, target_url, target_host, step_results=[])

        if candidate.get("request_steps"):
            return self._execute_steps(candidate["request_steps"], target_url, target_host, cve_id)

        if candidate.get("nuclei_yaml"):
            result = send_poc_and_capture(
                nuclei_yaml=candidate["nuclei_yaml"],
                target_url=target_url,
                cve_id=cve_id,
            )
            return _with_executor_metadata(result, self.name, target_url, target_host, step_results=[])

        raw_http = candidate.get("raw_http", "")
        if raw_http:
            raw_http = _prepare_raw_http(raw_http, target_host)
            result = send_poc_and_capture(raw_http=raw_http, cve_id=cve_id)
            return _with_executor_metadata(result, self.name, target_url, target_host, request_raw=raw_http, step_results=[])

        return _with_executor_metadata(
            {"success": False, "error": "候选缺少 raw_http、nuclei_yaml、request_steps 或 execution_spec"},
            self.name,
            target_url,
            target_host,
            step_results=[],
        )

    def _execute_steps(self, steps: list[dict[str, Any]], target_url: str, target_host: str, cve_id: str) -> dict[str, Any]:
        step_results = []
        last_result: dict[str, Any] = {"success": False, "error": "request_steps 为空"}
        for index, step in enumerate(steps, start=1):
            raw_http = _prepare_raw_http(
                str(step.get("raw_http") or step.get("request") or ""),
                target_host,
            )
            nuclei_yaml = str(step.get("nuclei_yaml") or "")
            if nuclei_yaml:
                result = send_poc_and_capture(nuclei_yaml=nuclei_yaml, target_url=target_url, cve_id=cve_id)
            elif raw_http:
                result = send_poc_and_capture(raw_http=raw_http, cve_id=cve_id)
            else:
                result = {"success": False, "error": f"第 {index} 步缺少可执行请求"}
            result = _with_executor_metadata(result, self.name, target_url, target_host, request_raw=raw_http, step_index=index)
            step_results.append(result)
            last_result = result
            if not result.get("success"):
                break
        return _with_executor_metadata(last_result, self.name, target_url, target_host, step_results=step_results)


@dataclass
class SuccessOracle:
    """Success judgment interface that combines IPS and target-side oracle."""

    name: str = "default_success_oracle"

    def evaluate(
        self,
        *,
        state: CVEState,
        candidate: dict[str, Any],
        result: dict[str, Any],
        environment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ips_matches = result.get("ips_matches", [])
        ips_classification = classify_ips_matches(ips_matches, state.cve_id)
        ips_summary = summarize_ips_classification(ips_classification)
        target_oracle = evaluate_target_oracle(candidate.get("validation_hint") or {}, result)

        ips_matched = ips_classification["ips_matched"]
        generic_ips_matched = ips_classification["generic_ips_matched"]
        request_success = bool(result.get("success", False))
        target_success = bool(target_oracle.get("success", False))

        db_oracle = result.get("oracle") if isinstance(result.get("oracle"), dict) else {}
        db_success = bool(db_oracle.get("success")) or (
            str(result.get("protocol") or "") == "database" and bool(result.get("success"))
        )

        if result.get("policy_blocked"):
            outcome = "execution_policy_blocked"
            final_status = "FAILURE"
            status_code = EXECUTION_POLICY_BLOCKED
            message = result.get("error") or status_description(EXECUTION_POLICY_BLOCKED)
            success_level = "not_executed"
        elif ips_matched:
            outcome = "cve_ips_matched"
            final_status = "SUCCESS"
            status_code = CAPTURE_SUCCESS
            message = status_description(CAPTURE_SUCCESS)
            success_level = "ips_cve_match"
        elif db_success:
            outcome = "database_oracle_success"
            final_status = "SUCCESS"
            status_code = str(result.get("status_code") or DB_ORACLE_SUCCESS)
            message = status_description(DB_ORACLE_SUCCESS)
            success_level = "database_oracle"
            target_oracle = {
                "evaluated": True,
                "success": True,
                "type": db_oracle.get("type") or "database",
                "evidence": db_oracle.get("evidence") or result.get("body") or "",
            }
            target_success = True
        elif target_success:
            outcome = "target_oracle_success"
            final_status = "SUCCESS"
            status_code = TARGET_ORACLE_SUCCESS
            message = status_description(TARGET_ORACLE_SUCCESS)
            success_level = "target_oracle"
        elif generic_ips_matched:
            outcome = "generic_ips_only"
            final_status = "FAILURE"
            status_code = IPS_GENERIC_MATCH_ONLY
            message = status_description(IPS_GENERIC_MATCH_ONLY)
            success_level = "generic_ips_only"
        elif request_success and target_oracle.get("evaluated"):
            outcome = "target_oracle_failed"
            final_status = "FAILURE"
            status_code = TARGET_ORACLE_FAILED
            message = status_description(TARGET_ORACLE_FAILED)
            success_level = "no_exploit_evidence"
        elif request_success:
            outcome = "http_success_no_ips"
            final_status = "FAILURE"
            status_code = NO_EXPLOIT_EVIDENCE
            message = status_description(NO_EXPLOIT_EVIDENCE)
            success_level = "no_exploit_evidence"
        else:
            outcome = "request_failed"
            final_status = "FAILURE"
            status_code = str(result.get("status_code") or "")
            message = result.get("error", "请求失败")
            success_level = "request_failed"

        return {
            "oracle": self.name,
            "status": final_status,
            "status_code": status_code,
            "message": message,
            "outcome": outcome,
            "success_level": success_level,
            "ips_matched": ips_matched,
            "generic_ips_matched": generic_ips_matched,
            "ips_classification": ips_classification,
            "ips_summary": ips_summary,
            "target_oracle": target_oracle,
            "environment": environment or {},
        }


def execute_candidate(
    candidate: dict[str, Any],
    environment: dict[str, Any] | None = None,
    *,
    cve_id: str = "",
) -> dict[str, Any]:
    """Execute a candidate with the default executor."""
    return RequestExecutor().execute(candidate, environment, cve_id=cve_id)


def evaluate_success(
    *,
    state: CVEState,
    candidate: dict[str, Any],
    result: dict[str, Any],
    environment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate an execution result with the default oracle."""
    return SuccessOracle().evaluate(state=state, candidate=candidate, result=result, environment=environment)


def evaluate_target_oracle(validation_hint: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Evaluate target-side evidence from a validation hint."""
    hint_type = str(validation_hint.get("type") or "").strip().lower()
    if not hint_type or hint_type == "ips":
        return {"evaluated": False, "success": False, "type": hint_type or "none", "evidence": ""}

    body = str(result.get("body") or "")
    if hint_type == "response_contains":
        markers = validation_hint.get("markers") or validation_hint.get("marker") or []
        if isinstance(markers, str):
            markers = [markers]
        case_sensitive = bool(validation_hint.get("case_sensitive", False))
        haystack = body if case_sensitive else body.lower()
        matched = []
        for marker in markers:
            marker_text = str(marker)
            needle = marker_text if case_sensitive else marker_text.lower()
            if needle and needle in haystack:
                matched.append(marker_text)
        return {
            "evaluated": True,
            "success": bool(matched),
            "type": hint_type,
            "evidence": f"response_contains matched={matched}" if matched else "response_contains 未匹配",
            "matched_markers": matched,
        }

    if hint_type == "status_code":
        expected = validation_hint.get("expected") or validation_hint.get("status_code")
        try:
            expected_code = int(expected)
        except (TypeError, ValueError):
            expected_code = 0
        actual = int(result.get("status_code") or 0)
        return {
            "evaluated": bool(expected_code),
            "success": bool(expected_code and actual == expected_code),
            "type": hint_type,
            "evidence": f"actual={actual}, expected={expected_code}",
        }

    if hint_type == "nuclei_match":
        matched = bool(result.get("matched", False))
        return {
            "evaluated": True,
            "success": matched,
            "type": hint_type,
            "evidence": result.get("result_info", "") or f"nuclei matched={matched}",
        }

    if hint_type == "callback":
        received = bool(result.get("callback_received", False))
        return {
            "evaluated": True,
            "success": received,
            "type": hint_type,
            "evidence": result.get("callback_evidence", "") or "callback_received 字段未返回 true",
            "callback_url": validation_hint.get("callback_url", ""),
        }

    if hint_type == "timing":
        try:
            elapsed_ms = float(result.get("elapsed_ms") or result.get("elapsed_seconds", 0) * 1000)
            min_elapsed_ms = float(validation_hint.get("min_elapsed_ms") or 0)
        except (TypeError, ValueError):
            elapsed_ms = 0.0
            min_elapsed_ms = 0.0
        return {
            "evaluated": bool(min_elapsed_ms),
            "success": bool(min_elapsed_ms and elapsed_ms >= min_elapsed_ms),
            "type": hint_type,
            "evidence": f"elapsed_ms={elapsed_ms}, min_elapsed_ms={min_elapsed_ms}",
        }

    return {
        "evaluated": False,
        "success": False,
        "type": hint_type,
        "evidence": f"oracle 类型 {hint_type} 尚未实现",
    }


def _with_executor_metadata(
    result: dict[str, Any],
    executor: str,
    target_url: str,
    target_host: str,
    *,
    request_raw: str = "",
    step_index: int | None = None,
    step_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    enriched = dict(result)
    enriched.setdefault("success", False)
    enriched["executor"] = executor
    enriched["target_url"] = target_url
    enriched["target_host"] = target_host
    if request_raw:
        enriched["request_raw"] = request_raw
    if step_index is not None:
        enriched["step_index"] = step_index
    if step_results is not None:
        enriched["step_results"] = step_results
    return enriched


def _default_target_url() -> str:
    if cfg.attack_env_target_url and not explicit_target_ip():
        return cfg.attack_env_target_url
    target_ip = effective_target_ip()
    if target_ip.startswith(("http://", "https://")):
        return target_ip
    return as_target_url(target_ip)


def _target_host_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc or parsed.path or effective_target_ip()


def _prepare_raw_http(raw_http: str, target_host: str) -> str:
    """Replace TARGET_HOST placeholders and inject Host when missing.

    Some LLM/reference candidates omit the Host header. The local http2pcap
    service rejects those as non-local (`unknown`), so fill Host from the
    current environment target before sending.
    """
    text = str(raw_http or "")
    if not text.strip():
        return text
    host = str(target_host or "").strip()
    if host:
        text = text.replace("{{TARGET_HOST}}", host).replace("{{target_host}}", host)

    normalized = text.replace("\r\n", "\n")
    if not host:
        return normalized.replace("\n", "\r\n") if "\r\n" not in text else text

    # Already has a Host header (after placeholder replacement).
    for line in normalized.split("\n"):
        if line.lower().startswith("host:"):
            value = line.split(":", 1)[1].strip()
            if value and "{{" not in value:
                return normalized.replace("\n", "\r\n") if "\r\n" not in text else text

    # Insert Host after the request line, or at the top if malformed.
    lines = normalized.split("\n")
    insert_at = 1 if lines else 0
    lines.insert(insert_at, f"Host: {host}")
    rebuilt = "\n".join(lines)
    return rebuilt.replace("\n", "\r\n")
