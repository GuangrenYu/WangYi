"""成功层级、失败归因与可重放归档。

成功层级（写入 result/batch 的 success_tier）：
- 连通 / 已执行 / 目标证据 / 检测证据 / 可复现归档 / 无

失败归因（failure_class）：
- 无 / 输入 / 情报 / 环境 / 前置 / 候选 / 执行 / 证据 / 策略 / 设施 / 未知
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from cve_hunter.status_codes import (
    AI_REPRODUCTION_FAILED,
    AUTH_OR_PRECONDITION_MISSING,
    BATCH_EXCEPTION,
    CAPTURE_SUCCESS,
    DB_EXECUTION_FAILED,
    DB_ORACLE_FAILED,
    DB_ORACLE_SUCCESS,
    EXECUTION_POLICY_BLOCKED,
    HTTP2PCAP_SERVICE_FAILED,
    HTTP_REQUEST_FAILED,
    INFRASTRUCTURE_FAILED,
    IPS_GENERIC_MATCH_ONLY,
    NOT_HTTP_VULN,
    NO_EXPLOIT_EVIDENCE,
    NVD_NOT_FOUND,
    NVD_RATE_LIMITED,
    NVD_REQUEST_FAILED,
    PARAMETER_ERROR,
    PCAP_CAPTURE_FAILED,
    POC_NOT_FOUND,
    POC_SOURCE_ACCESS_FAILED,
    PROTOCOL_UNSUPPORTED,
    TARGET_ACCESS_FAILED,
    TARGET_ORACLE_FAILED,
    TARGET_ORACLE_SUCCESS,
    TRAFFIC_DETECTED_ONLY,
    URL_ACCESS_FAILED,
    WEB_SEARCH_FAILED,
    API_AUTH_FAILED,
    API_QUOTA_EXHAUSTED,
    API_RATE_LIMITED,
    API_REQUEST_FAILED,
    normalize_status_code,
)


# 成功层级（中文）
SUCCESS_TIER_L0 = "连通"
SUCCESS_TIER_L1 = "已执行"
SUCCESS_TIER_L2 = "目标证据"
SUCCESS_TIER_L3 = "检测证据"
SUCCESS_TIER_L4 = "可复现归档"
SUCCESS_TIER_NONE = "无"

# 兼容旧英文层级
_LEGACY_TIER = {
    "L0_connectivity": SUCCESS_TIER_L0,
    "L1_executed": SUCCESS_TIER_L1,
    "L2_target_evidence": SUCCESS_TIER_L2,
    "L3_detection_evidence": SUCCESS_TIER_L3,
    "L4_repro_archived": SUCCESS_TIER_L4,
    "L_none": SUCCESS_TIER_NONE,
}

# 失败归因（中文）
FAILURE_CLASS_NONE = "无"
FAILURE_CLASS_INPUT = "输入"
FAILURE_CLASS_INTEL = "情报"
FAILURE_CLASS_ENVIRONMENT = "环境"
FAILURE_CLASS_PRECONDITION = "前置"
FAILURE_CLASS_CANDIDATE = "候选"
FAILURE_CLASS_EXECUTION = "执行"
FAILURE_CLASS_EVIDENCE = "证据"
FAILURE_CLASS_POLICY = "策略"
FAILURE_CLASS_INFRA = "设施"
FAILURE_CLASS_UNKNOWN = "未知"

_LEGACY_FAILURE = {
    "none": FAILURE_CLASS_NONE,
    "input": FAILURE_CLASS_INPUT,
    "intel": FAILURE_CLASS_INTEL,
    "environment": FAILURE_CLASS_ENVIRONMENT,
    "precondition": FAILURE_CLASS_PRECONDITION,
    "candidate": FAILURE_CLASS_CANDIDATE,
    "execution": FAILURE_CLASS_EXECUTION,
    "evidence": FAILURE_CLASS_EVIDENCE,
    "policy": FAILURE_CLASS_POLICY,
    "infrastructure": FAILURE_CLASS_INFRA,
    "unknown": FAILURE_CLASS_UNKNOWN,
}

_STATUS_TO_FAILURE_CLASS = {
    PARAMETER_ERROR: FAILURE_CLASS_INPUT,
    NOT_HTTP_VULN: FAILURE_CLASS_INPUT,
    PROTOCOL_UNSUPPORTED: FAILURE_CLASS_INPUT,
    NVD_NOT_FOUND: FAILURE_CLASS_INTEL,
    NVD_RATE_LIMITED: FAILURE_CLASS_INTEL,
    NVD_REQUEST_FAILED: FAILURE_CLASS_INTEL,
    API_QUOTA_EXHAUSTED: FAILURE_CLASS_INFRA,
    API_AUTH_FAILED: FAILURE_CLASS_INFRA,
    API_RATE_LIMITED: FAILURE_CLASS_INFRA,
    API_REQUEST_FAILED: FAILURE_CLASS_INFRA,
    URL_ACCESS_FAILED: FAILURE_CLASS_CANDIDATE,
    WEB_SEARCH_FAILED: FAILURE_CLASS_CANDIDATE,
    POC_SOURCE_ACCESS_FAILED: FAILURE_CLASS_CANDIDATE,
    POC_NOT_FOUND: FAILURE_CLASS_CANDIDATE,
    HTTP2PCAP_SERVICE_FAILED: FAILURE_CLASS_INFRA,
    TARGET_ACCESS_FAILED: FAILURE_CLASS_EXECUTION,
    HTTP_REQUEST_FAILED: FAILURE_CLASS_EXECUTION,
    DB_EXECUTION_FAILED: FAILURE_CLASS_EXECUTION,
    PCAP_CAPTURE_FAILED: FAILURE_CLASS_INFRA,
    IPS_GENERIC_MATCH_ONLY: FAILURE_CLASS_EVIDENCE,
    TRAFFIC_DETECTED_ONLY: FAILURE_CLASS_EVIDENCE,
    TARGET_ORACLE_FAILED: FAILURE_CLASS_EVIDENCE,
    DB_ORACLE_FAILED: FAILURE_CLASS_EVIDENCE,
    NO_EXPLOIT_EVIDENCE: FAILURE_CLASS_EVIDENCE,
    INFRASTRUCTURE_FAILED: FAILURE_CLASS_ENVIRONMENT,
    EXECUTION_POLICY_BLOCKED: FAILURE_CLASS_POLICY,
    AUTH_OR_PRECONDITION_MISSING: FAILURE_CLASS_PRECONDITION,
    AI_REPRODUCTION_FAILED: FAILURE_CLASS_EVIDENCE,
    BATCH_EXCEPTION: FAILURE_CLASS_INFRA,
    CAPTURE_SUCCESS: FAILURE_CLASS_NONE,
    TARGET_ORACLE_SUCCESS: FAILURE_CLASS_NONE,
    DB_ORACLE_SUCCESS: FAILURE_CLASS_NONE,
}


def classify_failure(status_code: str) -> str:
    """状态码 → 中文失败归因。"""
    code = normalize_status_code(status_code)
    if not code:
        return FAILURE_CLASS_UNKNOWN
    mapped = _STATUS_TO_FAILURE_CLASS.get(code)
    if mapped:
        return mapped
    # 兼容旧英文归因直接传入
    return _LEGACY_FAILURE.get(str(status_code or "").strip(), FAILURE_CLASS_UNKNOWN)


def normalize_failure_class(value: str) -> str:
    """把历史英文失败归因或状态码规范为中文归因。"""
    text = str(value or "").strip()
    if not text:
        return FAILURE_CLASS_UNKNOWN
    if text in _LEGACY_FAILURE:
        return _LEGACY_FAILURE[text]
    # 已是中文归因
    if text in {
        FAILURE_CLASS_NONE,
        FAILURE_CLASS_INPUT,
        FAILURE_CLASS_INTEL,
        FAILURE_CLASS_ENVIRONMENT,
        FAILURE_CLASS_PRECONDITION,
        FAILURE_CLASS_CANDIDATE,
        FAILURE_CLASS_EXECUTION,
        FAILURE_CLASS_EVIDENCE,
        FAILURE_CLASS_POLICY,
        FAILURE_CLASS_INFRA,
        FAILURE_CLASS_UNKNOWN,
    }:
        return text
    # 把状态码也映射到归因
    return classify_failure(text)


def normalize_success_tier(tier: str) -> str:
    text = str(tier or "").strip()
    return _LEGACY_TIER.get(text, text or SUCCESS_TIER_NONE)


def _milestone_status(milestones: dict[str, Any] | None, name: str) -> str:
    item = (milestones or {}).get(name) or {}
    return str(item.get("status") or "")


def _has_successful_request(attempt_history: list[dict[str, Any]] | None) -> bool:
    for item in attempt_history or []:
        if bool(item.get("request_success")):
            return True
    return False


def derive_success_tier(
    *,
    status_code: str = "",
    success_level: str = "",
    milestones: dict[str, Any] | None = None,
    attempt_history: list[dict[str, Any]] | None = None,
    ips_matched: bool = False,
    target_oracle_success: bool = False,
    repro_bundle_complete: bool = False,
    cleanup_status: str = "",
) -> str:
    """根据最终信号推导中文成功层级。"""
    code = normalize_status_code(status_code)
    level = str(success_level or "")
    cleanup = str(cleanup_status or _milestone_status(milestones, "environment_cleanup"))

    if ips_matched or code == CAPTURE_SUCCESS or level == "ips_cve_match":
        base = SUCCESS_TIER_L3
    elif (
        target_oracle_success
        or code in {TARGET_ORACLE_SUCCESS, DB_ORACLE_SUCCESS}
        or level in {"target_oracle", "database_oracle"}
    ):
        base = SUCCESS_TIER_L2
    elif _has_successful_request(attempt_history) or level in {
        "no_exploit_evidence",
        "generic_ips_only",
    }:
        base = SUCCESS_TIER_L1
    elif _milestone_status(milestones, "environment_ready") == "passed":
        base = SUCCESS_TIER_L0
    else:
        base = SUCCESS_TIER_NONE

    if base in {SUCCESS_TIER_L2, SUCCESS_TIER_L3} and repro_bundle_complete and cleanup in {"passed", "skipped"}:
        return SUCCESS_TIER_L4
    return base


def build_version_evidence(
    *,
    cve_id: str = "",
    nvd_description: str = "",
    attack_environment: dict[str, Any] | None = None,
    execution_spec: dict[str, Any] | None = None,
    executor_result: dict[str, Any] | None = None,
    oracle_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """从 NVD 描述、compose 镜像标签与执行结果拼装 claimed/verified 版本线索。

    不是完整 vulnerable/fixed 对照，而是可归档的轻量证据链：
    - claimed: 情报/文档宣称的受影响版本与镜像
    - verified: 实际环境/查询观察到的版本线索
    """
    import re

    env = attack_environment or {}
    spec = execution_spec or {}
    executor = executor_result or {}
    oracle = oracle_result or {}

    claimed_versions: list[str] = []
    # NVD 常见 "9.3 through 11.2" / "5.5.x before 5.5.24"
    for match in re.finditer(
        r"(\d+(?:\.\d+){0,3})\s*(?:through|to|–|-|—)\s*(\d+(?:\.\d+){0,3})",
        nvd_description or "",
        re.I,
    ):
        claimed_versions.append(f"{match.group(1)}-{match.group(2)}")
    for match in re.finditer(
        r"(?:before|prior to|<)\s*(\d+(?:\.\d+){1,3})",
        nvd_description or "",
        re.I,
    ):
        claimed_versions.append(f"<{match.group(1)}")

    compose_file = str(env.get("compose_file") or "")
    image_tags: list[str] = []
    if compose_file:
        try:
            text = Path(compose_file).read_text(encoding="utf-8", errors="ignore")
            image_tags = re.findall(r"image:\s*([^\s#]+)", text, re.I)
        except OSError:
            # 端口重映射后可能指向临时 yml，回退 workdir
            workdir = str(env.get("workdir") or "")
            for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml"):
                candidate = Path(workdir) / name if workdir else Path()
                if candidate.is_file():
                    try:
                        text = candidate.read_text(encoding="utf-8", errors="ignore")
                        image_tags = re.findall(r"image:\s*([^\s#]+)", text, re.I)
                        break
                    except OSError:
                        pass

    verified_versions: list[str] = []
    # 执行日志 / body 中的 version() 结果
    blobs = [
        str(executor.get("body") or ""),
        str((oracle.get("target_oracle") or {}).get("evidence") or ""),
        json.dumps(executor.get("logs") or [], ensure_ascii=False),
    ]
    for blob in blobs:
        for match in re.finditer(
            r"(PostgreSQL|MySQL|MariaDB)\s+(\d+\.\d+(?:\.\d+)?)",
            blob,
            re.I,
        ):
            verified_versions.append(f"{match.group(1)} {match.group(2)}")
        for match in re.finditer(r"\b(\d+\.\d+\.\d+)\b", blob):
            # 镜像标签式版本，弱证据
            if match.group(1) not in " ".join(verified_versions):
                pass
    for tag in image_tags:
        if ":" in tag:
            verified_versions.append(f"image:{tag}")

    # 去重保序
    def _uniq(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            key = item.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(item.strip())
        return out

    claimed_versions = _uniq(claimed_versions)
    verified_versions = _uniq(verified_versions)
    image_tags = _uniq(image_tags)

    return {
        "cve_id": cve_id,
        "claimed": {
            "source": "nvd_description",
            "version_ranges": claimed_versions,
            "notes": "从 NVD 描述启发式抽取的受影响版本区间，非官方 CPE 解析",
        },
        "environment": {
            "compose_file": compose_file,
            "image_tags": image_tags,
            "target_url": str(env.get("target_url") or env.get("target_host") or ""),
            "engine": str(spec.get("engine") or executor.get("engine") or ""),
        },
        "verified": {
            "source": "runtime_or_image",
            "observations": verified_versions,
            "oracle_type": str((oracle.get("target_oracle") or executor.get("oracle") or {}).get("type") or ""),
            "notes": "来自镜像标签与/或执行输出中的版本字符串；不等于完整 fixed 对照",
        },
        "comparison": {
            "has_claimed": bool(claimed_versions),
            "has_verified": bool(verified_versions),
            "status": (
                "claimed_and_verified"
                if claimed_versions and verified_versions
                else "claimed_only"
                if claimed_versions
                else "verified_only"
                if verified_versions
                else "empty"
            ),
        },
    }


def write_repro_bundle(
    output_dir: Path,
    *,
    cve_id: str,
    status: str,
    status_code: str,
    message: str,
    success_tier: str,
    failure_class: str,
    success_level: str,
    poc_source: str,
    poc_raw_http: str = "",
    poc_nuclei_yaml: str = "",
    pcap_file_path: str = "",
    attack_environment: dict[str, Any] | None = None,
    environment_spec: dict[str, Any] | None = None,
    environment_teardown_result: dict[str, Any] | None = None,
    oracle_result: dict[str, Any] | None = None,
    executor_result: dict[str, Any] | None = None,
    milestones: dict[str, Any] | None = None,
    attempt_history: list[dict[str, Any]] | None = None,
    execution_spec: dict[str, Any] | None = None,
    version_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """写入 output/<CVE>/repro/ 可重放包。"""
    repro_dir = Path(output_dir) / "repro"
    trigger_dir = repro_dir / "trigger"
    evidence_dir = repro_dir / "evidence"
    repro_dir.mkdir(parents=True, exist_ok=True)
    trigger_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, str] = {}
    errors: list[str] = []
    tier = normalize_success_tier(success_tier)
    fclass = classify_failure(status_code) if failure_class in {"", "unknown", "未知"} else (
        _LEGACY_FAILURE.get(failure_class, failure_class)
    )

    if poc_raw_http:
        path = trigger_dir / "poc.http"
        path.write_text(poc_raw_http, encoding="utf-8")
        artifacts["poc_http"] = str(path)
    if poc_nuclei_yaml:
        path = trigger_dir / "poc.yaml"
        path.write_text(poc_nuclei_yaml, encoding="utf-8")
        artifacts["poc_yaml"] = str(path)
    if execution_spec:
        path = trigger_dir / "execution_spec.json"
        path.write_text(json.dumps(execution_spec, ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts["execution_spec"] = str(path)

    last_success = None
    for item in reversed(attempt_history or []):
        if item.get("request_success"):
            last_success = item
            break
    if last_success:
        path = evidence_dir / "last_successful_attempt.json"
        path.write_text(json.dumps(last_success, ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts["last_successful_attempt"] = str(path)

    if oracle_result:
        path = evidence_dir / "oracle.json"
        path.write_text(json.dumps(oracle_result, ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts["oracle"] = str(path)
    if executor_result:
        path = evidence_dir / "executor.json"
        slim = dict(executor_result)
        body = str(slim.get("body") or "")
        if len(body) > 4000:
            slim["body"] = body[:4000] + "\n...<truncated>..."
        path.write_text(json.dumps(slim, ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts["executor"] = str(path)

    version_payload = version_evidence
    if version_payload is None:
        version_payload = build_version_evidence(
            cve_id=cve_id,
            attack_environment=attack_environment,
            execution_spec=execution_spec,
            executor_result=executor_result,
            oracle_result=oracle_result,
        )
    if version_payload:
        path = evidence_dir / "version_evidence.json"
        path.write_text(json.dumps(version_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts["version_evidence"] = str(path)

    if pcap_file_path:
        src = Path(pcap_file_path)
        if src.is_file():
            dest = evidence_dir / src.name
            try:
                shutil.copy2(src, dest)
                artifacts["pcap"] = str(dest)
            except OSError as exc:
                errors.append(f"复制 pcap 失败: {exc}")
        else:
            errors.append(f"pcap 不存在: {pcap_file_path}")

    env_path = repro_dir / "environment.json"
    env_path.write_text(
        json.dumps(
            {
                "attack_environment": attack_environment or {},
                "environment_spec": environment_spec or {},
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    artifacts["environment"] = str(env_path)

    teardown_path = repro_dir / "teardown.json"
    teardown_path.write_text(
        json.dumps(environment_teardown_result or {}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    artifacts["teardown"] = str(teardown_path)

    if milestones:
        ms_path = repro_dir / "milestones.json"
        ms_path.write_text(json.dumps(milestones, ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts["milestones"] = str(ms_path)

    complete = bool(
        tier in {SUCCESS_TIER_L2, SUCCESS_TIER_L3, SUCCESS_TIER_L4}
        and (
            artifacts.get("poc_http")
            or artifacts.get("poc_yaml")
            or artifacts.get("execution_spec")
            or artifacts.get("last_successful_attempt")
        )
        and (artifacts.get("oracle") or artifacts.get("pcap") or artifacts.get("executor"))
        and artifacts.get("environment")
        and artifacts.get("teardown")
        and not errors
    )

    manifest = {
        "cve_id": cve_id,
        "status": status,
        "status_code": normalize_status_code(status_code),
        "message": message,
        "success_tier": tier,
        "failure_class": fclass,
        "success_level": success_level,
        "poc_source": poc_source,
        "complete": complete,
        "artifacts": artifacts,
        "errors": errors,
        "timestamp": datetime.now().isoformat(),
    }
    manifest_path = repro_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    replay = [
        f"# {cve_id} 重放说明",
        "",
        f"- 状态: `{status}` / `{normalize_status_code(status_code)}`",
        f"- 成功层级: `{tier}`",
        f"- 失败归因: `{fclass}`",
        f"- 归档完整: `{complete}`",
        "",
        "## 环境",
        "",
        "见 `environment.json`。仅在授权本地靶场重放。",
        "",
        "## 触发",
        "",
    ]
    if artifacts.get("poc_http"):
        replay.append("- HTTP: `trigger/poc.http`")
    if artifacts.get("poc_yaml"):
        replay.append("- Nuclei: `trigger/poc.yaml`")
    if artifacts.get("execution_spec"):
        replay.append("- 执行规格: `trigger/execution_spec.json`")
    if not any(artifacts.get(k) for k in ("poc_http", "poc_yaml", "execution_spec")):
        replay.append("- 无独立触发文件")
    replay.extend(
        [
            "",
            "## 证据",
            "",
            "- `evidence/` 下 oracle/executor/pcap",
            "- `teardown.json` 回收记录",
            "",
            "```bash",
            f"python main.py {cve_id} --local-container",
            "```",
            "",
        ]
    )
    (repro_dir / "replay.md").write_text("\n".join(replay), encoding="utf-8")

    return {
        "path": str(repro_dir),
        "manifest_path": str(manifest_path),
        "complete": complete,
        "artifacts": artifacts,
        "errors": errors,
        "success_tier": tier,
        "failure_class": fclass,
    }
