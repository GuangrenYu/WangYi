"""LangGraph 工作流状态定义。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class CVEState:
    """贯穿整个工作流的状态对象。"""

    # ── 输入 ──
    cve_id: str = ""

    # ── NVD 信息 ──
    nvd_description: str = ""
    nvd_references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_severity: str = ""

    # ── AI 判断 ──
    is_http_vuln: bool = True
    vuln_type: str = ""

    # ── PoC 相关 ──
    reference_contents: list[dict[str, str]] = field(default_factory=list)
    poc_source: str = ""  # reference / nuclei / exploitdb / imfht / search / ai
    poc_raw_http: str = ""
    poc_nuclei_yaml: str = ""
    poc_payloads: list[str] = field(default_factory=list)
    poc_candidates: list[dict[str, Any]] = field(default_factory=list)
    current_candidate_index: int = 0
    attempt_history: list[dict[str, Any]] = field(default_factory=list)
    reflection_rounds: int = 0
    max_reflection_rounds: int = 2

    # ── Agent 中间产物 ──
    agent_trace: list[dict[str, Any]] = field(default_factory=list)
    environment_candidates: list[dict[str, Any]] = field(default_factory=list)
    attack_environment: dict[str, Any] = field(default_factory=dict)
    environment_spec: dict[str, Any] = field(default_factory=dict)
    environment_manifest_path: str = ""
    environment_setup_result: dict[str, Any] = field(default_factory=dict)
    trigger_candidates: list[dict[str, Any]] = field(default_factory=list)
    validation_hints: list[dict[str, Any]] = field(default_factory=list)
    candidate_reviews: list[dict[str, Any]] = field(default_factory=list)
    milestones: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ── 验证结果 ──
    http_status_code: int = 0
    http_response_body: str = ""
    pcap_file_path: str = ""
    ips_matched: bool = False
    generic_ips_matched: bool = False
    ips_match_details: list[dict[str, Any]] = field(default_factory=list)
    cve_ips_match_details: list[dict[str, Any]] = field(default_factory=list)
    generic_ips_match_details: list[dict[str, Any]] = field(default_factory=list)
    ips_match_summary: dict[str, Any] = field(default_factory=dict)
    executor_result: dict[str, Any] = field(default_factory=dict)
    oracle_result: dict[str, Any] = field(default_factory=dict)
    target_oracle_success: bool = False
    target_oracle_type: str = ""
    target_oracle_details: dict[str, Any] = field(default_factory=dict)
    success_level: str = ""

    # ── 流程控制 ──
    current_phase: str = "init"
    phases_tried: list[str] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)

    # ── 最终状态 ──
    status: Literal["SUCCESS", "FAILURE", "SKIPPED"] = "FAILURE"
    status_code: str = ""
    message: str = ""
    analysis_report: str = ""
    generate_report: bool = True  # 是否生成 LLM 分析报告（单CVE默认开启，批量默认关闭）
