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

    # ── 流程控制 ──
    current_phase: str = "init"
    phases_tried: list[str] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)

    # ── 最终状态 ──
    status: Literal["SUCCESS", "FAILURE", "SKIPPED"] = "FAILURE"
    status_code: str = ""
    message: str = ""
    analysis_report: str = ""
