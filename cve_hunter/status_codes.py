"""工作流状态码与错误归因（中文标识）。

对外写入 result/batch 的 status_code、failure_class、success_tier 一律使用简明中文。
Python 常量名保留英文，便于代码引用；常量值即中文状态码。
"""

from __future__ import annotations

from dataclasses import dataclass


# ── 成功 ──
CAPTURE_SUCCESS = "检测命中"
TARGET_ORACLE_SUCCESS = "目标命中"
DB_ORACLE_SUCCESS = "数据库命中"

# ── 输入/类型 ──
PARAMETER_ERROR = "参数错误"
NOT_HTTP_VULN = "非HTTP漏洞"  # 兼容旧语义；新路径优先用 协议未支持
PROTOCOL_UNSUPPORTED = "协议未支持"

# ── 情报 ──
NVD_NOT_FOUND = "情报未找到"
NVD_RATE_LIMITED = "情报限流"
NVD_REQUEST_FAILED = "情报失败"

# ── 外部 API ──
API_QUOTA_EXHAUSTED = "额度耗尽"
API_AUTH_FAILED = "鉴权失败"
API_RATE_LIMITED = "接口限流"
API_REQUEST_FAILED = "接口失败"

# ── 候选 ──
URL_ACCESS_FAILED = "链接失败"
WEB_SEARCH_FAILED = "搜索失败"
POC_SOURCE_ACCESS_FAILED = "来源失败"
POC_NOT_FOUND = "无可用PoC"

# ── 执行/基础设施 ──
HTTP2PCAP_SERVICE_FAILED = "发包服务失败"
TARGET_ACCESS_FAILED = "目标不可达"
HTTP_REQUEST_FAILED = "请求失败"
PCAP_CAPTURE_FAILED = "抓包失败"
DB_EXECUTION_FAILED = "数据库执行失败"
DB_ORACLE_FAILED = "数据库验证失败"

# ── 证据/策略/环境 ──
IPS_GENERIC_MATCH_ONLY = "仅通用检测"
TRAFFIC_DETECTED_ONLY = "仅流量检出"
TARGET_ORACLE_FAILED = "目标未验证"
INFRASTRUCTURE_FAILED = "环境失败"
EXECUTION_POLICY_BLOCKED = "策略拦截"
AUTH_OR_PRECONDITION_MISSING = "缺前置条件"
NO_EXPLOIT_EVIDENCE = "无利用证据"
AI_REPRODUCTION_FAILED = "复现失败"
BATCH_EXCEPTION = "批测异常"


# 旧英文码 → 中文码（读取历史结果时兼容）
LEGACY_STATUS_ALIASES = {
    "CAPTURE_SUCCESS": CAPTURE_SUCCESS,
    "TARGET_ORACLE_SUCCESS": TARGET_ORACLE_SUCCESS,
    "PARAMETER_ERROR": PARAMETER_ERROR,
    "NOT_HTTP_VULN": NOT_HTTP_VULN,
    "NVD_NOT_FOUND": NVD_NOT_FOUND,
    "NVD_RATE_LIMITED": NVD_RATE_LIMITED,
    "NVD_REQUEST_FAILED": NVD_REQUEST_FAILED,
    "API_QUOTA_EXHAUSTED": API_QUOTA_EXHAUSTED,
    "API_AUTH_FAILED": API_AUTH_FAILED,
    "API_RATE_LIMITED": API_RATE_LIMITED,
    "API_REQUEST_FAILED": API_REQUEST_FAILED,
    "URL_ACCESS_FAILED": URL_ACCESS_FAILED,
    "WEB_SEARCH_FAILED": WEB_SEARCH_FAILED,
    "POC_SOURCE_ACCESS_FAILED": POC_SOURCE_ACCESS_FAILED,
    "POC_NOT_FOUND": POC_NOT_FOUND,
    "HTTP2PCAP_SERVICE_FAILED": HTTP2PCAP_SERVICE_FAILED,
    "TARGET_ACCESS_FAILED": TARGET_ACCESS_FAILED,
    "HTTP_REQUEST_FAILED": HTTP_REQUEST_FAILED,
    "PCAP_CAPTURE_FAILED": PCAP_CAPTURE_FAILED,
    "IPS_GENERIC_MATCH_ONLY": IPS_GENERIC_MATCH_ONLY,
    "TRAFFIC_DETECTED_ONLY": TRAFFIC_DETECTED_ONLY,
    "TARGET_ORACLE_FAILED": TARGET_ORACLE_FAILED,
    "INFRASTRUCTURE_FAILED": INFRASTRUCTURE_FAILED,
    "EXECUTION_POLICY_BLOCKED": EXECUTION_POLICY_BLOCKED,
    "AUTH_OR_PRECONDITION_MISSING": AUTH_OR_PRECONDITION_MISSING,
    "NO_EXPLOIT_EVIDENCE": NO_EXPLOIT_EVIDENCE,
    "AI_REPRODUCTION_FAILED": AI_REPRODUCTION_FAILED,
    "BATCH_EXCEPTION": BATCH_EXCEPTION,
}


STATUS_DESCRIPTIONS = {
    CAPTURE_SUCCESS: "IPS 精确命中当前 CVE",
    TARGET_ORACLE_SUCCESS: "目标侧验证命中",
    DB_ORACLE_SUCCESS: "数据库侧验证命中",
    PARAMETER_ERROR: "CVE 编号格式错误",
    NOT_HTTP_VULN: "非 HTTP/Web 类漏洞",
    PROTOCOL_UNSUPPORTED: "当前协议执行器未实现",
    NVD_NOT_FOUND: "NVD 未找到该 CVE",
    NVD_RATE_LIMITED: "NVD 限流",
    NVD_REQUEST_FAILED: "NVD 请求失败",
    API_QUOTA_EXHAUSTED: "外部 API 额度/余额耗尽",
    API_AUTH_FAILED: "外部 API 鉴权失败",
    API_RATE_LIMITED: "外部 API 限流",
    API_REQUEST_FAILED: "外部 API 请求失败",
    URL_ACCESS_FAILED: "参考链接访问失败",
    WEB_SEARCH_FAILED: "联网搜索失败",
    POC_SOURCE_ACCESS_FAILED: "PoC 来源访问失败",
    POC_NOT_FOUND: "未找到可用 PoC",
    HTTP2PCAP_SERVICE_FAILED: "发包/抓包服务失败",
    TARGET_ACCESS_FAILED: "目标不可达",
    HTTP_REQUEST_FAILED: "HTTP 请求失败",
    PCAP_CAPTURE_FAILED: "抓包失败",
    DB_EXECUTION_FAILED: "数据库脚本执行失败",
    DB_ORACLE_FAILED: "数据库 oracle 未命中",
    IPS_GENERIC_MATCH_ONLY: "仅有通用检测，未精确匹配当前 CVE",
    TRAFFIC_DETECTED_ONLY: "仅检出攻击流量，目标侧未证实",
    TARGET_ORACLE_FAILED: "目标侧 oracle 未验证成功",
    INFRASTRUCTURE_FAILED: "环境或基础设施失败",
    EXECUTION_POLICY_BLOCKED: "执行策略拦截",
    AUTH_OR_PRECONDITION_MISSING: "缺少认证或其他前置条件",
    NO_EXPLOIT_EVIDENCE: "已执行但无利用证据",
    AI_REPRODUCTION_FAILED: "复现失败",
    BATCH_EXCEPTION: "批测异常",
}


STATUS_PRIORITY = {
    CAPTURE_SUCCESS: 1000,
    TARGET_ORACLE_SUCCESS: 980,
    DB_ORACLE_SUCCESS: 970,
    PARAMETER_ERROR: 950,
    NOT_HTTP_VULN: 900,
    PROTOCOL_UNSUPPORTED: 890,
    API_QUOTA_EXHAUSTED: 850,
    API_AUTH_FAILED: 840,
    NVD_RATE_LIMITED: 830,
    API_RATE_LIMITED: 820,
    NVD_REQUEST_FAILED: 760,
    NVD_NOT_FOUND: 740,
    HTTP2PCAP_SERVICE_FAILED: 700,
    EXECUTION_POLICY_BLOCKED: 690,
    TARGET_ACCESS_FAILED: 680,
    HTTP_REQUEST_FAILED: 660,
    DB_EXECUTION_FAILED: 650,
    PCAP_CAPTURE_FAILED: 640,
    WEB_SEARCH_FAILED: 620,
    API_REQUEST_FAILED: 610,
    URL_ACCESS_FAILED: 600,
    POC_SOURCE_ACCESS_FAILED: 580,
    IPS_GENERIC_MATCH_ONLY: 520,
    TRAFFIC_DETECTED_ONLY: 510,
    AUTH_OR_PRECONDITION_MISSING: 500,
    TARGET_ORACLE_FAILED: 480,
    DB_ORACLE_FAILED: 475,
    INFRASTRUCTURE_FAILED: 470,
    NO_EXPLOIT_EVIDENCE: 460,
    POC_NOT_FOUND: 300,
    AI_REPRODUCTION_FAILED: 100,
    BATCH_EXCEPTION: 50,
}


@dataclass(frozen=True)
class StatusHint:
    code: str
    message: str


def normalize_status_code(code: str) -> str:
    """把历史英文状态码规范为中文状态码。"""
    text = str(code or "").strip()
    if not text:
        return ""
    return LEGACY_STATUS_ALIASES.get(text, text)


def status_description(code: str) -> str:
    normalized = normalize_status_code(code)
    return STATUS_DESCRIPTIONS.get(normalized, normalized or STATUS_DESCRIPTIONS[AI_REPRODUCTION_FAILED])


def prefer_status(current: str, candidate: str) -> str:
    """按优先级保留更有诊断价值的失败状态码。"""
    current_n = normalize_status_code(current)
    candidate_n = normalize_status_code(candidate)
    if not candidate_n:
        return current_n
    if not current_n:
        return candidate_n
    if STATUS_PRIORITY.get(candidate_n, 0) > STATUS_PRIORITY.get(current_n, 0):
        return candidate_n
    return current_n


def make_status_update(current_code: str, candidate_code: str, message: str = "") -> dict[str, str]:
    """生成可合并到 LangGraph update 的状态字段。"""
    selected = prefer_status(current_code, candidate_code)
    current_n = normalize_status_code(current_code)
    if selected != current_n:
        return {"status_code": selected, "message": message or status_description(selected)}
    return {}


def classify_error(error: object, *, source: str = "", error_type: str = "") -> StatusHint:
    """根据错误内容和来源归因到状态码。"""
    source_key = source.strip().lower()
    error_text = _error_text(error, error_type)
    lower = error_text.lower()
    # An API rejection while extracting a reference is not a broken website.
    if "tavily api http " in lower or "for url 'https://api.tavily.com/" in lower:
        source_key = "tavily"
        source = "Tavily API"

    if _contains_any(lower, (
        "insufficient_quota",
        "quota exceeded",
        "quota_exceeded",
        "balance",
        "billing",
        "credit",
        "exhausted",
        "quota",
        "usage limit",
        "usage_limit",
        "exceeds your plan",
        "upgrade your plan",
        "set usage limit",
        "额度",
        "配额",
        "余额",
        "欠费",
    )):
        return StatusHint(API_QUOTA_EXHAUSTED, f"{source or 'API'} 额度或余额耗尽: {error_text}")

    api_like_source = source_key in {"llm", "tavily", "api", "nvd"}
    if _contains_any(lower, ("invalid api key", "invalid_api_key", "无效 api")) or (
        api_like_source
        and _contains_any(lower, ("401", "432", "433", "unauthorized", "authentication", "auth failed", "permission denied", "forbidden"))
    ):
        return StatusHint(API_AUTH_FAILED, f"{source or 'API'} 鉴权失败: {error_text}")

    if _contains_any(lower, ("429", "rate limit", "rate_limit", "too many requests", "限流", "请求过多")):
        if source_key == "nvd":
            return StatusHint(NVD_RATE_LIMITED, f"NVD API 限流: {error_text}")
        return StatusHint(API_RATE_LIMITED, f"{source or 'API'} 限流: {error_text}")

    if "nvd" in source_key:
        if "未找到" in error_text or "not found" in lower:
            return StatusHint(NVD_NOT_FOUND, error_text)
        return StatusHint(NVD_REQUEST_FAILED, f"NVD API 请求失败: {error_text}")

    if source_key == "policy" or error_type.strip().lower() in {"policy", "policy_blocked"}:
        return StatusHint(EXECUTION_POLICY_BLOCKED, error_text or status_description(EXECUTION_POLICY_BLOCKED))

    if source_key in {"database", "sql", "db"}:
        return StatusHint(DB_EXECUTION_FAILED, f"数据库执行失败: {error_text}")

    if "http2pcap" in source_key:
        if _contains_any(lower, ("未找到 nuclei", "nuclei not found", "找不到 nuclei")):
            return StatusHint(HTTP2PCAP_SERVICE_FAILED, f"发包服务失败: {error_text}")
        if _contains_any(lower, ("policy_blocked", "拒绝非本地", "非本地/私网", "non-local")):
            return StatusHint(EXECUTION_POLICY_BLOCKED, error_text)
        if error_type.strip().lower() == "capture_failed" or _contains_any(
            lower,
            ("capture failed", "pcap capture", "抓包失败", "npcap", "未捕获到数据包", "dumpcap"),
        ):
            return StatusHint(PCAP_CAPTURE_FAILED, f"抓包失败: {error_text}")
        return StatusHint(HTTP2PCAP_SERVICE_FAILED, f"发包服务失败: {error_text}")

    if "pcap" in lower or "抓包" in error_text or (
        "capture" in lower and "未找到 nuclei" not in error_text and "nuclei" not in lower
    ):
        return StatusHint(PCAP_CAPTURE_FAILED, f"抓包失败: {error_text}")

    if source_key in {"llm", "tavily", "api"}:
        return StatusHint(API_REQUEST_FAILED, f"{source or 'API'} 请求失败: {error_text}")

    if source_key in {"web_search", "search"}:
        return StatusHint(WEB_SEARCH_FAILED, f"联网搜索失败: {error_text}")

    if source_key in {"url", "reference", "web_extract"}:
        return StatusHint(URL_ACCESS_FAILED, f"网址访问失败: {error_text}")

    if source_key in {"poc_source", "nuclei", "exploit-db", "imfht"}:
        return StatusHint(POC_SOURCE_ACCESS_FAILED, f"PoC 来源访问失败: {error_text}")

    if source_key in {"target", "http_verify"}:
        if _contains_any(lower, ("connect", "connection", "timeout", "timed out", "refused", "unreachable", "no route", "name resolution", "dns", "network")):
            return StatusHint(TARGET_ACCESS_FAILED, f"目标不可达: {error_text}")
        return StatusHint(HTTP_REQUEST_FAILED, f"HTTP 请求失败: {error_text}")

    if _contains_any(lower, ("timeout", "timed out", "connect", "connection", "network", "dns", "name resolution")):
        return StatusHint(URL_ACCESS_FAILED, f"网址访问失败: {error_text}")

    return StatusHint(API_REQUEST_FAILED, error_text or status_description(API_REQUEST_FAILED))


def _error_text(error: object, error_type: str = "") -> str:
    parts = []
    if error_type:
        parts.append(str(error_type))
    if error:
        parts.append(str(error))
    return " | ".join(part.strip() for part in parts if part and str(part).strip()) or "未知错误"


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)
