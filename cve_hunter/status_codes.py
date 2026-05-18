"""工作流状态码与错误归因。"""

from __future__ import annotations

from dataclasses import dataclass


CAPTURE_SUCCESS = "CAPTURE_SUCCESS"
PARAMETER_ERROR = "PARAMETER_ERROR"
NOT_HTTP_VULN = "NOT_HTTP_VULN"

NVD_NOT_FOUND = "NVD_NOT_FOUND"
NVD_RATE_LIMITED = "NVD_RATE_LIMITED"
NVD_REQUEST_FAILED = "NVD_REQUEST_FAILED"

API_QUOTA_EXHAUSTED = "API_QUOTA_EXHAUSTED"
API_AUTH_FAILED = "API_AUTH_FAILED"
API_RATE_LIMITED = "API_RATE_LIMITED"
API_REQUEST_FAILED = "API_REQUEST_FAILED"

URL_ACCESS_FAILED = "URL_ACCESS_FAILED"
WEB_SEARCH_FAILED = "WEB_SEARCH_FAILED"
POC_SOURCE_ACCESS_FAILED = "POC_SOURCE_ACCESS_FAILED"
POC_NOT_FOUND = "POC_NOT_FOUND"

HTTP2PCAP_SERVICE_FAILED = "HTTP2PCAP_SERVICE_FAILED"
TARGET_ACCESS_FAILED = "TARGET_ACCESS_FAILED"
HTTP_REQUEST_FAILED = "HTTP_REQUEST_FAILED"
PCAP_CAPTURE_FAILED = "PCAP_CAPTURE_FAILED"
IPS_GENERIC_MATCH_ONLY = "IPS_GENERIC_MATCH_ONLY"

AI_REPRODUCTION_FAILED = "AI_REPRODUCTION_FAILED"
BATCH_EXCEPTION = "BATCH_EXCEPTION"


STATUS_DESCRIPTIONS = {
    CAPTURE_SUCCESS: "PoC 验证成功，IPS 日志 CVE 字段匹配当前 CVE",
    PARAMETER_ERROR: "CVE 编号格式错误",
    NOT_HTTP_VULN: "非 HTTP/Web 类漏洞",
    NVD_NOT_FOUND: "NVD 中未找到该 CVE",
    NVD_RATE_LIMITED: "NVD API 限流或配额限制",
    NVD_REQUEST_FAILED: "NVD API 请求失败",
    API_QUOTA_EXHAUSTED: "外部 API 余额或额度耗尽",
    API_AUTH_FAILED: "外部 API 鉴权失败",
    API_RATE_LIMITED: "外部 API 限流",
    API_REQUEST_FAILED: "外部 API 请求失败",
    URL_ACCESS_FAILED: "参考链接或网页访问失败",
    WEB_SEARCH_FAILED: "联网搜索失败",
    POC_SOURCE_ACCESS_FAILED: "PoC 来源站点访问失败",
    POC_NOT_FOUND: "未找到可用 PoC",
    HTTP2PCAP_SERVICE_FAILED: "http2pcap 服务调用失败",
    TARGET_ACCESS_FAILED: "目标网址访问失败",
    HTTP_REQUEST_FAILED: "PoC HTTP 请求发送失败",
    PCAP_CAPTURE_FAILED: "PCAP 抓包失败",
    IPS_GENERIC_MATCH_ONLY: "只检测到通用/非当前 CVE IPS 命中",
    AI_REPRODUCTION_FAILED: "所有源均已尝试，未能命中当前 CVE 的 IPS 规则",
    BATCH_EXCEPTION: "批量任务执行异常",
}


STATUS_PRIORITY = {
    CAPTURE_SUCCESS: 1000,
    PARAMETER_ERROR: 950,
    NOT_HTTP_VULN: 900,
    API_QUOTA_EXHAUSTED: 850,
    API_AUTH_FAILED: 840,
    NVD_RATE_LIMITED: 830,
    API_RATE_LIMITED: 820,
    NVD_REQUEST_FAILED: 760,
    NVD_NOT_FOUND: 740,
    HTTP2PCAP_SERVICE_FAILED: 700,
    TARGET_ACCESS_FAILED: 680,
    HTTP_REQUEST_FAILED: 660,
    PCAP_CAPTURE_FAILED: 640,
    WEB_SEARCH_FAILED: 620,
    URL_ACCESS_FAILED: 600,
    POC_SOURCE_ACCESS_FAILED: 580,
    API_REQUEST_FAILED: 560,
    IPS_GENERIC_MATCH_ONLY: 520,
    POC_NOT_FOUND: 300,
    AI_REPRODUCTION_FAILED: 100,
    BATCH_EXCEPTION: 50,
}


@dataclass(frozen=True)
class StatusHint:
    code: str
    message: str


def status_description(code: str) -> str:
    return STATUS_DESCRIPTIONS.get(code, code or STATUS_DESCRIPTIONS[AI_REPRODUCTION_FAILED])


def prefer_status(current: str, candidate: str) -> str:
    """按优先级保留更有诊断价值的失败状态码。"""
    if not candidate:
        return current
    if not current:
        return candidate
    if STATUS_PRIORITY.get(candidate, 0) > STATUS_PRIORITY.get(current, 0):
        return candidate
    return current


def make_status_update(current_code: str, candidate_code: str, message: str = "") -> dict[str, str]:
    """生成可合并到 LangGraph update 的状态字段。"""
    selected = prefer_status(current_code, candidate_code)
    if selected != current_code:
        return {"status_code": selected, "message": message or status_description(selected)}
    return {}


def classify_error(error: object, *, source: str = "", error_type: str = "") -> StatusHint:
    """根据错误内容和来源归因到状态码。"""
    source_key = source.strip().lower()
    error_text = _error_text(error, error_type)
    lower = error_text.lower()

    if _contains_any(lower, ("insufficient_quota", "quota exceeded", "quota_exceeded", "balance", "billing", "credit", "exhausted", "quota", "额度", "配额", "余额", "欠费")):
        return StatusHint(API_QUOTA_EXHAUSTED, f"{source or 'API'} 额度或余额耗尽: {error_text}")

    api_like_source = source_key in {"llm", "tavily", "api", "nvd"}
    if _contains_any(lower, ("invalid api key", "invalid_api_key", "无效 api")) or (
        api_like_source
        and _contains_any(lower, ("401", "unauthorized", "authentication", "auth failed", "permission denied", "forbidden"))
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

    if "http2pcap" in source_key:
        if _contains_any(lower, ("capture failed", "pcap capture", "抓包失败", "npcap", "permission")):
            return StatusHint(PCAP_CAPTURE_FAILED, f"PCAP 抓包失败: {error_text}")
        return StatusHint(HTTP2PCAP_SERVICE_FAILED, f"http2pcap 服务调用失败: {error_text}")

    if "pcap" in lower or "capture" in lower or "抓包" in error_text:
        return StatusHint(PCAP_CAPTURE_FAILED, f"PCAP 抓包失败: {error_text}")

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
            return StatusHint(TARGET_ACCESS_FAILED, f"目标网址访问失败: {error_text}")
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
