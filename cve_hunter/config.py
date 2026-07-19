"""全局配置，从环境变量 / .env 文件读取。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def _get_proxy() -> str:
    if os.getenv("CVE_HUNTER_DISABLE_PROXY", "").strip().lower() in {"1", "true", "yes", "on"}:
        return ""
    return (
        os.getenv("HTTPS_PROXY")
        or os.getenv("HTTP_PROXY")
        or os.getenv("http_proxy")
        or os.getenv("https_proxy")
        or ""
    )


def _csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.replace("，", ",").split(",") if item.strip()]


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_base_url: str = field(default_factory=lambda: os.getenv("LLM_BASE_URL", "https://api.deepseek.com"))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "deepseek-chat"))
    agent_llm_enabled: bool = field(
        default_factory=lambda: os.getenv("AGENT_LLM_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    )
    agent_llm_model: str = field(default_factory=lambda: os.getenv("AGENT_LLM_MODEL", ""))

    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))

    tavily_api_key: str = field(default_factory=lambda: os.getenv("TAVILY_API_KEY", ""))

    # http2pcap 外部服务地址（可选，不配置则使用内置 scapy 抓包）
    http2pcap_url: str = field(default_factory=lambda: os.getenv("HTTP2PCAP_URL", ""))

    # 防火墙/IPS 检测接口地址（供 http2pcap 服务环境使用）
    ips_api_url: str = field(default_factory=lambda: os.getenv("IPS_API_URL", ""))

    # wayback-cve 外部服务地址（可选，不配置则使用 httpx + trafilatura）
    wayback_url: str = field(default_factory=lambda: os.getenv("WAYBACK_URL", ""))

    # 本地 PoC 知识库目录
    poc_kb_dir: str = field(default_factory=lambda: os.getenv("POC_KB_DIR", "poc_kb"))
    # 工作流导入的本地 PCAP 数据目录，可从已生成攻击报文中反解 Raw HTTP PoC
    local_kb_pcap_dir: str = field(default_factory=lambda: os.getenv("LOCAL_KB_PCAP_DIR", "data/cve/pcaps"))
    # 本地 KB 命中 trickest GitHub 链接时是否继续联网猜测 raw 文件；默认关闭以保证本地搜索秒级返回
    local_kb_github_fetch: bool = field(
        default_factory=lambda: os.getenv("LOCAL_KB_GITHUB_FETCH", "false").strip().lower() in {"1", "true", "yes", "on"}
    )

    # 本地 NVD 数据库目录
    nvd_local_dir: str = field(default_factory=lambda: os.getenv("NVD_LOCAL_DIR", "poc_kb/nvd"))

    # 输出目录
    output_dir: str = field(default_factory=lambda: os.getenv("OUTPUT_DIR", "output"))
    # 测试流量按日期归档到该目录下的 YYYY-MM-DD 子目录
    pcap_output_dir: str = field(default_factory=lambda: os.getenv("PCAP_OUTPUT_DIR", "data/cve/pcaps"))

    # 请求超时(秒)
    request_timeout: int = field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "30")))

    # 目标 IP（用于 nuclei PoC 验证）
    target_ip: str = field(default_factory=lambda: os.getenv("TARGET_IP", "127.0.0.1"))

    # 自动攻击环境搭建（默认关闭，避免批量任务意外拉镜像/启动容器）
    auto_env_enabled: bool = field(
        default_factory=lambda: os.getenv("AUTO_ENV_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    )
    # 本地 vulhub 目录；若存在 **/<CVE-ID>/docker-compose.yml，可自动规划/启动
    vulhub_dir: str = field(default_factory=lambda: os.getenv("VULHUB_DIR", "third_party/vulhub"))
    # 其他本地漏洞环境源。Reapoc 允许 compose 位于 <CVE-ID>/vultarget/ 下。
    reapoc_dir: str = field(default_factory=lambda: os.getenv("REAPOC_DIR", "third_party/reapoc"))
    vulnerability_poc_dir: str = field(
        default_factory=lambda: os.getenv("VULNERABILITY_POC_DIR", "third_party/vulnerability-poc")
    )
    metarget_dir: str = field(default_factory=lambda: os.getenv("METARGET_DIR", "third_party/metarget"))
    environment_repo_auto_clone: bool = field(
        default_factory=lambda: _bool_env("ENVIRONMENT_REPO_AUTO_CLONE", True)
    )
    environment_healthcheck_timeout: int = field(
        default_factory=lambda: _int_env("ENVIRONMENT_HEALTHCHECK_TIMEOUT", 90)
    )
    environment_auto_cleanup: bool = field(
        default_factory=lambda: _bool_env("ENVIRONMENT_AUTO_CLEANUP", True)
    )
    # Metarget 会修改宿主机 Docker/Kubernetes/内核，必须单独显式授权。
    metarget_execution_enabled: bool = field(
        default_factory=lambda: _bool_env("METARGET_EXECUTION_ENABLED", False)
    )
    metarget_target_url: str = field(default_factory=lambda: os.getenv("METARGET_TARGET_URL", ""))
    # Vulfocus 开放 API。未配置完整认证信息时仅禁用该 provider，不影响其他环境源。
    vulfocus_api_url: str = field(default_factory=lambda: os.getenv("VULFOCUS_API_URL", ""))
    vulfocus_username: str = field(default_factory=lambda: os.getenv("VULFOCUS_USERNAME", ""))
    vulfocus_licence: str = field(default_factory=lambda: os.getenv("VULFOCUS_LICENCE", ""))
    # 显式指定 docker-compose 文件时优先使用
    attack_env_compose_file: str = field(default_factory=lambda: os.getenv("ATTACK_ENV_COMPOSE_FILE", ""))
    # 自动环境目标 URL；不配置时从 compose 端口映射猜测，猜不到则回退 TARGET_IP
    attack_env_target_url: str = field(default_factory=lambda: os.getenv("ATTACK_ENV_TARGET_URL", ""))
    # SSRF/RCE 等目标侧 oracle 可使用的回连地址
    callback_url: str = field(default_factory=lambda: os.getenv("CALLBACK_URL", ""))

    # 执行策略：默认只规划不发包。local_lab 仅允许本地/私有地址或 allowlist；
    # authorized_target 必须命中 allowlist。
    run_mode: str = field(default_factory=lambda: os.getenv("RUN_MODE", "plan_only").strip().lower())
    target_allowlist: list[str] = field(default_factory=lambda: _csv_env("TARGET_ALLOWLIST"))
    max_requests_per_cve: int = field(default_factory=lambda: _int_env("MAX_REQUESTS_PER_CVE", 20))
    max_candidates_per_cve: int = field(default_factory=lambda: _int_env("MAX_CANDIDATES_PER_CVE", 50))

    # HTTP/HTTPS 代理
    proxy: str = field(default_factory=_get_proxy)

    @property
    def httpx_proxy(self) -> str | None:
        """返回 httpx 可用的代理地址，无代理则 None。"""
        return self.proxy or None

    @property
    def effective_agent_llm_model(self) -> str:
        """Agent 专用模型；未配置时复用主 LLM_MODEL。"""
        return self.agent_llm_model or self.llm_model


cfg = Config()
