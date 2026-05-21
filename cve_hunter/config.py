"""全局配置，从环境变量 / .env 文件读取。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def _get_proxy() -> str:
    return (
        os.getenv("HTTPS_PROXY")
        or os.getenv("HTTP_PROXY")
        or os.getenv("http_proxy")
        or os.getenv("https_proxy")
        or ""
    )


@dataclass(frozen=True)
class Config:
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_base_url: str = field(default_factory=lambda: os.getenv("LLM_BASE_URL", "https://api.deepseek.com"))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "deepseek-chat"))

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

    # 输出目录
    output_dir: str = field(default_factory=lambda: os.getenv("OUTPUT_DIR", "output"))

    # 请求超时(秒)
    request_timeout: int = field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "30")))

    # 目标 IP（用于 nuclei PoC 验证）
    target_ip: str = field(default_factory=lambda: os.getenv("TARGET_IP", "127.0.0.1"))

    # HTTP/HTTPS 代理
    proxy: str = field(default_factory=_get_proxy)

    @property
    def httpx_proxy(self) -> str | None:
        """返回 httpx 可用的代理地址，无代理则 None。"""
        return self.proxy or None


cfg = Config()
