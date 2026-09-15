import unittest

from cve_hunter.status_codes import (
    API_AUTH_FAILED,
    API_REQUEST_FAILED,
    API_QUOTA_EXHAUSTED,
    API_RATE_LIMITED,
    CAPTURE_SUCCESS,
    EXECUTION_POLICY_BLOCKED,
    HTTP2PCAP_SERVICE_FAILED,
    NVD_NOT_FOUND,
    PCAP_CAPTURE_FAILED,
    POC_SOURCE_ACCESS_FAILED,
    TARGET_ACCESS_FAILED,
    URL_ACCESS_FAILED,
    classify_error,
    normalize_status_code,
    prefer_status,
    status_description,
)


class StatusCodeClassificationTests(unittest.TestCase):
    def test_tavily_reference_api_error_is_not_broken_link(self):
        for error, expected in [
            ("Tavily API HTTP 401 (extract): Unauthorized", API_AUTH_FAILED),
            ("Tavily API HTTP 432 (extract): Forbidden", API_AUTH_FAILED),
            ("Tavily API HTTP 503 (extract): unavailable", API_REQUEST_FAILED),
            ("Client error '432 ' for url 'https://api.tavily.com/extract'", API_AUTH_FAILED),
        ]:
            self.assertEqual(classify_error(error, source="reference").code, expected)

    def test_codes_are_chinese(self):
        self.assertEqual(CAPTURE_SUCCESS, "检测命中")
        self.assertEqual(status_description(CAPTURE_SUCCESS), "IPS 精确命中当前 CVE")
        self.assertEqual(normalize_status_code("CAPTURE_SUCCESS"), "检测命中")

    def test_api_quota_exhausted(self):
        hint = classify_error("insufficient_quota: account balance is not enough", source="llm")
        self.assertEqual(hint.code, API_QUOTA_EXHAUSTED)
        self.assertEqual(hint.code, "额度耗尽")

    def test_search_plan_usage_limit_is_quota_exhausted(self):
        hint = classify_error(
            "This request exceeds your plan's set usage limit. Please upgrade your plan.",
            source="web_search",
        )
        self.assertEqual(hint.code, API_QUOTA_EXHAUSTED)

    def test_api_auth_failed(self):
        hint = classify_error("401 unauthorized invalid api key", source="llm")
        self.assertEqual(hint.code, API_AUTH_FAILED)

    def test_nvd_not_found(self):
        hint = classify_error("NVD 中未找到 CVE-2099-0001", source="nvd")
        self.assertEqual(hint.code, NVD_NOT_FOUND)

    def test_rate_limited(self):
        hint = classify_error("429 too many requests", source="tavily")
        self.assertEqual(hint.code, API_RATE_LIMITED)

    def test_url_access_failed(self):
        hint = classify_error("ConnectTimeout timed out", source="reference")
        self.assertEqual(hint.code, URL_ACCESS_FAILED)

    def test_reference_forbidden_is_url_access_failed(self):
        hint = classify_error("Client error '403 Forbidden'", source="reference")
        self.assertEqual(hint.code, URL_ACCESS_FAILED)

    def test_target_access_failed(self):
        hint = classify_error("connection refused", source="target")
        self.assertEqual(hint.code, TARGET_ACCESS_FAILED)

    def test_prefer_higher_priority_status(self):
        selected = prefer_status(URL_ACCESS_FAILED, API_QUOTA_EXHAUSTED)
        self.assertEqual(selected, API_QUOTA_EXHAUSTED)

    def test_api_request_failure_beats_reference_access_failure(self):
        selected = prefer_status(URL_ACCESS_FAILED, API_REQUEST_FAILED)
        self.assertEqual(selected, API_REQUEST_FAILED)

    def test_execution_policy_beats_poc_source_access_failure(self):
        selected = prefer_status(POC_SOURCE_ACCESS_FAILED, EXECUTION_POLICY_BLOCKED)
        self.assertEqual(selected, EXECUTION_POLICY_BLOCKED)

    def test_missing_nuclei_is_http2pcap_service_failed_not_pcap(self):
        hint = classify_error(
            "未找到 nuclei，请安装 Wireshark/Npcap 或设置对应环境变量",
            source="http2pcap",
            error_type="capture_failed",
        )
        self.assertEqual(hint.code, HTTP2PCAP_SERVICE_FAILED)

    def test_empty_capture_is_pcap_capture_failed(self):
        hint = classify_error(
            "抓包完成但未捕获到数据包，请检查 CAPTURE_INTERFACE",
            source="http2pcap",
            error_type="capture_failed",
        )
        self.assertEqual(hint.code, PCAP_CAPTURE_FAILED)

    def test_policy_blocked_host_is_execution_policy(self):
        hint = classify_error(
            "本地服务拒绝非本地/私网目标: unknown",
            source="http2pcap",
            error_type="policy_blocked",
        )
        self.assertEqual(hint.code, EXECUTION_POLICY_BLOCKED)


if __name__ == "__main__":
    unittest.main()
