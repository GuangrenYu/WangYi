import unittest

from cve_hunter.status_codes import (
    API_AUTH_FAILED,
    API_QUOTA_EXHAUSTED,
    API_RATE_LIMITED,
    NVD_NOT_FOUND,
    TARGET_ACCESS_FAILED,
    URL_ACCESS_FAILED,
    classify_error,
    prefer_status,
)


class StatusCodeClassificationTests(unittest.TestCase):
    def test_api_quota_exhausted(self):
        hint = classify_error("insufficient_quota: account balance is not enough", source="llm")

        self.assertEqual(hint.code, API_QUOTA_EXHAUSTED)

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


if __name__ == "__main__":
    unittest.main()
