import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.tools import web_extract


class WebExtractTests(unittest.TestCase):
    def test_wayback_failure_falls_back_to_builtin(self):
        with (
            patch.object(web_extract, "cfg", SimpleNamespace(wayback_url="http://extractor")),
            patch.object(
                web_extract,
                "_extract_via_service",
                return_value={"url": "https://example.com", "title": "", "content": "", "error": "502 Bad Gateway"},
            ),
            patch.object(
                web_extract,
                "_extract_builtin",
                return_value={"url": "https://example.com", "title": "ok", "content": "body"},
            ),
        ):
            result = web_extract.extract_url_content("https://example.com")

        self.assertEqual(result["content"], "body")
        self.assertEqual(result["fallback_from"], "wayback")
        self.assertIn("502", result["service_error"])

    def test_wayback_and_builtin_errors_are_combined(self):
        with (
            patch.object(web_extract, "cfg", SimpleNamespace(wayback_url="http://extractor")),
            patch.object(
                web_extract,
                "_extract_via_service",
                return_value={"url": "https://example.com", "title": "", "content": "", "error": "502"},
            ),
            patch.object(
                web_extract,
                "_extract_builtin",
                return_value={"url": "https://example.com", "title": "", "content": "", "error": "timeout"},
            ),
        ):
            result = web_extract.extract_url_content("https://example.com")

        self.assertIn("wayback: 502", result["error"])
        self.assertIn("builtin: timeout", result["error"])


if __name__ == "__main__":
    unittest.main()
