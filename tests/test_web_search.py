import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.tools import web_search


class WebSearchFallbackTests(unittest.TestCase):
    def test_tavily_error_falls_back_to_duckduckgo(self):
        with (
            patch.object(web_search, "cfg", SimpleNamespace(tavily_api_key="key")),
            patch.object(
                web_search,
                "_search_tavily",
                return_value=[{"title": "搜索错误", "url": "", "content": "usage limit"}],
            ) as tavily,
            patch.object(
                web_search,
                "_search_duckduckgo",
                return_value=[{"title": "result", "url": "https://example.com", "content": ""}],
            ) as duckduckgo,
        ):
            results = web_search.search_web("CVE-2024-0001 PoC", max_results=3)

        tavily.assert_called_once_with("CVE-2024-0001 PoC", 3)
        duckduckgo.assert_called_once_with("CVE-2024-0001 PoC", 3)
        self.assertEqual(results[0]["title"], "result")

    def test_both_search_errors_are_preserved(self):
        with (
            patch.object(web_search, "cfg", SimpleNamespace(tavily_api_key="key")),
            patch.object(
                web_search,
                "_search_tavily",
                return_value=[{"title": "搜索错误", "url": "", "content": "tavily quota"}],
            ),
            patch.object(
                web_search,
                "_search_duckduckgo",
                return_value=[{"title": "搜索错误", "url": "", "content": "ddg timeout"}],
            ),
        ):
            results = web_search.search_web("CVE-2024-0001 PoC")

        self.assertEqual(results[0]["title"], "搜索错误")
        self.assertIn("Tavily: tavily quota", results[0]["content"])
        self.assertIn("DuckDuckGo: ddg timeout", results[0]["content"])


if __name__ == "__main__":
    unittest.main()
