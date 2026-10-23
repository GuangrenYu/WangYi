"""ReferenceAgent: fetch + cache + quality filter only."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cve_hunter.agents import run_reference_agent
from cve_hunter.state import CVEState
from cve_hunter.tools import ref_cache


class ReferenceAgentTests(unittest.TestCase):
    def setUp(self):
        # This suite tests root reference quality/cache; discovery is tested separately.
        from cve_hunter.tools import reference_crawl
        from types import SimpleNamespace
        self.discovery_config = patch.object(reference_crawl, "cfg", SimpleNamespace(reference_discovery_enabled=False))
        self.discovery_config.start()
        self.addCleanup(self.discovery_config.stop)

    def test_no_nvd_urls_still_runs_source_discovery(self):
        state = CVEState(cve_id="CVE-2020-0001", nvd_description="Example Product remote code execution")
        page = {"url": "https://example.org/poc.py", "content": 'requests.get("http://fixture/path")'}
        with TemporaryDirectory() as tmp, \
                patch.object(ref_cache, "_cache_root", return_value=Path(tmp)), \
                patch("cve_hunter.tools.reference_crawl.enrich_references", return_value={
                    "pages": [page], "errors": [], "elapsed_sec": 1, "budget_sec": 20,
                    "timed_out": False, "scheduled": 1,
                }) as discover:
            result=run_reference_agent(state)
        discover.assert_called_once()
        self.assertTrue(discover.call_args.kwargs["allow_network"])
        self.assertEqual(discover.call_args.kwargs["discovery_context"], state.nvd_description)
        self.assertEqual(result["reference_contents"], [page])

    def test_uses_cache_and_skips_network(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(ref_cache, "_cache_root", return_value=root):
                ref_cache.save_reference_cache(
                    "CVE-2016-6602",
                    [
                        {
                            "url": "https://example.com/a",
                            "title": "cached",
                            "content": "x" * 120,
                        }
                    ],
                )
                state = CVEState(
                    cve_id="CVE-2016-6602",
                    nvd_references=["https://example.com/a", "https://example.com/b"],
                    allow_reference_links=True,
                )
                with patch(
                    "cve_hunter.tools.reference_crawl.enrich_references",
                    return_value={"pages": [
                        {"url": "https://example.com/a", "content": "x" * 120},
                        {"url": "https://example.com/b", "content": "y" * 120}],
                        "errors": [], "elapsed_sec": 0, "budget_sec": 20,
                        "timed_out": False, "scheduled": 1},
                ) as fetch:
                    result = run_reference_agent(state, max_urls=8)

                self.assertEqual(result["trace"]["agent"], "ReferenceAgent")
                self.assertEqual(result["trace"]["data"]["cached_hits"], 1)
                self.assertEqual(result["trace"]["data"]["fetched"], 1)
                self.assertEqual(len(result["reference_contents"]), 2)
                fetch.assert_called_once()
                self.assertEqual(fetch.call_args.kwargs["reference_urls"],
                                 ["https://example.com/a", "https://example.com/b"])

    def test_rejects_too_short_content(self):
        state = CVEState(
            cve_id="CVE-2016-6602",
            nvd_references=["https://example.com/short"],
            allow_reference_links=False,
        )
        with (
            TemporaryDirectory() as tmp,
            patch.object(ref_cache, "_cache_root", return_value=Path(tmp)),
            patch(
                "cve_hunter.tools.reference_crawl.enrich_references",
                return_value={"pages": [], "errors": ["source content too short"],
                              "elapsed_sec": 0, "budget_sec": 20,
                              "timed_out": False, "scheduled": 1},
            ),
        ):
            result = run_reference_agent(state)
        self.assertEqual(result["reference_contents"], [])
        self.assertEqual(result["trace"]["status"], "empty")
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
