"""Reference enrichment tests use fixtures only; no target traffic."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx

from cve_hunter.tools import ref_cache, reference_crawl
from cve_hunter.tools.reference_evidence import (
    extract_links, page_from_response, reference_prompt_text, structure_reference,
)


class ReferenceEvidenceTests(unittest.TestCase):
    def test_html_preserves_code_relative_links_and_title(self):
        html = '''<html><head><title>Fixture</title></head><body><article>
        <p>This advisory contains a reproducible example and describes the prerequisites.</p>
        <p>Authentication is not required. Affected versions: 1.0 through 1.2.</p>
        <a href="/files/poc.py">PoC source</a><pre>print(&quot;fixture&quot;)\n</pre>
        </article></body></html>'''
        page = structure_reference(page_from_response("https://example.org/advisory", html, "text/html"))
        self.assertEqual(page["title"], "Fixture")
        evidence = page["poc_evidence"]
        self.assertEqual(evidence["code_blocks"][0]["text"], 'print("fixture")')
        self.assertEqual(evidence["poc_links"][0]["url"], "https://example.org/files/poc.py")
        self.assertIn("not required", evidence["conditions"]["authentication"][0]["quote"])

    def test_plain_code_is_not_passed_through_prose_extraction(self):
        code = '# fixture\nprint("hello")\n'
        page = structure_reference(page_from_response("https://example.org/poc.py", code, "text/plain"))
        self.assertEqual(page["content"], code)
        self.assertEqual(page["poc_evidence"]["code_blocks"][0]["text"], code)

    def test_links_exclude_request_examples_and_keep_relative_poc(self):
        links = extract_links(
            '[PoC](../files/poc.py) https://example.org/exploit?cmd=test '
            'http://{{TARGET_HOST}}/exploit https://example.org/image.png',
            "https://example.org/blog/advisory",
        )
        self.assertEqual([link["url"] for link in links], ["https://example.org/files/poc.py"])

    def test_malformed_ipv6_example_does_not_break_evidence_extraction(self):
        links = extract_links("http://[TARGET]/poc https://github.com/org/repo", "https://example.org/")
        self.assertEqual([link["url"] for link in links], ["https://github.com/org/repo"])

    def test_truncated_source_is_not_labelled_complete_code(self):
        page = structure_reference(page_from_response("https://example.org/poc.py", "x" * 30000))
        self.assertTrue(page["content_truncated"])
        self.assertEqual(page["poc_evidence"]["code_blocks"], [])

    def test_late_code_and_conditions_reach_prompt_without_extra_llm(self):
        page = {"url": "https://example.org/advisory", "content":
                "Introduction. " * 500 + '\nRequires Python 3.\n```python\nprint("late evidence")\n```'}
        text = reference_prompt_text([page])
        self.assertIn('print("late evidence")', text)
        self.assertIn("Requires Python 3.", text)
        self.assertLessEqual(len(text), 12000)

    def test_cache_retains_structure_and_descendant_provenance(self):
        page = structure_reference({"url": "https://example.org/poc.py", "content": "x" * 9000,
                                    "discovered_from": "https://example.org/advisory", "source": "reference_followup"})
        with TemporaryDirectory() as temp, patch.object(ref_cache, "_cache_root", return_value=Path(temp)):
            ref_cache.save_reference_cache("CVE-2020-0001", [page])
            cached = ref_cache.load_reference_cache("CVE-2020-0001")
        self.assertEqual(cached[0]["poc_evidence"], page["poc_evidence"])
        self.assertEqual(len(cached[0]["content"]), 9000)
        self.assertEqual(cached[0]["discovered_from"], page["discovered_from"])

    def test_enriched_cache_reuses_descendants_without_subprocess(self):
        parent = {"url": "https://example.org/advisory", "content": '[PoC](https://github.com/org/repo)'}
        child = structure_reference({"url": "https://raw.githubusercontent.com/org/repo/sha/poc.py",
                                     "content": 'requests.get("http://fixture/path")', "discovered_from": "https://github.com/org/repo"})
        repository = {"url": "https://github.com/org/repo", "content": "Repository summary",
                      "discovered_from": parent["url"]}
        with patch.object(reference_crawl.subprocess, "run") as run:
            result = reference_crawl.enrich_references("CVE-2020-0001", [parent], [repository, child])
        run.assert_not_called()
        self.assertIn(child["url"], [page["url"] for page in result["pages"]])

    def test_repo_files_reused_even_when_metadata_page_was_not_cached(self):
        parent = {"url": "https://example.org/advisory", "content": '[PoC](https://github.com/org/repo)'}
        child = structure_reference({"url": "https://raw.githubusercontent.com/org/repo/sha/poc.py",
                                     "content": 'requests.get("http://fixture/path")', "discovered_from": "https://github.com/org/repo",
                                     "source": "reference_followup"})
        with patch.object(reference_crawl.subprocess, "run") as run:
            result = reference_crawl.enrich_references("CVE-2020-0001", [parent], [child])
        run.assert_not_called()
        self.assertIn(child["url"], [page["url"] for page in result["pages"]])

    def test_readme_only_cache_does_not_prevent_missing_code_fetch(self):
        parent = {"url": "https://example.org/advisory", "content": '[PoC](https://github.com/org/repo)'}
        readme = structure_reference({"url": "https://raw.githubusercontent.com/org/repo/sha/README.md",
                                     "content": "Requires Python 3.", "discovered_from": "https://github.com/org/repo",
                                     "source": "reference_followup"})
        with patch.object(reference_crawl.subprocess, "run", return_value=SimpleNamespace(stdout="", returncode=0)) as run:
            result = reference_crawl.enrich_references("CVE-2020-0001", [parent], [readme])
        run.assert_called_once()
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertIn(readme["url"], payload["known_urls"])
        self.assertIn("https://github.com/org/repo", [target["url"] for target in payload["targets"]])
        self.assertEqual(len(result["pages"]), 2)

    def test_partial_repo_cache_resumes_missing_pinned_files_without_metadata_request(self):
        repo = "https://github.com/org/repo"
        readme_url = "https://raw.githubusercontent.com/org/repo/sha/README.md"
        code_url = "https://raw.githubusercontent.com/org/repo/sha/poc.py"
        parent = {"url": "https://example.org/advisory", "content": f"[PoC]({repo})"}
        readme = structure_reference({"url": readme_url, "content": "Requires Python 3.",
                                     "discovered_from": repo, "source": "reference_followup",
                                     "related_sources": [readme_url, code_url]})
        with patch.object(reference_crawl.subprocess, "run", return_value=SimpleNamespace(stdout="", returncode=0)) as run:
            reference_crawl.enrich_references("CVE-2020-0001", [parent], [readme])
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertEqual([target["url"] for target in payload["targets"]], [code_url])

    def test_offline_mode_structures_without_fetching(self):
        page = {"url": "https://github.com/org/repo", "content": "Requires Python 3."}
        with patch.object(reference_crawl.subprocess, "run") as run:
            result = reference_crawl.enrich_references("CVE-2020-0001", [page], [], allow_network=False)
        run.assert_not_called()
        self.assertTrue(result["pages"][0]["poc_evidence"]["conditions"]["dependencies"])

    def test_redirected_source_preserves_actual_evidence_url(self):
        page = structure_reference({
            "url": "https://example.org/old", "resolved_url": "https://example.org/new/",
            "content": "[PoC](poc.py)\nAuthentication is not required.",
        })
        evidence = page["poc_evidence"]
        self.assertEqual(evidence["poc_links"][0]["url"], "https://example.org/new/poc.py")
        self.assertEqual(evidence["conditions"]["authentication"][0]["evidence_url"], "https://example.org/new/")

    def test_reader_cli_protocol_with_empty_targets_makes_no_requests(self):
        completed = subprocess.run(
            [sys.executable, "-m", "cve_hunter.tools.reference_crawl"],
            input=json.dumps({"targets": [], "budget": 0.1}), text=True,
            capture_output=True, timeout=5, check=True,
        )
        summary = json.loads(completed.stdout)["summary"]
        self.assertEqual(summary["scheduled"], 0)
        self.assertFalse(summary["timed_out"])

    def test_hard_timeout_kills_reader_and_retains_completed_page(self):
        actual_run = subprocess.run
        page = {"url": "https://example.org/poc.py", "content": "Fixture source"}
        command = 'import time; print(' + repr(json.dumps({"page": page})) + ', flush=True); time.sleep(5)'

        def sleeping_reader(*args, **kwargs):
            return actual_run([sys.executable, "-c", command], **kwargs)

        with patch.object(reference_crawl, "cfg", SimpleNamespace(reference_crawl_budget=0.6)), \
                patch.object(reference_crawl.subprocess, "run", side_effect=sleeping_reader):
            started = time.monotonic()
            result = reference_crawl.enrich_references(
                "CVE-2020-0001", [{"url": "https://github.com/org/repo", "content": "Fixture"}], [],
            )
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertTrue(result["timed_out"])
        self.assertIn(page["url"], [item["url"] for item in result["pages"]])


class AsyncReferenceCrawlTests(unittest.IsolatedAsyncioTestCase):
    async def crawl(self, handler, targets, *, budget=1):
        real_client = httpx.AsyncClient
        with patch.object(reference_crawl, "_public_destination", AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx, "AsyncClient", side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler), **kwargs)):
            return await reference_crawl._crawl({"targets": targets, "budget": budget, "cve_id": "CVE-2020-0001"})

    async def test_repository_reads_readme_and_code_at_pinned_revision(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            if request.url.host == "api.github.com":
                return httpx.Response(200, json={"sha": "revision", "tree": [
                    {"type": "blob", "path": "README.md", "size": 50},
                    {"type": "blob", "path": "nested/poc.py", "size": 50},
                    {"type": "blob", "path": "image.png", "size": 50},
                ]})
            return httpx.Response(200, text="Requires Python 3. Authentication is not required.", headers={"content-type": "text/plain"})

        result = await self.crawl(handler, [{"url": "https://github.com/org/repo", "kind": "github_repo"}])
        self.assertEqual(len(result["pages"]), 2)
        self.assertTrue(any("/revision/nested/poc.py" in url for url in requests))
        self.assertTrue(any("/revision/README.md" in url for url in requests))
        self.assertFalse(any("image.png" in url for url in requests))

    async def test_raw_conversion_and_short_source_preservation(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            return httpx.Response(200, text='print("fixture")', headers={"content-type": "text/plain"})

        result = await self.crawl(handler, [
            {"url": "https://github.com/org/repo/blob/main/poc.py"},
            {"url": "https://www.exploit-db.com/exploits/12345"},
        ])
        self.assertIn("https://raw.githubusercontent.com/org/repo/main/poc.py", requests)
        self.assertIn("https://www.exploit-db.com/raw/12345", requests)
        self.assertEqual(len(result["pages"]), 2)

    async def test_slow_source_does_not_discard_fast_source(self):
        async def handler(request):
            if "slow" in str(request.url):
                await asyncio.sleep(5)
            return httpx.Response(200, text="Fixture source")

        result = await self.crawl(handler, [{"url": "https://example.org/poc.py"},
                                            {"url": "https://example.org/slow-poc.py"}], budget=0.03)
        self.assertTrue(result["timed_out"])
        self.assertEqual(len(result["pages"]), 1)

    async def test_aliases_are_deduplicated(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(200, text='print("fixture")')

        result = await self.crawl(handler, [
            {"url": "https://github.com/org/repo/blob/main/poc.py"},
            {"url": "https://raw.githubusercontent.com/org/repo/main/poc.py"},
        ])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(result["pages"]), 1)

    async def test_followup_depth_task_count_and_concurrency_are_bounded(self):
        active = 0
        peak = 0

        async def handler(request):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.001)
            active -= 1
            path = request.url.path
            return httpx.Response(200, text="\n".join(
                f"[PoC](https://example.org{path}-child{i}.md)" for i in range(12)))

        result = await self.crawl(handler, [{"url": f"https://example.org/poc{i}.md"} for i in range(4)])
        self.assertLessEqual(peak, 4)
        self.assertLessEqual(result["scheduled"], reference_crawl.MAX_PAGES)
        self.assertTrue(all(page["url"].count("child") <= 2 for page in result["pages"]))

    async def test_redirect_to_private_source_is_not_requested(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(302, headers={"location": "http://127.0.0.1/poc.py"})

        async def destination(url):
            return "127.0.0.1" not in url

        real_client = httpx.AsyncClient
        async with real_client(transport=httpx.MockTransport(handler)) as client:
            with patch.object(reference_crawl, "_public_destination", side_effect=destination):
                with self.assertRaises(ValueError):
                    await reference_crawl._get(client, "https://example.org/poc.py")
        self.assertEqual(len(calls), 1)

    async def test_public_destination_rejects_private_dns_and_credentials(self):
        self.assertFalse(await reference_crawl._public_destination("http://localhost/poc.py"))
        self.assertFalse(await reference_crawl._public_destination("https://user:pass@example.org/poc.py"))
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", AsyncMock(return_value=[(2, 1, 6, "", ("10.0.0.1", 443))])):
            self.assertFalse(await reference_crawl._public_destination("https://example.org/poc.py"))


if __name__ == "__main__":
    unittest.main()
