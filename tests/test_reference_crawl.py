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
    def test_wordpress_source_urls_preserve_explicit_revisions(self):
        cases = {
            'https://plugins.trac.wordpress.org/browser/example/trunk/app.php#L28':
                'https://plugins.svn.wordpress.org/example/trunk/app.php',
            'https://plugins.trac.wordpress.org/browser/example/trunk/app.php?rev=123#L28':
                'https://plugins.svn.wordpress.org/!svn/bc/123/example/trunk/app.php',
            'https://plugins.trac.wordpress.org/changeset/123/example/tags/1.0/app.php':
                'https://plugins.svn.wordpress.org/!svn/bc/123/example/tags/1.0/app.php',
        }
        for url, expected in cases.items():
            self.assertEqual(reference_crawl._raw_url(url), expected)
        changeset = 'https://plugins.trac.wordpress.org/changeset/123/'
        self.assertEqual(reference_crawl._raw_url(changeset), changeset)

    def test_github_large_diff_prefers_route_code_over_readme(self):
        page = reference_crawl._github_api_diff_page(
            "https://github.com/org/repo/commit/abc123",
            "github_commit",
            {
                "commit": {"message": "fix endpoint"},
                "files": [
                    {"filename": "README.md", "patch": "+ usage docs"},
                    {"filename": "router.py", "patch": "+ @router.post('/exact/endpoint')"},
                    {"filename": "CHANGELOG.md", "patch": "+ Updated release notes"},
                ],
            },
            "CVE-2024-0001",
        )
        self.assertEqual(page["poc_evidence"]["code_blocks"][0]["text"], "+ @router.post('/exact/endpoint')")
        self.assertIn("router.py", page["content"])

    def test_discovery_starts_even_when_cached_page_has_some_http_evidence(self):
        page = structure_reference({
            "url": "https://example.org/CVE-2020-0001/poc.py",
            "content": 'requests.get("https://example.org/other")',
        }, "CVE-2020-0001")
        with patch.object(reference_crawl, "cfg", SimpleNamespace(reference_crawl_budget=5,
                                                                    reference_discovery_enabled=True)), \
                patch.object(reference_crawl.subprocess, "run", return_value=SimpleNamespace(stdout="", returncode=0)) as run:
            reference_crawl.enrich_references(
                "CVE-2020-0001", [page], [page], discovery_context="Example Product issue",
            )
        self.assertTrue(json.loads(run.call_args.kwargs["input"])["discover"])

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

    def test_html_request_blocks_are_prioritized_over_policy_noise(self):
        html = '''<html><head><title>Fixture</title></head><body>
        <pre>Generic policy text.\nAlways use a strong password.</pre>
        <pre>POST /exact/endpoint HTTP/1.1\nHost: target.example\n</pre>
        </body></html>'''
        page = page_from_response("https://example.org/advisory", html, "text/html")
        self.assertIn("POST /exact/endpoint", page["code_blocks"][0]["text"])

    def test_plain_code_is_not_passed_through_prose_extraction(self):
        code = '# fixture\nprint("hello")\n'
        page = structure_reference(page_from_response("https://example.org/poc.py", code, "text/plain"))
        self.assertEqual(page["content"], code)
        self.assertEqual(page["poc_evidence"]["code_blocks"][0]["text"], code)

    def test_raw_browser_poc_is_preserved_instead_of_rendered_as_an_article(self):
        code = '<html><object id="example" classid="clsid:example"></object><script>example.Test("fixture")</script></html>'
        page = structure_reference(page_from_response('https://www.exploit-db.com/raw/1234', code, 'text/plain'))
        self.assertEqual(page['content'], code)
        self.assertEqual(page['poc_evidence']['code_blocks'][0]['text'], code)

    def test_nuclei_inline_path_is_http_evidence(self):
        from cve_hunter.tools.reference_evidence import has_http_evidence
        page = {"poc_evidence": {"code_blocks": [{
            "text": 'id: CVE-2020-0001\nhttp:\n  - path: ["{{BaseURL}}/exact/path"]'
        }]}}
        self.assertTrue(has_http_evidence(page))

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

    def test_markdown_url_label_does_not_merge_two_source_links(self):
        url = "https://github.com/org/repo/blob/main/poc.md"
        links = extract_links(f"[{url}]({url})", "https://example.org/advisory")
        self.assertEqual([link["url"] for link in links], [url])

    def test_github_navigation_does_not_consume_source_slots(self):
        links = extract_links(
            "https://github.com/features/copilot https://github.com/security/advanced-security "
            "https://github.com/org/repo", "https://example.org/advisory",
        )
        self.assertEqual([link["url"] for link in links], ["https://github.com/org/repo"])

    def test_repository_navigation_and_other_cve_links_are_not_sources(self):
        links = extract_links(
            'https://github.com/org/repo/issues https://github.com/org/repo/pulls '
            'https://example.org/exploit-CVE-2026-9999 '
            'https://github.com/org/repo/issues/123',
            'https://example.org/advisory', 'CVE-2020-0001',
        )
        self.assertEqual([link['url'] for link in links], ['https://github.com/org/repo/issues/123'])

    def test_server_source_is_preserved_as_code(self):
        code = '<?php $endpoint = "/public/endpoint"; ?>'
        page = structure_reference(page_from_response("https://example.org/poc.php", code, "text/plain"))
        self.assertEqual(page["poc_evidence"]["code_blocks"][0]["text"], code)

    def test_truncated_source_is_not_labelled_complete_code(self):
        page = structure_reference(page_from_response("https://example.org/poc.py", "x" * 30000))
        self.assertTrue(page["content_truncated"])
        self.assertEqual(page["poc_evidence"]["code_blocks"], [])

    def test_late_markdown_request_survives_prose_truncation(self):
        text = 'Long introduction. ' * 2000 + '\n```http\nPOST /late/evidence HTTP/1.1\nHost: example.test\n```'
        page = structure_reference(page_from_response('https://example.org/advisory.md', text))
        self.assertTrue(page['content_truncated'])
        self.assertIn('/late/evidence', page['poc_evidence']['code_blocks'][0]['text'])

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

    def test_exploitdb_landing_cache_with_snippet_still_downloads_raw_source(self):
        landing = structure_reference({
            'url': 'https://www.exploit-db.com/exploits/1234',
            'content': 'Introduction\n```http\nGET /example HTTP/1.1\n```',
            'content_format': 'html',
        })
        with patch.object(reference_crawl, 'cfg', SimpleNamespace(reference_crawl_budget=5,
                                                                 reference_discovery_enabled=False)), \
                patch.object(reference_crawl.subprocess, 'run', return_value=SimpleNamespace(stdout='', returncode=0)) as run:
            reference_crawl.enrich_references('CVE-2020-0001', [landing], [landing])
        run.assert_called_once()
        targets = json.loads(run.call_args.kwargs['input'])['targets']
        self.assertTrue(any(reference_crawl._raw_url(item['url']) == 'https://www.exploit-db.com/raw/1234'
                            for item in targets))

    def test_exploitdb_raw_cache_reused_even_when_landing_is_also_cached(self):
        landing = structure_reference({'url': 'https://www.exploit-db.com/exploits/1234', 'content': 'Introduction'})
        raw = structure_reference(page_from_response('https://www.exploit-db.com/raw/1234',
                                                    'requests.get("https://example.test/endpoint")', 'text/plain'))
        raw.update({'discovered_from': landing['url'], 'source': 'reference_followup'})
        with patch.object(reference_crawl, 'cfg', SimpleNamespace(reference_crawl_budget=5,
                                                                 reference_discovery_enabled=False)), \
                patch.object(reference_crawl.subprocess, 'run') as run:
            result = reference_crawl.enrich_references('CVE-2020-0001', [landing], [landing, raw])
        run.assert_not_called()
        self.assertIn(raw['url'], [page['url'] for page in result['pages']])

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
    async def test_complete_public_source_stops_before_slow_remaining_roots(self):
        real_client = httpx.AsyncClient

        async def handler(request):
            if request.url.path == '/slow':
                await asyncio.sleep(1)
                return httpx.Response(200, text='Unneeded slow article')
            return httpx.Response(200, text='import requests\nrequests.get("https://example.test/endpoint")',
                                  headers={'content-type': 'text/plain'})

        with patch.object(reference_crawl, '_public_destination', AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx, 'AsyncClient', side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler), **kwargs)):
            result = await reference_crawl._crawl({
                'cve_id': 'CVE-2020-0001', 'budget': .3, 'stop_on_complete_evidence': True,
                'targets': [{'url': 'https://example.org/poc.py'}, {'url': 'https://example.org/slow'}],
            })
        self.assertFalse(result['timed_out'])
        self.assertEqual([page['url'] for page in result['pages']], ['https://example.org/poc.py'])

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

    async def test_repository_follows_server_source_files_with_endpoint_evidence(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            if request.url.host == "api.github.com":
                return httpx.Response(200, json={"sha": "revision", "tree": [
                    {"type": "blob", "path": "poc.php", "size": 100},
                    {"type": "blob", "path": "poc.jsp", "size": 100},
                    {"type": "blob", "path": "poc.java", "size": 100},
                    {"type": "blob", "path": "poc.cs", "size": 100},
                ]})
            return httpx.Response(200, text='endpoint = "/source/evidence"',
                                  headers={"content-type": "text/plain"})

        result = await self.crawl(handler, [{"url": "https://github.com/org/repo", "kind": "github_repo"}])
        self.assertEqual(len(result["pages"]), 4)
        for extension in ("php", "jsp", "java", "cs"):
            self.assertIn(f"https://raw.githubusercontent.com/org/repo/revision/poc.{extension}", calls)
        self.assertTrue(all("/source/evidence" in page["content"] for page in result["pages"]))

    async def test_repository_rate_limit_uses_full_mirror_tree(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            if request.url.host == 'api.github.com':
                return httpx.Response(403, json={'message': 'rate limited'})
            if request.url.host == 'data.jsdelivr.com':
                return httpx.Response(200, json={'files': [
                    {'name': '/nested/CVE-2020-0001/poc.php', 'size': 100},
                    {'name': '/image.png', 'size': 100},
                ]})
            return httpx.Response(200, text='<?php $path = "/public/evidence"; ?>')

        result = await self.crawl(handler, [{'url': 'https://github.com/org/repo', 'kind': 'github_repo'}])
        self.assertIn('https://raw.githubusercontent.com/org/repo/HEAD/nested/CVE-2020-0001/poc.php', calls)
        self.assertEqual(len(result['pages']), 1)
        self.assertIn('/public/evidence', result['pages'][0]['poc_evidence']['code_blocks'][0]['text'])
        self.assertEqual(result['errors'], [])

    async def test_github_commit_uses_compact_public_patch_instead_of_large_html(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            if request.url.path.endswith(".patch"):
                return httpx.Response(200, text="""From abc Mon Sep 17 00:00:00 2001
Subject: [PATCH] Fix CVE-2024-7037 upload handling
diff --git a/backend/routers/pipelines.py b/backend/routers/pipelines.py
@@ -1 +1 @@
- old
+ path = '/api/pipelines/upload'
""", headers={"content-type": "text/plain"})
            return httpx.Response(413)

        result = await self.crawl(handler, [{
            "url": "https://github.com/org/repo/commit/0123456789abcdef",
            "kind": "github_commit",
        }])

        self.assertEqual(requests, ["https://github.com/org/repo/commit/0123456789abcdef.patch"])
        self.assertEqual(len(result["pages"]), 1)
        page = result["pages"][0]
        self.assertIn("/api/pipelines/upload", page["content"])
        self.assertEqual(page["title"], "https://github.com/org/repo/commit/0123456789abcdef")

    async def test_github_pull_request_uses_public_diff(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            return httpx.Response(200, text="@@ -1 +1 @@\n+ route('/exact/endpoint')")

        result = await self.crawl(handler, [{
            "url": "https://github.com/org/repo/pull/123/files",
            "kind": "github_pull_request",
        }])

        self.assertEqual(requests, ["https://github.com/org/repo/pull/123.patch"])
        self.assertEqual(len(result["pages"]), 1)
        self.assertIn("/exact/endpoint", result["pages"][0]["content"])

    async def test_github_issue_uses_public_api_body(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            return httpx.Response(200, json={
                "title": "CVE-2021-41746 reproduction",
                "body": "POST /login/changepswd.php HTTP/1.1",
            })

        result = await self.crawl(handler, [{
            "url": "https://github.com/org/repo/issues/456",
            "kind": "github_issue",
        }])

        self.assertEqual(requests, ["https://api.github.com/repos/org/repo/issues/456"])
        self.assertEqual(len(result["pages"]), 1)
        self.assertIn("/login/changepswd.php", result["pages"][0]["content"])

    async def test_github_issue_rate_limit_falls_back_to_html_and_follows_source(self):
        requests = []

        def handler(request):
            requests.append(str(request.url))
            if request.url.host == "api.github.com":
                return httpx.Response(403, json={"message": "API rate limit exceeded"})
            if request.url.host == "github.com":
                return httpx.Response(200, text='''<html><body><article>
                <p>Public reproduction for the issue is available below.</p>
                <pre>POST /public/endpoint HTTP/1.1</pre>
                <a href="https://example.org/poc.py">PoC source</a>
                </article></body></html>''', headers={"content-type": "text/html"})
            return httpx.Response(200, text='requests.post("https://target.example/public/endpoint")')

        result = await self.crawl(handler, [{
            "url": "https://github.com/org/repo/issues/456", "kind": "github_issue",
        }])
        self.assertEqual(requests, [
            "https://api.github.com/repos/org/repo/issues/456",
            "https://github.com/org/repo/issues/456", "https://example.org/poc.py",
        ])
        self.assertEqual(len(result["pages"]), 2)
        self.assertEqual(result["errors"], [])
        self.assertIn("/public/endpoint", result["pages"][0]["poc_evidence"]["code_blocks"][0]["text"])

    async def test_oversized_github_diff_falls_back_to_compact_file_patches(self):
        requests = []

        def handler(request):
            requests.append((str(request.url), request.headers.get("Range")))
            if request.url.host == "github.com":
                return httpx.Response(
                    206, text="partial diff",
                    headers={"content-range": "bytes 0-262143/9000000"},
                )
            return httpx.Response(200, json={
                "commit": {"message": "Fix endpoint"},
                "files": [{
                    "filename": "router.py",
                    "blob_url": "https://github.com/org/repo/blob/main/router.py",
                    "patch": "+ route = '/compact/path'",
                }],
            })

        result = await self.crawl(handler, [{
            "url": "https://github.com/org/repo/commit/abcdef0123456789",
            "kind": "github_commit",
        }])

        self.assertEqual(requests, [
            ("https://github.com/org/repo/commit/abcdef0123456789.patch", "bytes=0-262143"),
            ("https://api.github.com/repos/org/repo/commits/abcdef0123456789", None),
        ])
        self.assertEqual(len(result["pages"]), 1)
        self.assertIn("/compact/path", result["pages"][0]["content"])

    async def test_crawl_target_classifies_github_diff_pages(self):
        page = {
            "url": "https://example.org/advisory",
            "content": "\n".join([
                "https://github.com/org/repo/commit/abc123def4567890",
                "https://github.com/org/repo/pull/123/files",
                "https://github.com/org/repo/issues/456",
            ]),
        }
        kinds = {item["url"].rsplit("/", 1)[-1]: item["kind"]
                 for item in reference_crawl.crawl_targets([page], "CVE-2020-0001")}
        self.assertEqual(kinds["abc123def4567890"], "github_commit")
        self.assertEqual(kinds["files"], "github_pull_request")
        self.assertEqual(kinds["456"], "github_issue")

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

    async def test_discovery_keeps_slots_for_poc_files_linked_from_search_leads(self):
        real_client = httpx.AsyncClient

        def handler(request):
            path = request.url.path
            if path.startswith("/reference"):
                return httpx.Response(
                    200, text=f"[PoC](https://example.org/{path.strip('/')}-poc.md)",
                    headers={"content-type": "text/plain"},
                )
            if path.startswith("/search-lead"):
                return httpx.Response(
                    200, text=f"[PoC](https://example.org/{path.strip('/')}-poc.py)",
                    headers={"content-type": "text/plain"},
                )
            return httpx.Response(200, text="HTTP request example")

        async def discover(*args, **kwargs):
            await asyncio.sleep(0.03)
            return {
                "providers": {}, "errors": [],
                "leads": [{
                    "url": f"https://example.org/search-lead-{index}.md",
                    "score": 20 - index,
                    "discovery_provider": "duckduckgo",
                } for index in range(10)],
            }

        with patch.object(reference_crawl, "_public_destination", AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx, "AsyncClient", side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler), **kwargs)), \
                patch("cve_hunter.tools.source_discovery.discover_sources", side_effect=discover):
            result = await reference_crawl._crawl({
                "cve_id": "CVE-2020-0001",
                "targets": [{"url": f"https://example.org/reference-{index}.md", "score": 10}
                            for index in range(20)],
                "budget": 1, "discover": True,
            })

        attempted = set(result["attempted_urls"])
        self.assertLessEqual(result["scheduled"], reference_crawl.MAX_PAGES)
        self.assertTrue(any("search-lead-" in url and "-poc.py" in url for url in attempted))

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

    async def test_explicit_source_headers_are_sent_only_to_initial_url(self):
        calls = []
        def handler(request):
            calls.append((str(request.url), request.headers.get("X-Requested-With")))
            if len(calls) == 1:
                return httpx.Response(302, headers={"location": "https://example.org/results"})
            return httpx.Response(200, text="ok")
        real_client = httpx.AsyncClient
        async with real_client(transport=httpx.MockTransport(handler)) as client:
            with patch.object(reference_crawl, "_public_destination", AsyncMock(return_value=True)):
                await reference_crawl._get(
                    client, "https://example.org/search",
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
        self.assertEqual(calls, [
            ("https://example.org/search", "XMLHttpRequest"),
            ("https://example.org/results", None),
        ])

    async def test_public_destination_rejects_private_dns_and_credentials(self):
        self.assertFalse(await reference_crawl._public_destination("http://localhost/poc.py"))
        self.assertFalse(await reference_crawl._public_destination("https://user:pass@example.org/poc.py"))
        with patch.object(reference_crawl.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.1", 443))]):
            self.assertFalse(await reference_crawl._public_destination("https://example.org/poc.py"))

    async def test_stalled_dns_obeys_deadline_without_using_loop_executor(self):
        def stalled(*args, **kwargs):
            time.sleep(.2)
            return [(2, 1, 6, '', ('93.184.216.34', 443))]

        with patch.object(reference_crawl, 'DNS_TIMEOUT', .01), \
                patch.object(reference_crawl.socket, 'getaddrinfo', side_effect=stalled), \
                patch.object(asyncio.get_running_loop(), 'getaddrinfo', AsyncMock()) as loop_dns:
            with self.assertRaises(asyncio.TimeoutError):
                await reference_crawl._resolve_addresses('example.org', 443)
        loop_dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
