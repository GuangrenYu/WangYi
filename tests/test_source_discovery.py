from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from cve_hunter.tools.source_discovery import discover_sources, paid_discovery, parse_search_html
from cve_hunter.tools.reference_evidence import has_http_evidence


class SearchParsingTests(unittest.TestCase):
    def test_redirects_decode_once_and_keep_payload_encoding(self):
        text = '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fpoc%252Ffile">Source</a>'
        results = parse_search_html(text)
        self.assertEqual(results[0]["url"], "https://example.org/poc%2Ffile")

    def test_challenge_is_an_error_instead_of_an_empty_success(self):
        with self.assertRaises(ValueError):
            parse_search_html('<form id="challenge-form">Please confirm this search was made by a human</form>')

    def test_shell_upgrade_commands_are_not_http_evidence(self):
        self.assertFalse(has_http_evidence({"poc_evidence": {"code_blocks": [{"text": "pip install --upgrade example"}]}}))
        self.assertFalse(has_http_evidence({"poc_evidence": {"code_blocks": [{"text": "requests.post(url, data=payload)"}]}}))
        self.assertTrue(has_http_evidence({"content": 'requests.post("https://example.test/api", data=payload)'}))


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_configured_search_endpoint_can_be_local_but_redirect_cannot_change_that_trust(self):
        from cve_hunter.tools import reference_crawl
        calls=[]
        url='http://127.0.0.1:8888/search?q=CVE-2020-0001&format=json'
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(302,headers={'location':'http://127.0.0.1:8889/poc'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with patch.object(reference_crawl,'_public_destination',AsyncMock(return_value=False)):
                with self.assertRaises(ValueError):
                    await reference_crawl._get(client,url,trusted_search_url=url)
        self.assertEqual(calls,[url])

    async def test_search_discovery_does_not_lose_official_template_to_reference_fanout(self):
        from cve_hunter.tools import reference_crawl
        import asyncio
        real_client=httpx.AsyncClient
        async def handler(request):
            path=request.url.path
            return httpx.Response(200,text='\n'.join(f'[PoC](https://example.org{path}-poc{i}.md)' for i in range(12)),
                                  headers={'content-type':'text/plain'})
        async def delayed_discovery(*args,**kwargs):
            await asyncio.sleep(.02)
            return {'providers':{},'errors':[],'leads':[{
                'url':'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/2020/CVE-2020-0001.yaml',
                'kind':'page','score':20,'prefetched_text':'id: CVE-2020-0001\nhttp:\n - path: ["{{BaseURL}}/fixture"]',
                'discovery_provider':'official_nuclei',
            }]}
        with patch.object(reference_crawl,'_public_destination',AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx,'AsyncClient',side_effect=lambda **kwargs: real_client(transport=httpx.MockTransport(handler),**kwargs)), \
                patch('cve_hunter.tools.source_discovery.discover_sources',side_effect=delayed_discovery):
            result=await reference_crawl._crawl({'cve_id':'CVE-2020-0001','targets':[{'url':f'https://example.org/poc{i}.md'} for i in range(4)],
                                               'budget':1,'discover':True})
        self.assertTrue(any(page.get('discovery_provider')=='official_nuclei' for page in result['pages']))
        self.assertLessEqual(result['scheduled'],reference_crawl.MAX_PAGES)

    async def test_paid_discovery_is_not_invoked_when_free_sources_have_http_evidence(self):
        from cve_hunter.tools import reference_crawl
        real_client=httpx.AsyncClient
        async def handler(request):
            return httpx.Response(200,text='requests.get("http://fixture/path")',headers={'content-type':'text/plain'})
        with patch.object(reference_crawl,'_public_destination',AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx,'AsyncClient',side_effect=lambda **kwargs: real_client(transport=httpx.MockTransport(handler),**kwargs)), \
                patch('cve_hunter.tools.source_discovery.paid_discovery',AsyncMock()) as paid:
            result=await reference_crawl._crawl({'cve_id':'CVE-2020-0001','targets':[{'url':'https://example.org/poc.py'}],
                                               'budget':1,'paid_fallback':True})
        paid.assert_not_called()
        self.assertEqual(len(result['pages']),1)

    async def test_index_and_template_discovery_need_no_paid_api(self):
        async def get(url):
            if 'nomi-sec' in url:
                text = json.dumps([{"html_url": "https://github.com/org/CVE-2020-0001"}])
            elif 'nuclei-templates' in url:
                text = 'id: CVE-2020-0001\nhttp:\n  - path: ["{{BaseURL}}/fixture"]'
            else:
                text = '<a class="result__a" href="https://example.org/poc">PoC</a>'
            return url, text, 'text/plain'
        result = await discover_sources('CVE-2020-0001', get)
        self.assertEqual(len(result['leads']), 3)
        self.assertEqual(result['leads'][0]['discovery_provider'], 'official_nuclei')
        self.assertNotIn('github_search', result['providers'])

    async def test_blocked_html_and_missing_index_trigger_github_search(self):
        calls=[]
        async def get(url):
            calls.append(url)
            if 'api.github.com/search' in url:
                return url, json.dumps({'items':[{'html_url':'https://github.com/org/CVE-2020-0001'}]}), 'application/json'
            raise ValueError('provider unavailable')
        result = await discover_sources('CVE-2020-0001', get)
        self.assertEqual(result['leads'][0]['discovery_provider'], 'github_search')
        self.assertEqual(len(result['errors']), 3)

    async def test_searxng_uses_json_interface_instead_of_ddg(self):
        calls=[]
        async def get(url):
            calls.append(url)
            if 'search.example.org' in url:
                return url, json.dumps({'results':[{'url':'https://example.org/poc.py','title':'PoC'}]}), 'application/json'
            if 'nomi-sec' in url:
                return url, json.dumps([{'html_url':'https://github.com/org/repo'}]), 'application/json'
            raise ValueError('404')
        result = await discover_sources('CVE-2020-0001', get, searxng_url='https://search.example.org')
        self.assertTrue(any('format=json' in url for url in calls))
        self.assertFalse(any('duckduckgo' in url for url in calls))
        self.assertEqual(result['providers']['searxng']['results'], 1)

    async def test_paid_brave_transport_keeps_token_out_of_url(self):
        calls=[]
        def handler(request):
            calls.append(request)
            return httpx.Response(200,json={'web':{'results':[{'url':'https://example.org/poc.py'}]}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await paid_discovery('CVE-2020-0001 PoC',client,brave_key='fixture-key')
        self.assertEqual(result['provider'],'brave')
        self.assertNotIn('fixture-key',str(calls[0].url))
        self.assertEqual(calls[0].headers['X-Subscription-Token'],'fixture-key')

    async def test_paid_missing_configuration_makes_no_request(self):
        client=AsyncMock()
        result=await paid_discovery('CVE-2020-0001',client)
        client.get.assert_not_called()
        client.post.assert_not_called()
        self.assertEqual(result['provider'],'unconfigured')
