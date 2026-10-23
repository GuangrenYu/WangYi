from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from cve_hunter.tools.source_discovery import discover_sources, paid_discovery, parse_search_html
from cve_hunter.tools.reference_evidence import has_cve_related_http_evidence, has_http_evidence


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

    def test_unrelated_http_snippet_does_not_count_as_evidence_for_current_cve(self):
        page = {
            "url": "https://github.com/other/project/blob/main/README.md",
            "discovery_provider": "github_search",
            "poc_evidence": {"code_blocks": [{"text": 'requests.get("https://example.test/other")'}]},
        }
        self.assertTrue(has_http_evidence(page))
        self.assertFalse(has_cve_related_http_evidence(page, "CVE-2020-0001"))


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

    async def test_duckduckgo_initial_search_is_allowed_but_redirect_destination_is_checked(self):
        from cve_hunter.tools import reference_crawl
        calls=[]
        url='https://html.duckduckgo.com/html/?q=CVE-2020-0001'
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(302,headers={'location':'http://127.0.0.1/private'})
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
            result=await reference_crawl._crawl({'cve_id':'CVE-2020-0001','targets':[{'url':f'https://example.org/poc{i}.md'} for i in range(24)],
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

    async def test_blocked_search_starts_component_fallback_before_slow_roots_finish(self):
        import asyncio
        from cve_hunter.tools import reference_crawl
        real_client = httpx.AsyncClient

        async def handler(request):
            if request.url.host == 'slow.example.org':
                await asyncio.sleep(1)
            return httpx.Response(200, text='GET /public/evidence HTTP/1.1', headers={'content-type': 'text/plain'})

        paid = AsyncMock(return_value={'provider': 'tavily', 'errors': [], 'leads': [
            {'url': 'https://example.org/public-poc', 'score': 7},
        ]})
        discovery = AsyncMock(return_value={'providers': {'duckduckgo': {'status': 'error'}},
                                            'errors': [], 'leads': []})
        with patch.object(reference_crawl, '_public_destination', AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx, 'AsyncClient', side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler), **kwargs)), \
                patch('cve_hunter.tools.source_discovery.discover_sources', discovery), \
                patch('cve_hunter.tools.source_discovery.paid_discovery', paid):
            result = await reference_crawl._crawl({
                'cve_id': 'CVE-2020-0001', 'targets': [{'url': 'https://slow.example.org/advisory'}],
                'budget': .2, 'discover': True, 'paid_fallback': True,
                'discovery_context': 'Huaxia ERP has an issue in the file /user/getAllList.',
            })
        paid.assert_awaited_once()
        self.assertEqual(paid.call_args.args[0], '/user/getAllList Huaxia ERP PoC')
        self.assertTrue(any(page['url'] == 'https://example.org/public-poc' for page in result['pages']))

    async def test_paid_priority_fetches_source_before_free_discovery_finishes(self):
        import asyncio
        from cve_hunter.tools import reference_crawl
        real_client = httpx.AsyncClient

        async def slow_discovery(*args, **kwargs):
            await asyncio.sleep(1)
            return {'providers': {}, 'errors': [], 'leads': []}

        paid = AsyncMock(return_value={'provider': 'tavily', 'errors': [], 'leads': [
            {'url': 'https://example.org/CVE-2020-0001/poc.py', 'score': 7},
            {'url': 'https://example.org/CVE-2021-0002/poc.py', 'score': 7},
        ]})
        def handler(request):
            return httpx.Response(200, text='import requests\nrequests.get("https://example.test/endpoint")',
                                  headers={'content-type': 'text/plain'})

        with patch.object(reference_crawl, '_public_destination', AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx, 'AsyncClient', side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler), **kwargs)), \
                patch('cve_hunter.tools.source_discovery.discover_sources', side_effect=slow_discovery), \
                patch('cve_hunter.tools.source_discovery.paid_discovery', paid):
            result = await reference_crawl._crawl({
                'cve_id': 'CVE-2020-0001', 'targets': [], 'budget': .2,
                'discover': True, 'paid_fallback': True, 'paid_priority': True,
                'stop_on_complete_evidence': True,
                'discovery_context': 'Huaxia ERP issue in /user/getAllList',
            })
        self.assertFalse(result['timed_out'])
        self.assertEqual(len(result['pages']), 1)
        self.assertFalse(any('CVE-2021-0002' in url for url in result['attempted_urls']))
        self.assertEqual(paid.await_count, 2)
        self.assertIn('CVE-2020-0001 PoC exploit', [call.args[0] for call in paid.await_args_list])
        self.assertEqual(len(result['discovery']['paid_queries']), 2)

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

    async def test_description_context_is_used_in_search_and_mitre_references_become_leads(self):
        calls=[]
        async def get(url):
            calls.append(url)
            if 'cveawg.mitre.org' in url:
                return url, json.dumps({'containers': {'cna': {'references': [
                    {'url': 'https://vendor.example/advisory/CVE-2020-0001'}
                ]}, 'adp': [{'references': [
                    {'url': 'https://github.com/org/CVE-2020-0001-poc'}
                ]}]}}), 'application/json'
            if 'nomi-sec' in url:
                return url, '[]', 'application/json'
            if 'nuclei-templates' in url:
                return url, 'id: CVE-2020-0001\nhttp:\n - path: ["{{BaseURL}}/fixture"]', 'text/plain'
            return url, '<html></html>', 'text/html'
        result=await discover_sources(
            'CVE-2020-0001',get,context='Example Product allows remote code execution'
        )
        self.assertTrue(any('Example%20Product' in url for url in calls))
        self.assertEqual(result['providers']['mitre_cve']['results'],2)
        self.assertTrue(any(lead.get('discovery_provider')=='mitre_cve' for lead in result['leads']))

    async def test_search_keeps_concrete_source_filename_from_description(self):
        calls = []

        async def get(url):
            calls.append(url)
            if 'nuclei-templates' in url:
                raise ValueError('missing')
            if 'nomi-sec' in url:
                raise ValueError('missing')
            if 'exploit-db.com' in url:
                raise ValueError('missing')
            if 'cveawg.mitre.org' in url:
                raise ValueError('missing')
            if 'api.github.com/search' in url:
                raise ValueError('missing')
            return url, '<html></html>', 'text/html'

        result = await discover_sources(
            'CVE-2025-0786', get,
            context='A vulnerability affects the file /CDGServer3/appDetail.jsp; the flowId argument leads to SQL injection',
        )
        self.assertIn('appDetail.jsp', result['query'])
        self.assertIn('CDGServer3', result['query'])

    async def test_search_keeps_extensionless_endpoint_paths_from_description(self):
        async def get(url):
            if 'nuclei-templates' in url or 'nomi-sec' in url or 'exploit-db.com' in url:
                raise ValueError('missing')
            if 'cveawg.mitre.org' in url or 'api.github.com/search' in url:
                raise ValueError('missing')
            return url, '<html></html>', 'text/html'

        result = await discover_sources(
            'CVE-2024-0490', get,
            context='The issue affects the file /user/getAllList and allows information disclosure.',
        )
        self.assertIn('/user/getAllList', result['query'])
        self.assertIn('getAllList', result['query'])

    async def test_search_keeps_extensionless_route_named_via_in_description(self):
        async def get(url):
            if 'nuclei-templates' in url or 'nomi-sec' in url or 'exploit-db.com' in url:
                raise ValueError('missing')
            if 'cveawg.mitre.org' in url or 'api.github.com/search' in url:
                raise ValueError('missing')
            return url, '<html></html>', 'text/html'

        result = await discover_sources(
            'CVE-2022-27351', get,
            context='Zoo Management System was discovered to contain a file upload vulnerability via /public_html/apply_vacancy.',
        )
        self.assertIn('/public_html/apply_vacancy', result['query'])

    async def test_search_extracts_file_path_without_leading_slash(self):
        async def get(url):
            if 'nuclei-templates' in url:
                raise ValueError('missing')
            if 'nomi-sec' in url or 'exploit-db.com' in url or 'cveawg.mitre.org' in url:
                raise ValueError('missing')
            if 'api.github.com/search' in url:
                raise ValueError('missing')
            return url, '<html></html>', 'text/html'

        result = await discover_sources(
            'CVE-2023-2928', get,
            context='A vulnerability affects the file uploads/dede/article_allowurl_edit.php.',
        )
        self.assertIn('article_allowurl_edit.php', result['query'])

    async def test_exploitdb_results_are_added_as_raw_source_leads(self):
        async def get(url, *, headers=None):
            if 'exploit-db.com/search' in url:
                self.assertEqual(headers['X-Requested-With'], 'XMLHttpRequest')
                return url, json.dumps({'data': [{'id': '47951', 'description': ['Citrix XXE']}]}), 'application/json'
            if 'nomi-sec' in url:
                return url, '[]', 'application/json'
            raise ValueError('not found')
        result=await discover_sources('CVE-2018-10653',get)
        lead=next(item for item in result['leads'] if item.get('discovery_provider')=='exploit_db')
        self.assertEqual(lead['url'],'https://www.exploit-db.com/exploits/47951')
        self.assertEqual(lead['score'],20)

    async def test_exploitdb_hit_is_followed_to_raw_request_source(self):
        import asyncio
        from cve_hunter.tools import reference_crawl
        real_client=httpx.AsyncClient
        calls=[]
        def handler(request):
            calls.append(str(request.url))
            if request.url.host == 'www.exploit-db.com' and request.url.path == '/search':
                return httpx.Response(200,json={'data':[{'id':'47951','description':['Citrix XXE']}]})
            if request.url.host == 'www.exploit-db.com' and request.url.path == '/raw/47951':
                return httpx.Response(200,text='import requests\nrequests.put("https://target.example/zdm/ios/mdm", data="fixture")')
            if request.url.host == 'api.github.com':
                return httpx.Response(200,json={'items':[]})
            if 'cveawg.mitre.org' in str(request.url):
                return httpx.Response(200,json={'containers':{'cna':{'references':[]}}})
            if 'html.duckduckgo.com' in str(request.url):
                return httpx.Response(200,text='<html></html>')
            return httpx.Response(404)
        with patch.object(reference_crawl,'_public_destination',AsyncMock(return_value=True)), \
                patch.object(reference_crawl.httpx,'AsyncClient',side_effect=lambda **kwargs: real_client(
                    transport=httpx.MockTransport(handler),**kwargs)):
            result=await reference_crawl._crawl({
                'cve_id':'CVE-2018-10653','targets':[],'budget':1,
                'request_timeout':1,'discover':True,'paid_fallback':False,
            })
        self.assertIn('https://www.exploit-db.com/raw/47951',calls)
        page=next(page for page in result['pages'] if page['url']=='https://www.exploit-db.com/raw/47951')
        self.assertIn('/zdm/ios/mdm',page['poc_evidence']['code_blocks'][0]['text'])

    async def test_blocked_html_and_missing_index_trigger_github_search(self):
        calls=[]
        async def get(url):
            calls.append(url)
            if 'api.github.com/search' in url:
                return url, json.dumps({'items':[{'html_url':'https://github.com/org/CVE-2020-0001'}]}), 'application/json'
            raise ValueError('provider unavailable')
        result = await discover_sources('CVE-2020-0001', get)
        self.assertEqual(result['leads'][0]['discovery_provider'], 'github_search')
        self.assertEqual(len(result['errors']), 6)

    async def test_public_poc_index_preserves_links_without_inventing_evidence(self):
        async def get(url):
            if 'trickest/cve' in url:
                return url, ('### [CVE-2020-0001](https://cve.mitre.org/example)\n'
                             '#### Github\n- https://github.com/org/public-reproduction'), 'text/plain'
            raise ValueError('unavailable')

        result = await discover_sources('CVE-2020-0001', get)
        lead = next(item for item in result['leads'] if item['discovery_provider'] == 'public_poc_index')
        self.assertIn('public-reproduction', lead['prefetched_text'])
        self.assertFalse(has_http_evidence({'content': lead['prefetched_text']}))

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
