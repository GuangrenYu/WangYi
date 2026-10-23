"""Coverage accounting must not turn snippets into complete public PoCs."""

from cve_hunter.tools.reference_evidence import page_from_response, structure_reference
from scripts.regress_missing_reference_paths import complete_poc_sources


def test_complete_browser_source_counts_even_without_an_http_endpoint():
    code = '<html><object id="fixture"></object><script>fixture.Test()</script></html>'
    page = structure_reference(page_from_response('https://www.exploit-db.com/raw/1234', code, 'text/plain'))
    assert complete_poc_sources('CVE-2020-0001', [page]) == [page['url']]


def test_markdown_snippet_requires_review_and_is_not_a_complete_source_file():
    page = structure_reference(page_from_response(
        'https://example.org/advisory.md', '```http\nGET /endpoint HTTP/1.1\n```', 'text/plain',
    ))
    assert complete_poc_sources('CVE-2020-0001', [page]) == []


def test_truncated_or_unrelated_source_does_not_count_as_a_complete_poc():
    code = 'import requests\nrequests.get("https://example.test/endpoint")'
    page = structure_reference(page_from_response('https://example.org/poc.py', code, 'text/plain'))
    page['discovery_provider'] = 'tavily'
    assert complete_poc_sources('CVE-2020-0001', [page]) == []
    page['discovery_provider'] = 'reference'
    page['content_truncated'] = True
    assert complete_poc_sources('CVE-2020-0001', [page]) == []


def test_explicit_other_cve_source_is_not_trusted_even_with_reference_provenance():
    from cve_hunter.tools.reference_evidence import has_cve_related_http_evidence
    page = structure_reference(page_from_response(
        'https://example.org/CVE-2021-0002/poc.py',
        'import requests\nrequests.get("https://example.test/endpoint")', 'text/plain',
    ))
    page['discovery_provider'] = 'reference'
    page['discovered_from'] = 'https://example.org/CVE-2020-0001/advisory'
    assert not has_cve_related_http_evidence(page, 'CVE-2020-0001')
    assert complete_poc_sources('CVE-2020-0001', [page]) == []
