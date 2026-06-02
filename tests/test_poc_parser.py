import unittest

from cve_hunter.poc_parser import extract_http_requests, parse_poc_candidates_json, render_raw_http


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


if __name__ == "__main__":
    unittest.main()
