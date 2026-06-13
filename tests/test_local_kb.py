import unittest

from cve_hunter.tools import local_kb


class LocalKbTests(unittest.TestCase):
    def test_prioritizes_cve_specific_repos_over_generic_collections(self):
        repos = [
            {"label": "awesome", "url": "https://github.com/example/awesome-cve-poc"},
            {"label": "specific", "url": "https://github.com/mpgn/CVE-2018-3760"},
            {"label": "misc", "url": "https://github.com/example/bookmarks"},
        ]

        ordered = local_kb._prioritize_github_repos(repos, "CVE-2018-3760")

        self.assertEqual(ordered[0]["url"], "https://github.com/mpgn/CVE-2018-3760")

    def test_guess_raw_urls_uses_current_cve_without_double_prefix(self):
        urls = local_kb._guess_raw_urls("https://github.com/example/repo", "CVE-2018-3760")

        self.assertTrue(any(url.endswith("/CVE-2018-3760.py") for url in urls))
        self.assertFalse(any("CVE-CVE-2018-3760" in url for url in urls))

    def test_extracts_nuclei_yaml_for_current_cve(self):
        yaml_content = """```yaml
id: CVE-2018-3760
info:
  name: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/assets/file:%2f%2f/etc/passwd"
```"""

        extracted = local_kb._extract_nuclei_yaml(yaml_content, "CVE-2018-3760")

        self.assertIn("id: CVE-2018-3760", extracted)
        self.assertIn("http:", extracted)


if __name__ == "__main__":
    unittest.main()
