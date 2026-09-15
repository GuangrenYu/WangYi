import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.tools import local_kb


class LocalKbTests(unittest.TestCase):
    def test_poc0911_fallback_is_reference_only_and_ignores_old_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "poc0911" / "CVE-2024-23334"
            (directory / "repro" / "trigger").mkdir(parents=True)
            (directory / "poc.http").write_text("invalid", encoding="utf-8")
            (directory / "repro" / "trigger" / "poc.http").write_text(
                "GET /reference HTTP/1.1\nHost: old-host\n\n", encoding="utf-8")
            (directory / "result.json").write_text('{"status":"SUCCESS"}', encoding="utf-8")
            with (patch.object(local_kb, "_kb_base", return_value=root),
                  patch.object(local_kb, "_search_pcap_kb", return_value={}),
                  patch.object(local_kb, "_search_vulhub_readme", return_value={})):
                result = local_kb.search_local_kb("cve-2024-23334")
                self.assertTrue(result["reference_only"])
                self.assertEqual(result["source"], "local_kb_poc0911")
                self.assertIn("Host: {{TARGET_HOST}}", result["raw_http"])
                self.assertNotIn("status", result)
                custom = root / "custom" / "2024" / "CVE-2024-23334.md"
                custom.parent.mkdir(parents=True)
                custom.write_text("```http\nGET /trusted HTTP/1.1\nHost: target\n\n```", encoding="utf-8")
                self.assertEqual(local_kb.search_local_kb("CVE-2024-23334")["source"], "local_kb_custom")

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

    def test_search_local_kb_extracts_vulhub_readme_without_github_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            poc_kb = root / "poc_kb"
            vulhub_dir = root / "vulhub"
            readme_dir = vulhub_dir / "python" / "CVE-2024-23334"
            readme_dir.mkdir(parents=True)
            (readme_dir / "docker-compose.yml").write_text(
                "services:\n  web:\n    image: test\n    ports:\n      - '8080:8080'\n",
                encoding="utf-8",
            )
            (readme_dir / "README.zh-cn.md").write_text(
                "```text\n"
                "GET /static/../../../../../etc/passwd HTTP/1.1\n"
                "Host: your-ip:8080\n"
                "\n"
                "```",
                encoding="utf-8",
            )
            fake_cfg = SimpleNamespace(
                poc_kb_dir=str(poc_kb),
                vulhub_dir=str(vulhub_dir),
                local_kb_pcap_dir=str(root / "pcaps"),
                local_kb_github_fetch=False,
            )

            local_kb._pcap_index = None
            local_kb._vulhub_readme_index = None
            with patch("cve_hunter.tools.local_kb.cfg", fake_cfg):
                result = local_kb.search_local_kb("CVE-2024-23334")

        self.assertTrue(result["found"])
        self.assertEqual(result["source"], "local_kb_vulhub")
        self.assertIn("GET /static/../../../../../etc/passwd HTTP/1.1", result["raw_http"])
        self.assertIn("Host: {{TARGET_HOST}}", result["raw_http"])
        self.assertNotIn("Content-Length", result["raw_http"])

    def test_extract_http_request_from_pcap_payload_normalizes_host(self):
        payload = (
            b"GET /poc HTTP/1.1\r\n"
            b"Host: 10.0.0.1:8080\r\n"
            b"User-Agent: test\r\n"
            b"\r\n"
        )

        raw_http = local_kb._extract_http_request_from_bytes(payload)

        self.assertIn("GET /poc HTTP/1.1", raw_http)
        self.assertIn("Host: {{TARGET_HOST}}", raw_http)


if __name__ == "__main__":
    unittest.main()
