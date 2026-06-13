import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.tools import poc_sources


class PocSourcesTests(unittest.TestCase):
    def test_exploitdb_html_200_is_treated_as_no_match(self):
        class Response:
            status_code = 200

            def json(self):
                raise ValueError("not json")

        with (
            patch.object(poc_sources, "cfg", SimpleNamespace(request_timeout=30, httpx_proxy=None)),
            patch.object(poc_sources.httpx, "get", return_value=Response()),
        ):
            result = poc_sources.search_exploitdb("CVE-2018-3760")

        self.assertFalse(result["found"])
        self.assertEqual(result["source"], "exploit-db")
        self.assertNotIn("error", result)


if __name__ == "__main__":
    unittest.main()
