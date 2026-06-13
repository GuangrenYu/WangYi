import unittest

from cve_hunter.tools.reference_utils import normalize_reference_urls


class ReferenceUtilsTests(unittest.TestCase):
    def test_splits_concatenated_urls_and_dedupes(self):
        refs = normalize_reference_urls([
            "https://github.com/a/onehttps://github.com/b/two",
            "https://github.com/a/one",
            "",
        ])

        self.assertEqual(refs, ["https://github.com/a/one", "https://github.com/b/two"])


if __name__ == "__main__":
    unittest.main()
