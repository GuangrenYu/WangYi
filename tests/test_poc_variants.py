import unittest

from cve_hunter.poc_variants import generate_bounded_variants


class PocVariantTests(unittest.TestCase):
    def test_404_toggles_trailing_slash(self):
        candidate = {"kind": "raw_http", "raw_http": "GET /admin HTTP/1.1\nHost: {{TARGET_HOST}}\n\n"}
        variants = generate_bounded_variants(candidate, status_code=404)
        self.assertEqual(len(variants), 1)
        self.assertIn("GET /admin/ HTTP/1.1", variants[0]["raw_http"])
        self.assertEqual(variants[0]["variant_action"], "adjust_path")
        self.assertTrue(variants[0]["is_variant"])

    def test_405_switches_get_to_post(self):
        candidate = {"kind": "raw_http", "raw_http": "GET /submit HTTP/1.1\nHost: {{TARGET_HOST}}\n\n"}
        variants = generate_bounded_variants(candidate, status_code=405)
        self.assertEqual(len(variants), 1)
        self.assertIn("POST /submit HTTP/1.1", variants[0]["raw_http"])

    def test_415_switches_form_content_type(self):
        candidate = {
            "kind": "raw_http",
            "raw_http": "POST /submit HTTP/1.1\nHost: {{TARGET_HOST}}\nContent-Type: application/json\n\n{\"a\":1}",
        }
        variants = generate_bounded_variants(candidate, status_code=415)
        self.assertEqual(len(variants), 2)
        content_variant = next(item for item in variants if item["variant_action"] == "adjust_content_type")
        self.assertIn("Content-Type: application/x-www-form-urlencoded", content_variant["raw_http"])
        self.assertIn("a=1", content_variant["raw_http"])

    def test_body_request_gets_content_length_variant(self):
        candidate = {
            "kind": "raw_http",
            "raw_http": "POST /submit HTTP/1.1\nHost: {{TARGET_HOST}}\nContent-Type: application/json\n\n{\"a\":1}",
        }
        variants = generate_bounded_variants(candidate, status_code=200)
        self.assertEqual(len(variants), 1)
        self.assertIn("Content-Length: 7", variants[0]["raw_http"])
        self.assertEqual(variants[0]["variant_action"], "adjust_header")

    def test_generic_ips_preserves_payload_and_changes_only_encoding_case(self):
        candidate = {"kind": "raw_http", "raw_http": "GET /a?x=%2f HTTP/1.1\nHost: {{TARGET_HOST}}\n\n"}
        variants = generate_bounded_variants(candidate, generic_ips_matched=True)
        self.assertEqual(len(variants), 1)
        self.assertIn("x=%2F", variants[0]["raw_http"])
        self.assertEqual(variants[0]["variant_action"], "adjust_payload_encoding")

    def test_does_not_mutate_nuclei_or_multistep_candidates(self):
        self.assertEqual(generate_bounded_variants({"nuclei_yaml": "http: []"}, status_code=404), [])
        self.assertEqual(generate_bounded_variants({"request_steps": [{"raw_http": "GET / HTTP/1.1"}]}, status_code=404), [])

    def test_does_not_duplicate_root_path(self):
        candidate = {"kind": "raw_http", "raw_http": "GET / HTTP/1.1\nHost: {{TARGET_HOST}}\n\n"}
        self.assertEqual(generate_bounded_variants(candidate, status_code=404), [])

    def test_caps_variants_at_two(self):
        candidate = {
            "kind": "raw_http",
            "raw_http": "GET /a HTTP/1.1\nHost: {{TARGET_HOST}}\nContent-Type: application/json\n\n{\"x\":1}",
        }
        variants = generate_bounded_variants(candidate, status_code=415, generic_ips_matched=True, max_variants=2)
        self.assertLessEqual(len(variants), 2)


if __name__ == "__main__":
    unittest.main()
