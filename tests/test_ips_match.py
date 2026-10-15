import unittest

from cve_hunter.ips_match import classify_ips_matches, extract_cves_from_ips_match


class IPSMatchClassificationTests(unittest.TestCase):
    def test_current_cve_match_is_success(self):
        matches = [{"fields": {"CVE": "CVE-2021-44228", "AttackName": "Apache Log4j RCE"}}]

        result = classify_ips_matches(matches, "CVE-2021-44228")

        self.assertTrue(result["ips_matched"])
        self.assertFalse(result["generic_ips_matched"])
        self.assertEqual(result["cve_match_count"], 1)

    def test_empty_cve_is_generic_only(self):
        matches = [{"fields": {"CVE": "---", "AttackName": "通用SSTI模板注入攻击"}}]

        result = classify_ips_matches(matches, "CVE-2021-44228")

        self.assertFalse(result["ips_matched"])
        self.assertTrue(result["generic_ips_matched"])
        self.assertEqual(result["generic_match_count"], 1)
        self.assertEqual(result["missing_cve_match_count"], 1)

    def test_other_cve_is_not_current_success(self):
        matches = [{"fields": {"CVE": "CVE-2020-1234", "AttackName": "Other CVE"}}]

        result = classify_ips_matches(matches, "CVE-2021-44228")

        self.assertFalse(result["ips_matched"])
        self.assertTrue(result["generic_ips_matched"])
        self.assertEqual(result["other_cve_match_count"], 1)

    def test_extract_cve_without_prefix(self):
        match = {"fields": {"CVE": "2021-44228"}}

        self.assertEqual(extract_cves_from_ips_match(match), ["CVE-2021-44228"])

    def test_either_device_exact_hit_is_success(self):
        """H3C 仅通用 + 迪普精确命中 → 成功；两台告警都保留。"""
        matches = [
            {
                "id": 1,
                "source": "h3c",
                "cve_list": "|CVE-2005-0845|CVE-2018-10956|",
                "fields": {"CVE": "CVE-2005-0845 | CVE-2018-10956"},
                "attack_name": "Generic_etc_passwd_Directory_traversal_Vulnerability",
            },
            {
                "id": 2,
                "source": "dptech",
                "cve_list": "|CVE-2001-0214|",
                "fields": {"CVE": "CVE-2001-0214"},
                "attack_name": "way-board.cgi db 参数任意文件读取",
            },
        ]

        result = classify_ips_matches(matches, "CVE-2001-0214")

        self.assertTrue(result["ips_matched"])
        self.assertTrue(result["generic_ips_matched"])
        self.assertTrue(result["hit_dptech"])
        self.assertFalse(result["hit_h3c"])
        self.assertEqual(result["cve_match_count"], 1)
        self.assertEqual(result["total_count"], 2)
        self.assertEqual(result["cve_match_sources"], ["dptech"])

    def test_cve_list_top_level_is_read(self):
        matches = [{"source": "dptech", "cve_list": "|CVE-1999-0266|", "fields": {}}]

        result = classify_ips_matches(matches, "CVE-1999-0266")

        self.assertTrue(result["ips_matched"])
        self.assertEqual(result["cve_match_sources"], ["dptech"])


if __name__ == "__main__":
    unittest.main()
