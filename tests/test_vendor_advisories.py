import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cve_hunter.tools.vendor_advisories import (
    _is_exact_installer_url,
    _local_environment_matches_product,
    _msrc_months_from_index,
    _oracle_links,
    _oracle_mapping_links,
    _verify_media_urls,
    index_local_environments,
    parse_jenkins_advisory,
    parse_msrc_document,
    parse_oracle_advisory,
    parse_tomcat_security,
    read_cve_file,
    render_official_lab_report,
    write_official_lab_report,
)
from tools.discover_official_labs import parse_args


class VendorAdvisoryTests(unittest.TestCase):
    def test_cli_accepts_historical_cve_file(self):
        with patch("sys.argv", [
            "discover_official_labs",
            "--historical",
            "--cve-file",
            "targets.txt",
        ]):
            args = parse_args()

        self.assertTrue(args.historical)
        self.assertEqual(args.cve_file, Path("targets.txt"))

    def test_oracle_risk_matrix_becomes_manual_real_product_candidate(self):
        html = """
        <table>
          <tr><th>CVE ID</th><th>Product</th><th>Component</th><th>Protocol</th>
              <th>Remote Exploit without Auth.?</th><th>Base Score</th>
              <th>Supported Versions Affected</th><th>Notes</th></tr>
          <tr><td>CVE-2026-35273</td><td>PeopleSoft Enterprise PeopleTools</td>
              <td>Updates Environment Management</td><td>HTTP</td><td>Yes</td>
              <td>9.8</td><td>8.61, 8.62</td><td></td></tr>
        </table>
        """
        candidates = parse_oracle_advisory(
            html,
            "https://www.oracle.com/security-alerts/alert-cve-2026-35273.html",
            "Alert for CVE-2026-35273",
        )

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["cve_id"], "CVE-2026-35273")
        self.assertTrue(candidate["remote_without_auth"])
        self.assertEqual(candidate["cvss_score"], 9.8)
        self.assertEqual(candidate["lab_readiness"], "manual_media_required")
        self.assertEqual(candidate["lab_type"], "manual_licensed_real_product")
        self.assertEqual(candidate["deployment_type"], "manual")
        self.assertEqual(candidate["environment_status"], "not_present")
        self.assertEqual(candidate["media_status"], "license_required")

    def test_oracle_index_selects_latest_released_item_per_category(self):
        html = """
        <a href="/security-alerts/cpujul2026.html">Critical Patch Update - July 2026 - Pre-Release Announcement</a>
        <a href="/security-alerts/cpuapr2026.html">Critical Patch Update - April 2026</a>
        <a href="/security-alerts/cpujan2026.html">Critical Patch Update - January 2026</a>
        <a href="/security-alerts/cspujun2026.html">Critical Security Patch Update - June 2026</a>
        <a href="/security-alerts/alert-CVE-2026-35273.html">Alert for CVE-2026-35273</a>
        """
        links = _oracle_links(html, 1)

        self.assertEqual([title for _, title in links], [
            "Alert for CVE-2026-35273",
            "Critical Security Patch Update - June 2026",
            "Critical Patch Update - April 2026",
        ])

    def test_oracle_mapping_expands_rowspan_and_keeps_each_advisory_link(self):
        html = """
        <table>
          <tr><td rowspan="2">CVE-2021-2182</td><td>Product A</td>
              <td><a href="/security-alerts/cpuoct2021.html">October 2021</a></td></tr>
          <tr><td>Product B</td>
              <td><a href="/security-alerts/cpujan2022.html">January 2022</a></td></tr>
        </table>
        """

        links = _oracle_mapping_links(html, {"CVE-2021-2182"})

        self.assertEqual([title for _, title in links], ["October 2021", "January 2022"])

    def test_jenkins_core_advisory_produces_version_pinned_docker_candidate(self):
        html = """
        <h2>Descriptions</h2>
        <h3>Open redirect vulnerability</h3>
        <p>SECURITY-3711 / CVE-2026-53436</p>
        <p>Severity (CVSS): Medium</p>
        <p>Jenkins 2.567 and earlier, LTS 2.555.2 and earlier improperly validates a URL.</p>
        <p>Jenkins 2.568, LTS 2.555.3 rejects unsafe URLs.</p>
        <h2>Severity</h2>
        """
        candidates = parse_jenkins_advisory(
            html,
            "https://www.jenkins.io/security/advisory/2026-06-10/",
            "Jenkins Security Advisory 2026-06-10",
        )

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["affected_versions"], "Jenkins 2.567 and earlier, LTS 2.555.2 and earlier")
        self.assertEqual(candidate["fixed_versions"], "Jenkins 2.568, LTS 2.555.3")
        self.assertEqual(candidate["image_repository"], "jenkins/jenkins")
        self.assertEqual(candidate["version_pin"], "2.567")
        self.assertEqual(candidate["deployment_type"], "docker")
        self.assertEqual(candidate["media_status"], "unverified")
        self.assertTrue(candidate["media_url"].endswith("/2.567/jenkins.war"))

    def test_tomcat_security_section_produces_each_cve(self):
        html = """
        <h3><span>2026-07-07</span> Fixed in Apache Tomcat 9.0.120</h3>
        <div>
          Low: EncryptInterceptor requirements not clearly documented CVE-2026-59084
          Details. Affects: 9.0.13 to 9.0.119
          Moderate: Incorrect URL decoding CVE-2026-59083
          Details. Affects: 9.0.0.M1 to 9.0.119
        </div>
        <h3>Fixed in Apache Tomcat 9.0.119</h3><div>Low: Older CVE-2026-55955 Affects: 9.0.1 to 9.0.118</div>
        """
        candidates = parse_tomcat_security(
            html,
            "https://tomcat.apache.org/security-9.html",
            max_releases=1,
        )

        self.assertEqual({item["cve_id"] for item in candidates}, {"CVE-2026-59083", "CVE-2026-59084"})
        self.assertTrue(all(item["fixed_versions"] == "9.0.120" for item in candidates))
        self.assertTrue(all(item["version_pin"] == "9.0.119" for item in candidates))
        self.assertTrue(all(item["lab_readiness"] == "docker_recipe_candidate" for item in candidates))
        all_releases = parse_tomcat_security(
            html,
            "https://tomcat.apache.org/security-9.html",
            max_releases=None,
        )
        self.assertIn("CVE-2026-55955", {item["cve_id"] for item in all_releases})
        self.assertTrue(all(item["media_url"].endswith(".tar.gz") for item in all_releases))

    def test_msrc_document_maps_affected_products_to_vm_candidate(self):
        payload = {
            "ProductTree": {
                "Branch": [{"Items": [
                    {"ProductID": "p1", "Value": "Windows Server 2025"},
                    {"ProductID": "p2", "Value": "Microsoft Office"},
                ]}]
            },
            "Vulnerability": [{
                "CVE": "CVE-2026-50000",
                "Title": {"Value": "Windows HTTP vulnerability"},
                "ProductStatuses": [{"Type": 3, "ProductID": ["p1"]}],
                "Threats": [{"Type": 3, "Description": {"Value": "Critical"}}],
                "CVSSScoreSets": [{"BaseScore": 9.8, "Vector": "CVSS:3.1/AV:N/PR:N"}],
                "Notes": [{"Value": "A remote vulnerability."}],
            }],
        }
        candidates = parse_msrc_document(payload, "https://api.msrc.microsoft.com/test")

        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["affected_products"], ["Windows Server 2025"])
        self.assertEqual(candidate["affected_versions"], "Windows Server 2025")
        self.assertTrue(candidate["remote_without_auth"])
        self.assertEqual(candidate["lab_readiness"], "isolated_vm_required")
        self.assertEqual(candidate["deployment_type"], "vm")
        self.assertEqual(candidate["media_status"], "license_or_evaluation_required")

    def test_msrc_index_pages_until_target_month_is_found(self):
        client = Mock()
        client.get_json.side_effect = [
            (Mock(), {
                "value": [{"cveNumber": "CVE-2020-0001", "releaseDate": "2020-01-14T00:00:00Z"}],
                "@odata.nextLink": "https://api.msrc.microsoft.com/page-2",
            }),
            (Mock(), {
                "value": [{"cveNumber": "CVE-2022-41076", "releaseDate": "2022-11-08T00:00:00-08:00"}],
            }),
        ]
        sources = []
        errors = []

        months = _msrc_months_from_index(
            client,
            {"CVE-2022-41076"},
            sources,
            errors,
        )

        self.assertEqual(months, ["2022-Nov"])
        self.assertEqual(client.get_json.call_count, 2)
        self.assertEqual(sources[0]["advisories_checked"], 2)
        self.assertEqual(errors, [])

    def test_media_probe_only_heads_exact_package_urls(self):
        client = Mock()
        client.head.return_value = Mock(status_code=200)
        exact = {
            "vendor": "Apache",
            "media_url": "https://archive.apache.org/apache-tomcat-9.0.1.tar.gz",
            "media_status": "unverified",
        }
        directory = {
            "vendor": "Apache",
            "media_url": "https://archive.apache.org/dist/tomcat/",
            "media_status": "unverified",
        }

        _verify_media_urls(client, [exact, directory], [])

        client.head.assert_called_once_with(exact["media_url"])
        self.assertEqual(exact["media_status"], "verified_download")
        self.assertEqual(directory["media_status"], "not_exact_package_url")
        self.assertTrue(_is_exact_installer_url(exact["media_url"]))
        self.assertFalse(_is_exact_installer_url(directory["media_url"]))

    def test_read_cve_file_extracts_and_deduplicates_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text("CVE-2021-2182\nnotes cve-2022-41076\nCVE-2021-2182\n", encoding="utf-8")

            cve_ids = read_cve_file(path)

        self.assertEqual(cve_ids, {"CVE-2021-2182", "CVE-2022-41076"})

    def test_local_cve_match_requires_same_product(self):
        paths = [r"F:\labs\spring\CVE-2025-41242\docker-compose.yml"]

        self.assertFalse(_local_environment_matches_product("Oracle Enterprise Command Center Framework", paths))
        self.assertTrue(_local_environment_matches_product(
            "Apache Tomcat",
            [r"F:\labs\tomcat\CVE-2026-59083\docker-compose.yml"],
        ))

    def test_local_compose_match_marks_cve_as_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "product" / "CVE-2026-53436" / "docker-compose.yml"
            compose.parent.mkdir(parents=True)
            compose.write_text("services: {}\n", encoding="utf-8")
            index = index_local_environments([Path(tmp)])

        self.assertIn("CVE-2026-53436", index)
        self.assertEqual(len(index["CVE-2026-53436"]), 1)

    def test_report_writes_json_and_markdown(self):
        report = {
            "generated_at": "2026-07-17T00:00:00+00:00",
            "candidates": [{
                "lab_readiness": "docker_recipe_candidate",
                "vendor": "Jenkins",
                "cve_id": "CVE-2026-53436",
                "product": "Jenkins Core",
                "severity": "medium",
                "affected_versions": "2.567 and earlier",
                "fixed_versions": "2.568",
                "advisory_url": "https://www.jenkins.io/security/advisory/2026-06-10/",
            }],
            "errors": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            json_path, markdown_path = write_official_lab_report(report, Path(tmp))
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")

        self.assertEqual(loaded["candidates"][0]["vendor"], "Jenkins")
        self.assertIn("CVE-2026-53436", markdown)
        self.assertEqual(render_official_lab_report(report), markdown)


if __name__ == "__main__":
    unittest.main()
