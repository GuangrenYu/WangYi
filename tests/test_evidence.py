import json
import tempfile
import unittest
from pathlib import Path

from cve_hunter.evidence import (
    SUCCESS_TIER_L0,
    SUCCESS_TIER_L1,
    SUCCESS_TIER_L2,
    SUCCESS_TIER_L3,
    SUCCESS_TIER_L4,
    build_version_evidence,
    classify_failure,
    derive_success_tier,
    write_repro_bundle,
)
from cve_hunter.status_codes import (
    CAPTURE_SUCCESS,
    INFRASTRUCTURE_FAILED,
    NO_EXPLOIT_EVIDENCE,
    TARGET_ORACLE_SUCCESS,
)


class EvidenceHelperTests(unittest.TestCase):
    def test_failure_class_mapping_chinese(self):
        self.assertEqual(classify_failure(INFRASTRUCTURE_FAILED), "环境")
        self.assertEqual(classify_failure(NO_EXPLOIT_EVIDENCE), "证据")
        self.assertEqual(classify_failure(CAPTURE_SUCCESS), "无")
        self.assertEqual(classify_failure("INFRASTRUCTURE_FAILED"), "环境")

    def test_success_tier_chinese_ladders(self):
        self.assertEqual(
            derive_success_tier(milestones={"environment_ready": {"status": "passed"}}),
            SUCCESS_TIER_L0,
        )
        self.assertEqual(
            derive_success_tier(
                attempt_history=[{"request_success": True}],
                status_code=NO_EXPLOIT_EVIDENCE,
                success_level="no_exploit_evidence",
            ),
            SUCCESS_TIER_L1,
        )
        self.assertEqual(
            derive_success_tier(
                status_code=TARGET_ORACLE_SUCCESS,
                target_oracle_success=True,
                success_level="target_oracle",
            ),
            SUCCESS_TIER_L2,
        )
        self.assertEqual(
            derive_success_tier(
                status_code=CAPTURE_SUCCESS,
                ips_matched=True,
                success_level="ips_cve_match",
            ),
            SUCCESS_TIER_L3,
        )
        self.assertEqual(
            derive_success_tier(
                status_code=TARGET_ORACLE_SUCCESS,
                target_oracle_success=True,
                repro_bundle_complete=True,
                cleanup_status="passed",
            ),
            SUCCESS_TIER_L4,
        )

    def test_build_version_evidence_claimed_and_image(self):
        evidence = build_version_evidence(
            cve_id="CVE-2019-9193",
            nvd_description="In PostgreSQL 9.3 through 11.2, the COPY TO/FROM PROGRAM function allows ...",
            attack_environment={
                "compose_file": "third_party/vulhub/postgres/CVE-2019-9193/docker-compose.yml",
                "target_url": "tcp://127.0.0.1:5432",
            },
            execution_spec={"engine": "postgres"},
            executor_result={"body": "uid=999(postgres)", "engine": "postgres"},
        )
        self.assertTrue(evidence["claimed"]["version_ranges"])
        self.assertIn("9.3-11.2", evidence["claimed"]["version_ranges"])
        self.assertTrue(any("vulhub/postgres" in tag for tag in evidence["environment"]["image_tags"]))
        self.assertEqual(evidence["comparison"]["status"], "claimed_and_verified")

    def test_write_repro_bundle_for_target_oracle_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            result = write_repro_bundle(
                root,
                cve_id="CVE-2025-0001",
                status="SUCCESS",
                status_code=TARGET_ORACLE_SUCCESS,
                message="oracle hit",
                success_tier=SUCCESS_TIER_L2,
                failure_class="无",
                success_level="target_oracle",
                poc_source="reference",
                poc_raw_http="GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                pcap_file_path=str(pcap),
                attack_environment={"target_url": "http://127.0.0.1:8080"},
                environment_teardown_result={"success": True, "skipped": False},
                oracle_result={"status_code": TARGET_ORACLE_SUCCESS, "success_level": "target_oracle"},
                executor_result={"success": True, "status_code": 200, "body": "ok"},
                attempt_history=[{"request_success": True, "http_status_code": 200}],
            )

            self.assertTrue(result["complete"])
            self.assertEqual(result["success_tier"], "目标证据")
            self.assertEqual(result["failure_class"], "无")
            self.assertEqual((root / "capture.pcap").read_bytes(), pcap.read_bytes())
            self.assertIn("GET / HTTP/1.1", (root / "poc.http").read_text())
            self.assertEqual(result["artifacts"]["pcap"], str(root / "capture.pcap"))


if __name__ == "__main__":
    unittest.main()
