import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main


class BatchDeduplicationTests(unittest.TestCase):
    def test_collects_unique_cves_from_historical_pcap_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "漏洞类" / "2026年1月1日"
            root.mkdir(parents=True)
            (root / "CVE-2024-0001.pcap").write_bytes(b"pcap")
            (root / "cve-2024-0001-copy.pcap").write_bytes(b"pcap")
            (root / "capture.pcap").write_bytes(b"pcap")

            result = main.collect_successful_pcap_cve_ids(root.parent)

        self.assertEqual(result, {"CVE-2024-0001"})

    def test_collects_only_successful_batch_cves(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "batch.json").write_text(
                json.dumps({
                    "results": [
                        {"cve_id": "CVE-2024-0001", "status": "SUCCESS"},
                        {"cve_id": "CVE-2024-0002", "status": "FAILURE"},
                        {"cve_id": "CVE-2024-0003", "passed": True},
                    ],
                }),
                encoding="utf-8",
            )

            result = main.collect_successful_batch_cve_ids(root)

        self.assertEqual(result, {"CVE-2024-0001", "CVE-2024-0003"})

    def test_run_batch_skips_historical_success_without_renumbering(self):
        with tempfile.TemporaryDirectory() as tmp:
            test_file = Path(tmp) / "cases.txt"
            test_file.write_text("CVE-2024-0001\nCVE-2024-0002\n", encoding="utf-8")
            result = main.BatchResult(
                index=2,
                cve_id="CVE-2024-0002",
                passed=False,
                status="FAILURE",
                status_code="TEST",
                message="test",
                poc_source="none",
                pcap_file_path="",
                elapsed_seconds=0.1,
            )
            with (
                patch("main.resolve_test_file", return_value=test_file),
                patch("main.collect_successful_cve_ids", return_value={"CVE-2024-0001"}),
                patch("main.choose_terminal_count", return_value=1),
                patch("main.execute_cve_as_batch_result", return_value=result) as execute,
                patch("main.create_batch_results_path", return_value=Path(tmp) / "results.json"),
                patch("main.write_batch_results"),
                patch("main.print_batch_summary"),
                patch("main.console.print"),
            ):
                results = main.run_batch(
                    str(test_file),
                    start=1,
                    end=2,
                    terminal_count=1,
                )

        self.assertEqual(results, [result])
        self.assertEqual(execute.call_args.args[:2], (2, "CVE-2024-0002"))


if __name__ == "__main__":
    unittest.main()
