"""Device-level benchmark selection without network access."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import openpyxl

from scripts.evaluate_reference_evidence import device_hits


class ReferenceEvaluationTests(unittest.TestCase):
    def test_devices_are_compared_individually_and_duplicates_are_merged(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.xlsx"
            book = openpyxl.Workbook()
            sheet = book.active
            sheet.title = "迪普IPS待补充CVE运行结果"
            sheet.append(["cve", "命中h3c", "命中dptech"])
            sheet.append(["CVE-2020-0001", "是", None])
            sheet.append(["CVE-2020-0001", None, "是"])
            sheet.append(["CVE-2020-0002,CVE-2020-0003", None, "是"])
            book.save(path)
            book.close()
            hits = device_hits(path)
        self.assertEqual(hits["CVE-2020-0001"], {"h3c", "dptech"})
        self.assertEqual(hits["CVE-2020-0001"] - {"h3c"}, {"dptech"})
        self.assertEqual(hits["CVE-2020-0002"], {"dptech"})
        self.assertEqual(hits["CVE-2020-0003"], {"dptech"})
