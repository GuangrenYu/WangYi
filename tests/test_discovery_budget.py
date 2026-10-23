import unittest

from scripts.benchmark_discovery_budget import select_sample
from cve_hunter.config import Config


class BudgetTests(unittest.TestCase):
    def test_fit_and_holdout_selection_do_not_overlap_on_sufficient_rows(self):
        baseline = {'results':[
            {'cve_id':f'CVE-2020-{number:04d}', 'status':status}
            for offset,status in enumerate(['templates_generated','no_valid_templates','no_reference_content','error'])
            for number in range(offset*20,offset*20+20)
        ]}
        fit=set(select_sample(baseline))
        holdout=set(select_sample(baseline,holdout=True))
        self.assertEqual(len(fit),16)
        self.assertEqual(len(holdout),16)
        self.assertFalse(fit & holdout)

    def test_budget_configuration_is_bounded(self):
        from unittest.mock import patch
        with patch.dict('os.environ', {'REFERENCE_CRAWL_BUDGET':'120'}):
            self.assertEqual(Config().reference_crawl_budget,60)
        with patch.dict('os.environ', {'REFERENCE_CRAWL_BUDGET':'-1'}):
            self.assertEqual(Config().reference_crawl_budget,0)
