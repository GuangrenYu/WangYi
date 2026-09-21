"""refetch_ips_cve_matches 的窗口与归因回归测试。

背景：IPS 日志接口只认 ``start_time``/``end_time``。曾经写成 ``startTime``/``endTime``，
参数被忽略、服务端退回全天窗口，导致这个时序兜底既漏又串（实测返回整天 7554 条日志）。
"""

import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.tools import http_sender

CVE = "CVE-2024-1234"
SEND_EPOCH = time.mktime(time.strptime("2026-09-17 12:00:00", "%Y-%m-%d %H:%M:%S"))
BASE = "http://10.20.1.240:3013"


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def _alarm(received_at, cve=CVE):
    return {
        "id": received_at,
        "source": "dptech",
        "received_at": received_at,
        "cve_list": f"|{cve}|",
        "attack_name": f"{cve}_something",
        "fields": {"CVE": cve, "HttpFirstLine": "GET /x HTTP/1.1"},
    }


class IpsLogRefetchTests(unittest.TestCase):
    def _run(self, pages, cve=CVE):
        """pages: 每次轮询返回的数据列表（按调用顺序）。"""
        calls = []

        def fake_get(url, params=None, timeout=None, trust_env=None):
            calls.append({"url": url, "params": dict(params or {})})
            data = pages[min(len(calls) - 1, len(pages) - 1)]
            return _FakeResponse({"code": 200, "data": data})

        fake_cfg = SimpleNamespace(ips_api_url=f"{BASE}/api/cve-match")
        with (
            patch.object(http_sender, "cfg", fake_cfg),
            patch.object(http_sender.httpx, "get", side_effect=fake_get),
            patch.object(http_sender.time, "sleep", return_value=None),
        ):
            result = http_sender.refetch_ips_cve_matches(cve, SEND_EPOCH)
        return result, calls

    def test_query_uses_underscore_time_params(self):
        _, calls = self._run([[]])
        params = calls[0]["params"]
        self.assertIn("start_time", params)
        self.assertIn("end_time", params)
        self.assertNotIn("startTime", params)
        self.assertNotIn("endTime", params)
        self.assertEqual(params["page_size"], http_sender.IPS_LOG_PAGE_SIZE)
        self.assertEqual(calls[0]["url"], f"{BASE}/api/logs")

    def test_start_stays_before_send_time(self):
        _, calls = self._run([[]])
        start = time.mktime(time.strptime(calls[0]["params"]["start_time"], "%Y-%m-%d %H:%M:%S"))
        # 发包时刻前留 10s 余量，且不能早于发包时刻
        self.assertLessEqual(start, SEND_EPOCH)
        self.assertGreaterEqual(start, SEND_EPOCH - 10)

    def test_stale_alarm_is_not_counted(self):
        stale = _alarm("2026-09-17 09:00:00")
        fresh = _alarm("2026-09-17 12:00:05")
        result, _ = self._run([[stale, fresh]])
        self.assertEqual([r["received_at"] for r in result], ["2026-09-17 12:00:05"])

    def test_only_stale_matches_keeps_polling(self):
        stale = _alarm("2026-09-17 09:00:00")
        fresh = _alarm("2026-09-17 12:00:04")
        result, calls = self._run([[stale], [fresh]])
        self.assertEqual(len(calls), 2)
        self.assertEqual([r["received_at"] for r in result], ["2026-09-17 12:00:04"])

    def test_other_cve_is_ignored(self):
        other = _alarm("2026-09-17 12:00:05", cve="CVE-2024-9999")
        result, calls = self._run([[other]])
        self.assertEqual(result, [])
        self.assertEqual(len(calls), 3)  # 三次轮询全部用尽


if __name__ == "__main__":
    unittest.main()
