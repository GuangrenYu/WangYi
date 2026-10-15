"""Protocol gate: inferred http/database must continue even if LLM says non-HTTP."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.classifier import VulnTypeResult
from cve_hunter.executors.base import PROTOCOL_HTTP, infer_protocol
from cve_hunter.graph import (
    _is_runnable_protocol,
    node_vuln_type_check,
    route_after_type_check,
)
from cve_hunter.state import CVEState
from cve_hunter.status_codes import PROTOCOL_UNSUPPORTED


class ProtocolGateTests(unittest.TestCase):
    def test_infer_webnms_password_file_as_http(self):
        desc = (
            "ZOHO WebNMS Framework 5.2 and 5.2 SP1 use a weak obfuscation algorithm "
            "to store passwords, which allows context-dependent attackers to obtain "
            "cleartext passwords by leveraging access to WEB-INF/conf/securitydbData.xml."
        )
        protocol = infer_protocol(
            is_http_vuln=False,
            vuln_type="弱密码混淆/不安全凭证存储",
            description=desc,
        )
        self.assertEqual(protocol, PROTOCOL_HTTP)
        self.assertTrue(_is_runnable_protocol(protocol, False))

    def test_route_continues_when_protocol_http_even_if_flag_false(self):
        state = CVEState(is_http_vuln=False, protocol="http", local_container_mode=False)
        self.assertEqual(route_after_type_check(state), "local_kb_search")

    def test_route_stops_for_true_unsupported(self):
        state = CVEState(is_http_vuln=False, protocol="unsupported", local_container_mode=False)
        self.assertEqual(route_after_type_check(state), "generate_report")

    def test_infer_jackson_as_http_when_llm_says_no(self):
        desc = (
            "FasterXML jackson-databind mishandles interaction between "
            "serialization gadgets and typing, leading to remote code execution."
        )
        protocol = infer_protocol(
            is_http_vuln=False,
            vuln_type="反序列化漏洞",
            description=desc,
        )
        self.assertEqual(protocol, PROTOCOL_HTTP)
        self.assertTrue(_is_runnable_protocol(protocol, False))

    def test_infer_defaults_to_http_when_uncertain(self):
        protocol = infer_protocol(
            is_http_vuln=False,
            vuln_type="未知",
            description="An issue was found in example software package.",
        )
        self.assertEqual(protocol, PROTOCOL_HTTP)

    def test_vuln_type_check_does_not_mark_webnms_unsupported(self):
        desc = (
            "ZOHO WebNMS Framework 5.2 and 5.2 SP1 use a weak obfuscation algorithm "
            "to store passwords by leveraging access to WEB-INF/conf/securitydbData.xml."
        )
        state = CVEState(
            cve_id="CVE-2016-6602",
            nvd_description=desc,
            nvd_references=["https://example.com"],
            local_container_mode=False,
        )
        fake = VulnTypeResult(
            cve_id="CVE-2016-6602",
            is_http_vuln=False,
            vuln_type="弱密码混淆/不安全凭证存储",
            error="",
        )
        with (
            patch("cve_hunter.graph.classify_http_vuln_from_info", return_value=fake),
            patch("cve_hunter.graph.console.print"),
        ):
            update = node_vuln_type_check(state)

        self.assertEqual(update["protocol"], PROTOCOL_HTTP)
        self.assertTrue(update["is_http_vuln"])
        self.assertEqual(update["current_phase"], "local_kb_search")
        self.assertNotEqual(update.get("status_code"), PROTOCOL_UNSUPPORTED)


if __name__ == "__main__":
    unittest.main()
