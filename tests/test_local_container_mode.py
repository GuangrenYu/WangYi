import unittest
from pathlib import Path
from unittest.mock import patch

import main
from cve_hunter.graph import (
    node_environment_agent,
    node_local_kb_search,
    route_after_environment,
    route_after_type_check,
)
from cve_hunter.state import CVEState


class LocalContainerModeTests(unittest.TestCase):
    def test_http_path_skips_environment_agent(self):
        state = CVEState(is_http_vuln=True, protocol="http", local_container_mode=False)
        self.assertEqual(route_after_type_check(state), "local_kb_search")

    def test_local_container_still_enters_environment_agent(self):
        state = CVEState(is_http_vuln=True, protocol="http", local_container_mode=True)
        self.assertEqual(route_after_type_check(state), "environment_agent")

    def test_local_kb_seeds_default_target_when_environment_skipped(self):
        state = CVEState(cve_id="CVE-2024-1111", is_http_vuln=True)
        with (
            patch("cve_hunter.graph.search_local_kb", return_value={"found": False}),
            patch("cve_hunter.graph.console.print"),
            patch(
                "cve_hunter.graph.default_attack_environment",
                return_value={
                    "source": "default_target",
                    "target_url": "http://10.55.1.21",
                    "target_host": "10.55.1.21",
                    "setup_mode": "disabled",
                },
            ),
        ):
            update = node_local_kb_search(state)

        self.assertEqual(update["attack_environment"]["target_host"], "10.55.1.21")
        self.assertEqual(update["milestones"]["environment_planned"]["status"], "skipped")
        self.assertEqual(update["agent_trace"][-1]["action"], "skip_for_http_path")

    def test_poc0911_is_generation_context_not_direct_request(self):
        state = CVEState(cve_id="CVE-2024-23334", is_http_vuln=True)
        result = {
            "found": True,
            "source": "local_kb_poc0911",
            "reference_only": True,
            "raw_http": "GET /generic HTTP/1.1\nHost: {{TARGET_HOST}}\n\n",
            "raw_http_list": ["GET /generic HTTP/1.1\nHost: {{TARGET_HOST}}\n\n"],
            "content": "历史请求，仅供生成阶段参考",
        }
        with (
            patch("cve_hunter.graph.search_local_kb", return_value=result),
            patch("cve_hunter.graph.console.print"),
        ):
            update = node_local_kb_search(state)

        self.assertEqual(update["current_phase"], "reference_analysis")
        self.assertNotIn("poc_candidates", update)
        self.assertIn("历史请求", update["local_knowledge_context"])

    def test_environment_route_stops_after_local_match_failure(self):
        state = CVEState(current_phase="generate_report", local_container_mode=True)
        self.assertEqual(route_after_environment(state), "generate_report")

    def test_environment_route_continues_after_environment_ready(self):
        state = CVEState(current_phase="local_kb_search", local_container_mode=True)
        self.assertEqual(route_after_environment(state), "local_kb_search")

    def test_environment_miss_routes_directly_to_report(self):
        state = CVEState(cve_id="CVE-2024-9999", local_container_mode=True)
        agent_result = {
            "environment_candidates": [],
            "attack_environment": {"target_url": "", "target_host": ""},
            "errors": ["Vulhub 未匹配到环境，已跳过"],
            "trace": {
                "agent": "EnvironmentAgent",
                "action": "plan_attack_environment",
                "status": "not_found",
                "summary": "Vulhub 未匹配到环境，已跳过",
                "data": {},
            },
        }
        with (
            patch("cve_hunter.graph.run_environment_agent", return_value=agent_result),
            patch("cve_hunter.graph.write_environment_manifest", return_value=Path("manifest.json")),
            patch("cve_hunter.graph.console.print"),
        ):
            update = node_environment_agent(state)

        self.assertEqual(update["current_phase"], "generate_report")

    def test_batch_terminal_command_preserves_local_container_mode(self):
        with (
            patch("main.make_vscode_task", side_effect=lambda _label, args: {"args": args}) as make_task,
            patch("main.launch_vscode_task_group"),
        ):
            main.launch_batch_terminals(
                Path("cases.txt"),
                [(1, 10)],
                local_container_mode=True,
            )

        command_args = make_task.call_args.args[1]
        self.assertIn("--local-container", command_args)


if __name__ == "__main__":
    unittest.main()
