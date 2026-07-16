import unittest
from pathlib import Path
from unittest.mock import patch

import main
from cve_hunter.graph import node_environment_agent, route_after_environment
from cve_hunter.state import CVEState


class LocalContainerModeTests(unittest.TestCase):
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
