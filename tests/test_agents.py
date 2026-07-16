import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cve_hunter.agents import (
    _ensure_vulhub_repository,
    _find_docker_desktop_executable,
    _guess_target_url_from_compose,
    run_critic_agent,
    run_environment_agent,
    run_trigger_agent,
)
from cve_hunter.state import CVEState


class AgentTests(unittest.TestCase):
    def test_finds_docker_desktop_from_cli_install_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            install_dir = Path(tmp) / "DockerDesktop"
            docker_cli = install_dir / "resources" / "bin" / "docker.exe"
            desktop = install_dir / "Docker Desktop.exe"
            docker_cli.parent.mkdir(parents=True)
            docker_cli.touch()
            desktop.touch()

            with patch("cve_hunter.agents.shutil.which", return_value=str(docker_cli)):
                result = _find_docker_desktop_executable()

        self.assertEqual(result, desktop)

    def test_local_container_mode_without_compose_has_no_remote_target(self):
        state = CVEState(cve_id="CVE-2024-0001", local_container_mode=True)
        fake_cfg = SimpleNamespace(
            vulhub_dir="missing-vulhub",
            auto_env_enabled=False,
            agent_llm_enabled=False,
            attack_env_compose_file="",
            attack_env_target_url="http://1.1.60.21",
            target_ip="1.1.60.21",
        )

        with (
            patch("cve_hunter.agents.cfg", fake_cfg),
            patch("cve_hunter.agents._ensure_vulhub_repository", return_value={"success": True}),
        ):
            result = run_environment_agent(state)

        self.assertEqual(result["trace"]["status"], "not_found")
        self.assertEqual(result["attack_environment"]["target_url"], "")
        self.assertTrue(result["errors"])

    def test_missing_vulhub_is_cloned_in_local_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "vulhub"
            fake_cfg = SimpleNamespace(vulhub_dir=str(root))
            completed = SimpleNamespace(returncode=0, stdout="", stderr="")
            with (
                patch("cve_hunter.agents.cfg", fake_cfg),
                patch("cve_hunter.agents.shutil.which", return_value="git"),
                patch("cve_hunter.agents.subprocess.run", return_value=completed) as run,
            ):
                result = _ensure_vulhub_repository()

        self.assertTrue(result["success"])
        self.assertTrue(result["downloaded"])
        self.assertIn("clone", run.call_args.args[0])

    def test_local_mode_without_match_skips_environment_llm(self):
        state = CVEState(cve_id="CVE-2024-9999", local_container_mode=True)
        fake_cfg = SimpleNamespace(
            vulhub_dir="missing-vulhub",
            auto_env_enabled=False,
            agent_llm_enabled=True,
            agent_llm_model="test-model",
            llm_model="test-model",
            attack_env_compose_file="",
            attack_env_target_url="",
            target_ip="127.0.0.1",
        )
        with (
            patch("cve_hunter.agents.cfg", fake_cfg),
            patch("cve_hunter.agents._ensure_vulhub_repository", return_value={"success": True}),
            patch("cve_hunter.agents._run_environment_agent_llm") as llm,
        ):
            result = run_environment_agent(state)

        self.assertEqual(result["trace"]["status"], "not_found")
        self.assertEqual(result["attack_environment"]["target_url"], "")
        llm.assert_not_called()

    def test_environment_agent_discovers_local_vulhub_compose_without_starting(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "weblogic" / "CVE-2024-0001" / "docker-compose.yml"
            compose.parent.mkdir(parents=True)
            compose.write_text(
                "services:\n"
                "  target:\n"
                "    image: test/image\n"
                "    ports:\n"
                "      - \"18080:80\"\n",
                encoding="utf-8",
            )
            state = CVEState(cve_id="CVE-2024-0001")
            fake_cfg = SimpleNamespace(
                vulhub_dir=tmp,
                auto_env_enabled=False,
                agent_llm_enabled=False,
                attack_env_compose_file="",
                attack_env_target_url="",
                target_ip="127.0.0.1",
            )

            with patch("cve_hunter.agents.cfg", fake_cfg):
                result = run_environment_agent(state)

        self.assertEqual(len(result["environment_candidates"]), 1)
        self.assertEqual(result["attack_environment"]["target_url"], "http://127.0.0.1:18080")
        self.assertEqual(result["trace"]["agent"], "EnvironmentAgent")
        self.assertEqual(result["trace"]["status"], "planned")

    def test_compose_target_prefers_web_service_over_redis(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  redis:\n"
                "    image: redis:5-alpine\n"
                "    ports:\n"
                "      - \"6379:6379\"\n"
                "  airflow-webserver:\n"
                "    image: vulhub/airflow:1.10.10\n"
                "    ports:\n"
                "      - \"8080:8080\"\n",
                encoding="utf-8",
            )

            target = _guess_target_url_from_compose(compose)

        self.assertEqual(target, "http://127.0.0.1:8080")

    def test_trigger_agent_infers_file_read_oracle(self):
        state = CVEState(
            cve_id="CVE-2024-0002",
            nvd_description="Directory traversal allows arbitrary file read.",
            vuln_type="path traversal",
        )

        with patch("cve_hunter.agents.cfg", SimpleNamespace(agent_llm_enabled=False, callback_url="")):
            result = run_trigger_agent(state)

        trigger = result["trigger_candidates"][0]
        self.assertEqual(trigger["attack_objective"], "file_read")
        self.assertEqual(trigger["validation_hint"]["type"], "response_contains")
        self.assertIn("file_path", trigger["variable_slots"])

    def test_trigger_agent_infers_file_read_from_chinese_vuln_type(self):
        state = CVEState(
            cve_id="CVE-2018-3760",
            nvd_description="There is an information leak vulnerability in Sprockets.",
            vuln_type="路径遍历/信息泄露",
        )

        with patch("cve_hunter.agents.cfg", SimpleNamespace(agent_llm_enabled=False, callback_url="")):
            result = run_trigger_agent(state)

        trigger = result["trigger_candidates"][0]
        self.assertEqual(trigger["attack_objective"], "file_read")
        self.assertEqual(trigger["validation_hint"]["type"], "response_contains")

    def test_critic_agent_enriches_candidate_with_trigger(self):
        trigger = {
            "trigger_id": "cve-test-trigger-1",
            "attack_objective": "file_read",
            "preconditions": ["可能需要认证或管理员会话"],
            "validation_hint": {"type": "response_contains", "markers": ["root:"]},
        }
        state = CVEState(
            cve_id="CVE-2024-0003",
            trigger_candidates=[trigger],
            current_candidate_index=0,
        )
        candidate = {
            "kind": "raw_http",
            "source": "reference",
            "raw_http": "GET /../../etc/passwd HTTP/1.1\nHost: {{TARGET_HOST}}\n\n",
            "confidence": 0.7,
        }

        with patch("cve_hunter.agents.cfg", SimpleNamespace(agent_llm_enabled=False)):
            result = run_critic_agent(state, candidate)

        enriched = result["candidate"]
        self.assertEqual(enriched["trigger_id"], "cve-test-trigger-1")
        self.assertEqual(enriched["attack_objective"], "file_read")
        self.assertEqual(enriched["validation_hint"]["type"], "response_contains")
        self.assertTrue(result["review"]["accepted"])


if __name__ == "__main__":
    unittest.main()
