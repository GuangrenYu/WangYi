import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cve_hunter.agents import (
    _ensure_vulhub_repository,
    _find_docker_desktop_executable,
    _guess_target_url_from_compose,
    _compose_service_health,
    _run_environment_command,
    _start_compose_environment,
    _wait_for_compose_init,
    run_critic_agent,
    run_environment_agent,
    run_trigger_agent,
    teardown_environment,
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

    def test_environment_command_decodes_docker_output_as_utf8(self):
        completed = SimpleNamespace(returncode=0, stdout="服务 healthy", stderr="")
        with patch("cve_hunter.agents.subprocess.run", return_value=completed) as run:
            result = _run_environment_command(
                ["docker", "compose", "ps"],
                cwd=Path("."),
                timeout=30,
            )

        self.assertEqual(result["stdout"], "服务 healthy")
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")

    def test_environment_command_can_preserve_structured_output(self):
        stdout = '[{"Service":"web","Health":"healthy"}]' + (" " * 2500)
        completed = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        with patch("cve_hunter.agents.subprocess.run", return_value=completed):
            result = _run_environment_command(
                ["docker", "compose", "ps", "--format", "json"],
                cwd=Path("."),
                timeout=30,
                output_limit=None,
            )

        self.assertEqual(result["stdout"], stdout)

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

    def test_environment_agent_discovers_product_prefixed_cve_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "python" / "PIL-CVE-2017-8291" / "docker-compose.yml"
            compose.parent.mkdir(parents=True)
            compose.write_text(
                "services:\n"
                "  target:\n"
                "    image: test/image\n"
                "    ports:\n"
                "      - '18080:80'\n",
                encoding="utf-8",
            )
            state = CVEState(cve_id="CVE-2017-8291")
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
        self.assertIn("PIL-CVE-2017-8291", result["environment_candidates"][0]["compose_file"])

    def test_local_container_mode_does_not_fallback_to_remote_target_without_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "test" / "CVE-2024-0001" / "docker-compose.yml"
            compose.parent.mkdir(parents=True)
            compose.write_text(
                "services:\n"
                "  target:\n"
                "    image: test/image\n",
                encoding="utf-8",
            )
            state = CVEState(cve_id="CVE-2024-0001", local_container_mode=True)
            fake_cfg = SimpleNamespace(
                vulhub_dir=tmp,
                auto_env_enabled=False,
                agent_llm_enabled=False,
                attack_env_compose_file="",
                attack_env_target_url="http://1.1.60.21",
                target_ip="1.1.60.21",
            )
            failed_start = {
                "success": False,
                "error": "compose has no local target",
            }
            with (
                patch("cve_hunter.agents.cfg", fake_cfg),
                patch(
                    "cve_hunter.agents._start_environment_candidates",
                    side_effect=lambda candidates: (candidates[0], failed_start),
                ),
            ):
                result = run_environment_agent(state)

        self.assertEqual(result["environment_candidates"][0]["target_url"], "")
        self.assertEqual(result["attack_environment"]["target_url"], "")
        self.assertEqual(result["trace"]["status"], "setup_failed")

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

    def test_compose_with_free_host_ports_remaps_busy_port(self):
        from cve_hunter.agents import _compose_with_free_host_ports

        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text(
                "version: '2'\n"
                "services:\n"
                "  mysql:\n"
                "    image: vulhub/mysql:5.5.23\n"
                "    ports:\n"
                "      - \"3306:3306\"\n",
                encoding="utf-8",
            )
            with (
                patch("cve_hunter.agents._is_host_port_free", return_value=False),
                patch("cve_hunter.agents._allocate_free_host_port", return_value=13306),
            ):
                new_path, remap, target = _compose_with_free_host_ports(compose)

            self.assertNotEqual(new_path, compose)
            self.assertTrue(new_path.is_file())
            self.assertEqual(remap, {"3306": "13306"})
            self.assertEqual(target, "tcp://127.0.0.1:13306")
            text = new_path.read_text(encoding="utf-8")
            self.assertIn("13306:3306", text)
            self.assertNotIn("version", text.split("services", 1)[0])

    def test_teardown_owned_compose_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            environment = {
                "launcher": "docker_compose",
                "compose_file": str(compose),
                "setup_result": {
                    "success": True,
                    "started_by_orchestrator": True,
                    "project_name": "cvehunter-test-owned",
                },
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch("cve_hunter.agents.cfg", SimpleNamespace(environment_auto_cleanup=True)),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
            ):
                result = teardown_environment(environment)

        self.assertTrue(result["success"])
        self.assertFalse(result["skipped"])
        self.assertIn("cvehunter-test-owned", run.call_args.args[0])
        self.assertIn("down", run.call_args.args[0])
        self.assertIn("--volumes", run.call_args.args[0])

    def test_teardown_owned_compose_even_when_setup_failed(self):
        """Healthcheck/init failure still owns residual containers for reclaim."""
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            environment = {
                "launcher": "docker_compose",
                "compose_file": str(compose),
                "setup_result": {
                    "success": False,
                    "started_by_orchestrator": True,
                    "project_name": "cvehunter-test-residual",
                    "error": "healthcheck failed",
                },
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch("cve_hunter.agents.cfg", SimpleNamespace(environment_auto_cleanup=True)),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
            ):
                result = teardown_environment(environment)

        self.assertTrue(result["success"])
        self.assertFalse(result["skipped"])
        self.assertIn("cvehunter-test-residual", run.call_args.args[0])
        self.assertIn("down", run.call_args.args[0])

    def test_reclaim_owned_compose_projects_force_releases(self):
        from cve_hunter import agents as agents_mod

        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            agents_mod._owned_compose_projects.clear()
            agents_mod.register_owned_compose_project("cvehunter-force", compose)
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
            ):
                results = agents_mod.reclaim_owned_compose_projects()

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["success"])
        self.assertEqual(results[0]["project_name"], "cvehunter-force")
        self.assertEqual(agents_mod.list_owned_compose_projects(), {})
        self.assertIn("down", run.call_args.args[0])

    def test_failed_start_candidates_preserve_ownership_for_teardown(self):
        from cve_hunter.agents import _start_environment_candidates

        candidates = [{
            "provider": "vulhub",
            "source": "vulhub_local",
            "launcher": "docker_compose",
            "compose_file": "compose.yml",
            "target_url": "http://127.0.0.1:8080",
        }]
        failed = {
            "success": False,
            "started_by_orchestrator": True,
            "project_name": "cvehunter-residual",
            "error": "healthcheck failed",
            "cleanup_result": {"success": False, "error": "down failed"},
            "commands": [{"returncode": 1}],
        }
        with patch("cve_hunter.agents._start_environment_candidate", return_value=failed):
            selected, result = _start_environment_candidates(candidates)

        self.assertIs(selected, candidates[0])
        self.assertFalse(result["success"])
        self.assertTrue(result["started_by_orchestrator"])
        self.assertEqual(result["project_name"], "cvehunter-residual")
        self.assertEqual(result["cleanup_result"]["success"], False)

    def test_compose_start_refuses_preexisting_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:18080",
                "compose_project_name": "cvehunter-existing",
            }
            command_result = {
                "cmd": [],
                "returncode": 0,
                "stdout": "existing-container-id\n",
                "stderr": "",
            }
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
            ):
                result = _start_compose_environment(candidate)

        self.assertFalse(result["success"])
        self.assertTrue(result["preexisting_environment"])
        self.assertEqual(run.call_count, 1)

    def test_compose_start_uses_independent_project_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "CVE-2024-0001" / "docker-compose.yml"
            compose.parent.mkdir()
            compose.write_text("services: {}\n", encoding="utf-8")
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:18080",
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
                patch("cve_hunter.agents._wait_for_http_target", return_value=True),
            ):
                result = _start_compose_environment(candidate)

        project_name = result["project_name"]
        self.assertTrue(result["success"])
        self.assertTrue(project_name.startswith("cvehunter-cve-2024-0001-"))
        for call in run.call_args_list[:3]:
            self.assertIn(project_name, call.args[0])
        self.assertEqual(run.call_args_list[1].args[0][-3:], ["pull", "--policy", "missing"])

    def test_compose_start_waits_for_init_then_checks_only_target_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  database:\n"
                "    image: test/database\n"
                "  airflow-init:\n"
                "    image: test/app\n"
                "    command: initdb\n"
                "    depends_on: [database]\n"
                "  web:\n"
                "    image: test/app\n"
                "    ports: ['18080:8080']\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'true']\n"
                "  worker:\n"
                "    image: test/app\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'false']\n",
                encoding="utf-8",
            )
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:18080",
                "compose_project_name": "cvehunter-init-test",
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            init_result = {
                "success": True,
                "services": ["airflow-init"],
                "service_status": {"airflow-init": {"state": "exited", "exit_code": 0}},
                "status_error": "",
                "error": "",
            }
            health_result = {
                "success": True,
                "service_health": {"web": "healthy", "worker": "unhealthy"},
                "status_error": "",
            }
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
                patch("cve_hunter.agents._wait_for_compose_init", return_value=init_result) as init_wait,
                patch("cve_hunter.agents._wait_for_compose_health", return_value=health_result) as health_wait,
            ):
                result = _start_compose_environment(candidate)

        self.assertTrue(result["success"])
        self.assertEqual(result["initialization"], init_result)
        self.assertEqual(run.call_args_list[2].args[0][-3:], ["up", "-d", "airflow-init"])
        main_up = run.call_args_list[3].args[0]
        self.assertEqual(main_up[-5:], ["up", "-d", "database", "web", "worker"])
        self.assertNotIn("airflow-init", main_up[-3:])
        init_wait.assert_called_once()
        self.assertEqual(health_wait.call_args.args[3], ["web"])
        self.assertEqual(
            health_wait.call_args.kwargs["observed_services"],
            ["web", "worker"],
        )
        self.assertEqual(result["healthcheck"]["services"], ["web"])
        self.assertEqual(result["healthcheck"]["observed_services"], ["web", "worker"])
        self.assertEqual(result["healthcheck"]["service_health"]["worker"], "unhealthy")

    def test_compose_init_failure_cleans_project_before_main_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  airflow-init:\n"
                "    image: test/app\n"
                "    command: initdb\n"
                "  web:\n"
                "    image: test/app\n",
                encoding="utf-8",
            )
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:18080",
                "compose_project_name": "cvehunter-init-failed",
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            init_result = {
                "success": False,
                "services": ["airflow-init"],
                "service_status": {"airflow-init": {"state": "exited", "exit_code": 1}},
                "status_error": "",
                "error": "Compose 初始化服务执行失败: airflow-init=exit:1",
            }
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
                patch("cve_hunter.agents._wait_for_compose_init", return_value=init_result),
                patch("cve_hunter.agents._wait_for_compose_health") as health_wait,
            ):
                result = _start_compose_environment(candidate)

        self.assertFalse(result["success"])
        self.assertEqual(result["initialization"], init_result)
        self.assertIn("初始化服务执行失败", result["error"])
        self.assertIn("down", run.call_args_list[-1].args[0])
        self.assertFalse(any("web" in call.args[0][-1:] for call in run.call_args_list))
        health_wait.assert_not_called()

    def test_compose_start_failure_cleans_independent_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:18080",
                "compose_project_name": "cvehunter-failed",
            }
            command_results = [
                {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""},
                {"cmd": [], "returncode": 1, "stdout": "", "stderr": "pull failed"},
                {"cmd": [], "returncode": 1, "stdout": "", "stderr": "up failed"},
                {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""},
            ]
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", side_effect=command_results) as run,
            ):
                result = _start_compose_environment(candidate)

        self.assertFalse(result["success"])
        self.assertEqual(result["project_name"], "cvehunter-failed")
        self.assertTrue(result["cleanup_result"]["success"])
        cleanup_command = run.call_args_list[-1].args[0]
        self.assertIn("cvehunter-failed", cleanup_command)
        self.assertIn("down", cleanup_command)
        self.assertIn("--remove-orphans", cleanup_command)

    def test_compose_healthcheck_takes_priority_over_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  web:\n"
                "    image: test/image\n"
                "    healthcheck:\n"
                "      test: ['CMD', 'true']\n",
                encoding="utf-8",
            )
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:18080",
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result),
                patch(
                    "cve_hunter.agents._wait_for_compose_health",
                    return_value={
                        "success": True,
                        "service_health": {"web": "healthy"},
                        "status_error": "",
                    },
                ) as compose_wait,
                patch("cve_hunter.agents._wait_for_http_target") as http_wait,
            ):
                result = _start_compose_environment(candidate)

        self.assertTrue(result["success"])
        self.assertEqual(result["healthcheck"]["type"], "compose")
        self.assertEqual(result["healthcheck"]["service_health"], {"web": "healthy"})
        compose_wait.assert_called_once()
        http_wait.assert_not_called()

    def test_tcp_port_uses_tcp_readiness_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            candidate = {
                "compose_file": str(compose),
                "target_url": "http://127.0.0.1:6379",
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch("cve_hunter.agents._ensure_docker_running", return_value=(True, "ready")),
                patch("cve_hunter.agents._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result),
                patch("cve_hunter.agents._wait_for_tcp_target", return_value=True) as tcp_wait,
                patch("cve_hunter.agents._wait_for_http_target") as http_wait,
            ):
                result = _start_compose_environment(candidate)

        self.assertTrue(result["success"])
        self.assertEqual(result["healthcheck"]["type"], "tcp")
        tcp_wait.assert_called_once_with("http://127.0.0.1:6379", 90)
        http_wait.assert_not_called()

    def test_compose_health_parser_accepts_array_and_json_lines(self):
        array = '[{"Service":"web","Health":"healthy"}]'
        lines = '{"Service":"db","Health":"starting"}\n{"Service":"web","Health":"healthy"}'

        self.assertEqual(_compose_service_health(array), {"web": "healthy"})
        self.assertEqual(
            _compose_service_health(lines),
            {"db": "starting", "web": "healthy"},
        )
        self.assertEqual(
            _compose_service_health('[{"Service":"worker","Health":"","State":"exited"}]'),
            {"worker": "state:exited"},
        )

    def test_compose_init_wait_requires_zero_exit_code(self):
        compose = Path("docker-compose.yml")
        success_status = {
            "cmd": [],
            "returncode": 0,
            "stdout": '[{"Service":"airflow-init","State":"exited","ExitCode":0}]',
            "stderr": "",
        }
        failed_status = {
            "cmd": [],
            "returncode": 0,
            "stdout": '[{"Service":"airflow-init","State":"exited","ExitCode":2}]',
            "stderr": "",
        }
        with patch("cve_hunter.agents._run_environment_command", return_value=success_status):
            success = _wait_for_compose_init(
                ["docker", "compose"], compose, "cvehunter-test", ["airflow-init"], 1
            )
        with patch("cve_hunter.agents._run_environment_command", return_value=failed_status):
            failure = _wait_for_compose_init(
                ["docker", "compose"], compose, "cvehunter-test", ["airflow-init"], 1
            )

        self.assertTrue(success["success"])
        self.assertEqual(success["service_status"]["airflow-init"]["exit_code"], 0)
        self.assertFalse(failure["success"])
        self.assertIn("exit:2", failure["error"])

    def test_teardown_skips_environment_not_started_by_workflow(self):
        environment = {
            "launcher": "docker_compose",
            "setup_result": {"success": True},
        }
        with patch("cve_hunter.agents._docker_compose_command") as compose_command:
            result = teardown_environment(environment)

        self.assertTrue(result["skipped"])
        compose_command.assert_not_called()

    def test_teardown_metarget_uses_remove_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "metarget"
            executable.touch()
            environment = {
                "launcher": "metarget_appv",
                "workdir": tmp,
                "scenario_name": "thinkphp-5-0-23-rce",
                "setup_result": {"success": True, "started_by_orchestrator": True},
            }
            command_result = {"cmd": [], "returncode": 0, "stdout": "", "stderr": ""}
            with (
                patch(
                    "cve_hunter.agents.cfg",
                    SimpleNamespace(environment_auto_cleanup=True, metarget_execution_enabled=True),
                ),
                patch("cve_hunter.agents.platform.system", return_value="Linux"),
                patch("cve_hunter.agents.os.geteuid", return_value=0, create=True),
                patch("cve_hunter.agents._run_environment_command", return_value=command_result) as run,
            ):
                result = teardown_environment(environment)

        self.assertTrue(result["success"])
        self.assertEqual(
            run.call_args.args[0],
            [str(executable), "appv", "remove", "thinkphp-5-0-23-rce", "--verbose"],
        )

    def test_teardown_vulfocus_requests_stop(self):
        response = MagicMock()
        response.json.return_value = {"status": 200, "msg": "ok"}
        client = MagicMock()
        client.__enter__.return_value.post.return_value = response
        environment = {
            "launcher": "vulfocus_api",
            "image_name": "vulfocus/test:latest",
            "setup_result": {"success": True, "started_by_orchestrator": True},
        }
        fake_cfg = SimpleNamespace(
            environment_auto_cleanup=True,
            vulfocus_api_url="http://127.0.0.1:80",
            vulfocus_username="user",
            vulfocus_licence="licence",
            request_timeout=30,
            httpx_proxy=None,
        )
        with (
            patch("cve_hunter.agents.cfg", fake_cfg),
            patch("cve_hunter.agents.httpx.Client", return_value=client),
        ):
            result = teardown_environment(environment)

        self.assertTrue(result["success"])
        request_data = client.__enter__.return_value.post.call_args.kwargs["data"]
        self.assertEqual(request_data["requisition"], "stop")

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
