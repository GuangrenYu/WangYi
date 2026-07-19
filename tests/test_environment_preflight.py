import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cve_hunter.environment_preflight import (
    _index_compose_files,
    _inspect_compose,
    render_preflight_markdown,
    run_environment_preflight,
)


class EnvironmentPreflightTests(unittest.TestCase):
    def test_inspect_compose_reports_cached_images_and_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "CVE-2024-0001" / "docker-compose.yml"
            compose.parent.mkdir()
            compose.write_text(
                "services:\n"
                "  web:\n"
                "    image: example/web:1\n"
                "    ports:\n"
                "      - '18080:80'\n",
                encoding="utf-8",
            )
            effective = {
                "services": {
                    "web": {
                        "image": "example/web:1",
                        "ports": [{"published": "18080", "target": 80}],
                    },
                },
            }
            with patch(
                "cve_hunter.environment_preflight._load_effective_compose",
                return_value=(effective, ""),
            ):
                record = _inspect_compose(
                    index=1,
                    cve_id="CVE-2024-0001",
                    compose_file=compose,
                    alternative_compose_files=[],
                    compose_command=["docker", "compose"],
                    cached_images={"example/web:1"},
                )

        self.assertTrue(record["config_valid"])
        self.assertEqual(record["media_status"], "fully_cached")
        self.assertEqual(record["published_ports"], ["18080"])
        self.assertEqual(record["suggested_healthcheck"], "http")
        self.assertTrue(record["static_start_ready"])

    def test_report_records_port_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "vulhub"
            for cve_id in ("CVE-2024-0001", "CVE-2024-0002"):
                compose = root / cve_id / "docker-compose.yml"
                compose.parent.mkdir(parents=True)
                compose.write_text("services: {}\n", encoding="utf-8")
            effective = {
                "services": {
                    "web": {
                        "image": "example/web:1",
                        "ports": [{"published": "8080", "target": 80}],
                    },
                },
            }
            output = Path(tmp) / "output"
            input_file = Path(tmp) / "cases.txt"
            input_file.write_text("CVE-2024-0001\nCVE-2024-0002\n", encoding="utf-8")
            with (
                patch("cve_hunter.environment_preflight._docker_compose_command", return_value=["docker", "compose"]),
                patch("cve_hunter.environment_preflight._cached_images", return_value={"example/web:1"}),
                patch("cve_hunter.environment_preflight._load_effective_compose", return_value=(effective, "")),
                patch("cve_hunter.environment_preflight._guess_target_url_from_compose", return_value="http://127.0.0.1:8080"),
            ):
                report, json_path, markdown_path = run_environment_preflight(
                    ["CVE-2024-0001", "CVE-2024-0002"],
                    compose_root=root,
                    input_file=input_file,
                    output_dir=output,
                    range_start=1,
                    range_end=2,
                )
            self.assertEqual(report["summary"]["config_valid"], 2)
            self.assertEqual(report["summary"]["conflicting_ports"]["8080"], 2)
            self.assertTrue(json_path.name.endswith("_1_2.json"))
            self.assertIn("published_port_conflict", markdown_path.read_text(encoding="utf-8"))
        self.assertIn("Local Environment Preflight", render_preflight_markdown(report))

    def test_index_accepts_product_prefixed_cve_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "python" / "PIL-CVE-2018-16509" / "docker-compose.yml"
            compose.parent.mkdir(parents=True)
            compose.write_text("services: {}\n", encoding="utf-8")

            index = _index_compose_files(Path(tmp))

        self.assertEqual(index["CVE-2018-16509"], [compose.resolve()])


if __name__ == "__main__":
    unittest.main()
