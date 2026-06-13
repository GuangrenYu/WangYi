import json
import tempfile
import unittest
from pathlib import Path

from cve_hunter.environment import build_environment_spec, write_environment_manifest


class EnvironmentSpecTests(unittest.TestCase):
    def test_build_environment_spec_from_compose_candidate(self):
        spec = build_environment_spec(
            cve_id="CVE-2024-0001",
            environment={
                "source": "vulhub_local",
                "kind": "docker_compose",
                "target_url": "http://127.0.0.1:18080",
                "target_host": "127.0.0.1:18080",
                "compose_file": "vulhub/test/docker-compose.yml",
                "setup_mode": "disabled",
                "reason": "本地 vulhub 命中",
            },
            candidates=[],
            run_mode="local_lab",
            allowlist=["127.0.0.1"],
            evidence_urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
        )

        self.assertEqual(spec["cve_id"], "CVE-2024-0001")
        self.assertEqual(spec["target_url"], "http://127.0.0.1:18080")
        self.assertEqual(spec["safety"]["network_scope"], "local_or_private")
        self.assertGreaterEqual(spec["confidence"], 0.75)

    def test_write_environment_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = {"cve_id": "CVE-2024-0002", "target_url": "http://127.0.0.1"}
            path = write_environment_manifest(spec, Path(tmp))

            self.assertTrue(path.exists())
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["cve_id"], "CVE-2024-0002")


if __name__ == "__main__":
    unittest.main()
