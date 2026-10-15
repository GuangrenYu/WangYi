from pathlib import Path
from unittest.mock import patch

from cve_hunter import web_app


def test_web_reads_target_ip_from_current_dotenv(tmp_path):
    env = tmp_path / ".env"
    env.write_text("TARGET_IP=192.0.2.44\n", encoding="utf-8")
    with patch.object(web_app, "ROOT", tmp_path):
        assert web_app._live_target_ip() == "192.0.2.44"
        env.write_text("TARGET_IP=192.0.2.55\n", encoding="utf-8")
        assert web_app._live_target_ip() == "192.0.2.55"


def test_web_preserves_target_port_from_dotenv(tmp_path):
    env = tmp_path / ".env"
    env.write_text("TARGET_IP=192.0.2.44\nTARGET_PORT=7788\n", encoding="utf-8")
    with patch.object(web_app, "ROOT", tmp_path):
        # The live reader intentionally returns the explicit endpoint; it does
        # not depend on the long-lived Config object.
        assert web_app._live_target_ip() == "192.0.2.44:7788"
