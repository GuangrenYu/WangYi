from pathlib import Path
from unittest.mock import patch

from cve_hunter.config import cfg
from cve_hunter.web_app import app
from fastapi.testclient import TestClient


def test_txt_upload_and_env_url_target_are_accepted(tmp_path):
    with patch("cve_hunter.web_app.UPLOAD_DIR", tmp_path / "uploads"), patch("cve_hunter.web_app.TASK_DIR", tmp_path / "tasks"):
        from cve_hunter import web_app
        with patch.object(web_app.manager.executor, "submit"):
            with TestClient(app) as client:
                response = client.post("/api/tasks", files={"files": ("list.txt", b"CVE-2001-0075\n")}, data={"target_ip": "http://192.0.2.5:8000"})
                assert response.status_code == 200
                task = response.json()
                assert task["target_ip"] == "192.0.2.5"
                assert Path(task["upload_dir"]).joinpath("list.txt").is_file()
