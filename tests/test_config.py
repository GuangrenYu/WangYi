from unittest.mock import patch

from cve_hunter.config import _get_proxy


def test_disable_proxy_override_forces_direct_connection():
    with patch.dict(
        "os.environ",
        {
            "HTTPS_PROXY": "http://127.0.0.1:7890",
            "CVE_HUNTER_DISABLE_PROXY": "true",
        },
    ):
        assert _get_proxy() == ""
