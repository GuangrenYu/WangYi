from types import SimpleNamespace
from unittest.mock import Mock, patch

from cve_hunter import llm


def test_get_llm_disables_implicit_environment_proxy():
    http_client = Mock()
    chat = Mock()
    config = SimpleNamespace(
        llm_api_key="test-key",
        llm_model="test-model",
        llm_base_url="https://example.test",
        httpx_proxy=None,
    )
    llm._llm_cache.clear()

    with (
        patch("cve_hunter.llm.cfg", config),
        patch("httpx.Client", return_value=http_client) as client_class,
        patch("langchain_openai.ChatOpenAI", return_value=chat) as chat_class,
    ):
        actual = llm.get_llm()

    assert actual is chat
    client_class.assert_called_once_with(proxy=None, trust_env=False)
    assert chat_class.call_args.kwargs["http_client"] is http_client
    llm._llm_cache.clear()
