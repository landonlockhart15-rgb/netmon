from unittest.mock import MagicMock, patch

from monitoring import heartbeat


def _resp(status):
    r = MagicMock()
    r.status = status
    r.__enter__.return_value = r
    return r


def test_ping_noop_without_url():
    with patch("urllib.request.urlopen") as op:
        assert heartbeat.ping("") is False
        op.assert_not_called()


def test_ping_success():
    with patch("urllib.request.urlopen", return_value=_resp(200)) as op:
        assert heartbeat.ping("https://hc-ping.com/x") is True
        assert op.call_args[0][0].full_url == "https://hc-ping.com/x"


def test_ping_failure_is_swallowed():
    with patch("urllib.request.urlopen", side_effect=OSError("offline")):
        assert heartbeat.ping("https://hc-ping.com/x") is False


def test_env_url_wins(monkeypatch):
    monkeypatch.setenv("HEARTBEAT_URL", " https://hc-ping.com/env ")
    assert heartbeat.get_url() == "https://hc-ping.com/env"
