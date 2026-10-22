import os
import json
import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture(autouse=True, scope="session")
def disable_slack_webhooks_during_pytest():
    """
    Session-wide fixture that intercepts Slack notifications during pytest.
    Ensures that test suites never deliver dummy 'inc-test' notifications to live Slack channels.
    """
    # 1. Override Slack URL environment variables with a dummy test webhook
    mock_env = {
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/TEST/MOCK/TOKEN",
        "SLACK_BOT_TOKEN": "xoxb-mock-bot-token",
        "SLACK_APP_TOKEN": "xapp-mock-app-token",
    }

    # 2. Patch urllib.request.urlopen for slack endpoints so no network call reaches Slack
    import urllib.request
    orig_urlopen = urllib.request.urlopen

    def mock_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "hooks.slack.com" in url or "slack.com" in url:
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.read.return_value = b"ok"
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = None
            return mock_resp
        return orig_urlopen(req, *args, **kwargs)

    with patch.dict(os.environ, mock_env), \
         patch("urllib.request.urlopen", side_effect=mock_urlopen):
        yield
