import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import agent
from qyano.cli import agent_setup
from qyano.cli.main import main
from qyano.cli.router import dispatch


class AgentSetupTests(unittest.TestCase):
    def test_setup_command_prompts_checks_and_saves(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}, clear=True), \
             patch("builtins.input", return_value="openrouter"), \
             patch("getpass.getpass", return_value="test-secret"), \
             patch.object(agent_setup, "urlopen", return_value=io.BytesIO(b'{"data":{}}')) as network:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["agent", "setup"]), 0)
            request = network.call_args.args[0]
            self.assertEqual(request.full_url, agent_setup.CHECK_URLS["openrouter"])
            self.assertEqual(request.get_header("Authorization"), "Bearer test-secret")
            path = agent_setup.config_path()
            self.assertEqual(json.loads(path.read_text())["api_key"], "test-secret")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn("test-secret", output.getvalue())
            with patch.object(agent, "ENV_FILE", path.with_name("missing.env")):
                config, error = agent._provider_config()
            self.assertIsNone(error)
            self.assertEqual(config["api_key"], "test-secret")
            self.assertEqual(config["base_url"], "https://openrouter.ai/api/v1")

    def test_openai_check_and_env_override(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}, clear=True), \
             patch.object(agent_setup, "urlopen", return_value=io.BytesIO(b'{"object":"list","data":[]}')):
            result = agent_setup.configure("OPENAI", "openai-test")
            self.assertEqual(result["status"], "ok")
            with patch.object(agent, "ENV_FILE", agent_setup.config_path().with_name("missing.env")):
                config, error = agent._provider_config()
                self.assertIsNone(error)
                self.assertEqual(config["api_key"], "openai-test")
                self.assertEqual(config["base_url"], "https://api.openai.com/v1")
                with patch.dict(os.environ, {"OPENAI_API_KEY": "shell-key"}):
                    config, error = agent._provider_config()
                    self.assertEqual(config["api_key"], "shell-key")

    def test_rejected_or_unreachable_key_is_not_saved(self):
        cases = [HTTPError(agent_setup.CHECK_URLS["openai"], 401, "Unauthorized", None, None),
                 URLError("offline")]
        for error in cases:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory, \
                 patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}), \
                 patch.object(agent_setup, "urlopen", side_effect=error):
                result = agent_setup.configure("openai", "private-key")
                self.assertEqual(result["status"], "error")
                self.assertNotIn("private-key", str(result))
                self.assertFalse(agent_setup.config_path().exists())

    def test_invalid_provider_and_cli_errors(self):
        self.assertEqual(dispatch(["agent", "setup"]).value["agent_setup"], True)
        self.assertEqual(dispatch(["agent", "invalid"]).code, 2)
        with patch.object(agent_setup, "urlopen") as network:
            self.assertEqual(agent_setup.configure("other", "key")["status"], "error")
            network.assert_not_called()
        output = io.StringIO()
        with patch("builtins.input", return_value="other"), contextlib.redirect_stderr(output):
            self.assertEqual(main(["agent", "setup"]), 1)
        self.assertIn("Provider must be", output.getvalue())


if __name__ == "__main__":
    unittest.main()
