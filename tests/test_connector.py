import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qyano import connector
from qyano.cli.main import main
from qyano.cli.router import dispatch


class ConnectorTests(unittest.TestCase):
    def test_routes_and_template_values(self):
        self.assertEqual(dispatch([]).value, {"connector_action": "run"})
        self.assertEqual(dispatch(["connect"]).value, {"connector_action": "setup"})
        self.assertEqual(dispatch(["connect", "shell"]).value, {"connector_action": "shell"})
        self.assertEqual(dispatch(["connect", "bad"]).code, 2)
        item = connector.make_connector("scan", "tool -h &QUIC -w QUIC1 --mode QUIC2",
                                        {"QUIC1": "wordlist", "QUIC2": "mode"})
        self.assertEqual(item["plugins"]["QUIC2"], "mode")
        filled = connector.fill_command(item["command"], "192.0.2.1",
                                        {"QUIC1": "/tmp/a list; false", "QUIC2": "fast"})
        self.assertEqual(filled, "tool -h 192.0.2.1 -w '/tmp/a list; false' --mode fast")
        with self.assertRaises(ValueError):
            connector.make_connector("bad", "tool QUIC1", {"QUIC1": "wordlist"})

    def test_plugin_value_is_not_shell_code(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "should-not-exist"
            value = f"hello; touch {marker}"
            command = connector.fill_command("printf '%s' QUIC1", "192.0.2.1", {"QUIC1": value})
            with contextlib.redirect_stdout(io.StringIO()):
                code, output = connector.execute(command, {"target": ""})
            self.assertEqual(code, 0)
            self.assertEqual(output, value)
            self.assertFalse(marker.exists())

    def test_setup_runs_network_before_saving_then_opens_shell(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}), \
             patch("builtins.input", side_effect=["", "printf connected", "n", "n"]), \
             patch.object(connector, "execute", return_value=(0, "connected")) as execute, \
             patch.object(connector, "connector_shell", return_value=0) as shell, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["connect"]), 0)
            data = connector.load_config()
            self.assertEqual(data["ssh"]["target"], "")
            self.assertEqual(data["network_command"], "printf connected")
            self.assertFalse(data["ai_summary"])
            execute.assert_called_once_with("printf connected", data["ssh"])
            shell.assert_called_once()
            self.assertEqual(connector.config_path().stat().st_mode & 0o777, 0o600)

    def test_ssh_setup_checks_access_before_network(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}), \
             patch("builtins.input", side_effect=["user@example.test", "2222", "", "vpn-up", "n", "n"]), \
             patch.object(connector, "execute", side_effect=[(0, ""), (0, "")]) as execute, \
             patch.object(connector, "connector_shell", return_value=0), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["connect"]), 0)
            self.assertEqual(execute.call_args_list[0].args[0], "true")
            self.assertEqual(execute.call_args_list[1].args[0], "vpn-up")
            self.assertEqual(connector.load_config()["ssh"]["port"], 2222)

    def test_ai_summary_requires_provider_configuration(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}), \
             patch("builtins.input", side_effect=["", "", "y", "n"]), \
             patch("agent._provider_config", return_value=(None, {"error": "AI not enabled"})), \
             patch.object(connector, "connector_shell", return_value=0), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["connect"]), 0)
            self.assertFalse(connector.load_config()["ai_summary"])
            self.assertIn("qy agent setup", output.getvalue())

    def test_shell_add_edit_delete_and_run_with_summary(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}):
            data = connector.empty_config()
            data["network_command"] = "vpn-up"
            data["ai_summary"] = True
            connector.save_config(data)
            answers = ["add", "scan", "printf &QUIC QUIC1", "wordlist", "list", "edit scan", "", "printf &QUIC QUIC1 QUIC2", "wordlist", "mode", "exit"]
            with patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["connect", "shell"]), 0)
            saved = connector.load_config()
            self.assertEqual(len(saved["connectors"]), 1)
            self.assertEqual(saved["connectors"][0]["plugins"], {"QUIC1": "wordlist", "QUIC2": "mode"})
            answers = ["", "y", "192.0.2.1", "y", "/tmp/list", "fast"]
            with patch("builtins.input", side_effect=answers), \
                 patch.object(connector, "execute", side_effect=[(0, "vpn ok"), (0, "scan ok")]) as execute, \
                 patch("agent.ai_agent", return_value="Summary") as ai, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main([]), 0)
            self.assertEqual(execute.call_count, 2)
            self.assertEqual(execute.call_args_list[0].args[0], "vpn-up")
            self.assertEqual(execute.call_args_list[1].args[0], "printf 192.0.2.1 /tmp/list fast")
            self.assertFalse(connector.load_config()["ask_network"])
            self.assertIn("AI summary:\nSummary", output.getvalue())
            self.assertIn("scan ok", ai.call_args.args[0])
            with patch("builtins.input", side_effect=["del scan", "exit"]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["connect", "shell"]), 0)
            self.assertEqual(connector.load_config()["connectors"], [])

    def test_failed_network_stops_before_connector(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}):
            data = connector.empty_config()
            data["network_command"] = "vpn-up"
            data["ask_network"] = False
            data["connectors"] = [connector.make_connector("scan", "printf &QUIC", {})]
            connector.save_config(data)
            with patch.object(connector, "execute", return_value=(3, "failed")) as execute, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([]), 1)
            execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()
