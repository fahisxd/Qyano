import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qyano import con_engine, connector, vpn
from qyano.cli.main import main
from qyano.cli.router import dispatch


class ConnectorTests(unittest.TestCase):
    def test_routes_and_template_values(self):
        self.assertEqual(dispatch([]).value, {"con_action": "run", "args": []})
        self.assertEqual(dispatch(["con", "add"]).value, {"con_action": "manage", "args": ["add"]})
        self.assertEqual(dispatch(["vpn", "des"]).value, {"con_action": "vpn", "args": ["des"]})
        self.assertEqual(dispatch(["connect"]).value, {"con_action": "legacy", "args": []})
        item = connector.make_connector("scan", "tool -h &QUIC -w QUIC1 --mode QUIC2",
                                        {"QUIC1": "wordlist", "QUIC2": "mode"})
        self.assertEqual(item["plugins"]["QUIC2"], "mode")
        filled = connector.fill_command(item["command"], "192.0.2.1",
                                        {"QUIC1": "/tmp/a list; false", "QUIC2": "fast"})
        self.assertEqual(filled, "tool -h 192.0.2.1 -w '/tmp/a list; false' --mode fast")

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

    def test_profile_shell_configures_network_ssh_vpn_commands_and_arguments(self):
        answers = [
            "network ping -c 1 192.0.2.1",
            "ssh", "user@example.test", "2222", "",
            "vpn", "wg-quick up lab", "wg-quick down lab",
            "add scan", "printf &QUIC QUIC1", "wordlist", "/tmp/list",
            "list", "args scan", "", "/tmp/new",
            "edit scan", "printf &QUIC QUIC1 QUIC2", "", "", "mode", "fast",
            "show", "exit",
        ]
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}), \
             patch("builtins.input", side_effect=answers), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["con", "add", "lab"]), 0)
            data = con_engine.load_profiles()
            profile = con_engine.selected_profile(data)
            self.assertEqual(profile["network_command"], "ping -c 1 192.0.2.1")
            self.assertEqual(profile["ssh"]["target"], "user@example.test")
            self.assertEqual(profile["ssh"]["port"], 2222)
            self.assertEqual(profile["vpn"]["start"], "wg-quick up lab")
            self.assertEqual(profile["vpn"]["stop"], "wg-quick down lab")
            self.assertEqual(profile["commands"][0]["plugins"]["QUIC1"]["default"], "/tmp/new")
            self.assertEqual(profile["commands"][0]["plugins"]["QUIC2"]["label"], "mode")
            self.assertEqual(connector.config_path().stat().st_mode & 0o777, 0o600)
            with patch("builtins.input", side_effect=["del scan", "y", "exit"]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["con", "edit", "lab"]), 0)
            self.assertEqual(con_engine.selected_profile(con_engine.load_profiles())["commands"], [])

    def test_legacy_settings_migrate_without_losing_commands(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}):
            old = connector.empty_config()
            old["network_command"] = "network-up"
            old["connectors"] = [connector.make_connector("scan", "printf &QUIC QUIC1", {"QUIC1": "wordlist"})]
            connector.save_config(old)
            data = con_engine.load_profiles()
            profile = con_engine.selected_profile(data)
            self.assertEqual(profile["vpn"]["start"], "network-up")
            self.assertEqual(profile["commands"][0]["plugins"]["QUIC1"]["label"], "wordlist")
            con_engine.save_profiles(data)
            self.assertEqual(con_engine.load_profiles()["version"], 2)

    def test_runner_uses_active_profile_and_parameter_defaults(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}):
            data = con_engine.empty_profiles()
            profile = con_engine.new_profile("lab")
            profile["network_command"] = "network-check"
            profile["commands"] = [{"name": "scan", "command": "printf &QUIC QUIC1", "plugins":
                                    {"QUIC1": {"label": "wordlist", "default": "/tmp/list"}}}]
            profile["ai_summary"] = True
            data["profiles"].append(profile)
            data["active"] = "lab"
            con_engine.save_profiles(data)
            with patch("builtins.input", side_effect=["192.0.2.10", "y", ""]), \
                 patch.object(connector, "execute", side_effect=[(0, "network ok"), (0, "scan ok")]) as execute, \
                 patch("agent.ai_agent", return_value="Summary") as ai, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main([]), 0)
            self.assertEqual(execute.call_args_list[0].args[0], "network-check")
            self.assertEqual(execute.call_args_list[1].args[0], "printf 192.0.2.10 /tmp/list")
            self.assertIn("AI summary:\nSummary", output.getvalue())
            self.assertIn("scan ok", ai.call_args.args[0])

    def test_vpn_commands_are_profile_specific_and_runner_requires_vpn(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory}):
            data = con_engine.empty_profiles()
            first = con_engine.new_profile("first")
            first["vpn"]["start"] = "vpn-first"
            first["commands"] = [{"name": "scan", "command": "printf &QUIC", "plugins": {}}]
            second = con_engine.new_profile("second")
            second["vpn"]["start"] = "vpn-second"
            data["profiles"] = [first, second]
            data["active"] = "first"
            con_engine.save_profiles(data)
            with patch.object(vpn, "start", return_value="started") as start, \
                 patch.object(vpn, "stop", return_value="stopped") as stop, \
                 patch.object(vpn, "is_running", return_value=False), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["vpn"]), 0)
                self.assertEqual(start.call_args.args[0]["name"], "first")
                self.assertEqual(main(["vpn", "des", "second"]), 0)
                self.assertEqual(stop.call_args.args[0]["name"], "second")
                self.assertEqual(main([]), 1)


if __name__ == "__main__":
    unittest.main()
