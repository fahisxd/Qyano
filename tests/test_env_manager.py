import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from qyano import env_manager
from qyano.cli.router import dispatch


class EnvironmentManagerTests(unittest.TestCase):
    def test_install_and_update_create_link_and_use_expected_pip_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / ".venv"
            python = environment / "bin" / "python"
            executable = environment / "bin" / "qy"
            command = root / "user-bin" / "qy"
            python.parent.mkdir(parents=True)
            python.touch()
            executable.touch()
            with patch.object(env_manager, "PROJECT_ROOT", root), \
                 patch.object(env_manager, "paths", return_value=(environment, python, executable, command)), \
                 patch.object(env_manager.subprocess, "run") as run, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(env_manager.install(), 0)
                self.assertEqual(command.resolve(), executable)
                self.assertEqual(env_manager.install(upgrade=True), 0)
            self.assertEqual(run.call_args_list[0].args[0],
                             [str(python), "-m", "pip", "install", "-e", f"{root}[tui]"])
            self.assertEqual(run.call_args_list[1].args[0],
                             [str(python), "-m", "pip", "install", "--upgrade", "--upgrade-strategy", "eager", "-e", f"{root}[tui]"])

    def test_existing_command_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "user-bin" / "qy"
            command.parent.mkdir()
            command.write_text("existing")
            with patch.object(env_manager, "paths", return_value=(root / ".venv", root / ".venv/bin/python", root / ".venv/bin/qy", command)), \
                 patch.object(env_manager.subprocess, "run") as run, \
                 redirect_stderr(io.StringIO()):
                self.assertEqual(env_manager.install(), 1)
            self.assertEqual(command.read_text(), "existing")
            run.assert_not_called()

    def test_cli_routes_environment_commands(self):
        self.assertEqual(dispatch(["env", "status"]).value, {"env_action": "status"})
        self.assertEqual(dispatch(["update"]).value, {"env_action": "update"})
        self.assertEqual(dispatch(["env", "unknown"]).code, 2)


if __name__ == "__main__":
    unittest.main()
