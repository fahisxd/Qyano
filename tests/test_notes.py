import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qyano import connector, notes
from qyano.cli.main import main
from qyano.cli.router import dispatch


class NotesTests(unittest.TestCase):
    def test_disabled_until_enabled_and_json_storage(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_DATA_HOME": directory}):
            with contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(main(["n", "first"]), 1)
            self.assertIn("qy notes enable", error.getvalue())
            self.assertFalse(notes.data_path().exists())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["notes", "enable"]), 0)
                self.assertEqual(main(["n", "first"]), 0)
                self.assertEqual(main(["notes", "disable"]), 0)
            data = json.loads(notes.data_path().read_text())
            self.assertFalse(data["enabled"])
            self.assertEqual(data["notes"][0]["text"], "first")
            self.assertEqual(notes.data_path().stat().st_mode & 0o777, 0o600)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["notes"]), 1)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["notes", "enable"]), 0)
            self.assertEqual(notes.list_notes()[0]["id"], 1)

    def test_quick_input_search_edit_delete_and_export(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_DATA_HOME": directory}), \
             contextlib.redirect_stdout(io.StringIO()):
            notes.set_enabled(True)
            with patch("qyano.clipboard.read_text", return_value=None), \
                 patch("builtins.input", return_value="Research CVE-2021-44228"):
                self.assertEqual(main(["n"]), 0)
            notes.set_current_target("192.0.2.10")
            self.assertEqual(main(["n", "HTTP running on 8080"]), 0)
            self.assertEqual(notes.list_notes()[0]["target"], "192.0.2.10")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["notes", "search", "http"]), 0)
            self.assertIn("#2  [192.0.2.10]", output.getvalue())
            self.assertNotIn("#1", output.getvalue())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--json", "notes", "show", "2"]), 0)
            self.assertEqual(json.loads(output.getvalue())["text"], "HTTP running on 8080")
            self.assertEqual(main(["notes", "edit", "2", "HTTP on port 8080"]), 0)
            self.assertEqual(notes.find_note(2)["text"], "HTTP on port 8080")
            with patch("builtins.input", return_value="n"):
                self.assertEqual(main(["notes", "del", "2"]), 0)
            self.assertIsNotNone(notes.find_note(2))
            with patch("builtins.input", return_value="y"):
                self.assertEqual(main(["notes", "del", "2"]), 0)
            self.assertIsNone(notes.find_note(2))
            notes.set_current_target("192.0.2.10")
            self.assertEqual(main(["n", "SSH needs review"]), 0)
            destination = Path(directory) / "export.md"
            self.assertEqual(main(["notes", "export", str(destination)]), 0)
            markdown = destination.read_text()
            self.assertIn("#3 [192.0.2.10]", markdown)
            self.assertIn("#1 [GENERAL]", markdown)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(main(["notes", "target", "clear"]), 0)
            self.assertIsNone(notes.load_data()["current_target"])

    def test_connector_run_sets_current_note_target(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_DATA_HOME": directory, "XDG_CONFIG_HOME": directory}):
            notes.set_enabled(True)
            settings = connector.empty_config()
            settings["ask_network"] = False
            settings["connectors"] = [connector.make_connector("scan", "printf &QUIC", {})]
            connector.save_config(settings)
            with patch("builtins.input", side_effect=["192.0.2.10", "n"]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 0)
            self.assertEqual(notes.load_data()["current_target"], "192.0.2.10")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["n", "HTTP running on 8080"]), 0)
            self.assertEqual(notes.find_note(1)["target"], "192.0.2.10")

    def test_note_and_search_use_clipboard_when_text_is_omitted(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_DATA_HOME": directory}), \
             patch("qyano.clipboard.read_text", return_value="Copied SSH finding"), \
             contextlib.redirect_stdout(io.StringIO()):
            notes.set_enabled(True)
            self.assertEqual(main(["n"]), 0)
            self.assertEqual(notes.find_note(1)["text"], "Copied SSH finding")
            result = io.StringIO()
            with contextlib.redirect_stdout(result):
                self.assertEqual(main(["notes", "search"]), 0)
            self.assertIn("Copied SSH finding", result.getvalue())

    def test_setup_can_enable_notes(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"XDG_DATA_HOME": directory, "XDG_CONFIG_HOME": directory}), \
             patch("builtins.input", side_effect=["", "", "n", "y"]), \
             patch.object(connector, "connector_shell", return_value=0), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["connect"]), 0)
            self.assertTrue(notes.is_enabled())

    def test_routes(self):
        self.assertEqual(dispatch(["n", "hello"]).value["notes_action"], "add")
        self.assertEqual(dispatch(["notes", "search", "ssh"]).value["args"], ["search", "ssh"])


if __name__ == "__main__":
    unittest.main()
