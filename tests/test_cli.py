import contextlib
import asyncio
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from qyano.cli import aliases
from qyano.cli.main import main
from qyano.cli.router import dispatch


class CLITests(unittest.TestCase):
    def test_hash_and_base_routes(self):
        self.assertEqual(dispatch(["h", "hello"]).value, dispatch(["hash", "hello"]).value)
        self.assertEqual(dispatch(["hash", "hello"]).value["md5"], "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(dispatch(["e", "hello"]).value["base64/encode"], "aGVsbG8=")
        self.assertEqual(dispatch(["d", "aGVsbG8="]).value["base64/decode"], "hello")
        self.assertEqual(dispatch(["base", "decode", "!!!"]).code, 1)

    def test_unquoted_text_and_clipboard_fallback(self):
        with patch("qyano.clipboard.read_text", return_value="hello world") as clipboard:
            expected = dispatch(["hash", "hello world"]).value
            self.assertEqual(dispatch(["hash", "hello", "world"]).value, expected)
            self.assertEqual(dispatch(["hash"]).value, expected)
            self.assertEqual(dispatch(["base", "encode"]).value,
                             dispatch(["base", "encode", "hello", "world"]).value)
            self.assertEqual(dispatch(["iden"]).value["input"], "hello world")
            self.assertEqual(dispatch(["ihash"]).value["input"], "hello world")
            self.assertEqual(dispatch(["ibase"]).value["input"], "hello world")
            self.assertEqual(clipboard.call_count, 5)
        with patch("qyano.clipboard.read_text", return_value="443"):
            self.assertEqual(dispatch(["port"]).value, dispatch(["port", "443"]).value)
        with patch("qyano.clipboard.read_text", return_value="CVE-2021-44228"), \
             patch("agent.nvd_search", return_value={"status": "ok", "results": []}) as lookup:
            self.assertEqual(dispatch(["cve"]).code, 0)
            lookup.assert_called_once_with("CVE-2021-44228")
        with patch("qyano.clipboard.read_text", return_value="Explain this"), \
             patch("agent.ai_agent", return_value="answer") as ai:
            self.assertEqual(dispatch(["res"]).value, {"answer": "answer"})
            ai.assert_called_once_with("Explain this")
        with patch("qyano.clipboard.read_text", return_value=None):
            self.assertEqual(dispatch(["hash"]).code, 2)

    def test_identifier_filters_existing_engine(self):
        from eid import identifier_engine
        digest = "5d41402abc4b2a76b9719d911017c592"
        full = identifier_engine(digest)["identifiers"]
        self.assertEqual(dispatch(["ihash", digest]).value["identifiers"],
                         [item for item in full if item["type"] == "hash"])
        self.assertEqual(dispatch(["ibase", "aGVsbG8="]).value["identifiers"][0]["type"], "base64")
        self.assertEqual(dispatch(["identify", "aGVsbG8="]).value,
                         dispatch(["iden", "aGVsbG8="]).value)
        self.assertIn("quoted-printable", [item["type"] for item in identifier_engine("hello=20world")["identifiers"]])

    def test_alias_changes_and_no_shell_execution(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}):
            self.assertEqual(dispatch(["alias", "set", "xx", "base", "encode"]).code, 0)
            self.assertEqual(dispatch(["xx", "hello"]).value["base64/encode"], "aGVsbG8=")
            self.assertEqual(dispatch(["alias", "set", "bad", ";", "touch"]).code, 2)
            self.assertEqual(dispatch(["alias", "set", "hash", "port"]).code, 2)
            self.assertIn("xx", dispatch(["alias", "list"]).value)
            self.assertEqual(dispatch(["alias", "remove", "xx"]).code, 0)
            self.assertEqual(dispatch(["xx", "hello"]).code, 2)
            self.assertEqual(dispatch(["alias", "remove", "h"]).code, 0)
            self.assertEqual(dispatch(["h", "hello"]).code, 2)
            self.assertEqual(dispatch(["alias", "reset"]).code, 0)
            self.assertEqual(dispatch(["h", "hello"]).code, 0)

    def test_alias_values_can_come_from_clipboard(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}):
            with patch("qyano.clipboard.read_text", return_value="b base encode"):
                self.assertEqual(dispatch(["alias", "set"]).code, 0)
            self.assertEqual(dispatch(["b", "hello"]).value["base64/encode"], "aGVsbG8=")
            with patch("qyano.clipboard.read_text", return_value="b"):
                self.assertEqual(dispatch(["alias", "remove"]).code, 0)
            with patch("qyano.clipboard.read_text", return_value="base decode"):
                self.assertEqual(dispatch(["alias", "set", "b"]).code, 0)
            self.assertEqual(dispatch(["b", "aGVsbG8="]).value["base64/decode"], "hello")

    def test_json_and_errors(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["--json", "hash", "hello"]), 0)
        self.assertEqual(json.loads(out.getvalue())["md5"], "5d41402abc4b2a76b9719d911017c592")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["base", "decode", "!!!", "--json"]), 1)
        self.assertIn("error", json.loads(out.getvalue()))
        self.assertEqual(dispatch(["base", "hello"]).code, 2)
        self.assertEqual(dispatch(["missing"]).code, 2)

    def test_readable_output_for_engines(self):
        def run(*args):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                code = main(list(args))
            return code, output.getvalue()

        code, output = run("hash", "hello")
        self.assertEqual(code, 0)
        self.assertIn("SHA-256", output)
        self.assertIn("MD5", output)
        self.assertNotIn('"sha256"', output)
        self.assertIn("Base64 encoded\n  aGVsbG8=", run("e", "hello")[1])
        self.assertIn("No known format matched", run("ihash", "hello")[1])
        self.assertIn("Port lookup: 443", run("port", "443")[1])
        self.assertIn("https  •  443/tcp", run("port", "443")[1])
        self.assertIn("Aliases", run("alias", "list")[1])
        self.assertIn("Invalid Base64 input", run("base", "decode", "!!!")[1])

    def test_readable_cve_and_research_output(self):
        record = {"status": "ok", "verified_data": True, "total_results": 1,
                  "results": [{"id": "CVE-2021-44228", "status": "Analyzed",
                               "description": "Test description", "cvss": {
                                   "version": "3.1", "score": 9.8, "severity": "CRITICAL",
                                   "source": "nvd@nist.gov", "assessment_type": "Primary"},
                               "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                               "references": ["https://example.invalid/advisory"]}]}
        with patch("agent.nvd_search", return_value=record):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["cve", "CVE-2021-44228"]), 0)
        self.assertIn("CVSS 3.1: 9.8 CRITICAL", output.getvalue())
        self.assertIn("Test description", output.getvalue())
        self.assertIn("https://example.invalid/advisory", output.getvalue())
        self.assertNotIn('"verified_data"', output.getvalue())
        with patch("agent.ai_agent", return_value="AI not enabled"):
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(main(["res", "hello"]), 1)
            self.assertIn("qy agent setup", error.getvalue())

    def test_port_engine_and_nvd_independence(self):
        from portg import potg_engine
        self.assertEqual(dispatch(["port", "443"]).value, potg_engine("443"))
        self.assertEqual(dispatch(["p", "ssh"]).value, potg_engine("ssh"))
        with patch("agent.nvd_search", return_value={"status": "ok", "verified_data": True, "results": []}) as lookup, \
             patch("agent.ai_agent") as ai:
            self.assertEqual(dispatch(["cve", "CVE-2021-44228"]).value["status"], "ok")
            lookup.assert_called_once_with("CVE-2021-44228")
            ai.assert_not_called()
        with patch("agent.ai_agent", return_value="analysis") as ai:
            self.assertEqual(dispatch(["research", "Explain", "this"]).value["answer"], "analysis")
            ai.assert_called_once_with("Explain this")
        with patch("qyano.clipboard.read_text", return_value=None):
            self.assertEqual(dispatch(["res"]).value, {"interactive_research": True})

    def test_interactive_research_session(self):
        output = io.StringIO()
        with patch("qyano.clipboard.read_text", return_value=None), \
             patch("builtins.input", side_effect=["Analyze this", "/quit"]), \
             patch("agent.ai_agent", return_value="result") as ai, \
             contextlib.redirect_stdout(output):
            self.assertEqual(main(["res"]), 0)
        ai.assert_called_once_with("Analyze this")
        self.assertIn("result", output.getvalue())

    def test_import_isolation_and_no_identifier_output(self):
        command = [sys.executable, "-c", "import sys; from qyano.cli.router import dispatch; dispatch(['hash','hello']); print(','.join(sorted(set(sys.modules)&{'agent','portg','textual','eid'})))"]
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        self.assertEqual(process.stdout.strip(), "")
        process = subprocess.run([sys.executable, "-c", "import eid"], capture_output=True, text=True, check=True)
        self.assertEqual(process.stdout, "")

    @unittest.skipUnless(importlib.util.find_spec("textual"), "optional Textual dependency is not installed")
    def test_tui_uses_shared_router(self):
        from textual.widgets import Static
        from qyano.tui import create_app

        async def check():
            app = create_app()
            async with app.run_test() as pilot:
                await pilot.press("ctrl+2")
                await pilot.press("h", "e", "l", "l", "o", "enter")
                self.assertIn(dispatch(["hash", "hello"]).value["md5"],
                              str(app.query_one("#output", Static).content))
                self.assertIn("Hashes", str(app.query_one("#output", Static).content))
                with patch("qyano.clipboard.read_text", return_value="clipboard text"):
                    await pilot.press("enter")
                self.assertIn(dispatch(["hash", "clipboard text"]).value["md5"],
                              str(app.query_one("#output", Static).content))
                await pilot.press("ctrl+5")
                self.assertIn("port", str(app.query_one("#guide", Static).content).lower())

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
