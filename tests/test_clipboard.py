import subprocess
import unittest
from unittest.mock import patch

from qyano import clipboard


class ClipboardTests(unittest.TestCase):
    def test_first_available_reader_returns_text(self):
        result = subprocess.CompletedProcess(clipboard.READERS[0], 0, "copied text", "")
        with patch.object(clipboard.shutil, "which", side_effect=lambda name: name if name == "wl-paste" else None), \
             patch.object(clipboard.subprocess, "run", return_value=result) as run:
            self.assertEqual(clipboard.read_text(), "copied text")
            run.assert_called_once()

    def test_empty_or_unavailable_clipboard_returns_none(self):
        with patch.object(clipboard.shutil, "which", return_value=None):
            self.assertIsNone(clipboard.read_text())
        result = subprocess.CompletedProcess(clipboard.READERS[0], 0, "", "")
        with patch.object(clipboard.shutil, "which", side_effect=lambda name: name if name == "wl-paste" else None), \
             patch.object(clipboard.subprocess, "run", return_value=result):
            self.assertIsNone(clipboard.read_text())


if __name__ == "__main__":
    unittest.main()
