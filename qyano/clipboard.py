"""Read text from the system clipboard without a Python dependency."""

import shutil
import subprocess


READERS = (
    ("wl-paste", "--no-newline"),
    ("xclip", "-selection", "clipboard", "-o"),
    ("xsel", "--clipboard", "--output"),
    ("pbpaste",),
)


def read_text():
    for command in READERS:
        if not shutil.which(command[0]):
            continue
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    errors="replace", timeout=3, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout:
            return result.stdout
    return None
