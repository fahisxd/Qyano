"""Shared connector command templates, execution, and legacy settings helpers."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess


PLUGIN = re.compile(r"(?<![A-Za-z0-9_])QUIC([1-9][0-9]*)(?![A-Za-z0-9_])")
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*\Z")
TARGET = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9.:-]*\Z")
MAX_SUMMARY_OUTPUT = 4000


def config_path():
    root = os.environ.get("XDG_CONFIG_HOME")
    return (Path(root) if root else Path.home() / ".config") / "qyano" / "connector.json"


def empty_config():
    return {"ssh": {"target": "", "port": 22, "key": ""}, "network_command": "",
            "ask_network": True, "ai_summary": False, "connectors": []}


def load_config():
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(data, dict):
        raise ValueError("Invalid connector settings")
    return data


def save_config(data):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            os.chmod(temp, 0o600)
            json.dump(data, handle, indent=2)
            handle.write("\n")
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def ask_yes(prompt, default=False):
    answer = input(prompt).strip().lower()
    if not answer:
        return default
    if answer in ("y", "yes"):
        return True
    if answer in ("n", "no"):
        return False
    print("Please answer y or n.")
    return ask_yes(prompt, default)


def plugin_tokens(command):
    return [f"QUIC{number}" for number in sorted({int(match) for match in PLUGIN.findall(command)})]


def make_connector(name, command, labels):
    if not NAME.fullmatch(name):
        raise ValueError("Connector name must start with a letter and contain only letters, digits, _ or -")
    if "&QUIC" not in command:
        raise ValueError("Connector command must contain &QUIC for the target IP")
    tokens = plugin_tokens(command)
    if set(labels) != set(tokens) or any(not isinstance(labels[token], str) or not labels[token].strip() for token in tokens):
        raise ValueError("Each QUICn placeholder needs a label")
    return {"name": name, "command": command,
            "plugins": {token: labels[token].strip() for token in tokens}}


def fill_command(template, ip, values):
    missing = set(plugin_tokens(template)) - set(values)
    if missing:
        raise ValueError("Missing values for: " + ", ".join(sorted(missing)))
    command = template.replace("&QUIC", shlex.quote(ip))
    return PLUGIN.sub(lambda match: shlex.quote(values[f"QUIC{match.group(1)}"]), command)


def execute(command, ssh):
    target = ssh.get("target", "")
    if target:
        argv = ["ssh"]
        user_config = Path.home() / ".ssh" / "config"
        if user_config.is_file():
            argv.extend(["-F", str(user_config)])
        argv.extend(["-tt", "-p", str(ssh.get("port", 22))])
        if ssh.get("key"):
            argv.extend(["-i", ssh["key"]])
        argv.extend([target, command])
    else:
        argv = ["/bin/sh", "-lc", command]
    output = []
    length = 0
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors="replace", bufsize=1)
    try:
        with process.stdout:
            for line in process.stdout:
                print(line, end="", flush=True)
                if length < MAX_SUMMARY_OUTPUT:
                    fragment = line[:MAX_SUMMARY_OUTPUT - length]
                    output.append(fragment)
                    length += len(fragment)
        code = process.wait()
    except KeyboardInterrupt:
        process.terminate()
        process.wait()
        raise
    return code, "".join(output)
