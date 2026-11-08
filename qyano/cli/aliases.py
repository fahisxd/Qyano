"""Internal shortcut mappings; values are command tokens, never shell code."""

import json
import os
import re
from pathlib import Path


DEFAULTS = {
    "h": ["hash"], "hi": ["ihash"], "e": ["base", "encode"],
    "d": ["base", "decode"], "p": ["port"], "c": ["cve"],
    "r": ["res"],
}
TARGETS = {
    ("hash",), ("ihash",), ("base", "encode"), ("base", "decode"),
    ("ibase",), ("iden",), ("port",), ("cve",), ("res",),
}
RESERVED = {"hash", "ihash", "base", "ibase", "iden", "identify",
            "port", "cve", "res", "research", "alias", "agent", "tui", "help",
            "connect", "env", "update", "n", "notes"}


def config_path():
    root = os.environ.get("XDG_CONFIG_HOME")
    return (Path(root) if root else Path.home() / ".config") / "qyano" / "aliases.json"


def _read():
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"aliases": {}, "disabled": []}
    except (OSError, ValueError) as exc:
        raise ValueError(f"Could not read alias settings: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("aliases", {}), dict) or not isinstance(data.get("disabled", []), list):
        raise ValueError("Invalid alias settings file")
    aliases = data.get("aliases", {})
    disabled = data.get("disabled", [])
    if any(not isinstance(k, str) or not isinstance(v, list) or
           not all(isinstance(token, str) for token in v) or tuple(v) not in TARGETS
           for k, v in aliases.items()):
        raise ValueError("Invalid alias settings file")
    if any(not isinstance(k, str) for k in disabled):
        raise ValueError("Invalid alias settings file")
    return {"aliases": aliases, "disabled": disabled}


def _write(data):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def resolve(name):
    data = _read()
    if name in data["disabled"]:
        return None
    return data["aliases"].get(name, DEFAULTS.get(name))


def list_aliases():
    data = _read()
    merged = {**DEFAULTS, **data["aliases"]}
    return {name: target for name, target in sorted(merged.items()) if name not in data["disabled"]}


def set_alias(name, target):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name) or name in RESERVED:
        raise ValueError("Alias name must start with a letter, use letters, digits, _ or -, and not be a command")
    if tuple(target) not in TARGETS:
        raise ValueError("Alias target must be a supported command (for Base64: base encode or base decode)")
    data = _read()
    data["aliases"][name] = list(target)
    data["disabled"] = [item for item in data["disabled"] if item != name]
    _write(data)
    return {name: list(target)}


def remove_alias(name):
    data = _read()
    if name not in data["aliases"] and name not in DEFAULTS or name in data["disabled"]:
        raise ValueError(f"Alias not found: {name}")
    data["aliases"].pop(name, None)
    if name in DEFAULTS:
        data["disabled"].append(name)
    _write(data)
    return {"removed": name}


def reset_aliases():
    _write({"aliases": {}, "disabled": []})
    return list_aliases()
