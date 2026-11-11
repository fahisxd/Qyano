"""One registry and dispatcher for the CLI and TUI."""

class Result:
    __slots__ = ("value", "code")

    def __init__(self, value, code=0):
        self.value = value
        self.code = code


COMMANDS = {
    "hash": "hash", "ihash": "ihash", "base": "base", "ibase": "ibase",
    "iden": "iden", "identify": "iden", "port": "port", "cve": "cve",
    "res": "res", "research": "res", "alias": "alias", "tui": "tui",
    "help": "help", "agent": "agent", "env": "env", "update": "update",
    "connect": "connect", "n": "n", "notes": "notes",
}

HELP = """Usage: qy [--json] COMMAND [ARGS]

qy                            Run saved connectors
qy tui                        Open the terminal interface
qy connect                    Set up SSH, network, AI summary, and Quick Notes
qy connect shell              Add, list, edit, or delete connectors
qy n [TEXT]                   Save a quick note; omitted text uses clipboard
qy notes                      List recent notes
qy notes search QUERY         Search notes
qy notes show|edit|del ID     Read, edit, or delete a note
qy notes export [FILE]        Export notes to Markdown
qy notes enable|disable       Turn Quick Notes on or off
qy notes target [clear]       Show or clear the current target
qy hash [TEXT]               Generate SHA-256, MD5, and SHA-1
qy ihash [TEXT]              Identify hash shape
qy base encode|decode [TEXT] Encode or decode Base64
qy ibase [TEXT]              Identify Base64
qy iden [TEXT]               Identify formats (also: identify)
qy port [PORT|SERVICE] [PROTO] Look up the IANA port glossary
qy cve [CVE-ID|KEYWORDS]     Search NVD directly
qy res [PROMPT]              AI research; empty clipboard starts a session
qy agent setup [PROVIDER]     Verify and save an OpenRouter or OpenAI key
qy alias list|set|remove|reset  Manage shortcuts
qy env install|update|status  Manage the Python environment and user command
qy update                    Update Qyano and its dependencies

Defaults: h=hash, hi=ihash, e=base encode, d=base decode,
          p=port, c=cve, r=res. Omitted text uses the clipboard.
          Use --json for machine-readable output.
"""


def _usage(message):
    return Result({"error": message}, 2)


def _text(args):
    if args:
        return " ".join(args)
    from qyano.clipboard import read_text
    value = read_text()
    if value is None:
        raise ValueError("No text supplied and the clipboard is empty or unavailable")
    return value


def dispatch(argv):
    """Return a structured result; only the entry point renders it."""
    if not argv:
        return Result({"connector_action": "run"})
    name, *args = argv
    command = COMMANDS.get(name)
    if command is None:
        from .aliases import resolve
        try:
            target = resolve(name)
        except ValueError as exc:
            return _usage(str(exc))
        if target is None:
            return _usage(f"Unknown command: {name}. Run 'qy help' for usage.")
        return dispatch([*target, *args])

    if command == "help":
        return Result(HELP) if not args else _usage("help takes no arguments")
    if command == "tui":
        return Result({"launch_tui": True}) if not args else _usage("tui takes no arguments")
    if command == "connect":
        if not args:
            return Result({"connector_action": "setup"})
        if args == ["shell"]:
            return Result({"connector_action": "shell"})
        return _usage("Usage: qy connect [shell]")
    if command == "n":
        return Result({"notes_action": "add", "args": args})
    if command == "notes":
        return Result({"notes_action": "manage", "args": args})
    if command == "alias":
        return _alias(args)
    if command == "agent":
        if args and args[0] == "setup" and len(args) <= 2:
            return Result({"agent_setup": True, "provider": args[1] if len(args) == 2 else None})
        return _usage("Usage: qy agent setup [openrouter|openai]")
    if command == "update":
        return Result({"env_action": "update"}) if not args else _usage("update takes no arguments")
    if command == "env":
        return Result({"env_action": args[0]}) if len(args) == 1 and args[0] in ("install", "update", "status") else _usage("Usage: qy env install|update|status")
    if command == "res":
        if not args:
            from qyano.clipboard import read_text
            value = read_text()
            if value is None:
                return Result({"interactive_research": True})
            args = [value]
        from agent import ai_agent
        answer = ai_agent(" ".join(args))
        return Result({"answer": answer}, 1 if answer == "AI not enabled" else 0)
    if command == "base":
        if not args or args[0] not in ("encode", "decode"):
            return _usage("Usage: qy base encode|decode [TEXT]")
        try:
            value = _text(args[1:])
        except ValueError as exc:
            return _usage(str(exc))
        from hbe import hbe_engine
        result = hbe_engine(value, "enc" if args[0] == "encode" else "dec")
    elif command == "hash":
        try:
            value = _text(args)
        except ValueError as exc:
            return _usage(str(exc))
        from hbe import hbe_engine
        result = hbe_engine(value, "hash")
    elif command in ("ihash", "ibase", "iden"):
        try:
            value = _text(args)
        except ValueError as exc:
            return _usage(str(exc))
        from eid import identifier_engine
        result = identifier_engine(value)
        if command != "iden":
            wanted = ("hash",) if command == "ihash" else ("base64", "base64-url")
            matches = [entry for entry in result["identifiers"] if entry["type"] in wanted]
            result = {"input": value, "identifiers": matches or [{"type": "unknown"}]}
    elif command == "port":
        if len(args) > 2:
            return _usage("Usage: qy port [PORT|SERVICE] [PROTOCOL]")
        if not args:
            try:
                args = [_text([])]
            except ValueError as exc:
                return _usage(str(exc))
        from portg import potg_engine
        result = potg_engine(args[0], args[1] if len(args) == 2 else None)
    elif command == "cve":
        try:
            value = _text(args)
        except ValueError as exc:
            return _usage(str(exc))
        from agent import nvd_search
        result = nvd_search(value)
    else:
        return _usage(f"Unknown command: {name}")
    return Result(result, 1 if "error" in result or result.get("status") in ("error", "unavailable") else 0)


def _alias(args):
    from . import aliases
    if not args:
        return _usage("Usage: qy alias list|set|remove|reset")
    action, *rest = args
    try:
        if action == "list" and not rest:
            return Result(aliases.list_aliases())
        if action == "set" and len(rest) < 2:
            import shlex
            copied = shlex.split(_text([]))
            rest = [*rest, *copied]
        if action == "set" and len(rest) in (2, 3):
            return Result(aliases.set_alias(rest[0], rest[1:]))
        if action == "remove" and not rest:
            rest = [_text([]).strip()]
        if action == "remove" and len(rest) == 1:
            return Result(aliases.remove_alias(rest[0]))
        if action == "reset" and not rest:
            return Result(aliases.reset_aliases())
    except (ValueError, OSError) as exc:
        return _usage(str(exc))
    return _usage("Usage: qy alias list|set NAME COMMAND|remove NAME|reset")
