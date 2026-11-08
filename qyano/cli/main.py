"""Minimal entry point for every Qyano interaction mode."""

import json
import sys

from .router import dispatch


def _render(value):
    from .formatting import render
    return render(value)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in args
    args = [item for item in args if item != "--json"]
    result = dispatch(args)
    if isinstance(result.value, dict) and result.value.get("connector_action"):
        from qyano.connector import main as connector_main
        return connector_main(result.value["connector_action"])
    if isinstance(result.value, dict) and result.value.get("env_action"):
        from qyano.env_manager import main as manage_environment
        return manage_environment([result.value["env_action"]])
    if isinstance(result.value, dict) and result.value.get("launch_tui"):
        try:
            from qyano.tui import run
            return run()
        except ModuleNotFoundError as exc:
            if exc.name != "textual" and not (exc.name or "").startswith("textual."):
                raise
            print("TUI requires the optional dependency. Install with: pip install 'qyano[tui]'", file=sys.stderr)
            return 1
    if isinstance(result.value, dict) and result.value.get("interactive_research"):
        return _research_session(json_mode)
    if isinstance(result.value, dict) and result.value.get("agent_setup"):
        return _agent_setup(result.value["provider"], json_mode)
    output = json.dumps(result.value, ensure_ascii=False) if json_mode else _render(result.value)
    print(output, file=sys.stderr if result.code and not json_mode else sys.stdout)
    return result.code


def _research_session(json_mode):
    try:
        while True:
            prompt = input("research> ").strip()
            if prompt in ("/quit", "/exit"):
                return 0
            if not prompt:
                continue
            result = dispatch(["res", prompt])
            print(json.dumps(result.value, ensure_ascii=False) if json_mode else _render(result.value))
    except (EOFError, KeyboardInterrupt):
        print()
        return 0


def _agent_setup(provider, json_mode):
    import getpass
    from .agent_setup import configure

    try:
        if provider is None:
            provider = input("Provider (openrouter/openai) [openrouter]: ").strip() or "openrouter"
        if provider.strip().lower() not in ("openrouter", "openai"):
            result = {"status": "error", "error": "Provider must be openrouter or openai."}
        else:
            key = getpass.getpass("API key: ")
            result = configure(provider, key)
    except (EOFError, KeyboardInterrupt):
        result = {"status": "error", "error": "Setup cancelled."}
    except OSError as exc:
        result = {"status": "error", "error": f"Could not save agent settings: {exc.strerror or exc}"}
    print(json.dumps(result, ensure_ascii=False) if json_mode else
          result.get("message", result.get("error", "Setup failed.")),
          file=sys.stdout if json_mode or result["status"] == "ok" else sys.stderr)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
