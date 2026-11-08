"""Optional keyboard-first terminal interface for the shared command router."""

import shlex


def create_app():
    # Textual is deliberately imported only when `qy` or `qy tui` is used.
    from textual.app import App, ComposeResult
    from textual.containers import VerticalScroll
    from textual.widgets import Footer, Header, Input, Static

    from qyano.cli.main import _render
    from qyano.cli.router import dispatch

    sections = [
        ("Dashboard", "help"), ("Hash", "hash"), ("Base64", "base encode"),
        ("Identify", "iden"), ("Ports", "port"), ("CVE", "cve"),
        ("Research", "res"), ("Aliases", "alias list"),
    ]

    class QyanoApp(App):
        TITLE = "Qyano"
        SUB_TITLE = "Security tools"
        CSS = """
        Screen { background: #0b1114; color: #d5e3e2; }
        Header { background: #102126; color: #7ee0c3; }
        #menu { color: #70cbb8; padding: 1 2; }
        #guide { color: #9ab2b5; padding: 0 2 1 2; }
        #output { color: #d5e3e2; padding: 1 2; }
        Input { background: #142329; color: #e5faf6; border: tall #279f9b; margin: 0 2 1 2; }
        Input:focus { border: tall #5cdbad; }
        Footer { background: #102126; color: #70cbb8; }
        """
        BINDINGS = [("ctrl+q", "quit", "Quit"), ("ctrl+l", "clear", "Clear")]

        def __init__(self):
            super().__init__()
            self.section = 0

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static("", id="menu")
            yield Static("", id="guide")
            with VerticalScroll():
                yield Static("", id="output")
            yield Input(placeholder="Enter a command or value", id="command")
            yield Footer()

        def on_mount(self):
            self._show_section(0)
            self.query_one("#command", Input).focus()

        def _show_section(self, index):
            self.section = index
            menu = "   ".join(f"[{i+1}] {label}" for i, (label, _) in enumerate(sections))
            self.query_one("#menu", Static).update(menu)
            guides = [
                "Type a full command, or press Ctrl+1–8 to choose a tool. Ctrl+Q exits.",
                "Enter text to hash. Example: hello",
                "Enter text to encode; use 'base decode TEXT' to decode.",
                "Enter text to identify. Use 'ihash TEXT' or 'ibase TEXT' to filter.",
                "Enter a port or service name. Example: 443 or ssh",
                "Enter a CVE ID or keywords. NVD lookup runs without AI.",
                "Enter a research prompt. Set up a provider in your shell with 'qy agent setup'.",
                "Use 'alias list', 'alias set NAME COMMAND', 'alias remove NAME', or 'alias reset'.",
            ]
            self.query_one("#guide", Static).update(guides[index])
            if index == 0:
                self.query_one("#output", Static).update(_render(dispatch(["help"]).value))
            elif index == 7:
                self.query_one("#output", Static).update(_render(dispatch(["alias", "list"]).value))
            self.query_one("#command", Input).placeholder = f"{sections[index][0]} input or full command"

        def on_key(self, event):
            if event.key in tuple(f"ctrl+{i}" for i in range(1, 9)):
                self._show_section(int(event.key[-1]) - 1)
                event.stop()

        def on_input_submitted(self, event: Input.Submitted):
            raw = event.value.strip()
            event.input.value = ""
            if not raw:
                return
            try:
                tokens = shlex.split(raw)
            except ValueError as exc:
                self.query_one("#output", Static).update(str(exc))
                return
            if tokens[0] == "qy":
                tokens = tokens[1:]
            else:
                from qyano.cli.router import COMMANDS
                if tokens[0] not in COMMANDS:
                    from qyano.cli.aliases import resolve
                    try:
                        shortcut = resolve(tokens[0])
                    except ValueError:
                        shortcut = None
                    if shortcut is None:
                        tokens = shlex.split(sections[self.section][1]) + [raw]
            if not tokens:
                tokens = ["help"]
            result = dispatch(tokens)
            if isinstance(result.value, dict) and result.value.get("agent_setup"):
                output = "Run 'qy agent setup' in your shell to enter the key securely."
            elif isinstance(result.value, dict) and result.value.get("interactive_research"):
                output = "Enter a research prompt."
            else:
                output = _render(result.value)
            self.query_one("#output", Static).update(output)

        def action_clear(self):
            self.query_one("#output", Static).update("")

    return QyanoApp()


def run():
    create_app().run()
    return 0
