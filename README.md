# Qyano

Qyano is a Python command line toolkit for hashes, Base64, port lookups, CVE searches, AI research, and running saved command connectors. It also includes a terminal interface. All features run through the `qy` command.

## Install

Requires Python 3.10 or newer. From the project directory, run:

```sh
python3 -m qyano.env_manager install
qy hash hello
```

The manager creates `.venv`, installs Qyano and its terminal interface dependencies, and links `~/.local/bin/qy` to the environment's executable. You do not need to activate `.venv` to use `qy`.

If your shell cannot find `qy`, add the user bin directory to your `PATH`:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Add that line to your shell startup file to keep it across sessions. Keep this project directory in place: the command in `~/.local/bin` points into its `.venv`.

## Manage the environment

```sh
qy env status
qy update
qy env install
```

Before `qy` is available, run `python3 -m qyano.env_manager install` from this directory. The manager leaves an existing, unrelated `~/.local/bin/qy` untouched and reports the conflict.

## Use Qyano

Run `qy` to start the connector workflow after setup. Run `qy tui` to open the terminal interface. Use Ctrl+1 through Ctrl+8 to switch sections and Ctrl+Q to exit.

```sh
qy hash hello
qy ihash 5d41402abc4b2a76b9719d911017c592
qy base encode hello
qy base decode aGVsbG8=
qy ibase aGVsbG8=
qy iden aGVsbG8=
qy port 443
qy cve CVE-2021-44228
qy res 'Explain CVE-2021-44228'
qy res
```

Text commands accept unquoted words, such as `qy hash hello world`. When you omit a required value, Qyano reads it from the system clipboard. This applies to hashes, Base64, identification, port lookup, CVE search, research, notes, note IDs, and alias names or targets. An empty input in a selected TUI tool uses the clipboard too. `qy res` starts its interactive session if the clipboard is empty. Clipboard access uses an available system command such as `wl-paste`, `xclip`, `xsel`, or `pbpaste`.

Run `qy help` for the full command list. Most tool commands accept `--json` for machine-readable output.

Short aliases include `h` for `hash`, `hi` for `ihash`, `e` for `base encode`, `d` for `base decode`, `p` for `port`, `c` for `cve`, and `r` for `res`. You can also manage your own aliases:

```sh
qy alias set b base encode
qy b hello
qy alias list
qy alias remove b
qy alias reset
```

## Connectors

Run `qy connect` to set up the connector engine. It asks for an attack machine SSH target in `user@host` form; leave it empty to run commands locally. For SSH, you can supply a private key path, or let SSH use its configured keys or prompt for a password. Setup checks the SSH connection. Qyano saves the host, port, and key path, but never a password.

Setup then asks for a network or VPN command and runs it before continuing. Leave it empty if no connection command is needed. Finally, choose whether to enable an AI summary and Quick Notes. AI summaries require a configured key from `qy agent setup`. Setup opens the connector shell when complete.

You can reopen the connector shell with `qy connect shell`. It supports `add`, `list`, `edit NAME`, `del NAME`, and `exit`. When adding a connector, enter a name and a shell command. Use `&QUIC` where the target IP belongs and `QUIC1`, `QUIC2`, and so on for inputs. The shell asks you to label each extra input, such as `wordlist`, `subdomain`, or `mode`.

For example, a connector command could be `tool --host &QUIC --wordlist QUIC1 --mode QUIC2`. Qyano asks for the `wordlist` and `mode` values before running it. Keep placeholders unquoted in the saved command; Qyano quotes the values when it fills them.

Run `qy` to use saved connectors. It asks for the network command again, with an option to stop asking on later runs, then asks for a target IP. It offers each connector in saved order and prompts for any plugin values. If AI summaries are enabled, it summarizes the results at the end. A failed network command stops the run before any connector starts.

Connector settings live in `~/.config/qyano/connector.json` with owner-only permissions. Saved connector and network commands are shell commands, so only add commands you intend to run.

## Quick Notes Engine

Quick Notes is optional and works entirely offline. Enable it during `qy connect` setup or later with `qy notes enable`. Turning it off with `qy notes disable` keeps existing notes on disk.

```sh
qy n "Found SSH on port 22"
qy n
qy notes
qy notes search ssh
qy notes show 12
qy notes edit 12
qy notes del 12
qy notes export
```

`qy n` with no text saves the copied text, or opens a one-line note prompt if the clipboard is empty. `qy notes` lists the 20 most recent notes. Search checks note text and target labels without regard to case. `qy notes show`, `edit`, and `del` can read a copied note ID when you omit it. `qy notes edit ID` uses copied replacement text, or prompts if the clipboard is empty. Deletion always asks for confirmation. `qy notes export` writes a Markdown file in the current directory without replacing an existing file; you can also give it a path.

When you enter a target IP in the connector workflow, Qyano makes it the current note target. Later notes are tagged with that IP; notes saved before a target is set are tagged `GENERAL`. The current target remains set until the next connector target replaces it or you run `qy notes target clear`. Run `qy notes target` to check it.

Notes are stored as JSON in `~/.local/share/qyano/notes.json` (or under `XDG_DATA_HOME`) with owner-only permissions. IDs keep increasing even after deletion. Markdown exports are also created with owner-only permissions.

## AI research setup

`qy res` needs an OpenRouter or OpenAI API key. Run `qy agent setup` to choose a provider, enter a hidden key, and verify it. To select a provider directly, run `qy agent setup openai` or `qy agent setup openrouter`.

Verified settings are saved with owner-only permissions at `~/.config/qyano/agent.json`. Environment variables (`AI_PROVIDER`, the matching API key, and optional `AI_MODEL`) take precedence. `qy cve` searches NVD directly and does not require an AI key.

## Test

```sh
.venv/bin/python -m unittest discover -s tests -q
```
