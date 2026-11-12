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

A connector is a named profile containing SSH settings, an optional network check, an optional VPN, and an ordered set of commands. Create one with `qy con add lab`. This opens its connector shell. Use `qy con list` to see profiles, `qy con use lab` to make one active, and `qy con edit lab` to reopen its shell. `qy connect` remains an alias for opening the active profile or creating the first one.

Inside the connector shell, use `ssh` to set a `user@host`, port, and optional private key; `ssh local` runs commands on this machine. SSH can prompt for a password when no key is configured, but Qyano never saves the password. Use `network` for a one-shot connectivity check that should exit successfully before connector commands run. Use `vpn` to enter a VPN start command and optional disconnect command. Each profile has its own VPN settings.

Use `add` or `add NAME` in the shell to save a command, `list` to see commands, `edit NAME` to change one, `args NAME` to edit its parameter labels and defaults, and `del NAME` to remove one. A template can use `&QUIC` for the target IP and `QUIC1`, `QUIC2`, and so on for prompted arguments. For example: `tool --host &QUIC --wordlist QUIC1 --mode QUIC2`. Keep placeholders unquoted; Qyano quotes supplied values. The shell also has `ai` for per-profile AI summaries and `notes` to enable or disable Quick Notes.

```sh
qy con add lab
qy vpn
qy vpn status
qy
qy vpn des
```

`qy vpn` starts the active profile's VPN in a detached tmux terminal, so VPN output does not occupy the current terminal. `qy vpn des` stops that terminal and runs the profile's disconnect command. Use `qy vpn lab` or `qy vpn des lab` to address a specific profile. You can inspect the detached terminal with `tmux -L qyano-vpn attach -t qyano-vpn-lab`. A configured network check runs in the current terminal when `qy` starts, after the VPN is active. Use `qy vpn` first when a profile has VPN settings.

Running `qy` asks for the target IP, then offers each command in the active profile in order and prompts for any arguments. If AI summaries are enabled, it summarizes the results at the end. Existing single-command connector settings are migrated to a `default` profile when read; their previous network command becomes the VPN start command.

Connector settings live in `~/.config/qyano/connector.json` with owner-only permissions. Saved commands are shell commands, so only add commands you intend to run.

## Quick Notes Engine

Quick Notes is optional and works entirely offline. Enable it with `notes` inside a connector shell or with `qy notes enable`. Turning it off with `qy notes disable` keeps existing notes on disk.

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
