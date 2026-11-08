"""Install and maintain Qyano's project environment and user command."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import venv


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def paths():
    environment = PROJECT_ROOT / ".venv"
    return environment, environment / "bin" / "python", environment / "bin" / "qy", Path.home() / ".local" / "bin" / "qy"


def status():
    environment, python, executable, user_command = paths()
    installed = python.is_file() and executable.is_file()
    linked = user_command.is_symlink() and user_command.resolve() == executable.resolve()
    print(f"Environment: {environment} ({'ready' if installed else 'missing'})")
    print(f"Command: {user_command} ({'linked' if linked else 'missing or different'})")
    if linked and str(user_command.parent) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"Add {user_command.parent} to PATH to run qy from any directory.")
    return 0 if installed and linked else 1


def install(*, upgrade=False):
    environment, python, executable, user_command = paths()
    if user_command.is_symlink() and user_command.resolve() == executable.resolve():
        pass
    elif user_command.exists() or user_command.is_symlink():
        print(f"Cannot install: {user_command} already exists and belongs to another installation.", file=sys.stderr)
        return 1

    if not python.is_file():
        print(f"Creating {environment}")
        venv.create(environment, with_pip=True)

    command = [str(python), "-m", "pip", "install"]
    if upgrade:
        command.extend(["--upgrade", "--upgrade-strategy", "eager"])
    command.extend(["-e", f"{PROJECT_ROOT}[tui]"])
    print(f"{'Updating' if upgrade else 'Installing'} Qyano and its dependencies", flush=True)
    subprocess.run(command, check=True)
    if not executable.is_file():
        raise RuntimeError(f"pip did not create {executable}")

    user_command.parent.mkdir(parents=True, exist_ok=True)
    if not user_command.is_symlink():
        user_command.symlink_to(executable)
    print(f"Ready: {user_command}")
    if str(user_command.parent) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"Add {user_command.parent} to PATH to run qy from any directory.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manage Qyano's Python environment")
    parser.add_argument("action", choices=("install", "update", "status"))
    args = parser.parse_args(argv)
    try:
        if args.action == "status":
            return status()
        return install(upgrade=args.action == "update")
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"Qyano environment error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
