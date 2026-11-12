"""Run a connector VPN in a detached tmux terminal."""

from pathlib import Path
import shlex
import shutil
import subprocess
import time


def session_name(profile):
    return f"qyano-vpn-{profile['name']}"


def _ssh_command(ssh, command):
    argv = ["ssh"]
    user_config = Path.home() / ".ssh" / "config"
    if user_config.is_file():
        argv.extend(["-F", str(user_config)])
    argv.extend(["-p", str(ssh.get("port", 22))])
    if ssh.get("key"):
        argv.extend(["-i", ssh["key"]])
    argv.extend([ssh["target"], shlex.join(command)])
    return argv


def _run(profile, command, timeout=30):
    ssh = profile["ssh"]
    argv = _ssh_command(ssh, command) if ssh.get("target") else command
    return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                          timeout=timeout, check=False)


def _tmux(profile, *args):
    if not shutil.which("tmux"):
        raise RuntimeError("tmux is required for detached VPN terminals")
    return _run(profile, ["tmux", "-L", "qyano-vpn", *args])


def is_running(profile):
    if not shutil.which("tmux"):
        return False
    result = _tmux(profile, "has-session", "-t", f"={session_name(profile)}")
    return result.returncode == 0


def start(profile):
    command = profile["vpn"].get("start", "").strip()
    if not command:
        raise ValueError("This connector has no VPN start command. Configure it with 'vpn' in qy con shell.")
    if is_running(profile):
        return f"VPN already running in tmux session {session_name(profile)}."
    wrapper = (f"/bin/sh -lc {shlex.quote(command)}; code=$?; "
               "[ \"$code\" -eq 0 ] || exit \"$code\"; "
               "while :; do sleep 3600; done")
    result = _tmux(profile, "new-session", "-d", "-s", session_name(profile), wrapper)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Could not start VPN terminal")
    time.sleep(0.2)
    if not is_running(profile):
        raise RuntimeError("VPN command exited before its terminal stayed active")
    return f"VPN started in tmux session {session_name(profile)}."


def stop(profile):
    running = is_running(profile)
    if running:
        result = _tmux(profile, "kill-session", "-t", f"={session_name(profile)}")
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "Could not stop VPN terminal")
    command = profile["vpn"].get("stop", "").strip()
    if command:
        result = _run(profile, ["/bin/sh", "-lc", command], timeout=60)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"VPN disconnect command exited {result.returncode}")
    return "VPN disconnected." if running or command else "VPN was not running."


def status(profile):
    return ("running" if is_running(profile) else "stopped") + f" ({session_name(profile)})"
