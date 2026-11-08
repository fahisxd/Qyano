"""Offline JSON notes with optional connector target context."""

from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import sys


def data_path():
    root = os.environ.get("XDG_DATA_HOME")
    return (Path(root) if root else Path.home() / ".local" / "share") / "qyano" / "notes.json"


def empty_data():
    return {"version": 1, "enabled": False, "next_id": 1,
            "current_target": None, "notes": []}


def load_data():
    try:
        data = json.loads(data_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return empty_data()
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid notes JSON: {exc}") from exc
    if (not isinstance(data, dict) or data.get("version") != 1 or
            not isinstance(data.get("enabled"), bool) or
            type(data.get("next_id")) is not int or data["next_id"] < 1 or
            not isinstance(data.get("notes"), list) or "current_target" not in data or
            data["current_target"] is not None and not isinstance(data["current_target"], str)):
        raise ValueError("Invalid notes data")
    for note in data["notes"]:
        if (not isinstance(note, dict) or type(note.get("id")) is not int or
                not isinstance(note.get("text"), str) or
                not isinstance(note.get("created_at"), str) or
                not isinstance(note.get("updated_at"), str) or
                "target" not in note or
                note["target"] is not None and not isinstance(note["target"], str)):
            raise ValueError("Invalid note entry")
    return data


def _write_data(data):
    path = data_path()
    temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with temp.open("w", encoding="utf-8") as handle:
            os.chmod(temp, 0o600)
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def _change(action):
    path = data_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = path.with_name("notes.lock")
    with lock.open("a+", encoding="utf-8") as handle:
        os.chmod(lock, 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        data = load_data()
        result = action(data)
        _write_data(data)
        return result


def is_enabled():
    return load_data()["enabled"]


def set_enabled(enabled):
    if not enabled and not data_path().exists():
        return False

    def change(data):
        data["enabled"] = enabled
        if not enabled:
            data["current_target"] = None
        return enabled

    return _change(change)


def _require_enabled(data):
    if not data["enabled"]:
        raise ValueError("Quick Notes is disabled. Run 'qy notes enable' or enable it in 'qy connect'.")


def set_current_target(target):
    if not is_enabled():
        return

    def change(data):
        if data["enabled"]:
            data["current_target"] = target

    _change(change)


def clear_target():
    def change(data):
        _require_enabled(data)
        data["current_target"] = None

    _change(change)


def add_note(text):
    text = text.strip()
    if not text:
        raise ValueError("Note text cannot be empty")

    def change(data):
        _require_enabled(data)
        now = datetime.now(timezone.utc).isoformat()
        note = {"id": data["next_id"], "text": text,
                "target": data["current_target"], "created_at": now, "updated_at": now}
        data["next_id"] += 1
        data["notes"].append(note)
        return note

    return _change(change)


def find_note(note_id):
    data = load_data()
    _require_enabled(data)
    return next((note for note in data["notes"] if note["id"] == note_id), None)


def list_notes(query=None, limit=None):
    data = load_data()
    _require_enabled(data)
    notes = sorted(data["notes"], key=lambda note: note["id"], reverse=True)
    if query is not None:
        needle = query.casefold()
        notes = [note for note in notes if needle in note["text"].casefold() or
                 needle in (note["target"] or "").casefold()]
    return notes[:limit] if limit is not None else notes


def edit_note(note_id, text):
    text = text.strip()
    if not text:
        raise ValueError("Note text cannot be empty")

    def change(data):
        _require_enabled(data)
        note = next((item for item in data["notes"] if item["id"] == note_id), None)
        if note is None:
            raise ValueError(f"Note #{note_id} not found")
        note["text"] = text
        note["updated_at"] = datetime.now(timezone.utc).isoformat()
        return note

    return _change(change)


def delete_note(note_id):
    def change(data):
        _require_enabled(data)
        note = next((item for item in data["notes"] if item["id"] == note_id), None)
        if note is None:
            raise ValueError(f"Note #{note_id} not found")
        data["notes"].remove(note)
        return note

    return _change(change)


def _time_label(value):
    when = datetime.fromisoformat(value).astimezone()
    today = datetime.now().astimezone().date()
    if when.date() == today:
        return when.strftime("%H:%M")
    if when.date() == today - timedelta(days=1):
        return "Yesterday"
    return when.strftime("%Y-%m-%d %H:%M")


def _print_notes(notes):
    print("QYANO / NOTES")
    if not notes:
        print("No notes found.")
    for note in notes:
        print(f"\n#{note['id']}  [{note['target'] or 'GENERAL'}]")
        for line in note["text"].splitlines():
            print(f"     {line}")
        print(f"     {_time_label(note['created_at'])}")


def export_notes(destination=None):
    notes = list_notes()
    if destination is None:
        stem = f"qyano-notes-{datetime.now().astimezone():%Y-%m-%d}"
        destination = Path.cwd() / f"{stem}.md"
        number = 2
        while destination.exists():
            destination = Path.cwd() / f"{stem}-{number}.md"
            number += 1
    else:
        destination = Path(destination).expanduser()
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("# Qyano Notes\n")
        for note in notes:
            stamp = datetime.fromisoformat(note["created_at"]).astimezone().strftime("%Y-%m-%d %H:%M %Z")
            handle.write(f"\n## #{note['id']} [{note['target'] or 'GENERAL'}]\n\n")
            handle.write(note["text"] + f"\n\n*{stamp}*\n")
    return destination


def _id(value):
    if not value.isdecimal() or int(value) < 1:
        raise ValueError("Note ID must be a positive number")
    return int(value)


def _output(value, json_mode=False):
    if json_mode:
        print(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, str):
        print(value)
    elif isinstance(value, list):
        _print_notes(value)
    else:
        _print_notes([value])


def main(args, json_mode=False):
    try:
        if not args:
            _output(list_notes(limit=20), json_mode)
        elif args == ["enable"]:
            set_enabled(True)
            _output({"enabled": True} if json_mode else "Quick Notes enabled.", json_mode)
        elif args == ["disable"]:
            set_enabled(False)
            _output({"enabled": False} if json_mode else "Quick Notes disabled; saved notes remain on disk.", json_mode)
        elif args == ["status"]:
            data = load_data()
            state = {"enabled": data["enabled"], "count": len(data["notes"]),
                     "current_target": data["current_target"]}
            _output(state if json_mode else f"Quick Notes: {'enabled' if state['enabled'] else 'disabled'}; {state['count']} notes; target: {state['current_target'] or 'GENERAL'}", json_mode)
        elif args == ["target"]:
            data = load_data()
            _require_enabled(data)
            _output({"current_target": data["current_target"]} if json_mode else
                    f"Current target: {data['current_target'] or 'GENERAL'}", json_mode)
        elif args == ["target", "clear"]:
            clear_target()
            _output({"current_target": None} if json_mode else "Current target cleared.", json_mode)
        elif len(args) >= 2 and args[0] == "search":
            _output(list_notes(query=" ".join(args[1:])), json_mode)
        elif len(args) == 2 and args[0] == "show":
            note = find_note(_id(args[1]))
            if note is None:
                raise ValueError(f"Note #{args[1]} not found")
            _output(note, json_mode)
        elif len(args) >= 2 and args[0] == "edit":
            note_id = _id(args[1])
            note = find_note(note_id)
            if note is None:
                raise ValueError(f"Note #{note_id} not found")
            if len(args) == 2:
                print(f"Current text: {note['text']}")
                text = input("New note text: ")
            else:
                text = " ".join(args[2:])
            _output(edit_note(note_id, text), json_mode)
        elif len(args) == 2 and args[0] == "del":
            note_id = _id(args[1])
            if find_note(note_id) is None:
                raise ValueError(f"Note #{note_id} not found")
            if input(f"Delete note #{note_id}? [y/N]: ").strip().lower() not in ("y", "yes"):
                _output("Deletion cancelled.", json_mode)
            else:
                delete_note(note_id)
                _output({"deleted": note_id} if json_mode else f"Deleted note #{note_id}.", json_mode)
        elif args[0] == "export" and len(args) <= 2:
            destination = export_notes(args[1] if len(args) == 2 else None)
            _output({"path": str(destination)} if json_mode else f"Exported notes to {destination}", json_mode)
        else:
            raise ValueError("Usage: qy notes [search QUERY|show ID|edit ID|del ID|export [FILE]|enable|disable|status|target [clear]]")
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        message = "Cancelled." if isinstance(exc, (EOFError, KeyboardInterrupt)) else str(exc)
        print(json.dumps({"error": message}) if json_mode else message,
              file=sys.stdout if json_mode else sys.stderr)
        return 1
    return 0


def quick_note(args, json_mode=False):
    try:
        if not is_enabled():
            raise ValueError("Quick Notes is disabled. Run 'qy notes enable' or enable it in 'qy connect'.")
        text = " ".join(args) if args else input("note> ")
        _output(add_note(text), json_mode)
        return 0
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        message = "Cancelled." if isinstance(exc, (EOFError, KeyboardInterrupt)) else str(exc)
        print(json.dumps({"error": message}) if json_mode else message,
              file=sys.stdout if json_mode else sys.stderr)
        return 1
