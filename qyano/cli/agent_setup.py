"""Interactive AI provider setup and credential verification."""

import json
import os
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


CHECK_URLS = {
    "openai": "https://api.openai.com/v1/models",
    "openrouter": "https://openrouter.ai/api/v1/key",
}
MAX_CHECK_BYTES = 64 * 1024


def config_path():
    root = os.environ.get("XDG_CONFIG_HOME")
    return (Path(root) if root else Path.home() / ".config") / "qyano" / "agent.json"


def load_config():
    """Read saved credentials only when the AI agent is requested."""
    try:
        data = json.loads(config_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("provider") not in CHECK_URLS:
        return None
    if not isinstance(data.get("api_key"), str) or not data["api_key"].strip():
        return None
    return data


def check_key(provider, api_key):
    """Return (valid, explanation) without sending a completion or printing a key."""
    provider = provider.strip().lower() if isinstance(provider, str) else ""
    if provider not in CHECK_URLS:
        return False, "Provider must be openrouter or openai."
    if not isinstance(api_key, str) or not api_key.strip():
        return False, "API key cannot be empty."
    api_key = api_key.strip()
    if "\r" in api_key or "\n" in api_key:
        return False, "API key contains invalid line breaks."
    request = Request(CHECK_URLS[provider], headers={
        "Authorization": f"Bearer {api_key}", "Accept": "application/json",
        "User-Agent": "Qyano/0.1",
    })
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(MAX_CHECK_BYTES + 1)
        if len(body) > MAX_CHECK_BYTES:
            return False, "Provider response was too large to verify."
        payload = json.loads(body.decode("utf-8"))
        valid = (isinstance(payload, dict) and
                 (isinstance(payload.get("data"), list) if provider == "openai"
                  else isinstance(payload.get("data"), dict)))
        return (True, "Key verified.") if valid else (False, "Provider returned an unexpected response.")
    except HTTPError as exc:
        exc.close()
        if exc.code in (401, 403):
            return False, f"Provider rejected the key (HTTP {exc.code})."
        return False, f"Provider check failed (HTTP {exc.code})."
    except (URLError, TimeoutError):
        return False, "Could not reach the provider to verify the key."
    except (UnicodeError, ValueError):
        return False, "Provider returned an unreadable response."


def configure(provider, api_key):
    """Verify first, then atomically save credentials with owner-only access."""
    provider = provider.strip().lower() if isinstance(provider, str) else ""
    valid, message = check_key(provider, api_key)
    if not valid:
        return {"status": "error", "provider": provider, "error": message}
    path = config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".agent-", delete=False) as temp:
            temp_name = temp.name
            os.chmod(temp_name, 0o600)
            json.dump({"provider": provider, "api_key": api_key.strip()}, temp)
            temp.write("\n")
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    return {"status": "ok", "provider": provider, "message": "Key verified and saved.",
            "config_file": str(path)}
