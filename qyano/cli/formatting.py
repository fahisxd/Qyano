"""Readable presentation of engine results; structured data stays unchanged."""


HASH_LABELS = (("sha256", "SHA-256"), ("md5", "MD5"), ("sha1", "SHA-1"))
PORT_ERRORS = {
    "error/engines/potg/not-found": "No matching port or service was found.",
    "error/engines/potg/port-out-of-range": "Port must be between 0 and 65535.",
    "error/engines/potg/empty-query": "Enter a port number or service name.",
    "error/engines/potg/invalid-query": "Enter a valid port number or service name.",
    "error/engines/potg/invalid-protocol": "Enter a valid protocol.",
}


def _label(name):
    return name.replace("_", " ").replace("-", " ").capitalize()


def _shown(value):
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(map(str, value))
    return str(value)


def _error(message):
    if message in PORT_ERRORS:
        return PORT_ERRORS[message]
    if message.startswith("error/engines/hbe/"):
        detail = message.removeprefix("error/engines/hbe/")
        if detail.startswith("Only base64") or "base64" in detail.lower():
            return "Invalid Base64 input."
        return detail or "Could not process the input."
    return message


def _identifiers(value):
    lines = ["Identification", f"  Input: {value.get('input', '')}"]
    for item in value.get("identifiers", []):
        kind = item.get("type", "unknown")
        if kind == "unknown":
            lines.append("  No known format matched.")
            continue
        lines.append(f"  {_label(kind)}")
        for key, detail in item.items():
            if key != "type" and detail is not None:
                lines.append(f"    {_label(key)}: {_shown(detail)}")
    return "\n".join(lines)


def _ports(value):
    results = value.get("results", [])
    if not results:
        return _error(value.get("error", "No matching port or service was found."))
    lines = [f"Port lookup: {value.get('query', '')}"]
    for item in results:
        name = item.get("service_name") or "Unnamed service"
        protocol = item.get("protocol") or "unknown protocol"
        lines.append(f"  {name}  •  {item.get('port')}/{protocol}")
        if item.get("description"):
            lines.append(f"    {item['description']}")
        if item.get("assignee"):
            lines.append(f"    Assigned to: {item['assignee']}")
        if item.get("reference"):
            lines.append(f"    Reference: {item['reference']}")
    return "\n".join(lines)


def _cves(value):
    if value.get("status") != "ok":
        return _error(value.get("error", "NVD lookup failed."))
    results = value.get("results", [])
    if not results:
        return "No CVE records found in NVD."
    total = value.get("total_results", len(results))
    lines = [f"NVD results: {len(results)} shown" + (f" of {total}" if total != len(results) else "")]
    for item in results:
        lines.append("")
        lines.append(item.get("id") or "CVE record")
        if item.get("status"):
            lines.append(f"  Status: {item['status']}")
        if item.get("published"):
            lines.append(f"  Published: {item['published']}")
        score = item.get("cvss")
        if isinstance(score, dict) and score.get("score") is not None:
            assessment = ", ".join(str(part) for part in
                                   (score.get("source"), score.get("assessment_type")) if part)
            text = f"  CVSS {score.get('version') or '?'}: {score['score']}"
            if score.get("severity"):
                text += f" {score['severity']}"
            if assessment:
                text += f" ({assessment})"
            lines.append(text)
        if item.get("description"):
            import textwrap
            lines.append("  Description:")
            lines.append(textwrap.fill(item["description"], width=88,
                                       initial_indent="    ", subsequent_indent="    "))
        if item.get("url"):
            lines.append(f"  NVD: {item['url']}")
        references = item.get("references") or []
        if references:
            lines.append("  References:")
            lines.extend(f"    {reference}" for reference in references)
    return "\n".join(lines)


def render(value):
    """Format a router result for people without changing its JSON form."""
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return str(value)
    if "answer" in value:
        return value["answer"] if value["answer"] != "AI not enabled" else \
            "AI is not set up. Run 'qy agent setup' to add and verify a key."
    if "sha256" in value and "md5" in value:
        lines = ["Hashes"]
        lines.extend(f"  {label:<7}  {value[key]}" for key, label in HASH_LABELS if key in value)
        return "\n".join(lines)
    if "base64/encode" in value:
        return f"Base64 encoded\n  {value['base64/encode']}"
    if "base64/decode" in value:
        return f"Base64 decoded\n  {value['base64/decode']}"
    if "identifiers" in value:
        return _identifiers(value)
    if "query" in value and "results" in value:
        return _ports(value)
    if "verified_data" in value and "status" in value:
        return _cves(value)
    if "error" in value:
        return _error(str(value["error"]))
    if "removed" in value:
        return f"Removed alias: {value['removed']}"
    if value and all(isinstance(target, list) for target in value.values()):
        return "Aliases\n" + "\n".join(
            f"  {name:<8} → {' '.join(target)}" for name, target in value.items())
    if not value:
        return "No results."
    return "\n".join(f"{_label(key)}: {_shown(detail)}" for key, detail in value.items())
