import csv
from functools import lru_cache
from pathlib import Path


PORT_CSV = Path(__file__).resolve().parent / "qyano" / "data" / "service-names-port-numbers.csv"


@lru_cache(maxsize=1)
def _load_port_indexes():
    by_port = {}
    by_service = {}
    with PORT_CSV.open("r", encoding="utf-8", newline="") as source:
        for row in csv.DictReader(source):
            port_text = row.get("Port Number", "").strip()
            service_name = row.get("Service Name", "").strip()
            protocol = row.get("Transport Protocol", "").strip()

            try:
                port = int(port_text)
            except ValueError:
                continue

            detail = {
                "service_name": service_name or None,
                "port": port,
                "protocol": protocol or None,
                "description": row.get("Description", "").strip() or None,
                "assignee": row.get("Assignee", "").strip() or None,
                "registration_date": row.get("Registration Date", "").strip() or None,
                "modification_date": row.get("Modification Date", "").strip() or None,
                "reference": row.get("Reference", "").strip() or None,
                "service_code": row.get("Service Code", "").strip() or None,
                "unauthorized_use_reported": row.get("Unauthorized Use Reported", "").strip() or None,
                "assignment_notes": row.get("Assignment Notes", "").strip() or None,
            }
            by_port.setdefault(port, []).append(detail)
            if service_name:
                by_service.setdefault(service_name.casefold(), []).append(detail)

    return by_port, by_service


def potg_engine(query, protocol=None):
    if not isinstance(query, (str, int)) or isinstance(query, bool):
        return {"error": "error/engines/potg/invalid-query"}

    value = str(query).strip()
    if not value:
        return {"error": "error/engines/potg/empty-query"}

    port_number = None
    if value.isdecimal():
        port_number = int(value)
        if not 0 <= port_number <= 65535:
            return {"error": "error/engines/potg/port-out-of-range"}

    protocol_value = None
    if protocol is not None:
        if not isinstance(protocol, str) or not protocol.strip():
            return {"error": "error/engines/potg/invalid-protocol"}
        protocol_value = protocol.strip().casefold()

    try:
        by_port, by_service = _load_port_indexes()
    except OSError as exc:
        return {"error": f"error/engines/potg/source-unavailable: {exc}"}

    candidates = by_port.get(port_number, ()) if port_number is not None else by_service.get(value.casefold(), ())
    results = [
        detail.copy()
        for detail in candidates
        if protocol_value is None or (detail["protocol"] or "").casefold() == protocol_value
    ]

    if not results:
        return {"query": value, "protocol": protocol_value, "results": [],
                "error": "error/engines/potg/not-found"}

    return {"query": value, "protocol": protocol_value, "results": results}
