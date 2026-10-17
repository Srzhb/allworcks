"""Read normalized JSONL or XML exported from Windows Event Viewer."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET


class InputError(ValueError):
    """An input record cannot be interpreted without guessing."""


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_id: int
    computer: str
    process_guid: str
    process_id: int | None
    image: str
    command_line: str
    parent_image: str
    destination_ip: str
    destination_port: int | None
    protocol: str
    record_id: str


ALIASES = {
    "event_id": "EventID",
    "computer": "Computer",
    "process_guid": "ProcessGuid",
    "process_id": "ProcessId",
    "image": "Image",
    "command_line": "CommandLine",
    "parent_image": "ParentImage",
    "destination_ip": "DestinationIp",
    "destination_port": "DestinationPort",
    "protocol": "Protocol",
    "record_id": "EventRecordID",
}


def _string(value: Any, name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise InputError(f"{name}: expected a string")
    return str(value).strip()


def _integer(value: Any, name: str, maximum: int | None = None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise InputError(f"{name}: expected an integer")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise InputError(f"{name}: expected an integer") from exc
    if parsed < 0 or (maximum is not None and parsed > maximum):
        raise InputError(f"{name}: value out of range")
    return parsed


def normalize(data: dict[str, Any]) -> Event | None:
    """Return supported Sysmon events; other Event IDs are deliberately ignored."""
    fields = {
        name: data.get(name, data.get(alias)) for name, alias in ALIASES.items()
    }
    event_id = _integer(fields["event_id"], "event_id")
    if event_id is None:
        raise InputError("event_id is required")
    if event_id not in (1, 3):
        return None
    raw_timestamp = data.get("timestamp", data.get("UtcTime"))
    if not isinstance(raw_timestamp, str):
        raise InputError("timestamp or UtcTime is required")
    try:
        timestamp = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError("timestamp: expected ISO 8601") from exc
    if timestamp.tzinfo is None:
        if "timestamp" in data:
            raise InputError("timestamp: explicit timezone is required")
        # Sysmon documents UtcTime as UTC, although the field has no suffix.
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)
    computer = _string(fields["computer"], "computer")
    if not computer:
        raise InputError("computer is required to prevent joins across hosts")
    image = _string(fields["image"], "image").replace("/", "\\")
    if event_id == 1 and not image:
        raise InputError("image is required for process creation")
    destination_ip = _string(fields["destination_ip"], "destination_ip")
    destination_port = _integer(fields["destination_port"], "destination_port", 65535)
    if event_id == 3:
        try:
            destination_ip = str(ipaddress.ip_address(destination_ip))
        except ValueError as exc:
            raise InputError("destination_ip: expected an IPv4 or IPv6 address") from exc
        if destination_port is None:
            raise InputError("destination_port is required for network connections")
    return Event(
        timestamp=timestamp,
        event_id=event_id,
        computer=computer,
        process_guid=_string(fields["process_guid"], "process_guid").strip("{}").lower(),
        process_id=_integer(fields["process_id"], "process_id"),
        image=image,
        command_line=_string(fields["command_line"], "command_line"),
        parent_image=_string(fields["parent_image"], "parent_image").replace("/", "\\"),
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=_string(fields["protocol"], "protocol").lower(),
        record_id=_string(fields["record_id"], "record_id"),
    )


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_records(path: Path):
    try:
        # ElementTree does not fetch external entities; DTDs are unnecessary for
        # Event Viewer exports and rejected explicitly before parsing.
        content = path.read_bytes()
        markup = content.replace(b"\x00", b"").upper()
        if b"<!DOCTYPE" in markup or b"<!ENTITY" in markup:
            raise InputError("XML DTDs and entity declarations are not supported")
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise InputError(f"invalid XML: {exc}") from exc
    count = 0
    for node in root.iter():
        if _local_name(node.tag) != "Event":
            continue
        count += 1
        data: dict[str, Any] = {}
        for section in node:
            section_name = _local_name(section.tag)
            if section_name == "System":
                for child in section:
                    name = _local_name(child.tag)
                    if name == "Provider":
                        data["Provider"] = child.attrib.get("Name", "")
                    elif name == "TimeCreated":
                        data["timestamp"] = child.attrib.get("SystemTime", "")
                    else:
                        data[name] = child.text or ""
            elif section_name == "EventData":
                for child in section:
                    if _local_name(child.tag) == "Data" and "Name" in child.attrib:
                        data[child.attrib["Name"]] = child.text or ""
        # Security Event IDs have different meanings. An exported Event must
        # identify the Sysmon provider before interpreting Event IDs 1 and 3.
        if data.get("Provider", "").casefold() != "microsoft-windows-sysmon":
            continue
        yield f"XML event {count}", data
    if not count:
        raise InputError("XML contains no Event elements")


def _json_records(path: Path):
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(data, dict):
                raise InputError(f"line {line_number}: expected a JSON object")
            # JSONL is a normalized Sysmon dataset by contract. If a provider is
            # supplied, respect it instead of interpreting a different source.
            provider = data.get("provider", data.get("Provider"))
            if provider is not None and provider != "Microsoft-Windows-Sysmon":
                continue
            yield f"line {line_number}", data


def load_events(path: str | Path, input_format: str = "auto") -> list[Event]:
    path = Path(path)
    if input_format == "auto":
        input_format = "xml" if path.suffix.lower() == ".xml" else "jsonl"
    if input_format not in ("xml", "jsonl"):
        raise InputError("format must be jsonl, xml, or auto")
    records = _xml_records(path) if input_format == "xml" else _json_records(path)
    events = []
    for location, data in records:
        try:
            event = normalize(data)
        except InputError as exc:
            raise InputError(f"{location}: {exc}") from exc
        if event is not None:
            events.append(event)
    return events
