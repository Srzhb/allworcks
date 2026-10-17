"""Reference evaluation of three rules, with deterministic GUID correlation."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import re

from .ingestion import Event


ENCODED_SWITCH = re.compile(
    r"(?:^|\s)-(?:e|ec|enc|encodedcommand)(?:\s+|:\s*)[A-Za-z0-9+/=]{8,}(?:\s|$)",
    re.IGNORECASE,
)
POWERSHELL = {"powershell.exe", "pwsh.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
INTERPRETERS = POWERSHELL | {"cmd.exe", "wscript.exe", "cscript.exe"}
NETWORK_INTERPRETERS = POWERSHELL | {"wscript.exe", "cscript.exe"}
UNUSUAL_PORTS = {1337, 4444, 9001}

RULES = {
    "WH001": {
        "title": "PowerShell with an encoded command switch",
        "severity": "medium",
        "tags": ["attack.execution", "attack.t1059.001"],
    },
    "WH002": {
        "title": "Office application starts a command interpreter",
        "severity": "medium",
        "tags": ["attack.execution", "attack.t1204.002", "attack.t1059"],
    },
    "WH003": {
        "title": "Script interpreter connects to an unusual destination port",
        "severity": "medium",
        "tags": ["attack.execution", "attack.command-and-control", "attack.t1059"],
    },
}


def _iso(timestamp: datetime) -> str:
    return timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _basename(image: str) -> str:
    return image.rsplit("\\", 1)[-1].casefold()


def analyze(events: list[Event]) -> dict:
    """Analyze all supplied events in timestamp order, without PID fallback.

    Creation precedes network activity for tied timestamps. A missing GUID or
    host prevents correlation; a creation later than the connection cannot join.
    Each rule only evaluates its documented event category.
    """
    ordered = sorted(
        events,
        key=lambda event: (event.timestamp, event.event_id, event.computer.casefold(), event.record_id),
    )
    processes: dict[tuple[str, str], Event] = {}
    timeline = []
    detections = []
    for sequence, event in enumerate(ordered, 1):
        key = (event.computer.casefold(), event.process_guid)
        creation = None
        if event.event_id == 1 and event.process_guid:
            processes[key] = event
        elif event.event_id == 3 and event.process_guid:
            creation = processes.get(key)
        image = event.image or (creation.image if creation else "")
        command_line = event.command_line or (creation.command_line if creation else "")
        parent_image = event.parent_image or (creation.parent_image if creation else "")
        row = {
            "sequence": sequence,
            "timestamp": _iso(event.timestamp),
            "event_id": event.event_id,
            "kind": "process_creation" if event.event_id == 1 else "network_connection",
            "computer": event.computer,
            "record_id": event.record_id,
            "process_guid": event.process_guid,
            "process_id": event.process_id,
            "image": image,
            "command_line": command_line,
            "parent_image": parent_image,
            "destination_ip": event.destination_ip,
            "destination_port": event.destination_port,
            "protocol": event.protocol,
            "correlated_process_creation": _iso(creation.timestamp) if creation else None,
            "correlation_key": "computer+process_guid" if creation else None,
        }
        matches = []
        if event.event_id == 1:
            if _basename(image) in POWERSHELL and ENCODED_SWITCH.search(command_line):
                matches.append("WH001")
            if _basename(parent_image) in OFFICE and _basename(image) in INTERPRETERS:
                matches.append("WH002")
        elif (
            _basename(image) in NETWORK_INTERPRETERS
            and event.destination_port in UNUSUAL_PORTS
            and event.destination_ip not in {"127.0.0.1", "::1"}
        ):
            matches.append("WH003")
        row["rule_ids"] = matches
        timeline.append(row)
        for rule_id in matches:
            detections.append({
                "rule_id": rule_id,
                **RULES[rule_id],
                "timeline_sequence": sequence,
                "timestamp": row["timestamp"],
                "computer": event.computer,
                "process_guid": event.process_guid,
                "evidence": {
                    "image": image,
                    "command_line": command_line,
                    "parent_image": parent_image,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "correlated_process_creation": row["correlated_process_creation"],
                },
            })
    counts = Counter(item["rule_id"] for item in detections)
    return {
        "schema_version": 1,
        "evaluation": "Python reference subset; not a Sigma backend",
        "summary": {
            "event_count": len(events),
            "process_creations": sum(event.event_id == 1 for event in events),
            "network_connections": sum(event.event_id == 3 for event in events),
            "correlated_connections": sum(row["correlation_key"] is not None for row in timeline),
            "detection_count": len(detections),
            "detections_by_rule": {rule_id: counts[rule_id] for rule_id in RULES},
        },
        "detections": detections,
        "timeline": timeline,
    }
