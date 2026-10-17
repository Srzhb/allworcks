"""Разбор учебных событий: ошибки входа и индикаторы PowerShell."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import PurePosixPath
import re
from typing import Iterable, TextIO


SOURCES = {"windows_security", "linux_auth", "sysmon"}
EVENT_TYPES = {"authentication_failed", "authentication_success", "process_start"}


class EventError(ValueError):
    """Invalid normalized event or input file."""


def utc_string(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    event_key: str
    timestamp: datetime
    host: str
    account: str
    source: str
    event_type: str
    source_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None

    @classmethod
    def from_dict(cls, value: object) -> "Event":
        if not isinstance(value, dict):
            raise EventError("each event must be a JSON object")
        required = ("event_key", "timestamp", "host", "account", "source", "event_type")
        for name in required:
            if not isinstance(value.get(name), str) or not value[name].strip():
                raise EventError(f"{name} must be a non-empty string")
        try:
            timestamp = datetime.fromisoformat(value["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise EventError("timestamp must be ISO 8601 with a timezone") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise EventError("timestamp must include a timezone")
        if value["source"] not in SOURCES:
            raise EventError(f"source must be one of {sorted(SOURCES)}")
        if value["event_type"] not in EVENT_TYPES:
            raise EventError(f"event_type must be one of {sorted(EVENT_TYPES)}")
        source_ip = value.get("source_ip")
        if source_ip is not None:
            if not isinstance(source_ip, str):
                raise EventError("source_ip must be a valid IP address string")
            try:
                source_ip = str(ipaddress.ip_address(source_ip))
            except (ValueError, TypeError) as exc:
                raise EventError("source_ip must be a valid IP address") from exc
        for name in ("process_name", "command_line"):
            if value.get(name) is not None and not isinstance(value[name], str):
                raise EventError(f"{name} must be a string")
        if value["event_type"] == "process_start":
            if not value.get("process_name") or not value.get("command_line"):
                raise EventError("process_start needs process_name and command_line")
        return cls(
            event_key=value["event_key"], timestamp=timestamp.astimezone(timezone.utc),
            host=value["host"], account=value["account"], source=value["source"],
            event_type=value["event_type"], source_ip=source_ip,
            process_name=value.get("process_name"), command_line=value.get("command_line"),
        )


def load_events(stream: TextIO) -> list[Event]:
    events: list[Event] = []
    keys: set[str] = set()
    for line_number, line in enumerate(stream, 1):
        if not line.strip():
            continue
        try:
            event = Event.from_dict(json.loads(line))
            if event.event_key in keys:
                raise EventError(f"duplicate event_key {event.event_key!r}")
        except (json.JSONDecodeError, EventError) as exc:
            raise EventError(f"line {line_number}: {exc}") from exc
        keys.add(event.event_key)
        events.append(event)
    return events


@dataclass(frozen=True)
class AnalysisConfig:
    failure_threshold: int = 5
    window_seconds: int = 300
    allowed_source_ips: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if type(self.failure_threshold) is not int or self.failure_threshold < 2:
            raise ValueError("failure_threshold must be an integer >= 2")
        if type(self.window_seconds) is not int or self.window_seconds < 1:
            raise ValueError("window_seconds must be an integer >= 1")
        object.__setattr__(self, "allowed_source_ips", frozenset(
            str(ipaddress.ip_address(address)) for address in self.allowed_source_ips
        ))


def _alert(kind: str, event: Event, evidence: list[Event], severity: str, explanation: str) -> dict:
    identity = "|".join([kind, event.host, event.account, *(item.event_key for item in evidence)])
    return {
        "alert_id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "rule": kind,
        "severity": severity,
        "timestamp": utc_string(event.timestamp),
        "host": event.host,
        "account": event.account,
        "source_ips": sorted({item.source_ip for item in evidence if item.source_ip}),
        "evidence": [{"event_key": item.event_key, "timestamp": utc_string(item.timestamp)} for item in evidence],
        "explanation": explanation,
        "disposition": "requires_review",
    }


_ENCODED = re.compile(r"(?:^|\s)-(?:encodedcommand|enc)(?:\s|:|$)", re.IGNORECASE)
_EXECUTION = re.compile(r"\b(?:invoke-expression|iex)\b", re.IGNORECASE)
_NETWORK = re.compile(r"\b(?:downloadstring|downloadfile|invoke-webrequest|iwr)\b", re.IGNORECASE)


def analyze(events: Iterable[Event], config: AnalysisConfig | None = None) -> dict:
    """Replay in event-time order; keep host/account spellings exactly as supplied."""
    config = config or AnalysisConfig()
    # В файле строки могут идти не по порядку, поэтому сначала сортируем по времени.
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_key))
    keys = [event.event_key for event in ordered]
    if len(keys) != len(set(keys)):
        raise EventError("duplicate event_key in event sequence")
    windows: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    active: set[tuple[str, str]] = set()
    alerts: list[dict] = []
    ignored_failures = 0
    for event in ordered:
        if event.event_type == "authentication_failed":
            # Исключение по IP относится только к ошибкам входа.
            if event.source_ip in config.allowed_source_ips:
                ignored_failures += 1
                continue
            group = (event.host, event.account)
            window = windows[group]
            cutoff = event.timestamp - timedelta(seconds=config.window_seconds)
            # Убираем старые ошибки, чтобы считать только события внутри окна.
            while window and window[0].timestamp < cutoff:
                window.popleft()
            if len(window) < config.failure_threshold:
                active.discard(group)
            window.append(event)
            if len(window) >= config.failure_threshold and group not in active:
                alerts.append(_alert(
                    "repeated_authentication_failures", event, list(window), "medium",
                    f"{len(window)} failed authentications for this host/account within an inclusive "
                    f"{config.window_seconds}s window (threshold {config.failure_threshold}). "
                    "Possible password guessing or stale credentials; validate the account and source IPs.",
                ))
                active.add(group)
        elif event.event_type == "process_start":
            # Здесь проверяется текст команды. Сама команда никогда не запускается.
            process = PurePosixPath((event.process_name or "").replace("\\", "/")).name.lower()
            if process not in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
                continue
            command = event.command_line or ""
            indicators: list[str] = []
            if _ENCODED.search(command):
                indicators.append("encoded_command_flag")
            if _EXECUTION.search(command) and _NETWORK.search(command):
                indicators.append("network_download_and_expression_execution")
            if indicators:
                alert = _alert(
                    "powershell_review", event, [event],
                    "high" if "network_download_and_expression_execution" in indicators else "medium",
                    "PowerShell contains review indicators: " + ", ".join(indicators)
                    + ". Text matching alone does not establish malicious activity; check approved automation, "
                    "parent process and script provenance. The command was neither decoded nor executed.",
                )
                alert["indicators"] = indicators
                alerts.append(alert)
    alerts.sort(key=lambda alert: (alert["timestamp"], alert["rule"], alert["alert_id"]))
    return {
        "schema_version": 1,
        "mode": "offline_educational_reconstruction",
        "config": {
            "failure_threshold": config.failure_threshold,
            "window_seconds": config.window_seconds,
            "allowed_source_ips": sorted(config.allowed_source_ips),
            "group_by": ["host", "account"],
            "window_boundary": "inclusive",
        },
        "summary": {
            "events_read": len(ordered),
            "sources": dict(sorted(Counter(event.source for event in ordered).items())),
            "failed_authentication_events": sum(event.event_type == "authentication_failed" for event in ordered),
            "allowlisted_failure_events": ignored_failures,
            "alert_count": len(alerts),
        },
        "alerts": alerts,
    }
