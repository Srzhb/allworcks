"""Сводка DNS/HTTP, поиск серии SYN и проверка оповещений по пакетам."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime
import json
from pathlib import Path

from pcap import CaptureError, read_pcap


DEMO_DOMAIN = "beacon.example.test"


def demo_dns_match(packet: dict) -> bool:
    dns = packet.get("dns", {})
    return (packet.get("protocol") == "UDP" and packet.get("dest_port") == 53
            and not dns.get("response", True) and any(
                question["name"] == DEMO_DOMAIN for question in dns.get("questions", [])))


def find_scans(packets: list[dict], threshold: int, window: float) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for packet in packets:
        # Берём SYN без ACK. Повторы на один порт не увеличивают число портов.
        if packet.get("protocol") == "TCP" and packet.get("tcp_flags", 0) & 0x12 == 0x02:
            groups[(packet["src_ip"], packet["dest_ip"])].append(packet)
    findings = []
    for (source, destination), events in sorted(groups.items()):
        active: deque[dict] = deque()
        counts: Counter[int] = Counter()
        best = None
        for packet in sorted(events, key=lambda item: item["timestamp"]):
            while active and packet["timestamp"] - active[0]["timestamp"] > window:
                old = active.popleft()
                counts[old["dest_port"]] -= 1
                if counts[old["dest_port"]] == 0:
                    del counts[old["dest_port"]]
            active.append(packet)
            counts[packet["dest_port"]] += 1
            if len(counts) >= threshold and (best is None or len(counts) > len(best["ports"])):
                best = {"kind": "syn_port_scan_candidate", "src_ip": source, "dest_ip": destination,
                        "ports": sorted(counts), "window_seconds": window,
                        "start": active[0]["timestamp"], "end": packet["timestamp"],
                        "packet_numbers": [item["number"] for item in active],
                        "interpretation": "Heuristic candidate; successful connections and intent are unknown"}
        if best:
            findings.append(best)
    return findings


def correlate_eve(path: str | Path, packets: list[dict]) -> list[dict]:
    """Correlate offline pcap_cnt plus tuple/time; never guess a packet number."""
    results = []
    by_number = {packet["number"]: packet for packet in packets}
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            if len(line) > 1024 * 1024:
                raise CaptureError(f"EVE line {line_number} exceeds 1 MiB")
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise CaptureError(f"Invalid EVE JSON at line {line_number}: {error.msg}") from error
            if not isinstance(event, dict):
                raise CaptureError(f"EVE line {line_number} must contain an object")
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert", {})
            if not isinstance(alert, dict):
                raise CaptureError(f"EVE alert at line {line_number} must contain an object")
            result = {"line": line_number, "signature_id": alert.get("signature_id"),
                      "signature": alert.get("signature"), "packet_number": event.get("pcap_cnt"),
                      "source": "synthetic_expected_fixture" if event.get("lab_fixture") is True
                      else "supplied_eve_log", "status": "no_packet_reference"}
            number = event.get("pcap_cnt")
            if not isinstance(number, int) or isinstance(number, bool):
                results.append(result)
                continue
            packet = by_number.get(number)
            if packet is None:
                result["status"] = "packet_not_found"
                results.append(result)
                continue
            tuple_keys = ("src_ip", "dest_ip", "src_port", "dest_port")
            if any(key not in event for key in tuple_keys) or "proto" not in event:
                result["status"] = "insufficient_tuple_fields"
            elif (any(event[key] != packet.get(key) for key in tuple_keys)
                  or str(event["proto"]).upper() != packet.get("protocol")):
                result["status"] = "tuple_mismatch"
            else:
                try:
                    stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                    if stamp.tzinfo is None:
                        raise ValueError("Timestamp needs a timezone")
                    if abs(stamp.timestamp() - packet["timestamp"]) > 0.00001:
                        result["status"] = "timestamp_mismatch"
                        results.append(result)
                        continue
                except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
                    result["status"] = "invalid_or_missing_timestamp"
                    results.append(result)
                    continue
                sid = alert.get("signature_id")
                match = None
                if sid == 1000001:
                    match = demo_dns_match(packet)
                elif sid == 1000002:
                    match = packet.get("http", {}).get("target", "").lower().endswith(".exe")
                result["rule_payload_match"] = match
                result["status"] = ("verified_packet_evidence" if match else "payload_mismatch") if match is not None else "tuple_verified_rule_unsupported"
            results.append(result)
    return results


def analyze(path: str | Path, *, eve: str | Path | None = None,
            scan_threshold: int = 8, scan_window: float = 10.0) -> dict:
    capture = read_pcap(path)
    packets = capture["packets"]
    dns_events = []
    http_events = []
    indicators: dict[tuple[str, str], set[int]] = defaultdict(set)
    findings = find_scans(packets, scan_threshold, scan_window)
    for packet in packets:
        number = packet["number"]
        common = {key: packet.get(key) for key in ("src_ip", "dest_ip", "src_port", "dest_port")}
        if "dns" in packet:
            dns = packet["dns"]
            dns_events.append({"packet": number, **common, **dns})
            for question in dns["questions"]:
                if question["name"]:
                    indicators[("domain", question["name"])].add(number)
                if demo_dns_match(packet) and question["name"] == DEMO_DOMAIN:
                    findings.append({"kind": "demo_dns_rule_match", "packet": number,
                                     "domain": DEMO_DOMAIN, "interpretation": "Synthetic demonstration pattern; not a threat verdict"})
            for answer in dns["answers"]:
                if answer["type"] in (1, 28) and answer["value"]:
                    indicators[("ip", answer["value"])].add(number)
        if "http" in packet:
            request = packet["http"]
            http_events.append({"packet": number, **common, **request})
            host = request.get("host")
            if host:
                indicators[("http_host", host)].add(number)
                target = request["target"]
                url = target if target.startswith(("http://", "https://")) else f"http://{host}{target}"
                indicators[("url", url)].add(number)
            if request["target"].lower().endswith(".exe"):
                findings.append({"kind": "demo_executable_uri_match", "packet": number,
                                 "target": request["target"],
                                 "interpretation": "Executable suffix alone does not establish malicious content"})
    for finding in findings:
        if finding["kind"] == "syn_port_scan_candidate":
            indicators[("ip", finding["src_ip"])].update(finding["packet_numbers"])
    alerts = correlate_eve(eve, packets) if eve else []
    statuses = Counter(alert["status"] for alert in alerts)
    return {
        "schema_version": 1,
        "scope": "Offline educational observations; candidate indicators require investigation",
        "capture": {key: value for key, value in capture.items() if key != "packets"},
        "summary": {"packets": len(packets), "dns_messages": len(dns_events),
                    "http_requests": len(http_events), "scan_candidates": sum(
                        item["kind"] == "syn_port_scan_candidate" for item in findings),
                    "eve_alerts": len(alerts)},
        "parameters": {"scan_threshold": scan_threshold, "scan_window_seconds": scan_window},
        "dns": dns_events, "http": http_events, "findings": findings,
        "ioc_candidates": [{"type": kind, "value": value, "packet_numbers": sorted(numbers),
                            "classification": "observed_not_adjudicated"}
                           for (kind, value), numbers in sorted(indicators.items())],
        "packet_alert_verification": {"method": "pcap_cnt + 5-tuple + timestamp (10 microseconds) + supported demo payload predicate",
                                      "statuses": dict(sorted(statuses.items())), "alerts": alerts},
        "external_tools": {"executed_by_analyzer": [], "note": "Suricata/Zeek/Wireshark are optional; supplied EVE is evidence input, not proof of tool execution"},
        "limitations": ["Classic PCAP Ethernet/one VLAN/IPv4 only; no PCAPNG or IPv6 transport",
                        "No IP defragmentation, TCP reassembly, TLS decryption or checksum validation",
                        "HTTP/1 request headers must fit in one TCP packet; no bodies/responses/HTTP2",
                        "DNS over UDP port 53 only; bounded DNS records and compression traversal",
                        "Port-scan detection counts distinct destination ports with initial TCP SYN, including failed or unanswered attempts",
                        "Demo rule payload checks do not implement the complete Suricata detection engine"]}
