"""Создание небольшого PCAP для примера. Пакеты никуда не отправляются."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import struct


BASE_TIME = 1_700_000_000
# Адреса из диапазонов для документации, а домены ниже используют .test.
CLIENT = "192.0.2.10"
SERVER = "203.0.113.20"
DNS_SERVER = "198.51.100.53"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_bytes(value: str) -> bytes:
    return ipaddress.IPv4Address(value).packed


def ethernet_ipv4(source: str, destination: str, protocol: int, payload: bytes, identifier: int = 1) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), identifier, 0x4000,
                         64, protocol, 0, ip_bytes(source), ip_bytes(destination))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + payload


def pseudo_header(source: str, destination: str, protocol: int, length: int) -> bytes:
    return ip_bytes(source) + ip_bytes(destination) + struct.pack("!BBH", 0, protocol, length)


def udp_packet(source: str, destination: str, source_port: int, dest_port: int, data: bytes) -> bytes:
    length = 8 + len(data)
    header = struct.pack("!HHHH", source_port, dest_port, length, 0)
    value = checksum(pseudo_header(source, destination, 17, length) + header + data) or 0xFFFF
    return ethernet_ipv4(source, destination, 17, header[:6] + struct.pack("!H", value) + data)


def tcp_packet(source: str, destination: str, source_port: int, dest_port: int,
               *, sequence: int = 1000, ack: int = 0, flags: int = 2, data: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", source_port, dest_port, sequence, ack, 0x50, flags, 64240, 0, 0)
    value = checksum(pseudo_header(source, destination, 6, len(header) + len(data)) + header + data)
    header = header[:16] + struct.pack("!H", value) + header[18:]
    return ethernet_ipv4(source, destination, 6, header + data)


def dns_message(name: str, transaction_id: int, *, answer: str | None = None, nxdomain: bool = False) -> bytes:
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    flags = 0x8183 if nxdomain else (0x8180 if answer else 0x0100)
    data = struct.pack("!6H", transaction_id, flags, 1, int(answer is not None), 0, 0)
    data += encoded + struct.pack("!HH", 1, 1)
    if answer:
        data += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_bytes(answer)
    return data


def demo_packets() -> list[bytes]:
    packets = [
        udp_packet(CLIENT, DNS_SERVER, 53000, 53, dns_message("updates.example.test", 0x1001)),
        udp_packet(DNS_SERVER, CLIENT, 53, 53000, dns_message("updates.example.test", 0x1001, answer=SERVER)),
        udp_packet(CLIENT, DNS_SERVER, 53001, 53, dns_message("beacon.example.test", 0x1002)),
        udp_packet(DNS_SERVER, CLIENT, 53, 53001, dns_message("beacon.example.test", 0x1002, nxdomain=True)),
        tcp_packet(CLIENT, SERVER, 42000, 80),
        tcp_packet(SERVER, CLIENT, 80, 42000, sequence=9000, ack=1001, flags=0x12),
        tcp_packet(CLIENT, SERVER, 42000, 80, sequence=1001, ack=9001, flags=0x10),
    ]
    request1 = b"GET /health HTTP/1.1\r\nHost: updates.example.test\r\nUser-Agent: network-lab/1.0\r\n\r\n"
    request2 = b"GET /download/test-payload.exe HTTP/1.1\r\nHost: updates.example.test\r\nUser-Agent: network-lab/1.0\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    packets.extend([
        tcp_packet(CLIENT, SERVER, 42000, 80, sequence=1001, ack=9001, flags=0x18, data=request1),
        tcp_packet(SERVER, CLIENT, 80, 42000, sequence=9001, ack=1001 + len(request1), flags=0x18, data=response),
        tcp_packet(CLIENT, SERVER, 42000, 80, sequence=1001 + len(request1), ack=9001 + len(response), flags=0x18, data=request2),
        tcp_packet(SERVER, CLIENT, 80, 42000, sequence=9001 + len(response), ack=1001 + len(request1) + len(request2), flags=0x18, data=response),
    ])
    packets.extend(tcp_packet("198.51.100.42", "192.0.2.20", 50000 + port, port,
                              sequence=2000 + port) for port in range(20, 30))
    return packets


def write_demo(output: Path, eve_output: Path | None = None) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(demo_packets()):
            microseconds = index * 100_000
            stream.write(struct.pack("<4I", BASE_TIME + microseconds // 1_000_000,
                                     microseconds % 1_000_000, len(packet), len(packet)))
            stream.write(packet)
    if eve_output:
        eve_output.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for number, sid, source_port, destination, destination_port, protocol, message in (
            (3, 1000001, 53001, DNS_SERVER, 53, "UDP", "LAB synthetic beacon domain"),
            (10, 1000002, 42000, SERVER, 80, "TCP", "LAB executable URI suffix"),
        ):
            timestamp = datetime.fromtimestamp(BASE_TIME + (number - 1) * .1, timezone.utc).isoformat(timespec="microseconds")
            rows.append({"timestamp": timestamp, "event_type": "alert", "pcap_cnt": number,
                         "src_ip": CLIENT, "dest_ip": destination, "src_port": source_port,
                         "dest_port": destination_port, "proto": protocol, "lab_fixture": True,
                         "alert": {"signature_id": sid, "signature": message, "severity": 3}})
        eve_output.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Write deterministic synthetic packets, without sending traffic")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--eve-output", type=Path, help="Synthetic expected alerts; never presented as Suricata output")
    arguments = parser.parse_args()
    if arguments.eve_output and arguments.eve_output.resolve() == arguments.output.resolve():
        parser.error("PCAP and EVE output paths must differ")
    write_demo(arguments.output, arguments.eve_output)
    print(f"Wrote {len(demo_packets())} synthetic packets: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
