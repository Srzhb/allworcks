"""Bounded classic-PCAP/Ethernet/IPv4 reader; deliberately no TCP reassembly."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


class CaptureError(ValueError):
    """Invalid or unsupported capture container."""


class PacketError(ValueError):
    """A malformed packet or an unsupported packet feature."""


MAX_PACKET_BYTES = 16 * 1024 * 1024
MAX_PACKETS = 1_000_000


def dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a bounded DNS name, including compressed names and loop detection."""
    labels: list[str] = []
    visited: set[int] = set()
    end = None
    wire_length = 1
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise PacketError("DNS name is truncated or contains a pointer loop")
        visited.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise PacketError("Truncated DNS compression pointer")
            if end is None:
                end = offset + 2
            offset = ((size & 0x3F) << 8) | data[offset + 1]
            continue
        if size & 0xC0:
            raise PacketError("Unsupported DNS label encoding")
        offset += 1
        if not size:
            return ".".join(labels).lower(), end if end is not None else offset
        if offset + size > len(data):
            raise PacketError("Truncated DNS label")
        wire_length += size + 1
        if wire_length > 255:
            raise PacketError("DNS name exceeds 255 octets")
        # Escape non-printable bytes so JSON output remains safe and unambiguous.
        labels.append("".join(chr(b) if 33 <= b <= 126 and b not in (46, 92)
                              else f"\\{b:03d}" for b in data[offset:offset + size]))
        offset += size
    raise PacketError("DNS name exceeds traversal limit")


def parse_dns(data: bytes) -> dict:
    if len(data) < 12:
        raise PacketError("Truncated DNS header")
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
    if qdcount + ancount + nscount + arcount > 256:
        raise PacketError("DNS record count exceeds laboratory limit (256)")
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = dns_name(data, offset)
        if offset + 4 > len(data):
            raise PacketError("Truncated DNS question")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    answers = []
    for index in range(ancount + nscount + arcount):
        name, offset = dns_name(data, offset)
        if offset + 10 > len(data):
            raise PacketError("Truncated DNS resource record")
        rtype, rclass, ttl, length = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        end = offset + length
        if end > len(data):
            raise PacketError("Truncated DNS resource data")
        value = None
        if rtype == 1 and length == 4:
            value = str(ipaddress.IPv4Address(data[offset:end]))
        elif rtype == 28 and length == 16:
            value = str(ipaddress.IPv6Address(data[offset:end]))
        elif rtype in (2, 5, 12):
            value, name_end = dns_name(data, offset)
            if name_end != end:
                raise PacketError("DNS name does not match resource-data length")
        if index < ancount:
            answers.append({"name": name, "type": rtype, "class": rclass,
                            "ttl": ttl, "value": value})
        offset = end
    return {"id": transaction_id, "response": bool(flags & 0x8000),
            "rcode": flags & 15, "questions": questions, "answers": answers}


def parse_http(data: bytes) -> dict | None:
    methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
    if not data.startswith(methods):
        return None
    header_end = data.find(b"\r\n\r\n")
    if header_end < 0:
        raise PacketError("HTTP headers span packets or are incomplete; TCP reassembly is unsupported")
    if header_end > 65536:
        raise PacketError("HTTP headers exceed laboratory limit (64 KiB)")
    lines = data[:header_end].decode("iso-8859-1").split("\r\n")
    request = lines[0].split(" ")
    if len(request) != 3 or request[2] not in ("HTTP/1.0", "HTTP/1.1"):
        raise PacketError("Malformed HTTP/1 request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise PacketError("Malformed HTTP header")
        key, value = line.split(":", 1)
        key = key.strip().lower()
        headers[key] = headers.get(key, "") + (", " if key in headers else "") + value.strip()
    return {"method": request[0], "target": request[1], "version": request[2],
            "host": headers.get("host"), "user_agent": headers.get("user-agent")}


def parse_frame(data: bytes) -> dict:
    if len(data) < 14:
        raise PacketError("Truncated Ethernet header")
    ether_type = struct.unpack_from("!H", data, 12)[0]
    offset = 14
    if ether_type == 0x8100:
        if len(data) < 18:
            raise PacketError("Truncated VLAN header")
        ether_type = struct.unpack_from("!H", data, 16)[0]
        offset = 18
    if ether_type != 0x0800:
        return {"network": "unsupported", "ether_type": ether_type}
    ip = data[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise PacketError("Truncated or invalid IPv4 header")
    header_length = (ip[0] & 15) * 4
    total_length = struct.unpack_from("!H", ip, 2)[0]
    if header_length < 20 or total_length < header_length or len(ip) < total_length:
        raise PacketError("Invalid or truncated IPv4 lengths")
    packet = {"network": "IPv4", "src_ip": str(ipaddress.IPv4Address(ip[12:16])),
              "dest_ip": str(ipaddress.IPv4Address(ip[16:20])), "ip_protocol": ip[9]}
    if struct.unpack_from("!H", ip, 6)[0] & 0x3FFF:
        packet["warning"] = "IPv4 fragmentation is unsupported; transport not analyzed"
        return packet
    payload = ip[header_length:total_length]
    if ip[9] == 6:
        if len(payload) < 20:
            raise PacketError("Truncated TCP header")
        source_port, dest_port = struct.unpack_from("!HH", payload)
        tcp_length = (payload[12] >> 4) * 4
        if tcp_length < 20 or tcp_length > len(payload):
            raise PacketError("Invalid TCP data offset")
        packet.update({"protocol": "TCP", "src_port": source_port, "dest_port": dest_port,
                       "tcp_flags": payload[13], "payload_bytes": len(payload) - tcp_length})
        try:
            http = parse_http(payload[tcp_length:])
            if http:
                packet["http"] = http
        except PacketError as error:
            packet["warning"] = str(error)
    elif ip[9] == 17:
        if len(payload) < 8:
            raise PacketError("Truncated UDP header")
        source_port, dest_port, length, _ = struct.unpack_from("!HHHH", payload)
        if length < 8 or length > len(payload):
            raise PacketError("Invalid UDP length")
        packet.update({"protocol": "UDP", "src_port": source_port, "dest_port": dest_port,
                       "payload_bytes": length - 8})
        if 53 in (source_port, dest_port):
            try:
                packet["dns"] = parse_dns(payload[8:length])
            except PacketError as error:
                packet["warning"] = str(error)
    return packet


def read_pcap(path: str | Path) -> dict:
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
               b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    packets = []
    warnings = []
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in formats:
            raise CaptureError("Expected classic PCAP; PCAPNG is unsupported")
        byte_order, resolution = formats[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(byte_order + "HHiIII", header[4:])
        if (major, minor) != (2, 4) or linktype != 1:
            raise CaptureError("Only PCAP v2.4 with Ethernet (DLT_EN10MB=1) is supported")
        if not 0 < snaplen <= MAX_PACKET_BYTES:
            raise CaptureError("Invalid or excessive PCAP snaplen")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise CaptureError("Truncated PCAP record header")
            seconds, fraction, captured, original = struct.unpack(byte_order + "4I", record)
            if captured > snaplen or captured > MAX_PACKET_BYTES or captured > original:
                raise CaptureError("Invalid or excessive PCAP packet length")
            if fraction >= resolution:
                raise CaptureError("Invalid PCAP timestamp fraction")
            if len(packets) >= MAX_PACKETS:
                raise CaptureError("Capture exceeds laboratory limit (1,000,000 packets)")
            data = stream.read(captured)
            if len(data) != captured:
                raise CaptureError("Truncated PCAP packet data")
            number = len(packets) + 1
            packet = {"number": number, "timestamp": seconds + fraction / resolution,
                      "captured_bytes": captured, "original_bytes": original}
            if captured < original:
                warnings.append({"packet": number, "message": "Capture packet was truncated by snaplen"})
            try:
                packet.update(parse_frame(data))
            except PacketError as error:
                packet["warning"] = str(error)
            if "warning" in packet:
                warnings.append({"packet": number, "message": packet["warning"]})
            packets.append(packet)
    return {"format": "classic-pcap", "link_type": "Ethernet", "snaplen": snaplen,
            "timestamp_resolution": resolution, "packets": packets, "warnings": warnings}
