from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from network_lab.analysis import analyze, correlate_eve, find_scans
from network_lab.fixture import (BASE_TIME, checksum, demo_packets, dns_message,
                                 tcp_packet, udp_packet, write_demo)
from network_lab.pcap import CaptureError, PacketError, dns_name, parse_dns, parse_frame, parse_http, read_pcap


class NetworkLabTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.pcap = self.directory / "traffic.pcap"
        self.eve = self.directory / "expected.jsonl"
        write_demo(self.pcap, self.eve)

    def test_end_to_end_report_has_traceable_packet_evidence(self):
        report = analyze(self.pcap, eve=self.eve)
        self.assertEqual(report["summary"], {"packets": 21, "dns_messages": 4, "http_requests": 2,
                                             "scan_candidates": 1, "eve_alerts": 2})
        self.assertEqual(report["capture"]["warnings"], [])
        self.assertEqual(report["dns"][1]["answers"][0]["value"], "203.0.113.20")
        self.assertEqual(report["dns"][3]["rcode"], 3)
        scan = next(item for item in report["findings"] if item["kind"] == "syn_port_scan_candidate")
        self.assertEqual(scan["ports"], list(range(20, 30)))
        self.assertEqual(scan["packet_numbers"], list(range(12, 22)))
        self.assertEqual(report["packet_alert_verification"]["statuses"], {"verified_packet_evidence": 2})
        self.assertTrue(all(item["source"] == "synthetic_expected_fixture" for item in report["packet_alert_verification"]["alerts"]))
        self.assertTrue(any(item["value"] == "http://updates.example.test/download/test-payload.exe"
                            for item in report["ioc_candidates"]))

    def test_fixture_is_reproducible(self):
        other = self.directory / "second.pcap"
        other_eve = self.directory / "second.jsonl"
        write_demo(other, other_eve)
        self.assertEqual(self.pcap.read_bytes(), other.read_bytes())
        self.assertEqual(self.eve.read_bytes(), other_eve.read_bytes())

    def test_fixture_ip_and_transport_checksums_are_valid(self):
        # RFC 1071 example; an independent known value checks the checksum helper.
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        for frame in demo_packets():
            ip = frame[14:]
            self.assertEqual(checksum(ip[:20]), 0)
            transport = ip[20:]
            # Independently take endpoints directly from the encoded IP header.
            pseudo = ip[12:20] + struct.pack("!BBH", 0, ip[9], len(transport))
            self.assertEqual(checksum(pseudo + transport), 0)

    def test_dns_pointer_decode_and_loop_rejection(self):
        data = dns_message("updates.example.test", 1, answer="203.0.113.20")
        result = parse_dns(data)
        self.assertEqual(result["questions"][0]["name"], "updates.example.test")
        self.assertEqual(result["answers"][0]["name"], "updates.example.test")
        with self.assertRaises(PacketError):
            dns_name(b"\xc0\x00", 0)
        with self.assertRaises(PacketError):
            dns_name(b"\xc0\xff", 0)

    def test_dns_rejects_truncated_records_and_excess_counts(self):
        with self.assertRaises(PacketError):
            parse_dns(dns_message("x.test", 1, answer="203.0.113.1")[:-1])
        with self.assertRaises(PacketError):
            parse_dns(struct.pack("!6H", 1, 0, 257, 0, 0, 0))

    def test_fragment_is_explicitly_not_treated_as_transport(self):
        frame = bytearray(demo_packets()[0])
        struct.pack_into("!H", frame, 14 + 6, 0x2000)
        packet = parse_frame(bytes(frame))
        self.assertIn("fragmentation", packet["warning"])
        self.assertNotIn("dns", packet)

    def test_incomplete_http_does_not_claim_request_reassembly(self):
        with self.assertRaisesRegex(PacketError, "reassembly"):
            parse_http(b"GET / HTTP/1.1\r\nHost: example.test\r\n")
        packet = parse_frame(tcp_packet("192.0.2.1", "203.0.113.1", 2000, 80,
                                       flags=0x18, data=b"GET / HTTP/1.1\r\nHost: ex"))
        self.assertNotIn("http", packet)
        self.assertIn("reassembly", packet["warning"])

    def test_retransmissions_and_syn_ack_do_not_count_as_scan_ports(self):
        packets = [{"number": index, "timestamp": float(index), "protocol": "TCP",
                    "tcp_flags": 2, "src_ip": "192.0.2.1", "dest_ip": "203.0.113.1",
                    "dest_port": 80} for index in range(10)]
        packets.append({**packets[-1], "number": 10, "tcp_flags": 0x12, "dest_port": 81})
        self.assertEqual(find_scans(packets, 2, 20), [])

    def test_scan_window_expires_old_ports_and_sorts_timestamps(self):
        packets = [{"number": index, "timestamp": float(index) * 11, "protocol": "TCP",
                    "tcp_flags": 2, "src_ip": "192.0.2.1", "dest_ip": "203.0.113.1",
                    "dest_port": index} for index in range(10)]
        self.assertEqual(find_scans(packets[::-1], 2, 10), [])
        self.assertEqual(len(find_scans(packets[::-1], 2, 11)), 1)

    def test_eve_mismatch_and_missing_references_are_not_verified(self):
        original = json.loads(self.eve.read_text().splitlines()[0])
        variants = [
            {**original, "dest_port": 999},
            {**original, "pcap_cnt": 999},
            {key: value for key, value in original.items() if key != "pcap_cnt"},
            {**original, "timestamp": "2020-01-01T00:00:00+00:00"},
            {**original, "alert": {"signature_id": 1000002}},
            {**original, "alert": {"signature_id": 999999}},
            {**original, "pcap_cnt": True},
        ]
        self.eve.write_text("\n".join(json.dumps(item) for item in variants), encoding="utf-8")
        results = correlate_eve(self.eve, read_pcap(self.pcap)["packets"])
        self.assertEqual([item["status"] for item in results], ["tuple_mismatch", "packet_not_found",
                         "no_packet_reference", "timestamp_mismatch", "payload_mismatch",
                         "tuple_verified_rule_unsupported", "no_packet_reference"])

    def test_eve_rejects_non_objects_and_invalid_json(self):
        for invalid in ("[]\n", "not json\n", '{"event_type":"alert","alert":null}\n'):
            self.eve.write_text(invalid, encoding="utf-8")
            with self.assertRaises(CaptureError):
                correlate_eve(self.eve, [])

    def test_dns_query_from_port_53_to_ephemeral_port_does_not_match_rule(self):
        frame = udp_packet("192.0.2.10", "198.51.100.53", 53, 53000,
                           dns_message("beacon.example.test", 1))
        self.pcap.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                              + struct.pack("<4I", BASE_TIME, 0, len(frame), len(frame)) + frame)
        event = json.loads(self.eve.read_text().splitlines()[0])
        event.update({"pcap_cnt": 1, "src_port": 53, "dest_port": 53000,
                      "timestamp": "2023-11-14T22:13:20+00:00"})
        self.eve.write_text(json.dumps(event) + "\n", encoding="utf-8")
        report = analyze(self.pcap, eve=self.eve)
        self.assertFalse(any(item["kind"] == "demo_dns_rule_match" for item in report["findings"]))
        self.assertEqual(report["packet_alert_verification"]["alerts"][0]["status"], "payload_mismatch")

    def test_cli_invalid_utf8_eve_preserves_existing_report(self):
        self.eve.write_bytes(b"\xff\n")
        output = self.directory / "report.json"
        output.write_text("previous report", encoding="utf-8")
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(self.pcap),
                                 "--eve", str(self.eve), "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(output.read_text(), "previous report")

    def test_capture_rejects_pcapng_truncation_and_oversized_record(self):
        content = self.pcap.read_bytes()
        invalid_inputs = [b"\x0a\x0d\x0d\x0a" + b"\0" * 20, content[:-1],
                          content[:24] + struct.pack("<4I", BASE_TIME, 0, 999999999, 999999999)]
        for invalid in invalid_inputs:
            self.pcap.write_bytes(invalid)
            with self.assertRaises(CaptureError):
                read_pcap(self.pcap)

    def test_big_endian_and_nanosecond_capture_headers(self):
        packet = demo_packets()[0]
        for byte_order, magic, fraction, resolution in ((">", 0xA1B2C3D4, 123456, 1_000_000),
                                                       ("<", 0xA1B23C4D, 123456000, 1_000_000_000)):
            self.pcap.write_bytes(struct.pack(byte_order + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
                                  + struct.pack(byte_order + "4I", BASE_TIME, fraction, len(packet), len(packet)) + packet)
            capture = read_pcap(self.pcap)
            self.assertEqual(capture["timestamp_resolution"], resolution)
            self.assertAlmostEqual(capture["packets"][0]["timestamp"], BASE_TIME + .123456)

    def test_cli_writes_json_and_rejects_overwriting_input(self):
        output = self.directory / "nested" / "report.json"
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(self.pcap),
                                 "--output", str(output), "--eve", str(self.eve)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())["summary"]["packets"], 21)
        original = self.pcap.read_bytes()
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(self.pcap),
                                 "--output", str(self.pcap)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.pcap.read_bytes(), original)

    def test_cli_fails_cleanly_on_malformed_capture(self):
        self.pcap.write_bytes(b"bad capture")
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(self.pcap),
                                 "--output", str(self.directory / "out.json")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("classic PCAP", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_rejects_output_hardlink_to_pcap_and_preserves_source(self):
        output = self.directory / "pcap-hardlink.json"
        output.hardlink_to(self.pcap)
        original = self.pcap.read_bytes()
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(self.pcap),
                                 "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--output must differ", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.pcap.read_bytes(), original)
        self.assertEqual(output.read_bytes(), original)

    def test_cli_rejects_output_hardlink_to_eve_and_preserves_source(self):
        output = self.directory / "eve-hardlink.json"
        output.hardlink_to(self.eve)
        original = self.eve.read_bytes()
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(self.pcap),
                                 "--eve", str(self.eve), "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--output must differ", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.eve.read_bytes(), original)
        self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
