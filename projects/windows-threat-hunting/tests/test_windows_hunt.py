"""Deterministic contracts for fixtures, correlation, parsing and rule parity."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import csv
from datetime import timezone
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from windows_hunt import InputError, analyze, load_events
from windows_hunt.cli import main
from windows_hunt.ingestion import normalize


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
GUID = "{a1111111-1111-4111-8111-111111111111}"


def process(**overrides):
    data = {
        "timestamp": "2026-01-15T10:00:00Z", "event_id": 1,
        "computer": "LAB-WIN11", "process_guid": GUID, "process_id": 1000,
        "image": PS, "command_line": "powershell.exe -File C:\\Lab\\inventory.ps1",
        "parent_image": r"C:\Windows\explorer.exe",
    }
    data.update(overrides)
    return normalize(data)


def network(**overrides):
    data = {
        "timestamp": "2026-01-15T10:00:01Z", "event_id": 3,
        "computer": "LAB-WIN11", "process_guid": GUID, "process_id": 1000,
        "destination_ip": "203.0.113.20", "destination_port": 4444,
    }
    data.update(overrides)
    return normalize(data)


def rule_ids(events):
    return [item["rule_id"] for item in analyze(events)["detections"]]


class FixtureTests(unittest.TestCase):
    def test_demo_contract_and_benign_controls(self):
        events = load_events(PROJECT / "data/events.jsonl")
        report = analyze(events)
        self.assertEqual(report["summary"], {
            "event_count": 12, "process_creations": 6, "network_connections": 6,
            "correlated_connections": 4, "detection_count": 3,
            "detections_by_rule": {"WH001": 1, "WH002": 1, "WH003": 1},
        })
        expected = json.loads((PROJECT / "data/expected_rules.json").read_text())
        self.assertEqual({row["record_id"]: row["rule_ids"] for row in report["timeline"]}, expected)
        self.assertEqual(report, analyze(list(reversed(events))))
        connection = next(row for row in report["timeline"] if row["record_id"] == "4")
        self.assertEqual(connection["correlated_process_creation"], "2026-01-15T10:01:00.000Z")
        self.assertIn("-EncodedCommand", connection["command_line"])

    def test_exported_xml_namespace_and_guid_enrichment(self):
        events = load_events(PROJECT / "data/sysmon.xml")
        self.assertEqual(len(events), 3)
        report = analyze(events)
        self.assertEqual([item["rule_id"] for item in report["detections"]], ["WH001", "WH003"])
        self.assertEqual(report["timeline"][1]["image"], PS)
        self.assertEqual(report["summary"]["correlated_connections"], 1)


class DetectionTests(unittest.TestCase):
    def test_encoded_switches_and_case(self):
        for switch in ("-e", "-ec", "-enc", "-ENCODEDCOMMAND", "-enc:"):
            with self.subTest(switch=switch):
                self.assertEqual(rule_ids([process(command_line=f"powershell.exe {switch} VwByAGkAdABlAA==")]), ["WH001"])
        for command in (
            "powershell.exe -NoProfile -File inventory.ps1",
            "powershell.exe -enc", "powershell.exe -enc AAAA", "powershell.exe -encoding UTF8",
            "powershell.exe --enc VwByAGkAdABlAA==", "powershell.exe -enc !!!invalid!!!",
            "powershell.exe -enc VwByAGkAdABlAA==.txt",
        ):
            with self.subTest(command=command):
                self.assertEqual(rule_ids([process(command_line=command)]), [])
        self.assertEqual(rule_ids([process(image=r"C:\Lab\fakepowershell.exe", command_line="fakepowershell.exe -enc VwByAGkAdABlAA==")]), [])

    def test_office_requires_interpreter_child_and_office_parent(self):
        self.assertEqual(rule_ids([process(parent_image=WORD)]), ["WH002"])
        self.assertEqual(rule_ids([process(parent_image=WORD, image=r"C:\Program Files\Reader\AcroRd32.exe")]), [])
        self.assertEqual(rule_ids([process(parent_image=r"C:\Windows\explorer.exe")]), [])
        self.assertEqual(rule_ids([process(parent_image=r"C:\Lab\fakeWINWORD.EXE")]), [])

    def test_network_watchlist_and_loopback(self):
        for port in (1337, 4444, 9001):
            with self.subTest(port=port):
                self.assertEqual(rule_ids([network(image=PS, destination_port=port)]), ["WH003"])
        for override in (
            {"destination_port": 443}, {"destination_ip": "127.0.0.1"},
            {"destination_ip": "::1"}, {"image": r"C:\Program Files\Browser\chrome.exe"},
            {"image": ""},
        ):
            with self.subTest(override=override):
                self.assertEqual(rule_ids([network(**({"image": PS} | override))]), [])


class CorrelationTests(unittest.TestCase):
    def test_join_case_normalization_and_reverse_input_order(self):
        events = [network(computer="lab-win11", process_guid=GUID.upper()), process()]
        report = analyze(events)
        self.assertEqual(report["summary"]["correlated_connections"], 1)
        self.assertEqual(rule_ids(events), ["WH003"])
        self.assertEqual(report["timeline"][1]["correlation_key"], "computer+process_guid")

    def test_host_guid_and_time_boundaries_prevent_incorrect_joins(self):
        for connection, creation in (
            (network(computer="LAB-WIN12"), process()),
            (network(process_guid=""), process(process_guid="")),
            (network(process_guid="another-guid"), process()),
            (network(timestamp="2026-01-15T09:59:59Z"), process()),
            (network(timestamp="2026-01-15T10:00:00.001Z"), process(timestamp="2026-01-15T10:00:00.002Z")),
        ):
            with self.subTest(connection=connection):
                report = analyze([creation, connection])
                self.assertEqual(report["summary"]["correlated_connections"], 0)
                self.assertEqual(report["detections"], [])

    def test_same_timestamp_creation_precedes_connection(self):
        report = analyze([network(timestamp="2026-01-15T10:00:00Z"), process()])
        self.assertEqual(report["timeline"][0]["event_id"], 1)
        self.assertEqual(report["timeline"][1]["correlation_key"], "computer+process_guid")

    def test_network_image_takes_precedence_over_joined_image(self):
        report = analyze([process(), network(image=r"C:\Browser\chrome.exe")])
        self.assertEqual(report["summary"]["correlated_connections"], 1)
        self.assertEqual(report["detections"], [])
        self.assertEqual(report["timeline"][1]["image"], r"C:\Browser\chrome.exe")


class IngestionTests(unittest.TestCase):
    def test_sysmon_aliases_utc_and_slash_normalization(self):
        event = normalize({"EventID": "1", "UtcTime": "2026-01-15 10:00:00.123",
                           "Computer": "LAB", "Image": "C:/Windows/pwsh.exe"})
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.timestamp.microsecond, 123000)
        self.assertEqual(event.image, r"C:\Windows\pwsh.exe")
        self.assertIsNone(normalize({"event_id": 5}))

    def test_invalid_supported_records_fail_with_line_context(self):
        good = {"timestamp": "2026-01-15T10:00:00Z", "event_id": 3, "computer": "LAB",
                "destination_ip": "203.0.113.20", "destination_port": 4444}
        for override in (
            {"timestamp": "2026-01-15T10:00:00"}, {"timestamp": "yesterday"},
            {"computer": ""}, {"event_id": True}, {"destination_ip": "not-an-ip"},
            {"destination_port": 65536}, {"destination_port": 44.4}, {"destination_port": True},
            {"destination_port": None}, {"process_id": -1}, {"image": []},
        ):
            with self.subTest(override=override), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bad.jsonl"
                path.write_text("\n" + json.dumps(good | override) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(InputError, "line 2:"):
                    load_events(path)

    def test_invalid_json_is_rejected(self):
        for text in ("not-json\n", "[]\n"):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bad.jsonl"
                path.write_text(text)
                with self.assertRaisesRegex(InputError, "line 1:"):
                    load_events(path)

    def test_xml_provider_filter_single_event_and_utf16(self):
        xml = ('<Event><System><Provider Name="Microsoft-Windows-Sysmon"/>'
               '<EventID>1</EventID><TimeCreated SystemTime="2026-01-15T10:00:00Z"/>'
               '<Computer>LAB</Computer></System><EventData>'
               '<Data Name="Image">C:\\Windows\\pwsh.exe</Data></EventData></Event>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.xml"
            path.write_bytes(xml.encode("utf-16"))
            self.assertEqual(len(load_events(path)), 1)
            path.write_text(xml.replace("Microsoft-Windows-Sysmon", "Microsoft-Windows-Security-Auditing"))
            self.assertEqual(load_events(path), [])
        for encoding in ("utf-8", "utf-16"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "entity.xml"
                path.write_bytes(('<!DOCTYPE Events [<!ENTITY x "value">]><Events/>').encode(encoding))
                with self.assertRaisesRegex(InputError, "DTD"):
                    load_events(path)


class SigmaMirrorTests(unittest.TestCase):
    def test_sigma_reference_subset_matches_fixture_results(self):
        """Read only known scalar patterns, not arbitrary YAML/Sigma syntax.

        A separate pySigma syntax check is needed for schema/backend validation.
        This test enforces parity between the checked-in rule subset and code.
        """
        docs = {rule: (PROJECT / "sigma" / filename).read_text() for rule, filename in (
            ("WH001", "wh001_encoded_powershell.yml"),
            ("WH002", "wh002_office_interpreter.yml"),
            ("WH003", "wh003_interpreter_network.yml"),
        )}
        expressions = {rule: {field: re.compile(pattern) for field, pattern in re.findall(
            r"^    (\w+)\|re: '([^']+)'$", doc, re.MULTILINE)} for rule, doc in docs.items()}
        ports = {int(value) for value in re.findall(r"^      - (\d+)$", docs["WH003"], re.MULTILINE)}
        excluded_ips = set(re.findall(r"^      - '([^']+)'$", docs["WH003"], re.MULTILINE))
        self.assertEqual(ports, {1337, 4444, 9001})
        conditions = {
            "WH001": "selection_image and selection_command",
            "WH002": "selection_parent and selection_child",
            "WH003": "selection_image and selection_port and not filter_loopback",
        }
        for rule, condition in conditions.items():
            self.assertIn(f"  condition: {condition}\n", docs[rule])
        for row in analyze(load_events(PROJECT / "data/events.jsonl"))["timeline"]:
            values = {"Image": row["image"], "ParentImage": row["parent_image"], "CommandLine": row["command_line"]}
            expected = []
            if row["event_id"] == 1:
                if all(pattern.search(values[field]) for field, pattern in expressions["WH001"].items()):
                    expected.append("WH001")
                if all(pattern.search(values[field]) for field, pattern in expressions["WH002"].items()):
                    expected.append("WH002")
            elif (expressions["WH003"]["Image"].search(values["Image"])
                  and row["destination_port"] in ports and row["destination_ip"] not in excluded_ips):
                expected.append("WH003")
            self.assertEqual(row["rule_ids"], expected, row["record_id"])


class CliTests(unittest.TestCase):
    def test_report_and_csv_in_new_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reports/report.json"
            timeline = Path(directory) / "reports/timeline.csv"
            with redirect_stdout(io.StringIO()):
                result = main(["--input", str(PROJECT / "data/events.jsonl"), "--output", str(output), "--timeline-csv", str(timeline)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.read_text())["summary"]["detection_count"], 3)
            with timeline.open(newline="") as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 12)

    def test_csv_formula_escaping_keeps_json_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output, timeline = [Path(directory) / name for name in ("input.jsonl", "out.json", "out.csv")]
            source.write_text(json.dumps({"timestamp": "2026-01-15T10:00:00Z", "event_id": 1,
                                         "computer": "LAB", "image": PS, "command_line": "=SUM(1,2)"}) + "\n")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--input", str(source), "--output", str(output), "--timeline-csv", str(timeline)]), 0)
            self.assertEqual(json.loads(output.read_text())["timeline"][0]["command_line"], "=SUM(1,2)")
            with timeline.open(newline="") as stream:
                self.assertEqual(next(csv.DictReader(stream))["command_line"], "'=SUM(1,2)")

    def test_missing_input_returns_actionable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["--input", str(Path(directory) / "missing.jsonl"), "--output", str(Path(directory) / "out.json")])
            self.assertEqual(result, 2)
            self.assertIn("windows-hunt:", stderr.getvalue())
            self.assertFalse((Path(directory) / "out.json").exists())

    def test_input_output_collision_rejected(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["--input", "same.jsonl", "--output", "same.jsonl"])
        self.assertEqual(raised.exception.code, 2)

    def test_hardlink_collisions_preserve_source_and_existing_reports(self):
        for pair in ((0, 1), (0, 2), (1, 2)):
            with self.subTest(pair=pair), tempfile.TemporaryDirectory() as directory:
                paths = [Path(directory) / name for name in ("input.jsonl", "out.json", "timeline.csv")]
                original = (PROJECT / "data/events.jsonl").read_bytes()
                paths[0].write_bytes(original)
                if pair[0] == 1:
                    paths[1].write_bytes(b"existing report\n")
                paths[pair[1]].hardlink_to(paths[pair[0]])
                before = {path: path.read_bytes() for path in paths if path.exists()}
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    main(["--input", str(paths[0]), "--output", str(paths[1]), "--timeline-csv", str(paths[2])])
                self.assertEqual(raised.exception.code, 2)
                for path, content in before.items():
                    self.assertEqual(path.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
