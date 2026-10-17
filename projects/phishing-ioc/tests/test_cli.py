import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run import main

PROJECT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def test_offline_demo_outputs_defanged_report_without_network_client(self):
        with tempfile.TemporaryDirectory() as directory, patch("run.IntelligenceClient") as client:
            output = Path(directory) / "nested" / "report.json"
            self.assertEqual(main(["--input", str(PROJECT / "data" / "suspicious.eml"), "--output", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["intelligence"]["mode"], "offline")
            self.assertTrue(any(v["offline"]["status"] == "demo_match" for v in report["indicators"]))
            self.assertTrue(all("http://" not in v["indicator"] and "https://" not in v["indicator"] for v in report["indicators"]))
            client.assert_not_called()

    def test_online_budget_and_private_ioc_filter(self):
        with tempfile.TemporaryDirectory() as directory, patch("run.IntelligenceClient") as client:
            path = Path(directory) / "test.eml"
            path.write_text("From: a@example.test\n\nhttps://python.org/a https://pypi.org/b 192.0.2.1\n")
            instance = client.return_value
            instance.provider = "mock"
            instance.lookup.return_value = {"status": "ok"}
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["--input", str(path), "--online", "--max-lookups", "1"]), 0)
            # Two clients, one eligible indicator per client. URLs and documentation IP stay local.
            self.assertEqual(instance.lookup.call_count, 2)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["intelligence"]["mode"], "online_opt_in")
            self.assertTrue(any("budget" in v.get("reason", "") for item in report["indicators"] for v in item.get("online", [])))

    def test_invalid_fixture_or_missing_input_returns_safe_error(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text('{"synthetic": false, "secret": "never-output"}')
            for args in [["--input", str(Path(directory) / "missing.eml")], ["--input", str(PROJECT / "data" / "suspicious.eml"), "--fixtures", str(invalid)]]:
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(main(args), 2)
                self.assertNotIn("never-output", stderr.getvalue())

    def test_cli_rejects_invalid_request_limits(self):
        for args in [["--max-lookups", "0"], ["--timeout", "nan"], ["--timeout", "31"]]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                main(["--input", "unused", *args])
            self.assertEqual(exc.exception.code, 2)

    def test_output_cannot_overwrite_input_or_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            message = Path(directory) / "message.eml"
            message.write_bytes(b"From: a@example.test\n\nTraining")
            fixtures = Path(directory) / "fixtures.json"
            fixtures.write_text('{"synthetic": true, "indicators": {}}')
            symlink = Path(directory) / "message-link.eml"
            symlink.symlink_to(message)
            hardlink = Path(directory) / "fixtures-link.json"
            os.link(fixtures, hardlink)
            original_message = message.read_bytes()
            original_fixtures = fixtures.read_bytes()
            for output in [message, fixtures, symlink, hardlink]:
                with self.subTest(output=output), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["--input", str(message), "--fixtures", str(fixtures), "--output", str(output)]), 2)
                self.assertEqual(message.read_bytes(), original_message)
                self.assertEqual(fixtures.read_bytes(), original_fixtures)
