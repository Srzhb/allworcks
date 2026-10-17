import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis import Indicator
from intelligence import IntelligenceClient, MAX_RESPONSE_BYTES, offline_lookup, online_skip_reason


class IntelligenceTests(unittest.TestCase):
    def test_virustotal_sends_only_ioc_in_get_and_filters_response(self):
        opener = Mock(return_value=io.BytesIO(json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "undetected": 20, "unexpected_secret": "never-output"}, "raw_secret": "never-output"}}}).encode()))
        client = IntelligenceClient("virustotal", "fake-api-key", timeout=2.5, opener=opener)
        result = client.lookup(Indicator("hash", "a" * 64))
        req = opener.call_args.args[0]
        self.assertEqual(req.get_method(), "GET")
        self.assertIsNone(req.data)
        self.assertEqual(req.full_url, "https://www.virustotal.com/api/v3/files/" + "a" * 64)
        self.assertEqual(req.get_header("X-apikey"), "fake-api-key")
        self.assertEqual(opener.call_args.kwargs["timeout"], 2.5)
        self.assertEqual(result["summary"]["last_analysis_stats"], {"malicious": 2, "undetected": 20})
        self.assertNotIn("fake-api-key", json.dumps(result))
        self.assertNotIn("never-output", json.dumps(result))

    def test_otx_endpoint_and_pulse_count(self):
        opener = Mock(return_value=io.BytesIO(b'{"pulse_info":{"count":3},"other":"ignored"}'))
        result = IntelligenceClient("otx", "fake-otx-key", opener=opener).lookup(Indicator("domain", "python.org"))
        self.assertEqual(opener.call_args.args[0].full_url, "https://otx.alienvault.com/api/v1/indicators/domain/python.org/general")
        self.assertEqual(result["summary"]["pulse_count"], 3)

    def test_429_stops_further_requests_without_echoing_error(self):
        opener = Mock(side_effect=HTTPError("https://api.invalid/secret-value", 429, "secret-value", {}, None))
        client = IntelligenceClient("virustotal", "secret-value", opener=opener)
        first = client.lookup(Indicator("domain", "python.org"))
        second = client.lookup(Indicator("domain", "pypi.org"))
        self.assertEqual(first["status"], "rate_limited")
        self.assertEqual(second["status"], "skipped")
        self.assertEqual(opener.call_count, 1)
        self.assertNotIn("secret-value", json.dumps([first, second]))

    def test_auth_failures_stop_requests_and_other_http_errors_do_not(self):
        for code, expected in [(401, "authentication_error"), (403, "access_denied"), (404, "not_found"), (503, "http_error"), (302, "http_error")]:
            with self.subTest(code=code):
                opener = Mock(side_effect=HTTPError("hidden", code, "hidden", {}, None))
                client = IntelligenceClient("otx", "hidden", opener=opener)
                result = client.lookup(Indicator("domain", "python.org"))
                self.assertEqual(result["status"], expected)
                self.assertEqual(client.disabled_status is not None, code in {401, 403})
                self.assertNotIn("hidden", json.dumps(result))

    def test_timeout_and_network_error_are_sanitized(self):
        for failure in [TimeoutError("hidden-api-key"), URLError("hidden-api-key")]:
            result = IntelligenceClient("otx", "hidden-api-key", opener=Mock(side_effect=failure)).lookup(Indicator("ipv4", "8.8.8.8"))
            self.assertEqual(result["status"], "network_error")
            self.assertNotIn("hidden-api-key", json.dumps(result))

    def test_malformed_or_oversize_api_responses(self):
        for payload in [b"not JSON secret-value", b"[]", b'{"pulse_info":{"count":"secret-value"}}', b"x" * (MAX_RESPONSE_BYTES + 1)]:
            with self.subTest(size=len(payload)):
                result = IntelligenceClient("otx", "secret-value", opener=Mock(return_value=io.BytesIO(payload))).lookup(Indicator("domain", "python.org"))
                self.assertEqual(result["status"], "invalid_response")
                self.assertNotIn("secret-value", json.dumps(result))

    def test_missing_key_does_not_open_network(self):
        opener = Mock()
        result = IntelligenceClient("otx", None, opener=opener).lookup(Indicator("domain", "python.org"))
        self.assertEqual(result["status"], "skipped")
        opener.assert_not_called()

    def test_special_use_domain_suffixes_remain_local(self):
        opener = Mock()
        client = IntelligenceClient("otx", "test", opener=opener)
        for domain in ["mail.company.internal", "router.home.arpa", "hidden.onion", "name.alt", "host.localhost"]:
            self.assertEqual(client.lookup(Indicator("domain", domain))["status"], "skipped")
        opener.assert_not_called()

    def test_sensitive_url_and_nonpublic_addresses_remain_local(self):
        opener = Mock()
        client = IntelligenceClient("virustotal", "test", opener=opener)
        for indicator in [Indicator("url", "https://python.org/reset?token=secret"), Indicator("domain", "login.example.test"), Indicator("domain", "example.org"), Indicator("ipv4", "192.0.2.1"), Indicator("ipv4", "10.0.0.1"), Indicator("ipv4", "224.0.0.1"), Indicator("ipv6", "::1")]:
            self.assertIsNotNone(online_skip_reason(indicator))
            self.assertEqual(client.lookup(indicator)["status"], "skipped")
        opener.assert_not_called()

    def test_offline_absence_is_not_a_clean_verdict(self):
        result = offline_lookup(Indicator("domain", "python.org"), {})
        self.assertEqual(result["status"], "no_fixture")
        self.assertIn("not a clean", result["note"])
