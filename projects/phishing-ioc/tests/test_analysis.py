import sys
import unittest
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis import MAX_MESSAGE_BYTES, Indicator, analyze_message, defang, extract_indicators


class AnalysisTests(unittest.TestCase):
    def test_fixture_authentication_is_reported_and_never_verified(self):
        sample = Path(__file__).resolve().parents[1] / "data" / "suspicious.eml"
        report, indicators = analyze_message(sample.read_bytes())
        self.assertEqual(report["authentication"]["status"], "REPORTED")
        self.assertIn("may be forged", report["authentication"]["caveat"])
        self.assertIn("does not verify SPF, DKIM or DMARC", report["authentication"]["caveat"])
        self.assertEqual({v["code"] for v in report["findings"]}, {"reply_to_mismatch", "reported_auth_failure", "unencrypted_url", "ip_literal_url"})
        self.assertIn(Indicator("domain", "accounts.example.test"), indicators)
        self.assertIn(Indicator("ipv6", "2001:db8::25"), indicators)
        self.assertIn(Indicator("hash", "a" * 64), indicators)

    def test_encoded_html_links_and_attachment_exclusion(self):
        message = EmailMessage()
        message["From"] = "test@example.org"
        message.set_content("No visible URL.")
        message.add_alternative('<a href="https://hidden.example.test/a?x=1&amp;y=2">Here</a>', subtype="html", cte="base64")
        message.add_attachment(b"https://attachment.example.test/", maintype="application", subtype="octet-stream", filename="payload.bin")
        report, indicators = analyze_message(message.as_bytes())
        self.assertIn(Indicator("url", "https://hidden.example.test/a?x=1&y=2"), indicators)
        self.assertNotIn(Indicator("domain", "attachment.example.test"), indicators)
        self.assertEqual(report["message"]["skipped_attachments"], 1)

    def test_defanged_iocs_and_ipv6_url(self):
        indicators = extract_indicators("hxxps://login[.]example[.]test/path https://[2001:db8::1] (https://ok.example.test/a)")
        self.assertIn(Indicator("url", "https://login.example.test/path"), indicators)
        self.assertIn(Indicator("url", "https://[2001:db8::1]"), indicators)
        self.assertIn(Indicator("ipv6", "2001:db8::1"), indicators)
        self.assertIn(Indicator("url", "https://ok.example.test/a"), indicators)

    def test_url_paths_queries_do_not_create_standalone_indicators(self):
        indicators = extract_indicators("https://actual.example.net/download/payload.exe?file=agenda.pdf&ip=8.8.8.8&token=" + "a" * 64)
        self.assertEqual({v.value for v in indicators if v.kind == "domain"}, {"actual.example.net"})
        self.assertFalse(any(v.kind in {"hash", "ipv4"} for v in indicators))

    def test_nested_message_attachment_is_pruned(self):
        inner = EmailMessage()
        inner.set_content("https://only-in-attachment.example.test/secret")
        outer = EmailMessage()
        outer.set_content("Main text.")
        outer.add_attachment(inner, filename="inner.eml")
        report, indicators = analyze_message(outer.as_bytes())
        self.assertEqual(report["message"]["skipped_attachments"], 1)
        self.assertNotIn(Indicator("domain", "only-in-attachment.example.test"), indicators)

    def test_multipart_attachment_is_pruned(self):
        inner = EmailMessage()
        inner.set_content("https://nested-plain.example.test/secret")
        inner.add_alternative('<a href="https://nested-html.example.test/secret">Open</a>', subtype="html")
        inner["Content-Disposition"] = "attachment"
        outer = EmailMessage()
        outer.set_content("Main text.")
        outer.make_mixed()
        outer.attach(inner)
        report, indicators = analyze_message(outer.as_bytes())
        self.assertEqual(report["message"]["skipped_attachments"], 1)
        self.assertFalse(any("nested-" in v.value for v in indicators))

    def test_invalid_ip_and_hash_boundaries(self):
        indicators = extract_indicators("999.1.2.3 " + "a" * 65 + " " + "B" * 40)
        self.assertFalse(any(v.kind == "ipv4" for v in indicators))
        self.assertNotIn(Indicator("hash", "a" * 64), indicators)
        self.assertIn(Indicator("hash", "b" * 40), indicators)

    def test_no_auth_headers_and_matching_reply_to(self):
        report, _ = analyze_message(b"From: User <one@example.test>\nReply-To: one@example.test\n\nHello")
        self.assertEqual(report["authentication"]["status"], "NOT_PRESENT")
        self.assertFalse(report["findings"])

    def test_unknown_charset_is_tolerated(self):
        _, indicators = analyze_message(b'Content-Type: text/plain; charset="unknown-training-charset"\n\nhttps://example.test/path')
        self.assertIn(Indicator("domain", "example.test"), indicators)

    def test_defang(self):
        self.assertEqual(defang("https://a.example.test/a user@example.test 192.0.2.1"), "hxxps://a[.]example[.]test/a user[@]example[.]test 192[.]0[.]2[.]1")

    def test_oversize_message_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_message(b"x" * (MAX_MESSAGE_BYTES + 1))
