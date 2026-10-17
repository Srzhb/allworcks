"""Read-only IOC lookups: never submit email, attachments, or file bytes."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib import error, parse, request

from .analysis import Indicator

MAX_RESPONSE_BYTES = 1024 * 1024
SUPPORTED_KINDS = {"domain", "ipv4", "ipv6", "hash"}


def load_fixtures(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("synthetic") is not True or not isinstance(document.get("indicators"), dict):
        raise ValueError("TI fixtures require synthetic=true and an indicators object")
    fixtures = document["indicators"]
    for key, value in fixtures.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            raise ValueError("Each TI fixture must map an indicator key to an object")
        if not isinstance(value.get("label"), str) or not isinstance(value.get("note"), str):
            raise ValueError("Each TI fixture requires string label and note")
    return fixtures


def offline_lookup(indicator: Indicator, fixtures: dict) -> dict:
    fixture = fixtures.get(f"{indicator.kind}:{indicator.value}")
    if fixture is None:
        return {"source": "synthetic_fixture", "status": "no_fixture", "note": "No fixture entry; this is not a clean reputation result."}
    return {
        "source": "synthetic_fixture",
        "status": "demo_match",
        "label": fixture["label"],
        "note": fixture["note"],
    }


def online_skip_reason(indicator: Indicator) -> str | None:
    if indicator.kind == "url":
        return "Full URLs remain local; only extracted domain/IP/hash indicators are queried."
    if indicator.kind not in SUPPORTED_KINDS:
        return "Unsupported indicator type."
    if indicator.kind.startswith("ipv"):
        try:
            address = ipaddress.ip_address(indicator.value)
        except ValueError:
            return "Invalid IP address."
        if not address.is_global or address.is_multicast:
            return "Non-public, documentation or multicast IP addresses remain local."
    if indicator.kind == "domain":
        domain = indicator.value.lower()
        reserved = ("localhost", "example.com", "example.net", "example.org", "test", "invalid", "example", "local", "internal", "home.arpa", "onion", "alt")
        if any(domain == suffix or domain.endswith("." + suffix) for suffix in reserved):
            return "Reserved or local domains remain local."
    return None


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Credentials must never follow a redirect to another host.
        return None


class IntelligenceClient:
    """Bounded GET-only API client; failures expose no request or response text."""

    def __init__(self, provider: str, api_key: str | None, timeout: float = 5.0, opener=None):
        if provider not in {"virustotal", "otx"}:
            raise ValueError("Unknown intelligence provider")
        self.provider = provider
        self.api_key = api_key
        self.timeout = timeout
        self.opener = opener or request.build_opener(_NoRedirect()).open
        self.disabled_status: str | None = None

    def lookup(self, indicator: Indicator) -> dict:
        if not self.api_key:
            return {"provider": self.provider, "status": "skipped", "reason": "API key is not configured."}
        if self.disabled_status:
            return {"provider": self.provider, "status": "skipped", "reason": f"Provider disabled for this run after {self.disabled_status}."}
        skip_reason = online_skip_reason(indicator)
        if skip_reason:
            return {"provider": self.provider, "status": "skipped", "reason": skip_reason}
        if self.provider == "virustotal":
            resource = {"domain": "domains", "ipv4": "ip_addresses", "ipv6": "ip_addresses", "hash": "files"}[indicator.kind]
            url = f"https://www.virustotal.com/api/v3/{resource}/{parse.quote(indicator.value, safe='')}"
            headers = {"x-apikey": self.api_key}
        else:
            resource = {"domain": "domain", "ipv4": "IPv4", "ipv6": "IPv6", "hash": "file"}[indicator.kind]
            url = f"https://otx.alienvault.com/api/v1/indicators/{resource}/{parse.quote(indicator.value, safe='')}/general"
            headers = {"X-OTX-API-KEY": self.api_key}
        req = request.Request(url, headers={**headers, "Accept": "application/json", "User-Agent": "phishing-lab/1.0"}, method="GET")
        try:
            with self.opener(req, timeout=self.timeout) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                return {"provider": self.provider, "status": "invalid_response", "reason": "API response exceeds the size limit."}
            document = json.loads(data)
            summary = self._summary(document)
            return {"provider": self.provider, "status": "ok", "summary": summary}
        except error.HTTPError as exc:
            status = {401: "authentication_error", 403: "access_denied", 404: "not_found", 429: "rate_limited"}.get(exc.code, "http_error")
            if exc.code in {401, 403, 429}:
                self.disabled_status = status
            # Never serialize the error object: it may contain URLs, headers or secrets.
            return {"provider": self.provider, "status": status, "http_status": exc.code}
        except (error.URLError, TimeoutError, OSError):
            return {"provider": self.provider, "status": "network_error", "reason": "API request failed or timed out."}
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
            return {"provider": self.provider, "status": "invalid_response", "reason": "API response has an unexpected structure."}

    def _summary(self, document: dict) -> dict:
        if not isinstance(document, dict):
            raise ValueError("Expected an object")
        if self.provider == "virustotal":
            attributes = document["data"]["attributes"]
            if not isinstance(attributes, dict):
                raise ValueError("Expected attributes")
            stats = attributes.get("last_analysis_stats", {})
            if not isinstance(stats, dict):
                raise ValueError("Expected statistics")
            allowed = {"harmless", "malicious", "suspicious", "undetected", "timeout", "failure", "type-unsupported", "confirmed-timeout"}
            cleaned = {k: v for k, v in stats.items() if k in allowed and type(v) is int and v >= 0}
            return {"last_analysis_stats": cleaned, "caveat": "Vendor observations can be stale or incomplete; no detections does not prove safety."}
        pulses = document["pulse_info"]["count"]
        if type(pulses) is not int or pulses < 0:
            raise ValueError("Expected non-negative pulse count")
        return {"pulse_count": pulses, "caveat": "Pulse mentions are community context, not a maliciousness verdict."}
