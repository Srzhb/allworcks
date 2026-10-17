"""Разбор письма: заголовки, текст и индикаторы."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_MESSAGE_BYTES = 10 * 1024 * 1024
AUTH_CAVEAT = (
    "REPORTED: Authentication-Results headers are claims in the supplied EML. "
    "They may be forged or originate outside a trusted mail gateway. This tool "
    "does not verify SPF, DKIM or DMARC; validate them at the receiving gateway "
    "and establish its trusted header boundary."
)
URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})(?![\w-])", re.I)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HASH_RE = re.compile(r"(?<![a-zA-Z0-9])(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![a-zA-Z0-9])")


@dataclass(frozen=True, order=True)
class Indicator:
    kind: str
    value: str


class _HTMLLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.lower() in {"href", "src", "action"} and value:
                self.links.append(value)


def defang(value: str) -> str:
    """Make all displayed domain/IP/URL indicators non-clickable."""
    return re.sub(r"\bhttps?://", lambda m: "hxxps://" if m.group().lower().startswith("https") else "hxxp://", value, flags=re.I).replace(".", "[.]").replace("@", "[@]")


def _domain(value: str) -> str | None:
    try:
        value = value.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) <= 253 and DOMAIN_RE.fullmatch(value):
        return value
    return None


def extract_indicators(text: str) -> list[Indicator]:
    # Принимаем и обычные, и уже обезвреженные индикаторы.
    text = unescape(text).replace("[.]", ".").replace("[@]", "@")
    indicators: set[Indicator] = set()
    for match in URL_RE.finditer(text):
        url = match.group().rstrip(".,;!?")
        for closing, opening in ((")", "("), ("]", "["), ("}", "{")):
            while url.endswith(closing) and url.count(closing) > url.count(opening):
                url = url[:-1]
        url = re.sub(r"^hxxp", "http", url, flags=re.I)
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
        except ValueError:
            continue
        if not host:
            continue
        indicators.add(Indicator("url", url))
        try:
            ip = ipaddress.ip_address(host)
            indicators.add(Indicator("ipv4" if ip.version == 4 else "ipv6", str(ip)))
        except ValueError:
            domain = _domain(host)
            if domain:
                indicators.add(Indicator("domain", domain))
    # В пути и параметрах URL могут быть имена файлов и токены.
    # Отдельно проверяем только домен или IP из адреса сайта.
    standalone_text = URL_RE.sub(lambda match: " " * len(match.group()), text)
    for match in DOMAIN_RE.finditer(standalone_text):
        domain = _domain(match.group())
        if domain:
            indicators.add(Indicator("domain", domain))
    for match in IPV4_RE.finditer(standalone_text):
        try:
            indicators.add(Indicator("ipv4", str(ipaddress.IPv4Address(match.group()))))
        except ValueError:
            pass
    # ipaddress отсекает время из заголовков и другие строки с двоеточием.
    for token in re.findall(r"[0-9a-fA-F:]*:[0-9a-fA-F:.]+", standalone_text):
        try:
            indicators.add(Indicator("ipv6", str(ipaddress.IPv6Address(token))))
        except ValueError:
            pass
    for match in HASH_RE.finditer(standalone_text):
        indicators.add(Indicator("hash", match.group().lower()))
    return sorted(indicators)


def _addresses(message, name: str) -> list[str]:
    return [address.lower() for _, address in getaddresses([str(v) for v in message.get_all(name, [])]) if address]


def analyze_message(raw: bytes) -> tuple[dict, list[Indicator]]:
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("Message exceeds the 10 MiB limit")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = "\n".join(f"{key}: {value}" for key, value in message.items())
    bodies: list[str] = []
    skipped_attachments = 0
    def text_parts(part):
        nonlocal skipped_attachments
        # Вложение тоже может состоять из нескольких частей.
        # Не заходим внутрь него, даже если это другое письмо.
        if part.get_content_disposition() == "attachment" or part.get_filename() or part.get_content_maintype() == "message":
            skipped_attachments += 1
            return
        if part.is_multipart():
            for child in part.iter_parts():
                yield from text_parts(child)
            return
        yield part

    for part in text_parts(message):
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            body = payload.decode(charset, errors="replace")
        except LookupError:
            body = payload.decode("utf-8", errors="replace")
        bodies.append(body)
        if part.get_content_type() == "text/html":
            parser = _HTMLLinks()
            parser.feed(body)
            bodies.extend(parser.links)
    indicators = extract_indicators(headers + "\n" + "\n".join(bodies))
    from_addresses = _addresses(message, "From")
    reply_to = _addresses(message, "Reply-To")
    findings: list[dict] = []
    if reply_to and set(reply_to) != set(from_addresses):
        findings.append({"code": "reply_to_mismatch", "severity": "review", "detail": "From and Reply-To addresses differ; legitimate mailing workflows may also do this."})
    auth_headers = [str(value) for value in message.get_all("Authentication-Results", [])]
    if any(re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|softfail|temperror|permerror)\b", value, re.I) for value in auth_headers):
        findings.append({"code": "reported_auth_failure", "severity": "review", "detail": "An unverified Authentication-Results header reports an authentication error or failure."})
    for indicator in indicators:
        if indicator.kind != "url":
            continue
        parsed = urlsplit(indicator.value)
        if parsed.scheme.lower() == "http":
            findings.append({"code": "unencrypted_url", "severity": "review", "indicator": defang(indicator.value), "detail": "URL uses HTTP; this alone does not establish phishing."})
        try:
            ipaddress.ip_address(parsed.hostname or "")
        except ValueError:
            continue
        findings.append({"code": "ip_literal_url", "severity": "review", "indicator": defang(indicator.value), "detail": "URL uses an IP address instead of a hostname."})
    report = {
        "schema_version": 1,
        "purpose": "Educational triage; findings are review signals, not a phishing verdict.",
        "message": {
            "subject": defang(str(message.get("Subject", "")))[:1000],
            "from": [defang(v) for v in from_addresses],
            "reply_to": [defang(v) for v in reply_to],
            "date": str(message.get("Date", ""))[:200],
            "skipped_attachments": skipped_attachments,
            "parse_defects": sorted({type(defect).__name__ for part in message.walk() for defect in part.defects}),
        },
        "authentication": {
            "status": "REPORTED" if auth_headers else "NOT_PRESENT",
            "headers": [defang(v)[:4000] for v in auth_headers],
            "caveat": AUTH_CAVEAT,
        },
        "findings": findings,
        "indicators": [],
    }
    return report, indicators
