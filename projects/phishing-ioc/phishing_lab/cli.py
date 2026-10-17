"""Command line interface. Offline mode never constructs a network client."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .analysis import MAX_MESSAGE_BYTES, analyze_message, defang
from .intelligence import IntelligenceClient, load_fixtures, offline_lookup, online_skip_reason

DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "data" / "ti-fixtures.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline EML triage with defanged IOC output; --online opts into read-only TI requests.")
    parser.add_argument("--input", required=True, type=Path, help="Input .eml file (maximum 10 MiB)")
    parser.add_argument("--output", type=Path, help="Write JSON here; otherwise print to stdout")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES, help="Synthetic offline TI JSON database")
    parser.add_argument("--online", action="store_true", help="Send extracted public domain/IP/hash indicators to configured TI APIs; URLs and email content stay local")
    parser.add_argument("--max-lookups", type=int, default=20, help="Maximum eligible indicators queried per provider, 1-200 (default 20)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds per request, >0 and <=30 (default 5)")
    args = parser.parse_args(argv)
    if not 1 <= args.max_lookups <= 200:
        parser.error("--max-lookups must be between 1 and 200")
    if not 0 < args.timeout <= 30:
        parser.error("--timeout must be greater than 0 and no more than 30")
    try:
        if args.output:
            for protected in (args.input, args.fixtures):
                if args.output.resolve() == protected.resolve() or (
                    args.output.exists() and protected.exists() and args.output.samefile(protected)
                ):
                    print("Error: output must differ from the input message and fixture database.", file=sys.stderr)
                    return 2
        with args.input.open("rb") as handle:
            raw = handle.read(MAX_MESSAGE_BYTES + 1)
        report, indicators = analyze_message(raw)
        fixtures = load_fixtures(args.fixtures)
        clients = []
        if args.online:
            clients = [IntelligenceClient("virustotal", os.environ.get("VT_API_KEY"), args.timeout), IntelligenceClient("otx", os.environ.get("OTX_API_KEY"), args.timeout)]
        report["intelligence"] = {
            "mode": "online_opt_in" if args.online else "offline",
            "synthetic_fixtures": True,
            "max_indicators_per_provider": args.max_lookups if args.online else 0,
            "privacy": "Email bodies, headers, attachments and full URLs are never submitted. Online mode submits eligible extracted public domains, IP addresses and hash strings only.",
        }
        eligible_count = 0
        for indicator in indicators:
            item = {"type": indicator.kind, "indicator": defang(indicator.value), "offline": offline_lookup(indicator, fixtures)}
            if args.online:
                skip_reason = online_skip_reason(indicator)
                if skip_reason:
                    item["online"] = [{"provider": client.provider, "status": "skipped", "reason": skip_reason} for client in clients]
                elif eligible_count >= args.max_lookups:
                    item["online"] = [{"provider": client.provider, "status": "skipped", "reason": "Per-provider indicator budget reached."} for client in clients]
                else:
                    eligible_count += 1
                    item["online"] = [client.lookup(indicator) for client in clients]
            report["indicators"].append(item)
        serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized, encoding="utf-8")
        else:
            sys.stdout.write(serialized)
        return 0
    except (OSError, ValueError, RecursionError):
        # Do not echo file content, keys, or API response payloads in failure output.
        print("Error: unable to process input, fixture database, or output; check paths, permissions, JSON structure and the 10 MiB input limit.", file=sys.stderr)
        return 2
