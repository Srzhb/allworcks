from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

from .analysis import analyze
from .pcap import CaptureError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline PCAP analysis and optional Suricata EVE correlation")
    parser.add_argument("--input", required=True, type=Path, help="Classic Ethernet PCAP")
    parser.add_argument("--output", required=True, type=Path, help="JSON report")
    parser.add_argument("--eve", type=Path, help="Optional Suricata EVE JSONL with offline pcap_cnt")
    parser.add_argument("--scan-threshold", type=int, default=8)
    parser.add_argument("--scan-window", type=float, default=10.0)
    arguments = parser.parse_args(argv)
    if arguments.scan_threshold < 2:
        parser.error("--scan-threshold must be at least 2")
    if not math.isfinite(arguments.scan_window) or arguments.scan_window <= 0:
        parser.error("--scan-window must be a positive finite number")
    try:
        input_paths = [arguments.input] + ([arguments.eve] if arguments.eve else [])
        for input_path in input_paths:
            if (arguments.output.resolve() == input_path.resolve()
                    or (arguments.output.exists() and input_path.exists()
                        and arguments.output.samefile(input_path))):
                parser.error("--output must differ from input files")
        report = analyze(arguments.input, eve=arguments.eve,
                         scan_threshold=arguments.scan_threshold, scan_window=arguments.scan_window)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, UnicodeError, CaptureError) as error:
        print(f"network-lab: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(arguments.output), **report["summary"]}, ensure_ascii=False))
    return 0
