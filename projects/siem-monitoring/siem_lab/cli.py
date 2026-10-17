"""Command-line interface for an offline JSONL replay."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sys

from .analyzer import AnalysisConfig, EventError, analyze, load_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic normalized SIEM JSONL without executing commands.")
    parser.add_argument("--input", required=True, help="UTF-8 JSONL file, or - for stdin")
    parser.add_argument("--output", default="-", help="JSON report path, or - for stdout (default)")
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--allow-source-ip", action="append", default=[], help="Trusted source for authentication failures only; repeatable")
    args = parser.parse_args(argv)
    try:
        if args.input != "-" and args.output != "-":
            input_path, output_path = Path(args.input), Path(args.output)
            same_path = input_path.resolve() == output_path.resolve()
            same_file = input_path.exists() and output_path.exists() and input_path.samefile(output_path)
            if same_path or same_file:
                raise ValueError("input and output must be different files (including links)")
        config = AnalysisConfig(args.failure_threshold, args.window_seconds, frozenset(args.allow_source_ip))
        with ExitStack() as stack:
            stream = sys.stdin if args.input == "-" else stack.enter_context(Path(args.input).open(encoding="utf-8"))
            report = analyze(load_events(stream), config)
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output == "-":
            sys.stdout.write(rendered)
        else:
            Path(args.output).write_text(rendered, encoding="utf-8")
    except (OSError, UnicodeError, EventError, ValueError) as exc:
        print(f"siem_lab: {exc}", file=sys.stderr)
        return 2
    return 0
