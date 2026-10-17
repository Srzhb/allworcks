#!/usr/bin/env python3
"""Запуск анализа и сохранение JSON/CSV отчёта."""

import argparse
import csv
import json
from pathlib import Path
import sys

from analyze import analyze
from read_events import InputError, load_events


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline Sysmon timeline and rule evaluation")
    parser.add_argument("--input", required=True, type=Path, help="Normalized JSONL or Sysmon XML export")
    parser.add_argument("--output", required=True, type=Path, help="Destination JSON report")
    parser.add_argument("--format", choices=("auto", "jsonl", "xml"), default="auto")
    parser.add_argument("--timeline-csv", type=Path, help="Optional CSV timeline for spreadsheet analysis")
    args = parser.parse_args(argv)
    paths = [args.input, args.output] + ([args.timeline_csv] if args.timeline_csv else [])
    try:
        for index, left in enumerate(paths):
            for right in paths[index + 1:]:
                if left.resolve() == right.resolve() or (left.exists() and right.exists() and left.samefile(right)):
                    parser.error("input, output and timeline paths must be different files")
    except OSError as exc:
        parser.error(f"cannot validate input/output paths: {exc}")
    try:
        report = analyze(load_events(args.input, args.format))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if args.timeline_csv:
            args.timeline_csv.parent.mkdir(parents=True, exist_ok=True)
            fields = ["sequence", "timestamp", "event_id", "kind", "computer", "process_guid", "process_id",
                      "image", "command_line", "parent_image", "destination_ip", "destination_port",
                      "protocol", "correlated_process_creation", "rule_ids"]
            with args.timeline_csv.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for row in report["timeline"]:
                    # Не даём таблице принять строку журнала за формулу.
                    # В JSON остаётся исходное значение.
                    csv_row = {key: ("'" + value if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")) else value)
                               for key, value in row.items()}
                    csv_row["rule_ids"] = ",".join(row["rule_ids"])
                    writer.writerow(csv_row)
    except (OSError, UnicodeError, InputError) as exc:
        print(f"windows-hunt: {exc}", file=sys.stderr)
        return 2
    print(f"Events: {report['summary']['event_count']}; detections: {report['summary']['detection_count']}; report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
