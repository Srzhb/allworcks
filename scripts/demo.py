"""Запуск четырёх примеров на данных из папки data."""

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEMOS = (
    ("siem-monitoring", "events.jsonl", "siem.json"),
    ("network-analysis", "traffic.pcap", "network.json"),
    ("phishing-ioc", "suspicious.eml", "phishing.json"),
    ("windows-threat-hunting", "events.jsonl", "windows.json"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports")
    args = parser.parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, fixture, report in DEMOS:
        project = ROOT / "projects" / name
        command = [
            sys.executable,
            str(project / "run.py"),
            "--input", str(project / "data" / fixture),
            "--output", str(output_dir / report),
        ]
        if name == "network-analysis":
            command += ["--eve", str(project / "data" / "expected-alerts.eve.jsonl")]
        if name == "windows-threat-hunting":
            command += ["--timeline-csv", str(output_dir / "windows-timeline.csv")]
        print(f"Запускаю {name}", flush=True)
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
    print(f"Отчёты сохранены в {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
