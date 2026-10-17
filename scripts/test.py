"""Запуск тестов для каждой папки с проектом."""

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = (
    "siem-monitoring",
    "network-analysis",
    "phishing-ioc",
    "windows-threat-hunting",
)


def main() -> int:
    failed = []
    for name in PROJECTS:
        tests = ROOT / "projects" / name / "tests"
        if not tests.is_dir() or not list(tests.glob("test_*.py")):
            print(f"Не найдены тесты: {name}", file=sys.stderr)
            failed.append(name)
            continue
        print(f"\nПроверяю {name}", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(tests), "-v"],
            cwd=ROOT,
            check=False,
        )
        if result.returncode:
            failed.append(name)
    if failed:
        print("Не прошли проверки: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("\nВсе проверки прошли.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
