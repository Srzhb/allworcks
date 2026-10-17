"""Run each project's standard-library tests in an isolated process."""

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
            print(f"Missing tests: {name}", file=sys.stderr)
            failed.append(name)
            continue
        print(f"\nRunning {name}", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(tests), "-v"],
            cwd=ROOT,
            check=False,
        )
        if result.returncode:
            failed.append(name)
    if failed:
        print("Failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("\nAll four projects passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
