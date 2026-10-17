"""Validate Sigma syntax with pySigma and XML well-formedness.

This is not a Wazuh engine test or a Sigma backend integration test.
"""

from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    try:
        from sigma.rule import SigmaRule
    except ImportError:
        print("Install validation tools: python -m pip install -r requirements-dev.txt", file=sys.stderr)
        return 1
    rules = sorted((ROOT / "projects" / "windows-threat-hunting" / "sigma").rglob("*.yml"))
    rules += sorted((ROOT / "projects" / "windows-threat-hunting" / "sigma").rglob("*.yaml"))
    xml_files = sorted((ROOT / "projects" / "siem-monitoring").rglob("*.xml"))
    if not rules or not xml_files:
        print("Expected Sigma and Wazuh XML files are missing", file=sys.stderr)
        return 1
    failed = []
    identifiers = set()
    for path in rules:
        try:
            rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
            if rule.id is None or rule.id in identifiers:
                raise ValueError("Sigma rules require unique IDs")
            identifiers.add(rule.id)
            print(f"Sigma syntax OK: {path.relative_to(ROOT)}")
        except Exception as exc:
            failed.append(path)
            print(f"Invalid Sigma rule {path.relative_to(ROOT)}: {exc}", file=sys.stderr)
    for path in xml_files:
        try:
            ET.parse(path)
            print(f"XML syntax OK: {path.relative_to(ROOT)}")
        except (ET.ParseError, OSError) as exc:
            failed.append(path)
            print(f"Invalid XML {path.relative_to(ROOT)}: {exc}", file=sys.stderr)
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
