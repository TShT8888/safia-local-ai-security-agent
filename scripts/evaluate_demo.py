from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

EXPECTED_RULES = {
    "PY-SHELL-001",
    "PY-EVAL-001",
    "PY-SQL-001",
    "PY-YAML-001",
    "PY-PICKLE-001",
    "PY-DEBUG-001",
    "SECRET-001",
    "JS-XSS-001",
    "JS-PROTO-001",
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    json_report = root / "reports" / "demo-report.json"
    md_report = root / "reports" / "demo-report.md"
    command = [
        sys.executable,
        "-m",
        "safia_security_agent.cli",
        str(root / "examples"),
        "--no-llm",
        "--output",
        str(md_report),
        "--json",
        str(json_report),
    ]
    result = subprocess.run(command, cwd=root, text=True, capture_output=True)
    if result.returncode not in (0, 1):
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        return result.returncode

    report = json.loads(json_report.read_text(encoding="utf-8"))
    found = {item["rule_id"] for item in report["findings"]}
    true_positives = len(found & EXPECTED_RULES)
    recall = true_positives / len(EXPECTED_RULES)
    precision_proxy = true_positives / max(len(found), 1)

    print("Demo evaluation")
    print(f"Expected rules: {len(EXPECTED_RULES)}")
    print(f"Found rules: {len(found)}")
    print(f"Rule recall: {recall:.2f}")
    print(f"Precision proxy: {precision_proxy:.2f}")
    print(f"Markdown report: {md_report}")
    print(f"JSON report: {json_report}")
    return 0 if EXPECTED_RULES <= found else 1


if __name__ == "__main__":
    raise SystemExit(main())
