from pathlib import Path

from safia_security_agent.agent import scan_target


def test_demo_app_findings_cover_expected_classes():
    target = Path("examples").resolve()
    findings = scan_target(target, use_llm=False)
    rule_ids = {finding.rule_id for finding in findings}

    assert "PY-SHELL-001" in rule_ids
    assert "PY-EVAL-001" in rule_ids
    assert "PY-SQL-001" in rule_ids
    assert "PY-YAML-001" in rule_ids
    assert "PY-PICKLE-001" in rule_ids
    assert "SECRET-001" in rule_ids
    assert "JS-XSS-001" in rule_ids


def test_findings_are_sorted_by_severity():
    findings = scan_target(Path("examples").resolve(), use_llm=False)
    severities = [finding.severity for finding in findings]
    assert severities[:2] == ["critical", "critical"]
