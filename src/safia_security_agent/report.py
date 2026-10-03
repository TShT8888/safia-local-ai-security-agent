from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding


def finding_to_dict(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "cwe": finding.cwe,
        "confidence": finding.confidence,
        "evidence": [
            {"path": str(item.path), "line": item.line, "snippet": item.snippet}
            for item in finding.evidence
        ],
        "explanation": finding.explanation,
        "recommendation": finding.recommendation,
        "agent_notes": finding.agent_notes,
    }


def write_json(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "finding_count": len(findings),
                "findings": [finding_to_dict(finding) for finding in findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def write_markdown(findings: list[Finding], path: Path, target: Path, llm_used: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Local AI Security Agent Report",
        "",
        f"- Target: `{target}`",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Findings: `{len(findings)}`",
        f"- Local LLM refinement: `{'enabled when available' if llm_used else 'disabled'}`",
        "",
        "## Executive Summary",
        "",
    ]
    if not findings:
        lines += [
            "No findings were detected by the current rule base. This does not prove the target is secure; it only means the implemented checks did not find a matching pattern.",
            "",
        ]
    else:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        lines.append(
            "The agent found "
            + ", ".join(f"{count} {severity}" for severity, count in sorted(counts.items()))
            + " issue(s). The most important findings are listed first."
        )
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    for index, finding in enumerate(findings, 1):
        lines += [
            f"### {index}. {finding.title}",
            "",
            f"- Rule: `{finding.rule_id}`",
            f"- Severity: `{finding.severity}`",
            f"- CWE: `{finding.cwe}`",
            f"- Confidence: `{finding.confidence:.2f}`",
            "",
            "**Evidence**",
            "",
        ]
        for item in finding.evidence:
            lines.append(f"- `{item.path}:{item.line}`: `{item.snippet}`")
        lines += [
            "",
            "**Agent reasoning**",
            "",
            finding.explanation,
            "",
        ]
        if finding.agent_notes:
            lines.append("**Verification notes**")
            lines.append("")
            for note in finding.agent_notes:
                lines.append(f"- {note}")
            lines.append("")
        lines += [
            "**Recommended fix**",
            "",
            finding.recommendation,
            "",
        ]

    path.write_text("\n".join(lines), encoding="utf-8")
