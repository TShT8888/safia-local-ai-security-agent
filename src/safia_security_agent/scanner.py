from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from .models import Evidence, Finding, ScanConfig
from .rules import RULES, SEVERITY_ORDER

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}


class StaticSecurityScanner:
    """Small deterministic security scanner used as the agent's evidence collector."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def scan(self) -> list[Finding]:
        grouped: dict[tuple[str, Path], list[Evidence]] = defaultdict(list)
        seen_evidence: set[tuple[str, Path, int, str]] = set()
        for path in self._iter_files(self.config.target):
            suffix = path.suffix.lower().lstrip(".")
            text = self._read_text(path)
            if text is None:
                continue
            for rule in RULES:
                if suffix not in rule.languages:
                    continue
                for pattern in rule.patterns:
                    for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
                        line_no = text.count("\n", 0, match.start()) + 1
                        snippet = self._line_at(text, line_no)
                        evidence_key = (rule.rule_id, path, line_no, snippet)
                        if evidence_key in seen_evidence:
                            continue
                        seen_evidence.add(evidence_key)
                        grouped[(rule.rule_id, path)].append(Evidence(path=path, line=line_no, snippet=snippet))

        findings: list[Finding] = []
        rules_by_id = {rule.rule_id: rule for rule in RULES}
        for (rule_id, _path), evidence in grouped.items():
            rule = rules_by_id[rule_id]
            confidence, notes = self._verify(rule.verify_terms, evidence)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    confidence=confidence,
                    evidence=evidence[:5],
                    explanation=rule.description,
                    recommendation=rule.recommendation,
                    agent_notes=notes,
                )
            )

        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), str(f.primary_path), f.primary_line))
        return findings

    def _iter_files(self, target: Path):
        if target.is_file():
            yield target
            return
        for path in target.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file() and path.stat().st_size <= self.config.max_file_bytes:
                yield path

    def _read_text(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return None
        except OSError:
            return None

    @staticmethod
    def _line_at(text: str, line_no: int) -> str:
        lines = text.splitlines()
        if not 1 <= line_no <= len(lines):
            return ""
        return lines[line_no - 1].strip()

    @staticmethod
    def _verify(terms: tuple[str, ...], evidence: list[Evidence]) -> tuple[float, list[str]]:
        if not terms:
            return 0.80, ["Matched a high-signal pattern from the local rule base."]
        haystack = "\n".join(item.snippet.lower() for item in evidence)
        hits = [term for term in terms if term.lower() in haystack]
        if hits:
            return 0.88, [f"Matched source/sink context terms: {', '.join(sorted(set(hits)))}."]
        return 0.65, ["Pattern matched, but direct attacker-controlled data flow was not proven by the lightweight verifier."]
