from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Evidence:
    path: Path
    line: int
    snippet: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    cwe: str
    description: str
    recommendation: str
    languages: tuple[str, ...]
    patterns: tuple[str, ...]
    verify_terms: tuple[str, ...] = ()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    cwe: str
    confidence: float
    evidence: list[Evidence]
    explanation: str
    recommendation: str
    agent_notes: list[str] = field(default_factory=list)

    @property
    def primary_path(self) -> Path:
        return self.evidence[0].path

    @property
    def primary_line(self) -> int:
        return self.evidence[0].line


@dataclass(frozen=True)
class ScanConfig:
    target: Path
    max_file_bytes: int = 400_000
    use_llm: bool = True
    ollama_model: str = "qwen2.5-coder:7b"
    ollama_url: str = "http://127.0.0.1:11434/api/generate"
