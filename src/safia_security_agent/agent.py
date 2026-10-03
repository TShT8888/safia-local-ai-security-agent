from __future__ import annotations

from pathlib import Path

from .llm import LocalLLM
from .models import Finding, ScanConfig
from .scanner import StaticSecurityScanner


class SecurityAgent:
    """Coordinates collection, verification, and explanation."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.scanner = StaticSecurityScanner(config)
        self.llm = LocalLLM(config)

    def run(self) -> list[Finding]:
        findings = self.scanner.scan()
        for finding in findings:
            refined = self.llm.refine(finding)
            if refined:
                finding.explanation = refined
                finding.agent_notes.append(
                    f"Explanation refined by local model `{self.config.ollama_model}` through Ollama."
                )
            else:
                finding.agent_notes.append(
                    "Local LLM was unavailable or disabled; deterministic rule explanation was used."
                )
        return findings


def scan_target(target: Path, use_llm: bool = True, ollama_model: str = "qwen2.5-coder:7b") -> list[Finding]:
    return SecurityAgent(ScanConfig(target=target, use_llm=use_llm, ollama_model=ollama_model)).run()
