from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import Finding, ScanConfig


class LocalLLM:
    """Optional local model client.

    The case study asks for local-model usage where reasonable. This client talks to Ollama
    on localhost when it is available. The scanner still works without it, which keeps the
    project reproducible on machines that do not have a model downloaded yet.
    """

    def __init__(self, config: ScanConfig):
        self.config = config

    def refine(self, finding: Finding) -> str | None:
        if not self.config.use_llm:
            return None

        evidence = "\n".join(
            f"- {item.path}:{item.line}: {item.snippet}" for item in finding.evidence
        )
        prompt = f"""You are a local security-focused coding agent.
Review this finding and write a concise practical explanation.
Include why it matters, how to verify safely in an owned test environment, and the safest fix.

Finding: {finding.title}
Severity: {finding.severity}
CWE: {finding.cwe}
Evidence:
{evidence}

Return 3 short paragraphs. Do not invent extra files or claim exploitation succeeded.
"""
        payload = {
            "model": self.config.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.config.ollama_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None
        text = str(body.get("response", "")).strip()
        return text or None
