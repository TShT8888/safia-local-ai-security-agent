Subject: Safia ML Engineer Case Study Submission

Hello,

Thank you for the case study. I prepared a local AI security agent that reviews an owned codebase or intentionally vulnerable lab from a security perspective and reports likely vulnerabilities with evidence, CWE mapping, confidence notes, and remediation guidance.

Repository: https://github.com/TShT8888/safia-local-ai-security-agent

Short summary of my approach:

- I built a hybrid local agent instead of sending the whole task directly to an LLM. The deterministic scanner first collects concrete file/line evidence from the codebase, then the agent verifies the context and writes a human-readable report.
- The current rule base covers command injection, dynamic code execution, SQL injection-like query construction, unsafe deserialization, hard-coded secrets, debug mode, DOM XSS, and prototype pollution-style patterns.
- The agent can optionally use a local Ollama model (`qwen2.5-coder:7b`) to refine explanations, but it still works fully offline without a model download. I made this fallback intentionally so the project is reproducible on another machine.
- I included an intentionally vulnerable local lab, Markdown/JSON reporting, tests, and a small evaluation script. On the included demo target, the evaluation detects all expected rule classes.
- I focused on making the reasoning loop visible: evidence -> weakness -> confidence -> remediation. With more time, I would add Semgrep rule import, lightweight taint tracking, SARIF output, and retrieval over OWASP/CWE/ASVS material.

I am not currently a student.

How to try it:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python scripts/evaluate_demo.py
```

If Ollama is available locally:

```bash
ollama pull qwen2.5-coder:7b
python -m safia_security_agent.cli examples --output reports/demo-report.md --json reports/demo-report.json
```

Best regards,
Shakhzod Toshpulatov
