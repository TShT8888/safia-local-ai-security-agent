# Experiment Notes

## What I tried

I built the first version as a hybrid agent:

- deterministic security checks for evidence collection;
- a small verification step for confidence;
- optional local LLM reasoning through Ollama;
- Markdown and JSON reports;
- an intentionally vulnerable local lab for evaluation.

This split is important because security review should be grounded. The LLM is useful for summarizing impact and fixes, but the finding should point back to concrete lines of code.

## Evaluation setup

The demo target contains known vulnerabilities:

- command injection via `shell=True`;
- dynamic code execution through `eval`;
- SQL injection through f-string query construction;
- unsafe YAML loading;
- unsafe pickle deserialization;
- hard-coded secret;
- debug mode;
- DOM XSS through `innerHTML`;
- prototype pollution-style merge behavior.

The evaluation script checks whether the agent detects the expected rule IDs and prints a simple rule-level recall and precision proxy.

## Trade-offs

I preferred a small working system over a broad but shallow design. A larger version could call Semgrep, Bandit, Gitleaks, Trivy, or CodeQL, but then the case study becomes mostly integration work. This version keeps the core reasoning loop visible.

The most important trade-off is false positives versus coverage. I used explicit rules with confidence notes instead of pretending every pattern is exploitable. The report separates evidence from interpretation so a human reviewer can quickly confirm or reject each item.

## What I would improve with more time

I would add deeper data-flow analysis, SARIF output, patch generation, and a retrieval layer over OWASP/CWE material. I would also evaluate on public intentionally vulnerable apps such as DVWA-style local labs or small benchmark repositories, while keeping the "owned or authorized target only" boundary.
