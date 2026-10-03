# Safia Local AI Security Agent

This repository is my solution for Safia's ML Engineer case study: **build a local AI agent that reviews a codebase from a security perspective and identifies risky implementation choices or likely vulnerabilities**.

The project is intentionally small, runnable, and easy to inspect. The main idea is a hybrid agent:

- local deterministic checks collect grounded evidence from source code;
- a verifier adds confidence notes instead of claiming every pattern is exploitable;
- an optional local LLM through Ollama explains the finding and remediation;
- reports are produced in Markdown for humans and JSON for automation;
- an intentionally vulnerable local lab and evaluation script show what the agent can detect.

## Why this design

I did not want the solution to be only "send files to an LLM and hope it finds bugs." For security work, the model should reason from evidence. The deterministic scanner gives the agent concrete file/line/snippet evidence, maps it to CWE categories, and then the LLM is used as a local reasoning/explanation layer when available.

The current version focuses on Python and JavaScript/TypeScript patterns:

- command injection through `shell=True`;
- dynamic code execution with `eval` or `exec`;
- SQL injection-like string interpolation near `execute`;
- unsafe YAML loading;
- unsafe pickle deserialization;
- hard-coded secrets;
- Flask debug mode;
- DOM XSS sinks such as `innerHTML`;
- prototype pollution-style merge patterns.

## Safety boundary

Use this only on code, applications, infrastructure, or local labs that you own or are explicitly authorized to test. The tool does not attack third-party systems and does not exploit live services.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m safia_security_agent.cli examples --no-llm --output reports/demo-report.md --json reports/demo-report.json
```

The CLI exits with status `1` if critical or high findings are present, which makes it usable in CI. The report is still written before exit.

## Optional local LLM

The agent can refine explanations with a local Ollama model:

```bash
ollama pull qwen2.5-coder:7b
ollama serve
python -m safia_security_agent.cli examples --output reports/demo-report.md --json reports/demo-report.json
```

If Ollama is not running, the tool falls back to deterministic explanations. This keeps the project reproducible even without model downloads.

## Evaluation

Run:

```bash
python scripts/evaluate_demo.py
```

The evaluation scans `examples/`, compares findings against expected rule IDs, and prints a simple recall/precision proxy. This is not a complete benchmark; it is a sanity check that the agent detects the known weaknesses in the intentionally vulnerable lab.

## Example output

```text
Demo evaluation
Expected rules: 9
Found rules: 9
Rule recall: 1.00
Precision proxy: 1.00
```

## Repository structure

```text
src/safia_security_agent/
  agent.py       - coordinates scan, verification, and explanation
  scanner.py     - local evidence collector
  rules.py       - CWE-mapped security rules
  llm.py         - optional local Ollama client
  report.py      - Markdown and JSON report writers
examples/
  vulnerable_app.py
  vulnerable_frontend.js
scripts/
  evaluate_demo.py
docs/
  architecture.md
  experiment_notes.md
tests/
  test_scanner.py
```

## What I would improve next

- Add Semgrep-compatible rule import.
- Add lightweight taint tracking for Flask, FastAPI, Express, and common database clients.
- Add retrieval over OWASP, CWE, ASVS, and secure coding guides.
- Add SARIF output for code scanning integrations.
- Add patch suggestions with before/after diffs.
- Evaluate on more intentionally vulnerable local repositories.
