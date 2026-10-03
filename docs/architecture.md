# Architecture Notes

## Problem framing

The challenge is not only to detect bugs. A useful AI security agent should behave like a careful reviewer:

1. collect local evidence from code;
2. connect evidence to a security weakness;
3. verify whether the pattern has attacker-controlled context;
4. explain impact and remediation;
5. make uncertainty visible instead of overstating results.

This implementation focuses on that loop.

## Agent loop

The current loop is:

1. **Plan** - decide which file types and rules are relevant for the target.
2. **Collect evidence** - run local deterministic checks over Python and JavaScript/TypeScript files.
3. **Verify** - score confidence using source/sink context terms and CWE-specific heuristics.
4. **Explain** - use a local Ollama model when available; otherwise fall back to deterministic explanations.
5. **Report** - write Markdown for humans and JSON for automation.

The deterministic scanner is intentionally kept first in the pipeline. It gives the LLM grounded evidence and prevents the model from inventing files or vulnerabilities.

## Local model choice

The default local model name is `qwen2.5-coder:7b` through Ollama because it is small enough for many laptops while still being useful for code explanation. The code does not require a model to run; if Ollama is unavailable, the agent produces a complete deterministic report.

Suggested local setup:

```bash
ollama pull qwen2.5-coder:7b
ollama serve
```

Then run the scanner without `--no-llm`.

## Knowledge sources

The embedded rule base maps findings to CWE categories and remediation guidance. In a production version I would add retrieval over:

- OWASP Top 10 and ASVS;
- CWE entries;
- Semgrep community rules;
- secure coding guides for Python, Node.js, Docker, and cloud infrastructure.

I did not add network-based retrieval to keep the case study reproducible and fully local.

## Safety boundaries

The agent is designed for owned codebases and intentionally vulnerable labs. It does not scan third-party hosts, exploit live systems, or run payloads against external services.

## Limitations

- The current verifier is heuristic, not full taint analysis.
- The rule base is small and should be expanded.
- The LLM is used for explanation, not as the source of truth.
- There is no sandboxed dynamic execution yet.

## Next improvements

- Add Semgrep-compatible rule import.
- Add lightweight taint tracking for Flask, FastAPI, Express, and SQL clients.
- Add a RAG index over OWASP/CWE content.
- Add patch suggestions with before/after diffs.
- Add SARIF output for GitHub code scanning.
