from __future__ import annotations

import argparse
from pathlib import Path

from .agent import SecurityAgent
from .models import ScanConfig
from .report import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safia-sec-agent",
        description="Run a local AI security review over an owned codebase or intentionally vulnerable lab.",
    )
    parser.add_argument("target", type=Path, help="File or directory to scan.")
    parser.add_argument("--output", type=Path, default=Path("reports/report.md"), help="Markdown report path.")
    parser.add_argument("--json", dest="json_path", type=Path, default=None, help="Optional JSON report path.")
    parser.add_argument("--no-llm", action="store_true", help="Do not try to call a local Ollama model.")
    parser.add_argument("--model", default="qwen2.5-coder:7b", help="Ollama model name to use when available.")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434/api/generate")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = args.target.resolve()
    if not target.exists():
        parser.error(f"target does not exist: {target}")

    config = ScanConfig(
        target=target,
        use_llm=not args.no_llm,
        ollama_model=args.model,
        ollama_url=args.ollama_url,
    )
    findings = SecurityAgent(config).run()
    write_markdown(findings, args.output, target=target, llm_used=config.use_llm)
    if args.json_path:
        write_json(findings, args.json_path)

    print(f"Scanned {target}")
    print(f"Findings: {len(findings)}")
    print(f"Markdown report: {args.output}")
    if args.json_path:
        print(f"JSON report: {args.json_path}")
    return 1 if any(f.severity in {"critical", "high"} for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
