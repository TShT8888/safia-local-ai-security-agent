from __future__ import annotations

from .models import Rule


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PY-SHELL-001",
        title="Command execution uses shell=True",
        severity="high",
        cwe="CWE-78",
        description=(
            "The code executes commands through a shell. If user-controlled data reaches "
            "this call, shell metacharacters can turn a normal command into arbitrary code execution."
        ),
        recommendation=(
            "Pass arguments as a list, keep shell=False, and validate or allowlist every external value."
        ),
        languages=("py",),
        patterns=(r"subprocess\.(run|call|check_call|check_output|Popen)\([^\n]*shell\s*=\s*True",),
        verify_terms=("request", "input", "args", "form", "query", "param"),
    ),
    Rule(
        rule_id="PY-EVAL-001",
        title="Dynamic code execution",
        severity="critical",
        cwe="CWE-94",
        description=(
            "The code invokes eval or exec. These functions execute Python code, so any attacker influence "
            "over the input can become remote code execution."
        ),
        recommendation="Replace eval/exec with a parser for the expected data shape, such as json.loads or ast.literal_eval.",
        languages=("py",),
        patterns=(r"\b(eval|exec)\s*\(",),
        verify_terms=("request", "input", "args", "form", "query", "param"),
    ),
    Rule(
        rule_id="PY-YAML-001",
        title="Unsafe YAML deserialization",
        severity="high",
        cwe="CWE-502",
        description=(
            "yaml.load can instantiate arbitrary Python objects when used with an unsafe loader."
        ),
        recommendation="Use yaml.safe_load for untrusted YAML, or explicitly set SafeLoader.",
        languages=("py",),
        patterns=(r"yaml\.load\s*\(",),
    ),
    Rule(
        rule_id="PY-PICKLE-001",
        title="Pickle deserialization of untrusted data",
        severity="critical",
        cwe="CWE-502",
        description=(
            "pickle is a code execution format, not a safe interchange format. Loading attacker-controlled "
            "pickle data can execute arbitrary code."
        ),
        recommendation="Use JSON, protobuf, or another data-only format for untrusted input.",
        languages=("py",),
        patterns=(r"pickle\.loads?\s*\(",),
    ),
    Rule(
        rule_id="PY-SQL-001",
        title="SQL query appears to be built with string interpolation",
        severity="high",
        cwe="CWE-89",
        description=(
            "The query string is assembled with f-strings, percent formatting, or concatenation near a database execute call."
        ),
        recommendation="Use parameterized queries and keep user input outside the SQL string.",
        languages=("py",),
        patterns=(
            r"execute\s*\(\s*f[\"']",
            r"execute\s*\(\s*[\"'][^\"']*%s",
            r"execute\s*\([^\n]*\+",
        ),
        verify_terms=("request", "input", "args", "form", "query", "param"),
    ),
    Rule(
        rule_id="PY-DEBUG-001",
        title="Debug mode is enabled",
        severity="medium",
        cwe="CWE-489",
        description=(
            "Debug mode can expose stack traces, interactive consoles, and sensitive runtime details."
        ),
        recommendation="Disable debug mode outside local development and gate it behind environment-specific configuration.",
        languages=("py",),
        patterns=(r"debug\s*=\s*True", r"app\.run\([^\n]*debug\s*=\s*True"),
    ),
    Rule(
        rule_id="SECRET-001",
        title="Possible hard-coded secret",
        severity="high",
        cwe="CWE-798",
        description=(
            "A token, password, API key, or private key appears to be embedded directly in source code."
        ),
        recommendation="Move secrets to a secret manager or environment variables and rotate exposed values.",
        languages=("py", "js", "ts", "json", "env", "yaml", "yml"),
        patterns=(
            r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
            r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ),
    ),
    Rule(
        rule_id="JS-XSS-001",
        title="Potential DOM XSS sink",
        severity="high",
        cwe="CWE-79",
        description=(
            "The code writes data into the DOM through innerHTML or document.write. If the data is attacker-controlled, "
            "scripts or hostile HTML can run in the victim's browser."
        ),
        recommendation="Use textContent for plain text or sanitize HTML with a maintained sanitizer before insertion.",
        languages=("js", "ts", "jsx", "tsx", "html"),
        patterns=(r"\.innerHTML\s*=", r"document\.write\s*\("),
        verify_terms=("location", "search", "hash", "input", "param", "query"),
    ),
    Rule(
        rule_id="JS-PROTO-001",
        title="Prototype pollution pattern",
        severity="high",
        cwe="CWE-1321",
        description=(
            "Merging arbitrary object keys without blocking __proto__, constructor, or prototype can pollute object prototypes."
        ),
        recommendation="Reject dangerous keys during deep merge or use a hardened merge utility.",
        languages=("js", "ts"),
        patterns=(r"for\s*\([^\)]*\s+in\s+[^\)]*\)", r"Object\.assign\s*\("),
        verify_terms=("__proto__", "constructor", "prototype", "merge", "body"),
    ),
)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
