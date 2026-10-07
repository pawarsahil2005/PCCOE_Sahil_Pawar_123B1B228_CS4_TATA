"""Hybrid multi-language code analyzer.

Pipeline:
  Source Code -> Language Detection -> Language-Specific Heuristics
  -> Generic Security Checks -> RAG Retrieval -> Gemini Analysis
  -> Finding Normalization

This module never executes, compiles, or shells out to submitted source.
Checks are conservative heuristics, not formal vulnerability proofs.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ingest import RagError, format_retrieved_rules, retrieve_rules
from gemini_client import get_ai_provider

SUPPORTED_CODE_EXTENSIONS = {
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".java": "Java",
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
}
SUPPORTED_LOG_EXTENSIONS = {".txt": "Log/Text", ".log": "Log/Text"}
ALLOWED_EXTENSIONS = set(SUPPORTED_CODE_EXTENSIONS) | set(SUPPORTED_LOG_EXTENSIONS)
LANGUAGES = ["Auto Detect", "C", "C++", "Java", "Python", "JavaScript", "TypeScript"]

C_FAMILY = {"C", "C++"}
JS_FAMILY = {"JavaScript", "TypeScript"}


@dataclass
class Finding:
    finding_id: str = ""
    category: str = "Quality"
    severity: str = "Low"
    title: str = ""
    language: str = ""
    file: str = ""
    function: str = "unknown"
    line: str = "unknown"
    code_evidence: str = ""
    description: str = ""
    root_cause: str = ""
    relevant_rule: str = ""
    suggested_fix: str = ""
    confidence: str = "Medium"
    source: str = "Rule-Based Analysis"
    human_review_required: str = "YES"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisResult:
    language: str
    files: list[str]
    findings: list[Finding]
    retrieved_rules: list[dict]
    ai_status: str
    ai_raw_text: str = ""
    warnings: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_export_dict(self) -> dict:
        return {
            "language": self.language,
            "files": self.files,
            "summary": self.summary,
            "ai_status": self.ai_status,
            "warnings": self.warnings,
            "retrieved_rules": [
                {
                    "id": r.get("id"),
                    "title": r.get("title"),
                    "languages": r.get("languages"),
                    "score": r.get("score"),
                }
                for r in self.retrieved_rules
            ],
            "findings": [f.to_dict() for f in self.findings],
            "governance": (
                "AI-generated content must be traceable to approved source material "
                "and reviewed by authorized engineering specialists before it is used "
                "for compliance, design approval, software release, or vehicle validation."
            ),
            "metrics_placeholders": {
                "debug_resolution_time": "Not measured in this prototype",
                "review_throughput": "Not measured in this prototype",
                "finding_precision": "Not measured in this prototype",
                "defect_leakage": "Not measured in this prototype",
                "security_boundary_compliance": "Not measured in this prototype",
            },
        }


def detect_language(code: str, filename: str = "", user_language: str = "Auto Detect") -> str:
    if user_language and user_language != "Auto Detect":
        return user_language

    suffix = Path(filename).suffix.lower() if filename else ""
    if suffix in SUPPORTED_CODE_EXTENSIONS:
        return SUPPORTED_CODE_EXTENSIONS[suffix]
    if suffix in SUPPORTED_LOG_EXTENSIONS:
        return "Log/Text"

    snippets = [
        (r"^\s*#include\s*<iostream>", "C++"),
        (r"\bstd::\w+", "C++"),
        (r"^\s*#include\s*<", "C"),
        (r"\bpublic\s+class\b|\bSystem\.out\.println\b", "Java"),
        (r"^\s*import\s+\w+|def\s+\w+\s*\(|^\s*from\s+\w+\s+import", "Python"),
        (r"\binterface\s+\w+|:\s*\w+\s*=|export\s+(default\s+)?function", "TypeScript"),
        (r"\bfunction\s+\w+|document\.|console\.log|const\s+\w+\s*=", "JavaScript"),
    ]
    for pattern, language in snippets:
        if re.search(pattern, code, flags=re.MULTILINE):
            return language
    return "Unknown"


def _line_number(code: str, index: int) -> int:
    return code[:index].count("\n") + 1


def _guess_function(code: str, line_no: int) -> str:
    lines = code.splitlines()
    patterns = [
        r"def\s+([A-Za-z_]\w*)\s*\(",
        r"function\s+([A-Za-z_]\w*)\s*\(",
        r"(?:public|private|protected|static|void|int|char|float|double|bool|String|Object|auto)\s+([A-Za-z_]\w*)\s*\(",
        r"([A-Za-z_]\w*)\s*=\s*(?:async\s*)?(?:function|\()",
    ]
    for i in range(min(line_no, len(lines)) - 1, -1, -1):
        for pattern in patterns:
            match = re.search(pattern, lines[i])
            if match:
                name = match.group(1)
                if name not in {"if", "for", "while", "switch", "catch", "return"}:
                    return name
    return "unknown"


def _count_globals(code: str, language: str) -> int:
    if language == "Python":
        return len(re.findall(r"^[A-Z][A-Z0-9_]{2,}\s*=", code, flags=re.MULTILINE))
    if language in JS_FAMILY:
        return len(re.findall(r"^(?:var|let|const)\s+g[A-Z]\w*", code, flags=re.MULTILINE))
    if language == "Java":
        return len(
            re.findall(
                r"public\s+static\s+\w+\s+g[A-Z_]\w*",
                code,
                flags=re.MULTILINE,
            )
        )
    if language in C_FAMILY:
        return len(
            re.findall(
                r"^(?:static\s+)?(?:const\s+)?(?:int|char|float|double|bool)\s+g_\w+",
                code,
                flags=re.MULTILINE,
            )
        )
    return 0


def _add_finding(
    findings: list[Finding],
    *,
    category: str,
    severity: str,
    title: str,
    language: str,
    filename: str,
    code: str,
    match: re.Match | None,
    description: str,
    root_cause: str,
    relevant_rule: str,
    suggested_fix: str,
    confidence: str = "Medium",
    evidence: str | None = None,
) -> None:
    if match is not None:
        line = _line_number(code, match.start())
        snippet = (match.group(0) or "").strip()
        function = _guess_function(code, line)
    else:
        line = "unknown"
        snippet = evidence or ""
        function = "unknown"
    findings.append(
        Finding(
            category=category,
            severity=severity,
            title=title,
            language=language,
            file=filename or "pasted_code",
            function=function,
            line=str(line),
            code_evidence=snippet[:400],
            description=description,
            root_cause=root_cause,
            relevant_rule=relevant_rule,
            suggested_fix=suggested_fix,
            confidence=confidence,
            source="Rule-Based Analysis",
            human_review_required="YES",
        )
    )


def _scan(code: str, pattern: str, flags=0):
    return list(re.finditer(pattern, code, flags))


def analyze_c_family(code: str, language: str, filename: str, findings: list[Finding]) -> None:
    checks = [
        (
            r"\bgets\s*\(",
            "Possible unsafe buffer operation",
            "Security",
            "High",
            "SEC-005",
            "gets() does not bound the destination buffer.",
            "Unbounded input can overflow a stack buffer.",
            "Use fgets() or another bounded input function and pass the buffer size.",
            "High",
        ),
        (
            r"\bstrcpy\s*\(",
            "Possible unsafe buffer operation",
            "Security",
            "High",
            "SEC-005",
            "strcpy() copies until a null terminator without checking destination size.",
            "The destination buffer length may be smaller than the source string.",
            "Use a bounded copy and validate the source length.",
            "High",
        ),
        (
            r"\bstrcat\s*\(",
            "Possible unsafe buffer operation",
            "Security",
            "High",
            "SEC-005",
            "strcat() may write past the end of the destination buffer.",
            "Concatenation without remaining-space checks can overflow buffers.",
            "Track remaining capacity and use a bounded concatenation API.",
            "Medium",
        ),
        (
            r"\bsprintf\s*\(",
            "Possible unsafe buffer operation",
            "Security",
            "High",
            "SEC-005",
            "sprintf() can write more bytes than the destination array holds.",
            "Format output length is not constrained by the destination size.",
            "Prefer snprintf() and pass the destination size.",
            "High",
        ),
        (
            r"scanf\s*\(\s*\"[^\"]*%s",
            "Possible unbounded scanf",
            "Security",
            "High",
            "SEC-005",
            "scanf with %s does not limit the number of characters stored.",
            "Input size is assumed rather than enforced.",
            "Use a width specifier or a safer input routine.",
            "Medium",
        ),
        (
            r"\bsystem\s*\(",
            "Potential command injection risk",
            "Security",
            "High",
            "SEC-013",
            "system() may execute a shell command. If the argument is influenced by external data, this is a possible command injection risk.",
            "Command execution is not constrained to a fixed, validated program.",
            "Avoid shell execution. Use a fixed executable and validated arguments.",
            "High",
        ),
        (
            r"\b(malloc|calloc|realloc)\s*\(",
            "Possible missing allocation check",
            "Reliability",
            "Medium",
            "SEC-011",
            "Dynamic allocation appears. Confirm the return value is checked before use.",
            "Failed allocation may leave a null pointer that is later used.",
            "Check for NULL and define fail-safe behavior.",
            "Low",
        ),
        (
            r"->",
            "Possible null pointer dereference",
            "Reliability",
            "Medium",
            "SEC-002",
            "A pointer member access was found. Confirm the pointer is validated first.",
            "A null or invalid pointer may be dereferenced.",
            "Check pointers against NULL before dereference.",
            "Low",
        ),
        (
            r"\bfopen\s*\(",
            "Possible unchecked resource handle",
            "Reliability",
            "Medium",
            "SEC-006",
            "fopen() may return NULL. Confirm the handle is checked before use.",
            "A failed open can leave a null FILE pointer.",
            "Check the fopen result and handle the error path before reading or writing.",
            "Medium",
        ),
        (
            r"(?:int|char|long|float|double)\s+[A-Za-z_]\w*\s*;",
            "Possible uninitialized variable",
            "Reliability",
            "Medium",
            "SEC-003",
            "A local scalar appears to be declared without an initializer. Confirm it is assigned before it is read.",
            "Uninitialized storage can produce non-deterministic values.",
            "Initialize at declaration. Educational MISRA-oriented guidance recommends definite assignment before use.",
            "Low",
        ),
        (
            r"\[\s*[A-Za-z_]\w*\s*\]",
            "Possible array bounds issue",
            "Reliability",
            "Medium",
            "SEC-001",
            "An array is indexed with a variable. Confirm the index is checked against the actual length.",
            "An unchecked index may read or write outside the allocated range.",
            "Validate 0 <= index < length before access.",
            "Low",
        ),
        (
            r"2147483647|\bINT_MAX\b",
            "Suspicious arithmetic near integer limit",
            "Reliability",
            "Medium",
            "SEC-004",
            "Arithmetic involving INT_MAX or 2147483647 can overflow.",
            "Integer overflow can produce invalid sizes or wrap to negative values.",
            "Check ranges before addition and use a wider type when needed.",
            "Medium",
        ),
    ]
    for pattern, title, category, severity, rule, desc, root, fix, conf in checks:
        for match in _scan(code, pattern):
            _add_finding(
                findings,
                category=category,
                severity=severity,
                title=title,
                language=language,
                filename=filename,
                code=code,
                match=match,
                description=desc,
                root_cause=root,
                relevant_rule=rule,
                suggested_fix=fix,
                confidence=conf,
            )

    if re.search(r"\bmalloc\s*\(", code) and not re.search(r"\bfree\s*\(", code):
        _add_finding(
            findings,
            category="Reliability",
            severity="Medium",
            title="Possible resource leak",
            language=language,
            filename=filename,
            code=code,
            match=re.search(r"\bmalloc\s*\(", code),
            description="malloc appears without a matching free in this file. This may be a leak or ownership may be elsewhere.",
            root_cause="Resource lifetime is not obvious in the submitted fragment.",
            relevant_rule="SEC-006",
            suggested_fix="Pair every allocation with a release path, including error returns.",
            confidence="Low",
        )
    if language == "C++" and re.search(r"\bnew\s+", code) and not re.search(r"\bdelete\b", code):
        _add_finding(
            findings,
            category="Reliability",
            severity="Medium",
            title="Possible resource leak",
            language=language,
            filename=filename,
            code=code,
            match=re.search(r"\bnew\s+", code),
            description="new appears without delete in this file. Ownership may be missing or hidden.",
            root_cause="Manual resource management is incomplete in the visible code.",
            relevant_rule="SEC-006",
            suggested_fix="Prefer RAII (unique_ptr/shared_ptr) or match every new with delete.",
            confidence="Low",
        )


def analyze_java(code: str, filename: str, findings: list[Finding]) -> None:
    checks = [
        (
            r"ObjectInputStream|\.readObject\s*\(",
            "Possible unsafe deserialization",
            "Security",
            "High",
            "SEC-014",
            "Java object deserialization can instantiate unexpected types if the stream is untrusted.",
            "Untrusted serialized data may be reconstructed without an allow-list.",
            "Avoid native Java serialization for untrusted data. Prefer schema-checked formats.",
        ),
        (
            r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder",
            "Potential command injection risk",
            "Security",
            "High",
            "SEC-013",
            "Process execution APIs can run OS commands. Confirm arguments are not externally controlled.",
            "External input may influence the command line.",
            "Use a fixed executable and a validated argument list. Do not concatenate a shell string.",
        ),
        (
            r"catch\s*\([^)]*\)\s*\{\s*\}",
            "Possible swallowed exception",
            "Reliability",
            "Medium",
            "SEC-018",
            "An empty catch block may hide faults.",
            "Errors are discarded instead of handled.",
            "Catch specific exceptions and handle or log them without exposing secrets.",
        ),
        (
            r"\bnull\b",
            "Possible null risk",
            "Reliability",
            "Low",
            "SEC-002",
            "A null literal is present. Confirm objects are validated before use.",
            "A later dereference may throw NullPointerException.",
            "Validate references and avoid returning null when an empty value is clearer.",
        ),
        (
            r"(Statement\s+\w+\s*=|executeQuery\s*\(|\"SELECT\s+[^\"]*\"\s*\+)",
            "Possible SQL injection indicator",
            "Security",
            "High",
            "SEC-015",
            "SQL appears to be concatenated. This is a possible injection risk if input is untrusted.",
            "Query structure may be influenced by external data.",
            "Use parameterized queries (PreparedStatement) and validate input.",
        ),
    ]
    for pattern, title, category, severity, rule, desc, root, fix in checks:
        for match in _scan(code, pattern, flags=re.IGNORECASE):
            _add_finding(
                findings,
                category=category,
                severity=severity,
                title=title,
                language="Java",
                filename=filename,
                code=code,
                match=match,
                description=desc,
                root_cause=root,
                relevant_rule=rule,
                suggested_fix=fix,
            )


def analyze_python(code: str, filename: str, findings: list[Finding]) -> None:
    checks = [
        (
            r"\beval\s*\(",
            "Possible dangerous dynamic execution",
            "Security",
            "High",
            "SEC-015",
            "eval() executes a Python expression. If the argument is untrusted, this is a possible code-execution risk.",
            "Dynamic evaluation is not constrained to a safe grammar.",
            "Avoid eval. Parse data with ast.literal_eval or a dedicated parser when needed.",
        ),
        (
            r"\bexec\s*\(",
            "Possible dangerous dynamic execution",
            "Security",
            "High",
            "SEC-015",
            "exec() can run arbitrary Python statements.",
            "Untrusted code may be interpreted.",
            "Do not exec untrusted strings. Use explicit logic instead.",
        ),
        (
            r"subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True",
            "Potential command injection risk",
            "Security",
            "High",
            "SEC-013",
            "User-controlled or external data passed with shell=True is a possible command injection risk.",
            "The application does not sufficiently constrain command input.",
            "Avoid shell execution with untrusted input. Pass a fixed command and validated arguments separately.",
        ),
        (
            r"\bos\.system\s*\(",
            "Potential command injection risk",
            "Security",
            "High",
            "SEC-013",
            "os.system() invokes a shell. Confirm the command is not built from untrusted input.",
            "Shell metacharacters may change command meaning.",
            "Use subprocess with a list of arguments and shell=False.",
        ),
        (
            r"pickle\.loads|yaml\.load\s*\(|marshal\.loads",
            "Possible unsafe deserialization",
            "Security",
            "High",
            "SEC-014",
            "These loaders can execute unexpected object constructors on untrusted data.",
            "Serialized payloads are treated as trusted objects.",
            "Prefer json with schema validation, or a safe loader such as yaml.safe_load.",
        ),
        (
            r"except\s*:",
            "Possible exception handling problem",
            "Reliability",
            "Medium",
            "SEC-018",
            "A bare except clause can hide unexpected faults, including system-exiting exceptions in some cases.",
            "Errors are caught too broadly.",
            "Catch specific exception types and handle them explicitly.",
        ),
        (
            r"open\s*\(",
            "Possible resource handling gap",
            "Reliability",
            "Low",
            "SEC-006",
            "open() is used. Confirm the file is closed on all paths, preferably with a context manager.",
            "File handles may leak if exceptions occur.",
            "Use `with open(...) as handle:` so the file is closed automatically.",
        ),
        (
            r"['\"]SELECT\s+[^'\"]*['\"]\s*\+",
            "Possible SQL injection indicator",
            "Security",
            "High",
            "SEC-015",
            "SQL appears to be concatenated with other data. This is a possible injection risk if that data is untrusted.",
            "Query structure may be influenced by external input.",
            "Use parameterized queries and validate input length and type.",
        ),
    ]
    for pattern, title, category, severity, rule, desc, root, fix in checks:
        for match in _scan(code, pattern):
            _add_finding(
                findings,
                category=category,
                severity=severity,
                title=title,
                language="Python",
                filename=filename,
                code=code,
                match=match,
                description=desc,
                root_cause=root,
                relevant_rule=rule,
                suggested_fix=fix,
                confidence="High" if "eval" in title.lower() or "command" in title.lower() else "Medium",
            )


def analyze_js_family(code: str, language: str, filename: str, findings: list[Finding]) -> None:
    checks = [
        (
            r"\beval\s*\(",
            "Possible dangerous dynamic execution",
            "Security",
            "High",
            "SEC-015",
            "eval() interprets a string as code. This is a possible injection risk if the string is untrusted.",
            "Dynamic JavaScript execution is not sandboxed here.",
            "Avoid eval. Use JSON.parse for data and explicit functions for behavior.",
        ),
        (
            r"\.innerHTML\s*=",
            "Possible DOM injection indicator",
            "Security",
            "High",
            "SEC-015",
            "Assigning to innerHTML can insert markup. If the value is untrusted, this is a possible XSS risk.",
            "HTML is constructed from data that may not be encoded.",
            "Use textContent or a vetted sanitizer. Encode untrusted data for HTML context.",
        ),
        (
            r"document\.write\s*\(",
            "Possible DOM injection indicator",
            "Security",
            "Medium",
            "SEC-015",
            "document.write can insert markup into the page.",
            "Untrusted strings may be interpreted as HTML/script.",
            "Avoid document.write; update the DOM with safe APIs.",
        ),
        (
            r"child_process\.exec|execSync\s*\(",
            "Potential command injection risk",
            "Security",
            "High",
            "SEC-013",
            "A process execution API is used. Confirm the command is not built from untrusted input.",
            "External data may reach a shell.",
            "Use execFile/spawn with an argument array and a fixed executable.",
        ),
        (
            r"fetch\s*\(\s*['\"]http://",
            "Possible insecure API usage",
            "Security",
            "Medium",
            "SEC-020",
            "An HTTP URL is used. Sensitive data sent without TLS may be exposed.",
            "Transport protection may be missing.",
            "Use HTTPS and validate the endpoint against an allow-list.",
        ),
        (
            r"localStorage\.setItem|sessionStorage\.setItem",
            "Possible sensitive data handling issue",
            "Security",
            "Medium",
            "SEC-017",
            "Browser storage is not a secure secret store.",
            "Tokens in web storage can be read by script on the same origin.",
            "Avoid storing long-lived secrets in localStorage. Use httpOnly cookies if appropriate.",
        ),
        (
            r"['\"]SELECT\s+[^'\"]*['\"]\s*\+",
            "Possible SQL injection indicator",
            "Security",
            "High",
            "SEC-015",
            "SQL appears to be concatenated with other data. This is a possible injection risk if that data is untrusted.",
            "Query structure may be influenced by external input.",
            "Use parameterized queries or a query builder and validate input.",
        ),
    ]
    for pattern, title, category, severity, rule, desc, root, fix in checks:
        for match in _scan(code, pattern):
            _add_finding(
                findings,
                category=category,
                severity=severity,
                title=title,
                language=language,
                filename=filename,
                code=code,
                match=match,
                description=desc,
                root_cause=root,
                relevant_rule=rule,
                suggested_fix=fix,
            )


def analyze_generic(code: str, language: str, filename: str, findings: list[Finding]) -> None:
    secret_patterns = [
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", "Possible hardcoded password", "SEC-012"),
        (r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Possible hardcoded API key", "SEC-012"),
        (r"(?i)(token|auth[_-]?token|bearer)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Possible hardcoded token", "SEC-012"),
        (r"(?i)(AKIA[0-9A-Z]{8,}|sk-live-[A-Za-z0-9_-]+)", "Possible hardcoded secret", "SEC-012"),
    ]
    for pattern, title, rule in secret_patterns:
        for match in _scan(code, pattern):
            _add_finding(
                findings,
                category="Security",
                severity="High",
                title=title,
                language=language,
                filename=filename,
                code=code,
                match=match,
                description="A secret-like literal appears in source. This is a possible credential leak if the value is real.",
                root_cause="Sensitive values are embedded in the repository text instead of a secret store.",
                relevant_rule=rule,
                suggested_fix="Remove the secret, rotate it if it was real, and load credentials from a controlled environment.",
                confidence="High",
            )

    for match in _scan(
        code,
        r"(?i)(log|print|printf|console\.log|System\.out\.println|logging\.\w+)\s*\([^;]*\b(password|token|api[_-]?key|secret|authorization)\b",
    ):
        _add_finding(
            findings,
            category="Security",
            severity="High",
            title="Possible sensitive information in logs",
            language=language,
            filename=filename,
            code=code,
            match=match,
            description="A log or print statement appears to include a secret-related name.",
            root_cause="Diagnostic output may expose credentials or tokens.",
            relevant_rule="SEC-019",
            suggested_fix="Redact secrets from logs. Log identifiers, not credential values.",
            confidence="Medium",
        )

    if re.search(r"(?i)(request|user_input|argv|input\(|scanf|args\[)", code) and not re.search(
        r"(?i)(validate|sanitize|allowlist|whitelist|isinstance|strlen|length)",
        code,
    ):
        _add_finding(
            findings,
            category="Security",
            severity="Medium",
            title="Possible missing input validation",
            language=language,
            filename=filename,
            code=code,
            match=re.search(r"(?i)(request|user_input|argv|input\(|scanf|args\[)", code),
            description="External input appears to be used without an obvious validation routine in this fragment.",
            root_cause="Trust-boundary checks are not visible in the submitted code.",
            relevant_rule="SEC-007",
            suggested_fix="Validate type, length, range, and encoding at the trust boundary before use.",
            confidence="Low",
        )

    if re.search(r"\b(goto)\b", code):
        for match in _scan(code, r"\bgoto\b"):
            _add_finding(
                findings,
                category="Quality",
                severity="Low",
                title="Dangerous or unstructured control flow",
                language=language,
                filename=filename,
                code=code,
                match=match,
                description="goto was found. Educational MISRA-oriented guidance prefers structured control flow. This is not an official MISRA compliance result.",
                root_cause="Unstructured jumps make review and error-path analysis harder.",
                relevant_rule="SEC-009",
                suggested_fix="Replace goto with structured error handling where practical.",
                confidence="Medium",
            )

    global_count = _count_globals(code, language)
    if global_count >= 3:
        _add_finding(
            findings,
            category="Quality",
            severity="Low",
            title="Excessive global state",
            language=language,
            filename=filename,
            code=code,
            match=None,
            description=f"This file appears to declare about {global_count} global-style variables.",
            root_cause="Shared mutable state increases coupling and review difficulty.",
            relevant_rule="SEC-008",
            suggested_fix="Limit globals and pass state explicitly through functions or encapsulated modules.",
            confidence="Low",
            evidence=f"{global_count} global-style names",
        )

    if language in C_FAMILY and re.search(r"\bint\s+main\s*\(", code) and not re.search(r"\breturn\b", code):
        _add_finding(
            findings,
            category="Quality",
            severity="Low",
            title="Possible missing return in main",
            language=language,
            filename=filename,
            code=code,
            match=re.search(r"\bint\s+main\s*\(", code),
            description="main may not return a status on all paths.",
            root_cause="Caller-visible status may be undefined.",
            relevant_rule="SEC-011",
            suggested_fix="Return an explicit status code from main.",
            confidence="Low",
        )


def analyze_logs(text: str, filename: str, findings: list[Finding]) -> None:
    """Interpret compiler / static-analysis log lines without executing anything."""
    patterns = [
        r"(?i)(warning|error|note):\s*(.+)",
        r"(?i)(C\d{4}|MISRA|cert|clang-tidy|spotbugs|pmd|bandit)[:\s].+",
        r".+:\d+:\d+:\s*(warning|error).*",
    ]
    hits = 0
    for pattern in patterns:
        for match in _scan(text, pattern):
            hits += 1
            line = _line_number(text, match.start())
            findings.append(
                Finding(
                    category="Reliability",
                    severity="Medium" if "error" not in match.group(0).lower() else "High",
                    title="Compiler or static-analysis warning explanation",
                    language="Log/Text",
                    file=filename or "uploaded_log",
                    function="n/a",
                    line=str(line),
                    code_evidence=match.group(0)[:400],
                    description=(
                        "This looks like a compiler or static-analysis diagnostic. "
                        "The assistant explains it for reviewers; it does not replace the original tool."
                    ),
                    root_cause="The referenced source likely violates a type, bounds, or style rule reported by another tool.",
                    relevant_rule="SEC-011",
                    suggested_fix="Open the cited file and line, confirm the diagnostic, and apply a minimal fix under human review.",
                    confidence="Medium",
                    source="Rule-Based Analysis (log interpretation)",
                    human_review_required="YES",
                )
            )
            if hits >= 20:
                return
    if hits == 0:
        findings.append(
            Finding(
                category="Quality",
                severity="Low",
                title="Log text did not match common compiler formats",
                language="Log/Text",
                file=filename or "uploaded_log",
                function="n/a",
                line="unknown",
                code_evidence=text[:200],
                description="The file was treated as a log/text artifact. No common compiler warning pattern was recognized.",
                root_cause="The log format may be vendor-specific.",
                relevant_rule="SEC-011",
                suggested_fix="Paste a few representative warning lines or upload the original source as well.",
                confidence="Low",
                source="Rule-Based Analysis (log interpretation)",
                human_review_required="YES",
            )
        )


def summarize_code(code: str, language: str) -> str:
    functions = []
    for pattern in (
        r"def\s+([A-Za-z_]\w*)\s*\(",
        r"function\s+([A-Za-z_]\w*)\s*\(",
        r"(?:public|private|protected|static|void|int|char|bool|String)\s+([A-Za-z_]\w*)\s*\(",
    ):
        functions.extend(re.findall(pattern, code))
    unique = []
    for name in functions:
        if name not in unique and name not in {"if", "for", "while", "switch"}:
            unique.append(name)
    loc = len([ln for ln in code.splitlines() if ln.strip()])
    preview = ", ".join(unique[:8]) or "no obvious functions"
    return f"{language} fragment with about {loc} non-empty lines. Visible functions/methods: {preview}."


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen = set()
    unique = []
    for item in findings:
        key = (item.title, item.file, item.line, item.code_evidence[:80])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _assign_ids(findings: list[Finding]) -> None:
    for i, item in enumerate(findings, start=1):
        item.finding_id = f"F{i:03d}"


def _severity_rank(severity: str) -> int:
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    return order.get(severity.title(), 4)


def _build_rag_query(code: str, language: str, findings: list[Finding]) -> str:
    titles = " ".join(sorted({f.title for f in findings[:12]}))
    rules = " ".join(sorted({f.relevant_rule for f in findings[:12] if f.relevant_rule}))
    snippet = " ".join(code.split()[:80])
    return f"{language} secure code review {titles} {rules} {snippet}"


def _cross_file_notes(files: list[dict]) -> str:
    names = [item.get("filename", "") for item in files]
    notes = [f"Uploaded files: {', '.join(names)}"]
    for item in files:
        name = item.get("filename", "")
        stem = Path(name).stem
        others = [n for n in names if n != name]
        for other in others:
            if stem and stem.lower() in item.get("code", "").lower():
                notes.append(f"{name} may reference related module {other}.")
    return "\n".join(notes)


def analyze_source(
    files: list[dict],
    user_language: str = "Auto Detect",
    top_k: int = 3,
    use_ai: bool = True,
) -> AnalysisResult:
    """files: list of {filename, code} dicts. Never executed."""
    warnings: list[str] = []
    findings: list[Finding] = []
    detected_languages = []

    if not files:
        raise ValueError("No source was provided. Paste code or upload a supported file.")

    for item in files:
        filename = item.get("filename") or "pasted_code"
        code = item.get("code") or ""
        if not code.strip():
            warnings.append(f"{filename}: empty file skipped.")
            continue
        language = detect_language(code, filename, user_language)
        detected_languages.append(language)

        if language == "Log/Text":
            analyze_logs(code, filename, findings)
            continue

        if language in C_FAMILY:
            analyze_c_family(code, language, filename, findings)
        elif language == "Java":
            analyze_java(code, filename, findings)
        elif language == "Python":
            analyze_python(code, filename, findings)
        elif language in JS_FAMILY:
            analyze_js_family(code, language, filename, findings)

        analyze_generic(code, language, filename, findings)

        findings.append(
            Finding(
                category="Quality",
                severity="Low",
                title="Function/module summary",
                language=language,
                file=filename,
                function="module",
                line="n/a",
                code_evidence=summarize_code(code, language),
                description="This is a high-level summary to help reviewers navigate the fragment. It is not a defect claim.",
                root_cause="n/a",
                relevant_rule="SEC-009",
                suggested_fix="Use the summary only as orientation; confirm behavior by reading the source.",
                confidence="Medium",
                source="Rule-Based Analysis",
                human_review_required="YES",
            )
        )

    findings = _dedupe_findings(findings)
    primary_language = detected_languages[0] if detected_languages else "Unknown"
    if len(set(detected_languages)) > 1:
        primary_language = "Mixed (" + ", ".join(sorted(set(detected_languages))) + ")"

    combined_code = "\n\n".join(
        f"// FILE: {item.get('filename')}\n{item.get('code', '')}" for item in files
    )
    extra_context = _cross_file_notes(files)

    retrieved_rules: list[dict] = []
    try:
        retrieved_rules = retrieve_rules(
            _build_rag_query(combined_code, primary_language, findings),
            top_k=top_k,
        )
        for finding in findings:
            if finding.source.startswith("Rule-Based") and retrieved_rules:
                finding.source = "Rule-Based Analysis + RAG"
    except RagError as exc:
        warnings.append(str(exc))

    ai_status = "Gemini skipped — showing deterministic analysis."
    ai_raw = ""
    ai_findings: list[dict] = []
    if use_ai:
        provider = get_ai_provider()
        result = provider.analyze(
            language=primary_language,
            source_code=combined_code,
            rule_based_findings=[f.to_dict() for f in findings if f.title != "Function/module summary"],
            retrieved_rules=format_retrieved_rules(retrieved_rules),
            extra_context=extra_context,
        )
        ai_status = result.status
        ai_raw = result.raw_text
        ai_findings = result.findings
        if not result.available:
            ai_status = f"Gemini unavailable — showing deterministic analysis. {result.status}"
            warnings.append(ai_status)
        elif result.error == "invalid_json" and result.raw_text:
            warnings.append("Gemini JSON could not be validated; raw text is shown in AI Analysis Status.")

        existing_keys = {(f.title.lower(), f.file, str(f.line)) for f in findings}
        for item in ai_findings:
            title = item.get("title") or "AI finding"
            key = (title.lower(), files[0].get("filename", "pasted_code"), str(item.get("line")))
            if any(title.lower() == f.title.lower() for f in findings):
                continue
            if key in existing_keys:
                continue
            findings.append(
                Finding(
                    category=item.get("category") or "Quality",
                    severity=(item.get("severity") or "Low").title(),
                    title=title,
                    language=primary_language,
                    file=files[0].get("filename") or "pasted_code",
                    function=item.get("function") or "unknown",
                    line=str(item.get("line") or "unknown"),
                    code_evidence=item.get("code_evidence") or "",
                    description=item.get("description") or "",
                    root_cause=item.get("root_cause") or "",
                    relevant_rule=item.get("relevant_rule") or "",
                    suggested_fix=item.get("suggested_fix") or "",
                    confidence=item.get("confidence") or "Medium",
                    source="Rule-Based Analysis + RAG + Gemini",
                    human_review_required="YES",
                )
            )
    else:
        ai_status = "Gemini disabled by the user — showing deterministic analysis."

    defect_findings = [f for f in findings if f.title != "Function/module summary"]
    defect_findings.sort(key=lambda f: _severity_rank(f.severity))
    summaries = [f for f in findings if f.title == "Function/module summary"]
    findings = defect_findings + summaries
    _assign_ids(findings)

    summary = {
        "High": sum(1 for f in defect_findings if f.severity.lower() == "high"),
        "Medium": sum(1 for f in defect_findings if f.severity.lower() == "medium"),
        "Low": sum(1 for f in defect_findings if f.severity.lower() == "low"),
        "Total": len(defect_findings),
    }

    return AnalysisResult(
        language=primary_language,
        files=[item.get("filename") or "pasted_code" for item in files],
        findings=findings,
        retrieved_rules=retrieved_rules,
        ai_status=ai_status,
        ai_raw_text=ai_raw,
        warnings=warnings,
        summary=summary,
    )
