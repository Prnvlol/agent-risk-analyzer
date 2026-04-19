"""
VULN-012: Sensitive Data in Logs   — ATLAS AML.T0048 | OWASP LLM02
VULN-016: Verbose Error Messages   — ATLAS AML.T0048 | OWASP LLM02

Detects:
  - API keys / secrets logged via print() or logging.*
  - Verbose tracebacks / stack traces exposed to users
  - LLM prompts and responses logged in plaintext
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

# Sensitive variable name patterns (likely to contain secrets)
SENSITIVE_VAR_NAMES = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|credential|auth|private[_-]?key|"
    r"system[_-]?prompt|prompt|llm[_-]?response|model[_-]?response)",
)

# Logging call patterns (AST names)
LOG_CALL_NAMES = {"print", "debug", "info", "warning", "error", "critical", "exception", "log"}

# Verbose error patterns in code
VERBOSE_ERROR_PATTERNS = re.compile(
    r"(?i)(traceback\.print_exc|traceback\.format_exc|sys\.exc_info|"
    r"raise.*from\s+e|print\(e\)|print\(err\)|print\(error\)|"
    r"str\(exception\)|str\(e\).*response|json\.dumps.*error)",
)

# Patterns that indicate structured/safe logging (less likely to leak)
SAFE_LOGGING_INDICATORS = re.compile(
    r"(?i)(logging\.basicConfig.*WARNING|log[_-]?level.*WARNING|"
    r"SensitiveFormatter|mask[_-]?secrets|redact|sanitize[_-]?log)",
)


class LoggingDetector(BaseDetector):
    name = "logging_detector"
    description = "Detects sensitive data in logs and verbose error exposure"
    vuln_ids = ["VULN-012", "VULN-016"]
    supported_extensions = {".py"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in context.python_files():
            tree = context.get_ast(path)
            content = context.get_text(path)
            if not content:
                continue

            findings.extend(self._check_sensitive_logging(tree, path, content, context))
            findings.extend(self._check_verbose_errors(content, path, context))

        return findings

    # ------------------------------------------------------------------
    # VULN-012: Sensitive data in logs
    # ------------------------------------------------------------------

    def _check_sensitive_logging(
        self,
        tree: ast.Module | None,
        path: Path,
        content: str,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if tree is None:
            return findings

        lines = content.splitlines()
        has_safe_logging = bool(SAFE_LOGGING_INDICATORS.search(content))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            call_name = ""

            # print(...)
            if isinstance(func, ast.Name) and func.id in LOG_CALL_NAMES:
                call_name = func.id
            # logging.info(...), logger.debug(...), etc.
            elif isinstance(func, ast.Attribute) and func.attr in LOG_CALL_NAMES:
                call_name = func.attr

            if not call_name:
                continue

            # Check if any argument is a sensitive variable
            for arg in node.args:
                arg_name = self._extract_name(arg)
                if arg_name and SENSITIVE_VAR_NAMES.match(arg_name):
                    lineno = getattr(node, "lineno", None)
                    snippet = lines[lineno - 1].strip() if lineno and lineno <= len(lines) else None

                    severity = Severity.HIGH if not has_safe_logging else Severity.MEDIUM

                    findings.append(
                        self._make_finding(
                            vuln_id="VULN-012",
                            title=f"Sensitive variable '{arg_name}' passed to {call_name}()",
                            severity=severity,
                            confidence=Confidence.SUSPECTED,
                            description=(
                                f"The variable '{arg_name}' — which likely contains sensitive "
                                f"data (API key, secret, prompt, or token) — is passed directly "
                                f"to {call_name}(). This may expose secrets in log files, "
                                "stdout, or observability platforms."
                            ),
                            file_path=path,
                            line_number=lineno,
                            code_snippet=snippet,
                            fix_suggestion=(
                                "Never log raw secrets, API keys, or system prompts. "
                                "Use a log sanitizer/formatter that redacts sensitive fields. "
                                "Set log level to WARNING+ in production. "
                                "Consider structured logging with field-level masking."
                            ),
                            atlas_id="AML.T0048",
                            owasp_ref="LLM02",
                            target_root=context.target_path,
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # VULN-016: Verbose error messages
    # ------------------------------------------------------------------

    def _check_verbose_errors(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            if VERBOSE_ERROR_PATTERNS.search(line):
                findings.append(
                    self._make_finding(
                        vuln_id="VULN-016",
                        title="Verbose error / traceback may be exposed",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            "A full traceback, exception string, or error detail is "
                            "returned or printed. Verbose error messages can leak "
                            "internal implementation details, file paths, or credentials "
                            "to end users or LLM outputs."
                        ),
                        file_path=path,
                        line_number=lineno,
                        code_snippet=line.strip(),
                        fix_suggestion=(
                            "Return generic error messages to users. Log full tracebacks "
                            "server-side at DEBUG level only. Use a centralized error "
                            "handler that sanitizes exceptions before surfacing them."
                        ),
                        atlas_id="AML.T0048",
                        owasp_ref="LLM02",
                        target_root=context.target_path,
                    )
                )

        return findings

    @staticmethod
    def _extract_name(node: ast.expr) -> str | None:
        """Extract variable name from an AST expression node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None
