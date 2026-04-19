"""
VULN-003: Unrestricted Code Execution Detector
ATLAS: AML.T0050 | OWASP: LLM06

AST-based scan for exec(), eval(), compile(), subprocess.*,
os.system(), os.popen() — and checks for sandbox indicators.
"""

from __future__ import annotations

import ast
from pathlib import Path

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

# ---------------------------------------------------------------------------
# Dangerous built-in calls
# ---------------------------------------------------------------------------

DANGEROUS_BUILTINS: dict[str, str] = {
    "exec": "Arbitrary Python code execution via exec()",
    "eval": "Arbitrary Python code execution via eval()",
    "compile": "Dynamic code compilation — can be used to execute arbitrary code",
}

# ---------------------------------------------------------------------------
# Dangerous module.attribute calls
# ---------------------------------------------------------------------------

DANGEROUS_ATTRS: dict[tuple[str, str], str] = {
    ("subprocess", "run"):    "Shell command execution via subprocess.run()",
    ("subprocess", "Popen"):  "Shell subprocess spawning via subprocess.Popen()",
    ("subprocess", "call"):   "Shell command execution via subprocess.call()",
    ("subprocess", "check_output"): "Shell command execution via subprocess.check_output()",
    ("os", "system"):  "OS shell command via os.system()",
    ("os", "popen"):   "OS shell pipe via os.popen()",
    ("os", "execv"):   "OS exec family via os.execv()",
    ("os", "execve"):  "OS exec family via os.execve()",
    ("os", "execvp"):  "OS exec family via os.execvp()",
    ("os", "spawnl"):  "OS process spawn via os.spawnl()",
    ("shlex", "split"): "Shell lexer — often paired with dangerous subprocess calls",
}

# ---------------------------------------------------------------------------
# Sandbox / safety indicators (reduce false positives for sandboxed exec)
# ---------------------------------------------------------------------------

SANDBOX_INDICATORS = {
    "e2b", "docker", "sandbox", "container", "isolat",
    "RestrictedPython", "builtins", "safe_globals",
}


class CodeExecutionDetector(BaseDetector):
    name = "code_execution"
    description = "Detects unrestricted code execution patterns via AST analysis"
    vuln_ids = ["VULN-003"]
    supported_extensions = {".py"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in context.python_files():
            tree = context.get_ast(path)
            if tree is None:
                continue

            content = context.get_text(path)
            has_sandbox = self._has_sandbox_indicator(content)

            for node in ast.walk(tree):
                finding = self._check_node(node, path, context, has_sandbox)
                if finding:
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------

    def _check_node(
        self,
        node: ast.AST,
        path: Path,
        context: ScanContext,
        has_sandbox: bool,
    ) -> Finding | None:
        if not isinstance(node, ast.Call):
            return None

        label: str | None = None
        func = node.func

        # exec(), eval(), compile() bare calls
        if isinstance(func, ast.Name) and func.id in DANGEROUS_BUILTINS:
            label = DANGEROUS_BUILTINS[func.id]

        # module.method() attribute calls
        elif isinstance(func, ast.Attribute):
            obj_name = self._resolve_name(func.value)
            key = (obj_name, func.attr)
            if key in DANGEROUS_ATTRS:
                label = DANGEROUS_ATTRS[key]

        if label is None:
            return None

        # Downgrade severity if sandbox is present in the same file
        severity = Severity.HIGH if has_sandbox else Severity.CRITICAL
        confidence = Confidence.CONFIRMED

        lineno = getattr(node, "lineno", None)
        snippet = self._get_snippet(context.get_text(path), lineno)

        return self._make_finding(
            vuln_id="VULN-003",
            title="Unrestricted code execution",
            severity=severity,
            confidence=confidence,
            description=(
                f"{label}. If an attacker can influence the input to this call "
                "(e.g. via prompt injection), they can execute arbitrary code on the host."
            ),
            file_path=path,
            line_number=lineno,
            code_snippet=snippet,
            fix_suggestion=(
                "Avoid exec/eval entirely. If code execution is required for agent tools, "
                "run it inside an isolated sandbox (E2B, Docker, RestrictedPython). "
                "Never pass unsanitized LLM output to these functions."
            ),
            atlas_id="AML.T0050",
            owasp_ref="LLM06",
            target_root=context.target_path,
        )

    @staticmethod
    def _resolve_name(node: ast.expr) -> str:
        """Best-effort name resolution for attribute access."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def _has_sandbox_indicator(content: str) -> bool:
        lower = content.lower()
        return any(ind in lower for ind in SANDBOX_INDICATORS)

    @staticmethod
    def _get_snippet(content: str, lineno: int | None) -> str | None:
        if lineno is None or not content:
            return None
        lines = content.splitlines()
        idx = lineno - 1
        if 0 <= idx < len(lines):
            return lines[idx].strip()
        return None
