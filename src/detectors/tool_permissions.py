"""
VULN-005: Over-Permissioned Tools   — ATLAS AML.T0053 | OWASP LLM06
VULN-007: Tool Result Poisoning     — ATLAS AML.T0097 | OWASP LLM06
VULN-011: Insecure Tool Input       — ATLAS AML.T0053 | OWASP LLM06
VULN-018: Missing Human-in-the-Loop — ATLAS AML.T0053 | OWASP LLM06
VULN-020: Third-Party Plugin Risk   — ATLAS AML.T0010.003 | OWASP LLM03

Detection strategy:
  - Scan for dangerous tool registrations (shell, python_repl, subprocess)
  - Count tools per agent and flag over-permissioning
  - Check for missing input validation on tool calls
  - Check for missing HITL approval patterns
  - Flag unverified third-party plugin imports
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

# ---------------------------------------------------------------------------
# Dangerous tool names that give the agent broad system access
# ---------------------------------------------------------------------------

DANGEROUS_TOOL_NAMES = re.compile(
    r"(?i)(shell[_-]?exec|bash[_-]?exec|python[_-]?repl|"
    r"terminal|run[_-]?command|execute[_-]?code|system[_-]?command|"
    r"ShellTool|BashProcess|PythonREPLTool|process[_-]?executor)",
)

# Too many tools registered on a single agent (over-permissioning signal)
TOOL_COUNT_THRESHOLD = 10

# Patterns indicating third-party plugin imports (not core framework)
THIRD_PARTY_TOOL_PATTERNS = re.compile(
    r"(?i)(langchain[_-]?community|langchain[_-]?experimental|"
    r"crewai[_-]?tools|autogen[_-]?ext|composio|browseruse|"
    r"playwright[_-]?agent|selenium|puppeteer)",
)

# Human-in-the-loop indicators
HITL_INDICATORS = re.compile(
    r"(?i)(human[_-]?approval|require[_-]?approval|confirm[_-]?action|"
    r"human[_-]?in[_-]?the[_-]?loop|hitl|await[_-]?confirmation|"
    r"interrupt|human[_-]?feedback|ask[_-]?user)",
)

# Tool result validation indicators
TOOL_RESULT_VALIDATION = re.compile(
    r"(?i)(validate[_-]?result|sanitize[_-]?output|check[_-]?result|"
    r"result[_-]?filter|tool[_-]?output[_-]?guard)",
)

# LangChain / CrewAI / AutoGen tool registration patterns
TOOL_REGISTRATION_PATTERNS = re.compile(
    r"(?i)(tools\s*=\s*\[|@tool|Tool\(|BaseTool|StructuredTool|"
    r"FunctionTool|tool_calls|register[_-]?tool|add[_-]?tool)",
)


class ToolPermissionsDetector(BaseDetector):
    name = "tool_permissions"
    description = "Detects over-permissioned, unvalidated, or dangerous tool configurations"
    vuln_ids = ["VULN-005", "VULN-007", "VULN-011", "VULN-018", "VULN-020"]
    supported_extensions = {".py", ".yaml", ".yml", ".json"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in context.python_files():
            content = context.get_text(path)
            tree = context.get_ast(path)
            if not content:
                continue

            findings.extend(self._check_dangerous_tools(content, path, context))
            findings.extend(self._check_tool_count(tree, content, path, context))
            findings.extend(self._check_tool_result_validation(content, path, context))
            findings.extend(self._check_hitl(content, path, context))
            findings.extend(self._check_third_party_plugins(content, path, context))

        return findings

    # ------------------------------------------------------------------
    # VULN-005: Dangerous tool names
    # ------------------------------------------------------------------

    def _check_dangerous_tools(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            if DANGEROUS_TOOL_NAMES.search(line):
                findings.append(
                    self._make_finding(
                        vuln_id="VULN-005",
                        title="Dangerous tool registered: broad system access",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            "A tool that grants the agent unrestricted shell/code execution "
                            "access is registered. If an attacker influences the agent's "
                            "decision-making (e.g. via prompt injection), they can execute "
                            "arbitrary commands on the host."
                        ),
                        file_path=path,
                        line_number=lineno,
                        code_snippet=line.strip(),
                        fix_suggestion=(
                            "Avoid registering shell/REPL tools in production agents. "
                            "If code execution is required, sandbox it (E2B, Docker). "
                            "Apply an allowlist of permitted commands and validate all "
                            "tool arguments before execution."
                        ),
                        atlas_id="AML.T0053",
                        owasp_ref="LLM06",
                        target_root=context.target_path,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # VULN-005 (secondary): Too many tools — over-permissioned agent
    # ------------------------------------------------------------------

    def _check_tool_count(
        self,
        tree: ast.Module | None,
        content: str,
        path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if tree is None:
            return findings

        # Count @tool decorators and Tool( instantiations as a proxy for registered tools
        tool_count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id == "tool":
                        tool_count += 1
                    elif isinstance(decorator, ast.Attribute) and decorator.attr == "tool":
                        tool_count += 1
            # tools=[...] list assignment
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "tools":
                        if isinstance(node.value, ast.List):
                            tool_count += len(node.value.elts)

        if tool_count > TOOL_COUNT_THRESHOLD:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-005",
                    title=f"Agent has {tool_count} tools registered — excessive permissions",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        f"This agent registers {tool_count} tools, exceeding the "
                        f"recommended threshold of {TOOL_COUNT_THRESHOLD}. "
                        "Over-permissioned agents increase blast radius if compromised."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Apply the principle of least privilege. Split large tool sets across "
                        "specialized sub-agents. Only grant tools that are strictly required "
                        "for the agent's defined purpose."
                    ),
                    atlas_id="AML.T0053",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # VULN-007: Missing tool result validation
    # ------------------------------------------------------------------

    def _check_tool_result_validation(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []

        has_tools = bool(TOOL_REGISTRATION_PATTERNS.search(content))
        has_validation = bool(TOOL_RESULT_VALIDATION.search(content))

        if has_tools and not has_validation:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-007",
                    title="Tool results used without validation",
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        "Tool outputs are passed back to the LLM without validation. "
                        "An attacker who controls a tool's data source can inject "
                        "malicious instructions into the agent's context "
                        "(tool result / indirect prompt injection)."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Validate and sanitize tool outputs before feeding them back "
                        "to the LLM. Check for unexpected formats, injection patterns, "
                        "or oversized payloads. Treat tool results as untrusted input."
                    ),
                    atlas_id="AML.T0097",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # VULN-018: Missing Human-in-the-Loop
    # ------------------------------------------------------------------

    def _check_hitl(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []

        has_destructive = bool(
            re.search(
                r"(?i)(delete|remove|drop|truncate|write[_-]?file|"
                r"send[_-]?email|post[_-]?message|deploy|push|commit)",
                content,
            )
        )
        has_hitl = bool(HITL_INDICATORS.search(content))

        if has_destructive and not has_hitl:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-018",
                    title="Destructive operations without human approval",
                    severity=Severity.LOW,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        "This file contains destructive or irreversible operations "
                        "(delete, write, send, deploy) but no human-in-the-loop "
                        "approval pattern was detected. Autonomous agents that can "
                        "perform irreversible actions without confirmation pose "
                        "significant operational risk."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Add a human approval step before destructive tool calls. "
                        "In LangChain use HumanApprovalCallbackHandler. In CrewAI "
                        "use human_input=True on tasks. Consider an interrupt/resume "
                        "pattern for high-risk operations."
                    ),
                    atlas_id="AML.T0053",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # VULN-020: Third-Party Plugin Risk
    # ------------------------------------------------------------------

    def _check_third_party_plugins(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            if THIRD_PARTY_TOOL_PATTERNS.search(line) and (
                "import" in line or "from" in line
            ):
                findings.append(
                    self._make_finding(
                        vuln_id="VULN-020",
                        title="Third-party agent tool imported — review supply chain",
                        severity=Severity.LOW,
                        confidence=Confidence.SUSPECTED,
                        description=(
                            "A third-party or community tool package is imported. "
                            "These packages extend agent capabilities but introduce "
                            "supply chain risk — a malicious or compromised package "
                            "could execute arbitrary actions via the agent."
                        ),
                        file_path=path,
                        line_number=lineno,
                        code_snippet=line.strip(),
                        fix_suggestion=(
                            "Pin all third-party tool packages to exact versions. "
                            "Review the package's source and maintainer history. "
                            "Consider running dependency vulnerability scans (pip-audit, "
                            "safety). Prefer official framework-core tools over community ones."
                        ),
                        atlas_id="AML.T0010.003",
                        owasp_ref="LLM03",
                        target_root=context.target_path,
                    )
                )

        return findings
