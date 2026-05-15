"""
Framework-specific detector coverage for LangChain, CrewAI, and AutoGen.

These checks complement the generic detectors with framework-aware patterns
that have clear security meaning only in a particular agent framework.
"""

from __future__ import annotations

import ast
from pathlib import Path

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity


class FrameworkSpecificDetector(BaseDetector):
    name = "framework_specific"
    description = "Detects unsafe LangChain, CrewAI, and AutoGen framework patterns"
    vuln_ids = ["VULN-003", "VULN-006", "VULN-015", "VULN-020"]
    supported_extensions = {".py"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in context.python_files():
            tree = context.get_ast(path)
            if tree is None:
                continue

            content = context.get_text(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                call_name = self._call_name(node.func)
                findings.extend(
                    self._check_langchain_call(node, call_name, content, path, context)
                )
                findings.extend(
                    self._check_crewai_call(node, call_name, content, path, context)
                )
                findings.extend(
                    self._check_autogen_call(node, call_name, content, path, context)
                )

        return findings

    # ------------------------------------------------------------------
    # LangChain
    # ------------------------------------------------------------------

    def _check_langchain_call(
        self,
        node: ast.Call,
        call_name: str,
        content: str,
        path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if (
            call_name.endswith("FAISS.load_local")
            and self._keyword_is_true(node, "allow_dangerous_deserialization")
        ):
            findings.append(
                self._make_finding(
                    vuln_id="VULN-020",
                    title="LangChain FAISS dangerous deserialization enabled",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "LangChain FAISS loading is configured with "
                        "allow_dangerous_deserialization=True. Loading a tampered vector "
                        "store can execute malicious pickle payloads."
                    ),
                    file_path=path,
                    line_number=getattr(node, "lineno", None),
                    code_snippet=self._get_snippet(content, getattr(node, "lineno", None)),
                    fix_suggestion=(
                        "Only load vector stores from trusted build artifacts. Keep "
                        "allow_dangerous_deserialization disabled, or verify and rebuild "
                        "the index from source documents before use."
                    ),
                    framework="langchain",
                    atlas_id="AML.T0010.003",
                    owasp_ref="LLM03",
                    target_root=context.target_path,
                )
            )

        if self._is_langchain_agent_call(call_name) and self._keyword_is_unbounded(
            node, "max_iterations"
        ):
            findings.append(
                self._make_finding(
                    vuln_id="VULN-006",
                    title="LangChain agent explicitly configured without iteration limits",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "A LangChain agent is configured with an unbounded "
                        "max_iterations value. Attackers can exploit recursive or "
                        "tool-heavy tasks to burn budget or keep the agent running."
                    ),
                    file_path=path,
                    line_number=getattr(node, "lineno", None),
                    code_snippet=self._get_snippet(content, getattr(node, "lineno", None)),
                    fix_suggestion=(
                        "Set a small positive max_iterations value and pair it with a "
                        "wall-clock timeout or budget limit for production agents."
                    ),
                    framework="langchain",
                    atlas_id="AML.T0053",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # CrewAI
    # ------------------------------------------------------------------

    def _check_crewai_call(
        self,
        node: ast.Call,
        call_name: str,
        content: str,
        path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if "crewai" not in content.lower():
            return findings

        is_agent_call = call_name == "Agent" or call_name.endswith(".Agent")
        if not is_agent_call:
            return findings

        if self._keyword_is_true(node, "allow_code_execution") and not self._has_safe_code_mode(
            node
        ):
            findings.append(
                self._make_finding(
                    vuln_id="VULN-003",
                    title="CrewAI code execution enabled without safe mode",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "CrewAI code execution is enabled without code_execution_mode='safe'. "
                        "If task inputs or delegated instructions are attacker-controlled, "
                        "the agent can execute code on the host."
                    ),
                    file_path=path,
                    line_number=getattr(node, "lineno", None),
                    code_snippet=self._get_snippet(content, getattr(node, "lineno", None)),
                    fix_suggestion=(
                        "Disable allow_code_execution unless it is required. When it is "
                        "required, set code_execution_mode='safe' and run the workload in "
                        "an isolated container with narrow filesystem access."
                    ),
                    framework="crewai",
                    atlas_id="AML.T0050",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        if self._keyword_is_true(node, "allow_delegation") and not self._has_crewai_boundaries(
            node
        ):
            findings.append(
                self._make_finding(
                    vuln_id="VULN-015",
                    title="CrewAI delegation enabled without runtime boundaries",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        "A CrewAI agent can delegate work to other agents, but no max_iter "
                        "or max_rpm boundary is set on the agent. Delegation expands the "
                        "trust boundary and can amplify malicious or mistaken instructions."
                    ),
                    file_path=path,
                    line_number=getattr(node, "lineno", None),
                    code_snippet=self._get_snippet(content, getattr(node, "lineno", None)),
                    fix_suggestion=(
                        "Disable allow_delegation by default. If delegation is required, "
                        "set explicit max_iter and max_rpm limits and validate delegated "
                        "task inputs before execution."
                    ),
                    framework="crewai",
                    atlas_id="AML.T0087",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # AutoGen
    # ------------------------------------------------------------------

    def _check_autogen_call(
        self,
        node: ast.Call,
        call_name: str,
        content: str,
        path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if "autogen" not in content.lower():
            return findings

        if self._is_autogen_agent_call(call_name):
            code_config = self._keyword(node, "code_execution_config")
            if self._is_true_literal(code_config):
                findings.append(
                    self._autogen_code_execution_finding(
                        path=path,
                        context=context,
                        content=content,
                        node=node,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        detail=(
                            "AutoGen code execution is enabled with code_execution_config=True, "
                            "but no Docker sandbox settings are present."
                        ),
                    )
                )
            elif isinstance(code_config, ast.Dict):
                docker_value = self._dict_value(code_config, "use_docker")
                if self._is_false_literal(docker_value):
                    findings.append(
                        self._autogen_code_execution_finding(
                            path=path,
                            context=context,
                            content=content,
                            node=node,
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            detail=(
                                "AutoGen code execution is configured with use_docker=False. "
                                "Generated code can run directly on the host."
                            ),
                        )
                    )
                elif docker_value is None:
                    findings.append(
                        self._autogen_code_execution_finding(
                            path=path,
                            context=context,
                            content=content,
                            node=node,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.SUSPECTED,
                            detail=(
                                "AutoGen code execution is configured, but no explicit "
                                "use_docker sandbox setting was found."
                            ),
                        )
                    )

        if call_name == "GroupChat" or call_name.endswith(".GroupChat"):
            if self._keyword_is_unbounded(node, "max_round"):
                findings.append(
                    self._make_finding(
                        vuln_id="VULN-006",
                        title="AutoGen group chat explicitly configured without round limits",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            "An AutoGen GroupChat is configured with an unbounded max_round "
                            "value. Multi-agent conversations can loop indefinitely or "
                            "consume unbounded tokens."
                        ),
                        file_path=path,
                        line_number=getattr(node, "lineno", None),
                        code_snippet=self._get_snippet(
                            content, getattr(node, "lineno", None)
                        ),
                        fix_suggestion=(
                            "Set max_round to a small positive value and add a timeout or "
                            "budget cap around multi-agent runs."
                        ),
                        framework="autogen",
                        atlas_id="AML.T0053",
                        owasp_ref="LLM06",
                        target_root=context.target_path,
                    )
                )

        return findings

    def _autogen_code_execution_finding(
        self,
        *,
        path: Path,
        context: ScanContext,
        content: str,
        node: ast.Call,
        severity: Severity,
        confidence: Confidence,
        detail: str,
    ) -> Finding:
        return self._make_finding(
            vuln_id="VULN-003",
            title="AutoGen code execution lacks a Docker sandbox",
            severity=severity,
            confidence=confidence,
            description=(
                f"{detail} If an attacker influences generated code, the agent can "
                "execute commands against the host environment."
            ),
            file_path=path,
            line_number=getattr(node, "lineno", None),
            code_snippet=self._get_snippet(content, getattr(node, "lineno", None)),
            fix_suggestion=(
                "Set code_execution_config={'use_docker': True, ...} and point work_dir "
                "at a disposable directory. Disable code execution for agents that do not "
                "strictly need it."
            ),
            framework="autogen",
            atlas_id="AML.T0050",
            owasp_ref="LLM06",
            target_root=context.target_path,
        )

    # ------------------------------------------------------------------
    # AST helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = FrameworkSpecificDetector._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _keyword(node: ast.Call, name: str) -> ast.expr | None:
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    @classmethod
    def _keyword_is_true(cls, node: ast.Call, name: str) -> bool:
        return cls._is_true_literal(cls._keyword(node, name))

    @classmethod
    def _keyword_is_unbounded(cls, node: ast.Call, name: str) -> bool:
        value = cls._keyword(node, name)
        if isinstance(value, ast.Constant):
            if value.value is None:
                return True
            if isinstance(value.value, int | float):
                return value.value <= 0
        return False

    @classmethod
    def _dict_value(cls, node: ast.Dict, key: str) -> ast.expr | None:
        for item_key, item_value in zip(node.keys, node.values, strict=False):
            if isinstance(item_key, ast.Constant) and item_key.value == key:
                return item_value
        return None

    @staticmethod
    def _is_true_literal(node: ast.expr | None) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    @staticmethod
    def _is_false_literal(node: ast.expr | None) -> bool:
        return isinstance(node, ast.Constant) and node.value is False

    @staticmethod
    def _is_langchain_agent_call(call_name: str) -> bool:
        return call_name in {
            "AgentExecutor",
            "initialize_agent",
            "create_react_agent",
        } or call_name.endswith(".AgentExecutor")

    @staticmethod
    def _is_autogen_agent_call(call_name: str) -> bool:
        return call_name == "UserProxyAgent" or call_name.endswith(
            (
                ".UserProxyAgent",
                ".ConversableAgent",
                ".AssistantAgent",
            )
        )

    @classmethod
    def _has_safe_code_mode(cls, node: ast.Call) -> bool:
        mode = cls._keyword(node, "code_execution_mode")
        return isinstance(mode, ast.Constant) and mode.value == "safe"

    @classmethod
    def _has_crewai_boundaries(cls, node: ast.Call) -> bool:
        return cls._has_positive_numeric_keyword(
            node, "max_iter"
        ) or cls._has_positive_numeric_keyword(node, "max_rpm")

    @classmethod
    def _has_positive_numeric_keyword(cls, node: ast.Call, name: str) -> bool:
        value = cls._keyword(node, name)
        return isinstance(value, ast.Constant) and isinstance(value.value, int) and value.value > 0

    @staticmethod
    def _get_snippet(content: str, lineno: int | None) -> str | None:
        if lineno is None or not content:
            return None
        lines = content.splitlines()
        idx = lineno - 1
        if 0 <= idx < len(lines):
            return lines[idx].strip()
        return None
