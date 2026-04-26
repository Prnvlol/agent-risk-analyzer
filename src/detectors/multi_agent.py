"""
VULN-006: Unbounded Autonomy           — ATLAS AML.T0053 | OWASP LLM06
VULN-008: Memory / Context Poisoning   — ATLAS AML.T0087  | OWASP LLM04
VULN-015: Insecure Multi-Agent Trust   — ATLAS AML.T0087  | OWASP LLM06

Checks for:
  - Agents running without max_iterations / max_turns limits
  - Memory modules with no validation
  - Multi-agent setups accepting messages without trust checks
"""

from __future__ import annotations

import re
from pathlib import Path

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

# Patterns indicating an agent is created
AGENT_CREATION = re.compile(
    r"(?i)(AgentExecutor|initialize_agent|CrewAI|Crew\(|AssistantAgent|"
    r"ConversableAgent|GroupChat|autogen\.Agent|create_react_agent)",
)

# Iteration / turn limit keywords
LIMIT_INDICATORS = re.compile(
    r"(?i)(max_iterations|max_turns|max_round|max_rpm|max_steps|"
    r"iteration_limit|step_limit|recursion_limit)",
)

# Memory usage patterns
MEMORY_PATTERNS = re.compile(
    r"(?i)(ConversationBufferMemory|ConversationSummaryMemory|"
    r"VectorStoreRetrieverMemory|memory\.save|memory\.add|"
    r"agent_memory|long[_-]?term[_-]?memory|MemorySaver)",
)

# Memory validation indicators
MEMORY_VALIDATION = re.compile(
    r"(?i)(validate[_-]?memory|sanitize[_-]?memory|memory[_-]?filter|"
    r"memory[_-]?guard|verify[_-]?memory)",
)

# Trust check patterns for incoming agent messages
TRUST_INDICATORS = re.compile(
    r"(?i)(verify[_-]?sender|authenticate[_-]?agent|trust[_-]?level|"
    r"agent[_-]?signature|hmac|authorized[_-]?agents|allowed[_-]?agents)",
)


class MultiAgentDetector(BaseDetector):
    name = "multi_agent"
    description = "Detects unsafe multi-agent patterns: unbounded loops, memory poisoning, trust issues"
    vuln_ids = ["VULN-006", "VULN-008", "VULN-015"]
    supported_extensions = {".py"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in context.python_files():
            content = context.get_text(path)
            if not content:
                continue

            findings.extend(self._check_unbounded_autonomy(content, path, context))
            findings.extend(self._check_memory_poisoning(content, path, context))
            findings.extend(self._check_multi_agent_trust(content, path, context))

        return findings

    # ------------------------------------------------------------------
    # VULN-006: Unbounded Autonomy
    # ------------------------------------------------------------------

    def _check_unbounded_autonomy(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []

        has_agent = bool(AGENT_CREATION.search(content))
        has_limits = bool(LIMIT_INDICATORS.search(content))

        if has_agent and not has_limits:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-006",
                    title="Agent created without iteration or turn limits",
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        "An agent is instantiated but no max_iterations, max_turns, or "
                        "max_round limit was detected. Unbounded agents can loop indefinitely, "
                        "consume unbounded API budget, or be coerced into long task chains "
                        "by an attacker."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Set explicit limits: max_iterations in LangChain AgentExecutor, "
                        "max_rounds in AutoGen GroupChat, max_rpm in CrewAI. "
                        "Implement a timeout or budget cap as a secondary safeguard."
                    ),
                    atlas_id="AML.T0053",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # VULN-008: Memory / Context Poisoning
    # ------------------------------------------------------------------

    def _check_memory_poisoning(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []

        has_memory = bool(MEMORY_PATTERNS.search(content))
        has_validation = bool(MEMORY_VALIDATION.search(content))

        if has_memory and not has_validation:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-008",
                    title="Agent memory written without validation",
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        "Agent memory (conversation history or long-term memory) is used "
                        "but no validation of memory contents was detected. An attacker "
                        "who can influence what gets stored (via prompt injection) can "
                        "persist malicious instructions across sessions."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Validate content before writing to agent memory. Limit memory "
                        "scope to relevant context. Periodically audit or summarize memory "
                        "to prevent accumulation of injected instructions. "
                        "Consider separate memory namespaces per user session."
                    ),
                    atlas_id="AML.T0087",
                    owasp_ref="LLM04",
                    target_root=context.target_path,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # VULN-015: Insecure Multi-Agent Trust
    # ------------------------------------------------------------------

    def _check_multi_agent_trust(
        self, content: str, path: Path, context: ScanContext
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Look for multi-agent communication patterns
        has_multi_agent = bool(
            re.search(
                r"(?i)(GroupChat|initiate_chat|send[_-]?message[_-]?to|"
                r"agent[_-]?network|agent[_-]?collaboration|delegate|"
                r"CrewAI.*crew|multi[_-]?agent)",
                content,
            )
        )
        has_trust_check = bool(TRUST_INDICATORS.search(content))

        if has_multi_agent and not has_trust_check:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-015",
                    title="Multi-agent messages accepted without trust verification",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        "A multi-agent setup is detected but no agent authentication or "
                        "trust verification was found. A compromised sub-agent or an "
                        "attacker impersonating an agent can send malicious instructions "
                        "that other agents will execute without question."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Implement agent identity verification before acting on inter-agent "
                        "messages. Use signed messages (HMAC), maintain an allowlist of "
                        "trusted agent IDs, and validate message provenance. "
                        "Apply least-privilege trust levels between agents."
                    ),
                    atlas_id="AML.T0087",
                    owasp_ref="LLM06",
                    target_root=context.target_path,
                )
            )

        return findings
