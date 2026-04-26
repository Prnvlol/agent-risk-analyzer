"""
VULN-013: Missing Rate Limiting
ATLAS: AML.T0054 | OWASP: LLM10

Checks for absence of rate limiting / request throttling on
LLM API calls — a prerequisite for unbounded consumption attacks.
"""

from __future__ import annotations

import re

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

# LLM client instantiation patterns
LLM_CLIENT_PATTERNS = re.compile(
    r"(?i)(ChatOpenAI|OpenAI\(|Anthropic\(|ChatAnthropic|"
    r"AzureChatOpenAI|ChatBedrock|ChatGoogleGenerativeAI|"
    r"litellm\.completion|ollama\.chat|groq\.chat)",
)

# Rate limiting indicators
RATE_LIMIT_INDICATORS = re.compile(
    r"(?i)(rate[_-]?limit|max[_-]?rpm|max[_-]?rps|throttl|"
    r"RateLimiter|token[_-]?bucket|requests[_-]?per|calls[_-]?per|"
    r"slowapi|limits\.strategies|tenacity\.wait|backoff\.on)",
)

# Budget / cost cap indicators
BUDGET_INDICATORS = re.compile(
    r"(?i)(max[_-]?cost|budget[_-]?limit|token[_-]?limit|max[_-]?tokens|"
    r"cost[_-]?cap|spending[_-]?limit|usage[_-]?limit)",
)


class RateLimitingDetector(BaseDetector):
    name = "rate_limiting"
    description = "Detects missing rate limiting on LLM API calls"
    vuln_ids = ["VULN-013"]
    supported_extensions = {".py"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path in context.python_files():
            content = context.get_text(path)
            if not content:
                continue

            has_llm_client = bool(LLM_CLIENT_PATTERNS.search(content))
            has_rate_limit = bool(RATE_LIMIT_INDICATORS.search(content))
            has_budget = bool(BUDGET_INDICATORS.search(content))

            if has_llm_client and not has_rate_limit and not has_budget:
                findings.append(
                    self._make_finding(
                        vuln_id="VULN-013",
                        title="LLM client used without rate limiting or budget cap",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.SUSPECTED,
                        description=(
                            "An LLM API client is instantiated but no rate limiting, "
                            "RPM cap, or cost budget was detected. An attacker who can "
                            "trigger repeated LLM calls (e.g. via a public endpoint) "
                            "can cause unbounded API spend or denial-of-service."
                        ),
                        file_path=path,
                        fix_suggestion=(
                            "Add rate limiting at the API gateway or application level. "
                            "In LangChain use max_retries and per-user rate limits. "
                            "In CrewAI set max_rpm. Use a token budget to cap spending. "
                            "Consider slowapi for FastAPI or similar middleware."
                        ),
                        atlas_id="AML.T0054",
                        owasp_ref="LLM10",
                        target_root=context.target_path,
                    )
                )

        return findings
