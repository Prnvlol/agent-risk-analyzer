"""
VULN-014: Hardcoded Credentials Detector
ATLAS: AML.T0037 | OWASP: LLM02

Scans .py, .yaml, .yml, .json, .toml, .env files for
hardcoded API keys, secrets, and tokens using regex patterns.
"""

from __future__ import annotations

import re
from pathlib import Path

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

# ---------------------------------------------------------------------------
# Credential patterns  (pattern, human label, atlas_id, owasp_ref)
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS: list[tuple[str, str]] = [
    # LLM provider keys
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
    (r'sk-proj-[a-zA-Z0-9\-_]{20,}', "OpenAI Project Key"),
    (r'sk-ant-[a-zA-Z0-9\-_]{20,}', "Anthropic API Key"),
    (r'sk-or-v1-[a-zA-Z0-9\-_]{20,}', "OpenRouter API Key"),

    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?', "AWS Secret Access Key"),

    # GCP / Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'ya29\.[0-9A-Za-z\-_]+', "Google OAuth Token"),

    # GitHub
    (r'gh[pousr]_[A-Za-z0-9_]{36,}', "GitHub Token"),
    (r'github_pat_[A-Za-z0-9_]{82}', "GitHub Fine-Grained PAT"),

    # Slack
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "Slack Token"),

    # HuggingFace
    (r'hf_[A-Za-z0-9]{34,}', "HuggingFace API Token"),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key"),
    (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe Restricted Key"),

    # Generic high-signal patterns
    (
        r'(?i)(api[_-]?key|secret[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|'
        r'private[_-]?key|password|passwd|db[_-]?pass)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "Possible hardcoded secret",
    ),
]

# Compiled with their labels for fast reuse
_COMPILED = [(re.compile(pat), label) for pat, label in CREDENTIAL_PATTERNS]

# ---------------------------------------------------------------------------
# Exclusion patterns — reduce false positives
# ---------------------------------------------------------------------------

EXCLUSION_PATTERNS: list[str] = [
    r'sk-[a-z]*\.\.\.',             # Redacted examples: sk-abc...
    r'sk-xxx+',                      # Placeholder
    r'your[_-]?api[_-]?key',        # Template variable
    r'<your[_-]',                    # Placeholder bracket
    r'INSERT[_-]',                   # Template marker
    r'\$\{[^}]+\}',                  # Shell variable reference
    r'\$[A-Z_][A-Z0-9_]*',          # Env var reference ($OPENAI_API_KEY)
    r'os\.environ',                  # Python env lookup
    r'getenv\(',                     # getenv() call
    r'#.*',                          # Comments (checked per-line separately)
    # Word-boundary placeholders only — avoids matching inside real-looking keys
    r'\b(example|placeholder|dummy|changeme|xxxx|your[_-]key)\b',
]

_EXCLUSION_RE = re.compile(
    "|".join(EXCLUSION_PATTERNS), re.IGNORECASE
)

SCAN_EXTENSIONS = {".py", ".yaml", ".yml", ".json", ".toml", ".env", ".txt"}


class CredentialsDetector(BaseDetector):
    name = "credentials"
    description = "Detects hardcoded API keys and secrets in source files"
    vuln_ids = ["VULN-014"]
    supported_extensions = SCAN_EXTENSIONS

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for ext in self.supported_extensions:
            for path in context.files.get(ext, []):
                findings.extend(self._scan_file(path, context))

        return findings

    # ------------------------------------------------------------------

    def _scan_file(self, path: Path, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        content = context.get_text(path)
        if not content:
            return findings

        seen_lines: set[int] = set()  # deduplicate multiple pattern hits on same line

        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()

            # Skip blank lines, pure comments
            if not stripped or stripped.startswith("#"):
                continue

            # Skip lines that look like env-var references or placeholders
            if _EXCLUSION_RE.search(stripped):
                continue

            for pattern, label in _COMPILED:
                match = pattern.search(stripped)
                if match and lineno not in seen_lines:
                    seen_lines.add(lineno)

                    # Redact the matched value in the snippet shown
                    snippet = self._redact(stripped, match)

                    findings.append(
                        self._make_finding(
                            vuln_id="VULN-014",
                            title=f"Hardcoded credential: {label}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            description=(
                                f"A {label} appears to be hardcoded in this file. "
                                "Hardcoded secrets in source code are frequently leaked "
                                "via version control history, logs, or error messages."
                            ),
                            file_path=path,
                            line_number=lineno,
                            code_snippet=snippet,
                            fix_suggestion=(
                                "Move the secret to an environment variable and load it "
                                "with os.environ.get() or python-dotenv. Never commit "
                                "real credentials to version control."
                            ),
                            atlas_id="AML.T0037",
                            owasp_ref="LLM02",
                            target_root=context.target_path,
                        )
                    )
                    break  # one finding per line is enough

        return findings

    @staticmethod
    def _redact(line: str, match: re.Match) -> str:  # type: ignore[type-arg]
        """Replace the matched secret value with [REDACTED]."""
        start, end = match.span()
        return line[:start] + "[REDACTED]" + line[end:]
