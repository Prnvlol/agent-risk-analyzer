"""Core data models for Agent Risk Analyzer."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> int:
        """Scoring weight used in grade calculation."""
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]

    @property
    def color(self) -> str:
        """Rich color string for terminal output."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "dim",
        }[self]


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"  # Deterministic — the pattern exists verbatim
    SUSPECTED = "SUSPECTED"  # Heuristic — absence-of-safeguard or fuzzy match


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single security finding produced by a detector."""

    vuln_id: str = Field(..., description="e.g. VULN-014")
    title: str = Field(..., description="Short human-readable title")
    severity: Severity
    confidence: Confidence
    description: str = Field(..., description="What was found and why it matters")
    file_path: str = Field(..., description="Relative path to the file")
    line_number: int | None = Field(None, description="Line number (1-based)")
    code_snippet: str | None = Field(None, description="Offending code excerpt")
    fix_suggestion: str = Field(..., description="Concrete remediation advice")
    detector: str = Field(..., description="Name of the detector that found this")
    framework: str | None = Field(None, description="Framework context if applicable")

    # Community standard references
    atlas_id: str | None = Field(None, description="MITRE ATLAS technique ID")
    owasp_ref: str | None = Field(None, description="OWASP LLM Top 10 reference e.g. LLM01")


# ---------------------------------------------------------------------------
# ScanConfig
# ---------------------------------------------------------------------------


class ScanConfig(BaseModel):
    """User-supplied configuration for a scan run."""

    target_path: Path
    output_format: str = "terminal"          # terminal | json | markdown
    output_file: Path | None = None
    min_severity: Severity = Severity.LOW
    ci_mode: bool = False                    # Fail on any finding
    deep: bool = False                       # Enable optional LLM analysis
    disabled_rules: list[str] = Field(default_factory=list)
    extra_patterns: list[str] = Field(default_factory=list)
    include_suspected: bool = True


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class ScanResult(BaseModel):
    """Aggregated result of a full scan run."""

    target_path: str
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0
    framework_detected: str | None = None
    grade: str = "A"
    score: int = 0
    ara_version: str = "0.2.0"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.HIGH])


# ---------------------------------------------------------------------------
# Grade calculation
# ---------------------------------------------------------------------------


def calculate_grade(findings: list[Finding]) -> tuple[str, int]:
    """
    Return (grade, score) based on weighted severity.

    Weights:  CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
    Grades:   A=0, B=1-5, C=6-15, D=16-30, F=31+
    """
    score = sum(f.severity.weight for f in findings)

    if score == 0:
        grade = "A"
    elif score <= 5:
        grade = "B"
    elif score <= 15:
        grade = "C"
    elif score <= 30:
        grade = "D"
    else:
        grade = "F"

    return grade, score


GRADE_COLOR: dict[str, str] = {
    "A": "bold green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}
