"""Tests for grade calculation and ScanResult model."""

from __future__ import annotations

from src.models import Confidence, Finding, Severity, calculate_grade


def _finding(severity: Severity) -> Finding:
    return Finding(
        vuln_id="VULN-001",
        title="Test finding",
        severity=severity,
        confidence=Confidence.CONFIRMED,
        description="desc",
        file_path="test.py",
        fix_suggestion="fix",
        detector="test",
    )


def test_grade_a_no_findings():
    grade, score = calculate_grade([])
    assert grade == "A"
    assert score == 0


def test_grade_b_low_findings():
    findings = [_finding(Severity.LOW), _finding(Severity.LOW)]
    grade, score = calculate_grade(findings)
    assert grade == "B"
    assert score == 2


def test_grade_c_medium():
    findings = [_finding(Severity.MEDIUM)] * 4
    grade, score = calculate_grade(findings)
    assert grade == "C"
    assert score == 8


def test_grade_d_high():
    findings = [_finding(Severity.HIGH)] * 4
    grade, score = calculate_grade(findings)
    assert grade == "D"
    assert score == 20


def test_grade_f_critical():
    findings = [_finding(Severity.CRITICAL)] * 4
    grade, score = calculate_grade(findings)
    assert grade == "F"
    assert score == 40


def test_severity_weights():
    assert Severity.CRITICAL.weight == 10
    assert Severity.HIGH.weight == 5
    assert Severity.MEDIUM.weight == 2
    assert Severity.LOW.weight == 1


def test_finding_serialization():
    f = _finding(Severity.HIGH)
    data = f.model_dump()
    assert data["severity"] == "HIGH"
    assert data["confidence"] == "CONFIRMED"
