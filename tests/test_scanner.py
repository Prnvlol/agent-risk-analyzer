"""Tests for the Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path

from src.models import ScanConfig, Severity
from src.scanner import Scanner


def _scanner(tmp_path: Path, **kwargs) -> Scanner:
    config = ScanConfig(
        target_path=tmp_path,
        min_severity=Severity.LOW,
        **kwargs,
    )
    return Scanner(config)


def test_scan_empty_directory(tmp_path):
    result = _scanner(tmp_path).run()
    assert result.grade == "A"
    assert result.score == 0
    assert result.findings == []


def test_scan_detects_hardcoded_key(tmp_path):
    (tmp_path / "agent.py").write_text(
        'API_KEY = "sk-abc123fakekey1234567890abcdefghijklmnop"'
    )
    result = _scanner(tmp_path).run()
    assert len(result.findings) >= 1
    assert result.grade != "A"


def test_scan_detects_exec(tmp_path):
    (tmp_path / "tools.py").write_text("exec(user_input)")
    result = _scanner(tmp_path).run()
    vuln_ids = [f.vuln_id for f in result.findings]
    assert "VULN-003" in vuln_ids


def test_scan_files_counted(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("y = 2")
    result = _scanner(tmp_path).run()
    assert result.files_scanned >= 2


def test_min_severity_filter(tmp_path):
    (tmp_path / "agent.py").write_text("exec(user_input)")
    # Only show CRITICAL findings
    config = ScanConfig(
        target_path=tmp_path,
        min_severity=Severity.CRITICAL,
    )
    result = Scanner(config).run()
    for f in result.findings:
        assert f.severity == Severity.CRITICAL


def test_disabled_rule(tmp_path):
    (tmp_path / "agent.py").write_text(
        'API_KEY = "sk-abc123fakekey1234567890abcdefghijklmnop"'
    )
    config = ScanConfig(
        target_path=tmp_path,
        min_severity=Severity.LOW,
        disabled_rules=["VULN-014"],
    )
    result = Scanner(config).run()
    vuln_ids = [f.vuln_id for f in result.findings]
    assert "VULN-014" not in vuln_ids


def test_scan_vulnerable_example(tmp_path):
    """Scan the bundled vulnerable_agent example and expect grade F."""
    examples_dir = Path(__file__).parent.parent / "examples" / "vulnerable_agent"
    if not examples_dir.exists():
        return  # Skip if example doesn't exist yet

    config = ScanConfig(target_path=examples_dir, min_severity=Severity.LOW)
    result = Scanner(config).run()

    assert result.findings, "Vulnerable example should produce findings"
    assert result.grade in ("D", "F"), f"Expected D or F, got {result.grade}"
