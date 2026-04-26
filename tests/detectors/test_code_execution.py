"""Tests for CodeExecutionDetector."""

from __future__ import annotations

import pytest

from src.detectors.code_execution import CodeExecutionDetector
from src.models import Severity
from tests.conftest import make_context


@pytest.fixture
def detector():
    return CodeExecutionDetector()


def test_detects_exec(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": "exec(user_code)"
    })
    findings = detector.scan(ctx)
    assert len(findings) == 1
    assert findings[0].vuln_id == "VULN-003"
    assert findings[0].severity == Severity.CRITICAL


def test_detects_eval(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": "result = eval(user_input)"
    })
    findings = detector.scan(ctx)
    assert any(f.vuln_id == "VULN-003" for f in findings)


def test_detects_os_system(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "tools.py": "import os\nos.system(cmd)"
    })
    findings = detector.scan(ctx)
    assert any(f.vuln_id == "VULN-003" for f in findings)


def test_detects_subprocess_run(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "tools.py": "import subprocess\nsubprocess.run(cmd, shell=True)"
    })
    findings = detector.scan(ctx)
    assert any(f.vuln_id == "VULN-003" for f in findings)


def test_downgrade_severity_with_sandbox(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "tools.py": "import e2b\nexec(code)"
    })
    findings = detector.scan(ctx)
    # Sandbox present — severity should be HIGH not CRITICAL
    assert findings
    assert findings[0].severity == Severity.HIGH


def test_no_false_positive_on_safe_code(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": "result = agent.run(input_text)"
    })
    findings = detector.scan(ctx)
    assert len(findings) == 0


def test_atlas_ref(detector, tmp_path):
    ctx = make_context(tmp_path, {"agent.py": "exec(x)"})
    findings = detector.scan(ctx)
    assert findings[0].atlas_id == "AML.T0050"
