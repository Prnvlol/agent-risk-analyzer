"""Tests for CredentialsDetector."""

from __future__ import annotations

import pytest

from src.detectors.credentials import CredentialsDetector
from src.models import Confidence, Severity
from tests.conftest import make_context


@pytest.fixture
def detector():
    return CredentialsDetector()


def test_detects_openai_key(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": 'api_key = "sk-abc123fakekey1234567890abcdefghijklmnop"'
    })
    findings = detector.scan(ctx)
    assert len(findings) == 1
    assert findings[0].vuln_id == "VULN-014"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.CONFIRMED


def test_detects_anthropic_key(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "config.py": 'ANTHROPIC_KEY = "sk-ant-api03-realkey1234567890abcdefghij"'
    })
    findings = detector.scan(ctx)
    assert any(f.vuln_id == "VULN-014" for f in findings)


def test_detects_aws_key(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "creds.py": 'aws_id = "AKIAIOSFODNN7EXAMPLE"'
    })
    findings = detector.scan(ctx)
    assert len(findings) >= 1


def test_detects_in_env_file(detector, tmp_path):
    ctx = make_context(tmp_path, {
        ".env": "OPENAI_API_KEY=sk-abc123fakekey1234567890abcdefghijklmnop"
    })
    # .env has no suffix match directly — register it manually
    path = tmp_path / ".env"
    ctx.files.setdefault(".env", []).append(path)
    ctx.file_contents[path] = "OPENAI_API_KEY=sk-abc123fakekey1234567890abcdefghijklmnop"
    findings = detector.scan(ctx)
    assert len(findings) >= 1


def test_ignores_env_var_reference(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": 'api_key = os.environ.get("OPENAI_API_KEY")'
    })
    findings = detector.scan(ctx)
    assert len(findings) == 0


def test_ignores_placeholder(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": '# api_key = "sk-your-api-key-here"'
    })
    findings = detector.scan(ctx)
    assert len(findings) == 0


def test_snippet_is_redacted(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": 'KEY = "sk-abc123fakekey1234567890abcdefghijklmnop"'
    })
    findings = detector.scan(ctx)
    assert findings
    assert "REDACTED" in (findings[0].code_snippet or "")


def test_atlas_and_owasp_refs(detector, tmp_path):
    ctx = make_context(tmp_path, {
        "agent.py": 'KEY = "sk-abc123fakekey1234567890abcdefghijklmnop"'
    })
    findings = detector.scan(ctx)
    assert findings[0].atlas_id == "AML.T0037"
    assert findings[0].owasp_ref == "LLM02"
