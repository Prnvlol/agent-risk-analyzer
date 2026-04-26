"""Tests for MCPConfigDetector."""

from __future__ import annotations

import pytest

from src.detectors.mcp_config import MCPConfigDetector
from tests.conftest import make_context


@pytest.fixture
def detector():
    return MCPConfigDetector()


VULNERABLE_MCP = """\
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
      "permissions": ["*"]
    }
  }
}
"""

SAFE_MCP = """\
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
      "env": {
        "token": "my-secret-token"
      }
    }
  }
}
"""


def test_detects_root_path(detector, tmp_path):
    ctx = make_context(tmp_path, {"claude_desktop_config.json": VULNERABLE_MCP})
    findings = detector.scan(ctx)
    titles = [f.title for f in findings]
    assert any("broad filesystem" in t for t in titles)


def test_detects_wildcard_permissions(detector, tmp_path):
    ctx = make_context(tmp_path, {"claude_desktop_config.json": VULNERABLE_MCP})
    findings = detector.scan(ctx)
    assert any("wildcard" in f.title.lower() for f in findings)


def test_detects_missing_auth(detector, tmp_path):
    ctx = make_context(tmp_path, {"claude_desktop_config.json": VULNERABLE_MCP})
    findings = detector.scan(ctx)
    assert any("authentication" in f.title.lower() for f in findings)


def test_safe_config_produces_no_root_finding(detector, tmp_path):
    ctx = make_context(tmp_path, {"claude_desktop_config.json": SAFE_MCP})
    findings = detector.scan(ctx)
    # Should not flag restricted path
    assert not any("broad filesystem" in f.title.lower() for f in findings)


def test_non_mcp_json_ignored(detector, tmp_path):
    ctx = make_context(tmp_path, {"some_config.json": '{"key": "value"}'})
    findings = detector.scan(ctx)
    assert len(findings) == 0


def test_atlas_ref(detector, tmp_path):
    ctx = make_context(tmp_path, {"mcp.json": VULNERABLE_MCP})
    findings = detector.scan(ctx)
    assert all(f.atlas_id == "AML.T0088" for f in findings)
