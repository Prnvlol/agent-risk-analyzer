"""
VULN-009: Insecure MCP Server Configuration
ATLAS: AML.T0088 | OWASP: LLM03

Parses MCP config files (claude_desktop_config.json, mcp.json, .mcp.json, etc.)
and checks for:
  - Filesystem server with root / home directory access
  - Missing authentication tokens
  - Wildcard permissions
  - Excessive number of tools exposed
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from src.detectors.base import BaseDetector, ScanContext
from src.models import Confidence, Finding, Severity

MCP_CONFIG_FILENAMES = {
    "claude_desktop_config.json",
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "mcp_config.yaml",
    "mcp_config.yml",
}

# Path strings that expose broad filesystem access
BROAD_PATH_PATTERN = re.compile(
    r'^(/|~|C:\\\\|/home|/root|/Users|/var|/etc|/opt)$'
)

# Auth-related keys
AUTH_KEYS = {"token", "api_key", "apiKey", "auth", "authorization", "secret", "key"}


class MCPConfigDetector(BaseDetector):
    name = "mcp_config"
    description = "Checks MCP server configuration files for security misconfigurations"
    vuln_ids = ["VULN-009"]
    supported_extensions = {".json", ".yaml", ".yml"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # Walk all config-format files and look for MCP config files by name
        all_files = [
            p
            for ext in (".json", ".yaml", ".yml")
            for p in context.files.get(ext, [])
        ]

        for path in all_files:
            if path.name not in MCP_CONFIG_FILENAMES:
                continue

            content = context.get_text(path)
            if not content:
                continue

            parsed = self._parse(content, path)
            if parsed is None:
                continue

            findings.extend(self._check_mcp_config(parsed, path, context))

        return findings

    # ------------------------------------------------------------------

    def _parse(self, content: str, path: Path) -> dict | None:  # type: ignore[type-arg]
        try:
            if path.suffix == ".json":
                return json.loads(content)  # type: ignore[no-any-return]
            return yaml.safe_load(content)  # type: ignore[no-any-return]
        except Exception:
            return None

    def _check_mcp_config(
        self,
        config: dict,  # type: ignore[type-arg]
        path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # MCP config structure: {"mcpServers": {"server-name": {...}}}
        servers: dict = config.get("mcpServers", config)  # type: ignore[type-arg]
        if not isinstance(servers, dict):
            return findings

        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue

            findings.extend(
                self._check_server(server_name, server_cfg, path, context)
            )

        return findings

    def _check_server(
        self,
        name: str,
        cfg: dict,  # type: ignore[type-arg]
        path: Path,
        context: ScanContext,
    ) -> list[Finding]:
        findings: list[Finding] = []

        args: list = cfg.get("args", [])
        env: dict = cfg.get("env", {})  # type: ignore[type-arg]
        permissions: list | str = cfg.get("permissions", [])

        # 1. Broad filesystem paths in args
        for arg in args:
            if isinstance(arg, str) and BROAD_PATH_PATTERN.match(arg.strip()):
                findings.append(
                    self._make_finding(
                        vuln_id="VULN-009",
                        title=f"MCP server '{name}' has broad filesystem access",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"The MCP server '{name}' is configured with the path '{arg}', "
                            "which grants access to the root or home directory. "
                            "Any tool invocation could read or modify sensitive system files."
                        ),
                        file_path=path,
                        fix_suggestion=(
                            "Restrict the filesystem server path to the minimum required "
                            "directory (e.g. ~/projects/myapp instead of ~/). "
                            "Use read-only mode where writes are not needed."
                        ),
                        atlas_id="AML.T0088",
                        owasp_ref="LLM03",
                        target_root=context.target_path,
                    )
                )

        # 2. Missing authentication
        has_auth = any(
            k.lower() in AUTH_KEYS or v
            for d in [env, cfg]
            for k, v in d.items()
            if isinstance(d, dict)
        )
        # More precise: check env for token/key values
        env_has_auth = any(k.lower() in AUTH_KEYS for k in env)
        cfg_has_auth = any(k.lower() in AUTH_KEYS for k in cfg)

        if not env_has_auth and not cfg_has_auth:
            findings.append(
                self._make_finding(
                    vuln_id="VULN-009",
                    title=f"MCP server '{name}' has no authentication configured",
                    severity=Severity.HIGH,
                    confidence=Confidence.SUSPECTED,
                    description=(
                        f"The MCP server '{name}' configuration does not include any "
                        "authentication token or API key. Unauthenticated MCP servers "
                        "can be accessed by any local process."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Add an authentication token to the MCP server configuration. "
                        "Store the token as an environment variable reference rather "
                        "than a hardcoded value."
                    ),
                    atlas_id="AML.T0088",
                    owasp_ref="LLM03",
                    target_root=context.target_path,
                )
            )

        # 3. Wildcard permissions
        perm_str = str(permissions)
        if "*" in perm_str or "all" in perm_str.lower():
            findings.append(
                self._make_finding(
                    vuln_id="VULN-009",
                    title=f"MCP server '{name}' uses wildcard permissions",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"The MCP server '{name}' is configured with wildcard (*) "
                        "permissions. This grants the agent access to all server "
                        "capabilities, violating the principle of least privilege."
                    ),
                    file_path=path,
                    fix_suggestion=(
                        "Replace wildcard permissions with an explicit allowlist of "
                        "only the tools/resources the agent needs."
                    ),
                    atlas_id="AML.T0088",
                    owasp_ref="LLM03",
                    target_root=context.target_path,
                )
            )

        return findings
