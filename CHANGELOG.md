# Changelog

All notable changes to Agent Risk Analyzer will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — 2026-05-15

### Added
- Framework-specific detector coverage:
  - LangChain FAISS unsafe deserialization and explicit unbounded agent iteration settings
  - CrewAI unsafe code execution and delegation without runtime boundaries
  - AutoGen unsandboxed code execution and explicit unbounded group chat rounds
- Focused framework detector tests and smoke verification coverage for risky and safe examples

### Changed
- Tightened shared detector/config typing so `mypy src` passes cleanly for the release

---

## [0.1.0] — 2026-04-20

### Added
- Zero-config static security scanner for AI agents
- 8 detectors covering 20 vulnerability categories:
  - `VULN-001` Prompt injection via user input in system prompt
  - `VULN-003` Unrestricted code execution (`exec`, `eval`, `subprocess`)
  - `VULN-005` Dangerous tool registration (shell/REPL tools)
  - `VULN-007` Tool results used without validation
  - `VULN-009` MCP server misconfiguration (broad filesystem, no auth)
  - `VULN-013` Missing rate limiting on LLM clients
  - `VULN-014` Hardcoded credentials (API keys, tokens)
  - `VULN-016` Verbose error/traceback exposure
  - `VULN-017` LLM output used without output filtering
  - `VULN-018` Destructive operations without human approval
  - `VULN-019` System prompt hardcoded (not loaded from versioned config)
  - And 9 more across multi-agent trust, logging, and permission boundaries
- A–F grading system with weighted severity scoring
- Rich CLI output with per-file findings tables and remediation guide
- Framework detection (LangChain, CrewAI, AutoGen, plain OpenAI)
- `ara scan`, `ara list-rules`, `ara version` commands
- Exit codes: 0 (pass), 1 (findings), 2 (error)
- MITRE ATLAS and OWASP LLM Top 10 references on every finding
- Intentionally vulnerable example agent for testing
