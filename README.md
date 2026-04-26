# 🛡️ Agent Risk Analyzer (ARA)

**Zero-config, fully local static security scanner for AI agents.**

[![CI](https://github.com/Prnvlol/agent-risk-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Prnvlol/agent-risk-analyzer/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/arascan)](https://pypi.org/project/arascan/)
[![Python](https://img.shields.io/pypi/pyversions/arascan)](https://pypi.org/project/arascan/)
[![License](https://img.shields.io/github/license/Prnvlol/agent-risk-analyzer)](LICENSE)

ARA detects **20 vulnerability categories** across LangChain, CrewAI, AutoGen, and MCP agent projects — no API keys, no cloud, no LLM required.

```
$ ara scan ./my-agent

──────────────────────────── Agent Risk Analyzer ────────────────────────────
  Target:  /path/to/my-agent
  Files:   3 scanned  |  Duration: 0.04s  |  Framework: langchain

  Grade   Score   🔴 Critical   🟠 High   🟡 Medium   ⚪ Low   Total
    F      116         6            9          3          5       23

╭─────────────────────────────────────────────────────────────────────────────╮
│ Grade F  Score: 116  —  Unsafe for production — critical issues must be     │
│ fixed immediately.                                                           │
╰─────────────────────────────────────────────────────────────────────────────╯
```

---

## ✨ Features

- **🔒 Fully local** — no data leaves your machine, no API keys needed
- **⚡ Zero config** — point at a directory, get a graded report
- **🎯 20 vulnerability rules** mapped to [MITRE ATLAS](https://atlas.mitre.org/) and [OWASP LLM Top 10 2025](https://genai.owasp.org/)
- **🧠 AST + regex** — two-tier detection with CONFIRMED / SUSPECTED confidence levels
- **📊 A–F grading** — weighted severity scoring for instant risk posture
- **🔌 Multi-format output** — terminal (Rich), JSON, Markdown
- **🤖 CI/CD ready** — `--ci` flag returns exit code 1 on findings

---

## 📦 Installation

```bash
pip install arascan
```

> **Requires Python 3.11+**

For development:

```bash
git clone https://github.com/Prnvlol/agent-risk-analyzer.git
cd agent-risk-analyzer
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## 🚀 Usage

### Basic scan

```bash
ara scan ./my-agent-project
```

### JSON report (for CI pipelines)

```bash
ara scan ./my-agent --format json --output report.json
```

### Markdown report

```bash
ara scan ./my-agent --format markdown --output report.md
```

### CI mode (fail on findings)

```bash
ara scan ./my-agent --ci --min-severity HIGH
```

### Filter options

```bash
# Only show CONFIRMED findings (hide heuristic checks)
ara scan ./my-agent --no-suspected

# Disable specific rules
ara scan ./my-agent --disable VULN-017,VULN-019

# Set minimum severity threshold
ara scan ./my-agent --min-severity MEDIUM
```

### List all rules

```bash
ara list-rules
```

---

## 🎯 What ARA Detects

| ID | Vulnerability | Severity | ATLAS | OWASP |
|---|---|---|---|---|
| VULN-001 | Direct Prompt Injection | CRITICAL | AML.T0051.000 | LLM01 |
| VULN-002 | Indirect Prompt Injection | CRITICAL | AML.T0051.001 | LLM01 |
| VULN-003 | Unrestricted Code Execution | CRITICAL | AML.T0050 | LLM06 |
| VULN-005 | Over-Permissioned Tools | HIGH | AML.T0053 | LLM06 |
| VULN-006 | Unbounded Agent Autonomy | HIGH | AML.T0053 | LLM06 |
| VULN-007 | Tool Result Poisoning | HIGH | AML.T0097 | LLM06 |
| VULN-008 | Memory / Context Poisoning | HIGH | AML.T0087 | LLM04 |
| VULN-009 | Insecure MCP Configuration | HIGH | AML.T0088 | LLM03 |
| VULN-010 | System Prompt Leakage | HIGH | AML.T0056.001 | LLM07 |
| VULN-011 | Insecure Tool Input | MEDIUM | AML.T0053 | LLM06 |
| VULN-012 | Sensitive Data in Logs | HIGH | AML.T0048 | LLM02 |
| VULN-013 | Missing Rate Limiting | MEDIUM | AML.T0054 | LLM10 |
| VULN-014 | Hardcoded Credentials | MEDIUM | AML.T0037 | LLM02 |
| VULN-015 | Insecure Multi-Agent Trust | MEDIUM | AML.T0087 | LLM06 |
| VULN-016 | Verbose Error Messages | LOW | AML.T0048 | LLM02 |
| VULN-017 | Missing Output Filtering | LOW | AML.T0048 | LLM05 |
| VULN-018 | Missing Human-in-the-Loop | LOW | AML.T0053 | LLM06 |
| VULN-019 | Unversioned Prompts | LOW | AML.T0088 | LLM07 |
| VULN-020 | Third-Party Plugin Risk | LOW | AML.T0010.003 | LLM03 |

---

## 📊 Grading System

Findings are scored by severity weight, then mapped to a letter grade:

| Weight | Severity |
|---|---|
| 10 | CRITICAL |
| 5 | HIGH |
| 2 | MEDIUM |
| 1 | LOW |

| Grade | Score Range | Meaning |
|---|---|---|
| **A** | 0 | No findings |
| **B** | 1 – 5 | Minor issues |
| **C** | 6 – 15 | Needs attention |
| **D** | 16 – 30 | Significant risk |
| **F** | 31+ | Unsafe for production |

---

## 🏗️ Architecture

```
src/
├── cli.py               # Typer CLI (scan, list-rules, version)
├── scanner.py           # File discovery, AST parsing, detector dispatch
├── models.py            # Pydantic models (Finding, ScanResult, grades)
├── report.py            # Rich terminal, JSON, Markdown renderers
└── detectors/
    ├── base.py          # BaseDetector ABC + ScanContext
    ├── credentials.py   # VULN-014: hardcoded secrets (15 regex patterns)
    ├── code_execution.py    # VULN-003: exec/eval/subprocess (AST)
    ├── prompt_injection.py  # VULN-001/002/010/017/019
    ├── tool_permissions.py  # VULN-005/007/011/018/020
    ├── mcp_config.py    # VULN-009: MCP misconfigurations
    ├── multi_agent.py   # VULN-006/008/015
    ├── logging_detector.py  # VULN-012/016
    └── rate_limiting.py     # VULN-013
```

**Design principles:**
- **No LLM dependency** — all detection is deterministic (AST + regex)
- **Two-tier confidence** — `CONFIRMED` (pattern exists verbatim) vs `SUSPECTED` (absence-of-safeguard heuristic)
- **Single-pass scan** — files read once into `ScanContext`, shared across all detectors
- **Fail-safe detectors** — a crashing detector never stops the scan

---

## 🧪 Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

---

## 📋 Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (no findings, or non-CI mode) |
| `1` | Findings detected (CI mode only) |
| `2` | Error (bad arguments, scan failure) |

---

## 🗺️ Roadmap

- [ ] **Framework-specific detectors** — deep checks for LangChain, CrewAI, AutoGen patterns
- [ ] **`--deep` mode** — optional local LLM analysis via Ollama for semantic prompt review
- [ ] **GitHub Actions workflow** — pre-built CI action
- [x] **PyPI release** — `pip install arascan`
- [ ] **VS Code extension** — inline findings in the editor

---

## 🔗 Related

| Tool | What it does |
|---|---|
| **ARA** (this) | Static scanner — find vulnerabilities before deployment |
| **[parry-ai](https://github.com/Prnvlol/parry)** | Runtime guardrail — block threats while your agent is running |

> Use ARA to find the issues. Use parry to fix them at runtime.

---

## 📄 License

[MIT](LICENSE)

---

<p align="center">
  Built with 🐍 Python — no clouds, no APIs, no excuses.
</p>
