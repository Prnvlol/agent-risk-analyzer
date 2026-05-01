# Contributing to Agent Risk Analyzer

Thanks for helping make AI agent projects safer.

ARA is focused on local, deterministic static analysis for agent codebases. The best contributions improve detection quality, reduce noise, or make scanner results easier to use in development and CI.

## Good First Contributions

Useful starter areas:

- Add a new fixture to `examples/vulnerable_agent/`.
- Add detector test cases for a false positive or false negative.
- Improve a rule description or remediation message.
- Add framework-specific examples for LangChain, CrewAI, AutoGen, or MCP.
- Improve JSON or Markdown report usability.

## Development Setup

```bash
git clone https://github.com/Prnvlol/agent-risk-analyzer.git
cd agent-risk-analyzer
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Run these before opening a pull request:

```bash
ruff check src/ tests/
mypy src/
pytest
```

## Pull Request Guidelines

- Keep changes focused and easy to review.
- Add tests for detector, scanner, model, and report changes.
- Prefer deterministic AST, config, and pattern checks over LLM-dependent behavior.
- Include a minimal vulnerable sample for new rule behavior when useful.
- Update `README.md` or `CHANGELOG.md` for user-facing behavior.

## Detector Guidelines

Good detector changes should explain:

- The vulnerability category and rule ID.
- Why the pattern matters for AI agents.
- Whether the finding is confirmed or suspected.
- The severity and remediation path.
- A minimal example that should trigger the rule.

ARA should be strict enough to catch real agent risks and transparent enough that teams can triage findings quickly.

## Security Reports

Please do not disclose vulnerabilities publicly before a fix is available. See `SECURITY.md` for the reporting process.
