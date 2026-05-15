"""
Scanner Engine — orchestrates file discovery, AST parsing,
framework detection, and detector dispatch.
"""

from __future__ import annotations

import ast
import time
from collections.abc import Iterator
from pathlib import Path

from src.detectors import ALL_DETECTORS
from src.detectors.base import ScanContext
from src.models import Finding, ScanConfig, ScanResult, calculate_grade

# ---------------------------------------------------------------------------
# File discovery config
# ---------------------------------------------------------------------------

SCAN_EXTENSIONS = {
    ".py", ".yaml", ".yml", ".json", ".toml", ".env", ".md", ".txt",
}

SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "site-packages", "eggs", ".eggs", "egg-info",
    "reports",
}

# Framework fingerprints: import name → friendly label
FRAMEWORK_FINGERPRINTS: dict[str, str] = {
    "langchain": "langchain",
    "langchain_core": "langchain",
    "langchain_community": "langchain",
    "crewai": "crewai",
    "autogen": "autogen",
    "pyautogen": "autogen",
}


class Scanner:
    """Main scanner — walks a directory, builds ScanContext, runs detectors."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def run(self) -> ScanResult:
        start = time.perf_counter()

        context = self._build_context()
        findings = self._run_detectors(context)

        # Apply config filters
        findings = self._filter_findings(findings)

        grade, score = calculate_grade(findings)
        duration = time.perf_counter() - start

        return ScanResult(
            target_path=str(self.config.target_path),
            findings=sorted(
                findings,
                key=lambda f: (
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.severity.value),
                    f.file_path,
                ),
            ),
            files_scanned=sum(len(v) for v in context.files.values()),
            scan_duration_seconds=round(duration, 3),
            framework_detected=context.detected_framework,
            grade=grade,
            score=score,
        )

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    def _build_context(self) -> ScanContext:
        target = self.config.target_path

        files: dict[str, list[Path]] = {}
        file_contents: dict[Path, str] = {}
        ast_cache: dict[Path, ast.Module] = {}

        for path in self._walk(target):
            ext = path.suffix.lower()
            files.setdefault(ext, []).append(path)

            # Read file content
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                file_contents[path] = content
            except OSError:
                continue  # Skip unreadable files

            # Parse Python ASTs
            if ext == ".py":
                try:
                    ast_cache[path] = ast.parse(content, filename=str(path))
                except SyntaxError:
                    pass  # Still do regex-based checks on raw content

        context = ScanContext(
            target_path=target,
            config=self.config,
            files=files,
            file_contents=file_contents,
            ast_cache=ast_cache,
        )
        context.detected_framework = self._detect_framework(file_contents)

        return context

    def _walk(self, root: Path) -> Iterator[Path]:
        """Yield all scannable files under root, skipping SKIP_DIRS."""
        for item in root.rglob("*"):
            if item.is_file():
                # Skip files inside any skip directory
                if any(part in SKIP_DIRS for part in item.parts):
                    continue
                if item.suffix.lower() in SCAN_EXTENSIONS or item.name.startswith(".env"):
                    yield item

    def _detect_framework(self, file_contents: dict[Path, str]) -> str | None:
        for content in file_contents.values():
            for fingerprint, label in FRAMEWORK_FINGERPRINTS.items():
                if fingerprint in content:
                    return label
        return None

    # ------------------------------------------------------------------
    # Detector dispatch
    # ------------------------------------------------------------------

    def _run_detectors(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        disabled = set(self.config.disabled_rules)

        for detector in ALL_DETECTORS:
            # Skip disabled detectors
            if detector.name in disabled:
                continue
            if any(vid in disabled for vid in detector.vuln_ids):
                continue

            try:
                results = detector.scan(context)
                findings.extend(results)
            except Exception as exc:  # noqa: BLE001
                # Never let a single detector crash the whole scan
                import warnings
                warnings.warn(
                    f"Detector '{detector.name}' raised an exception: {exc}",
                    stacklevel=2,
                )

        return findings

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------

    def _filter_findings(self, findings: list[Finding]) -> list[Finding]:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        min_idx = severity_order.index(self.config.min_severity.value)

        filtered = [
            f for f in findings
            if severity_order.index(f.severity.value) <= min_idx
        ]

        if not self.config.include_suspected:
            from src.models import Confidence
            filtered = [f for f in filtered if f.confidence == Confidence.CONFIRMED]

        return filtered
