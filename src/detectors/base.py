"""Base class and shared context for all ARA detectors."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from src.models import Finding, ScanConfig


@dataclass
class ScanContext:
    """
    Pre-processed scan state shared across all detectors.

    Files are read once and cached here so every detector
    works from memory rather than re-reading from disk.
    """

    target_path: Path
    config: ScanConfig

    # Extension → list of file paths
    files: dict[str, list[Path]] = field(default_factory=dict)

    # Absolute path → raw text content
    file_contents: dict[Path, str] = field(default_factory=dict)

    # Absolute path → parsed AST (Python files only)
    ast_cache: dict[Path, ast.Module] = field(default_factory=dict)

    # Detected framework ("langchain", "crewai", "autogen", "mcp", None)
    detected_framework: str | None = None

    def get_text(self, path: Path) -> str:
        """Return cached file content."""
        return self.file_contents.get(path, "")

    def get_ast(self, path: Path) -> ast.Module | None:
        """Return cached AST, or None if the file wasn't parseable."""
        return self.ast_cache.get(path)

    def python_files(self) -> list[Path]:
        return self.files.get(".py", [])

    def config_files(self) -> list[Path]:
        return [
            p
            for ext in (".yaml", ".yml", ".json", ".toml", ".env")
            for p in self.files.get(ext, [])
        ]


class BaseDetector(ABC):
    """
    Abstract base class for all ARA security detectors.

    To add a new detector:
      1. Subclass BaseDetector
      2. Set class attributes (name, description, vuln_ids, supported_extensions)
      3. Implement scan()
      4. Register it in src/detectors/__init__.py
    """

    # Override in subclasses --------------------------------------------------
    name: str = ""
    description: str = ""
    vuln_ids: list[str] = []
    supported_extensions: set[str] = set()
    # -------------------------------------------------------------------------

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """
        Run detection logic against the scan context.

        Never raise — catch exceptions internally and return
        whatever findings were collected before the error.
        """
        ...

    # ------------------------------------------------------------------
    # Convenience helpers available to all detectors
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        *,
        vuln_id: str,
        title: str,
        severity: "Finding.__class__",  # type: ignore[assignment]
        confidence: "Finding.__class__",  # type: ignore[assignment]
        description: str,
        file_path: Path,
        line_number: int | None = None,
        code_snippet: str | None = None,
        fix_suggestion: str,
        framework: str | None = None,
        atlas_id: str | None = None,
        owasp_ref: str | None = None,
        target_root: Path | None = None,
    ) -> Finding:
        """Build a Finding with relative path and detector name pre-filled."""
        rel = (
            str(file_path.relative_to(target_root))
            if target_root and file_path.is_absolute()
            else str(file_path)
        )
        return Finding(
            vuln_id=vuln_id,
            title=title,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            description=description,
            file_path=rel,
            line_number=line_number,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            detector=self.name,
            framework=framework,
            atlas_id=atlas_id,
            owasp_ref=owasp_ref,
        )
