"""Shared fixtures for ARA test suite."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from src.detectors.base import ScanContext
from src.models import ScanConfig, Severity


def make_context(
    tmp_path: Path,
    files: dict[str, str],
) -> ScanContext:
    """
    Build a ScanContext from a dict of {filename: content}.
    Files are written to tmp_path and then loaded into the context.
    """
    config = ScanConfig(target_path=tmp_path, min_severity=Severity.LOW)
    context = ScanContext(target_path=tmp_path, config=config)

    for filename, content in files.items():
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")

        ext = path.suffix.lower()
        context.files.setdefault(ext, []).append(path)
        context.file_contents[path] = textwrap.dedent(content)

        if ext == ".py":
            try:
                context.ast_cache[path] = ast.parse(
                    textwrap.dedent(content), filename=str(path)
                )
            except SyntaxError:
                pass

    return context
