"""Extracts a few lines of source context around a finding's line number,
for display in the UI and HTML report."""

from __future__ import annotations

from slopguard.models import SnippetLine

_DEFAULT_CONTEXT = 1  # lines of context before/after the target line


def extract_snippet(
    content: str, target_line: int, context: int = _DEFAULT_CONTEXT
) -> list[SnippetLine] | None:
    """
    Returns up to (2*context + 1) SnippetLine objects centered on
    target_line (1-indexed, matching ast.lineno / regex-loop line
    numbers used elsewhere in the scanner). Returns None if target_line
    is out of range for the given content.
    """
    if target_line is None or target_line < 1:
        return None

    lines = content.splitlines()
    if target_line > len(lines):
        return None

    start = max(1, target_line - context)
    end = min(len(lines), target_line + context)

    return [
        SnippetLine(line=i, text=lines[i - 1], is_target=(i == target_line))
        for i in range(start, end + 1)
    ]
