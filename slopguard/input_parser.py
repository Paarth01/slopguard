"""Turns a folder path into a list of FileToScan objects."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from slopguard.static_scan import FileToScan, detect_language

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".ts", ".tsx"}

_GLOB_CHARS = set("*?[")


def parse_exclude_arg(raw: str) -> list[str]:
    """Parses a comma-separated --exclude value into a clean pattern list."""
    return [p.strip() for p in raw.split(",") if p.strip()]


def _is_excluded(rel_path: Path, exclude: list[str]) -> bool:
    rel_str = rel_path.as_posix()
    for pattern in exclude:
        if any(c in pattern for c in _GLOB_CHARS):
            # Glob pattern (e.g. "dist/*", "*.generated.py") -- match
            # against the full relative path.
            if fnmatch.fnmatch(rel_str, pattern):
                return True
        else:
            # Plain name (e.g. "tests", "legacy") -- match any path
            # component exactly, same behavior as the built-in _SKIP_DIRS,
            # so "tests" excludes the whole tests/ subtree, not just a
            # file literally named "tests".
            if pattern in rel_path.parts:
                return True
    return False


def collect_files(root: str, exclude: list[str] | None = None) -> list[FileToScan]:
    root_path = Path(root)
    exclude = exclude or []
    files: list[FileToScan] = []

    if root_path.is_file():
        candidates = [root_path]
    else:
        candidates = [
            p
            for p in root_path.rglob("*")
            if p.is_file()
            and p.suffix.lower() in _SUPPORTED_SUFFIXES
            and not any(part in _SKIP_DIRS for part in p.parts)
        ]

    for path in candidates:
        rel = path.relative_to(root_path) if root_path.is_dir() else path
        if exclude and _is_excluded(rel, exclude):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        files.append(
            FileToScan(path=str(rel), content=content, language=detect_language(str(path)))
        )

    return files
