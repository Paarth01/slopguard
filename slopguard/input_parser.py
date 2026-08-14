"""Turns a folder path into a list of FileToScan objects."""

from __future__ import annotations

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


def collect_files(root: str) -> list[FileToScan]:
    root_path = Path(root)
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
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = str(path.relative_to(root_path)) if root_path.is_dir() else str(path)
        files.append(FileToScan(path=rel, content=content, language=detect_language(str(path))))

    return files
