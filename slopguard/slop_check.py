"""
Dependency hallucination checker ("slop check").

Extracts imports from Python/JS/TS files and checks each package name
against the real PyPI or npm registry. Flags:
  - names that don't exist at all -> hallucination candidate (an LLM
    invented a plausible-sounding package that a "slopsquatter" could
    register and load with malware)
  - names that exist but were only very recently published -> weaker
    signal, surfaced as a lower-severity note

Registry responses are cached to a local JSON file so repeated runs
(and CI runs across the same PR) don't hammer the public APIs.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from slopguard.models import Finding, Severity
from slopguard.static_scan import FileToScan

PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}"

# Standard library / built-in modules should never be looked up.
# sys.stdlib_module_names (Python 3.10+) gives the full, accurate list --
# far more complete than a hand-maintained set. An earlier hand-picked list
# here missed __future__, inspect, types, errno, operator, platform, and
# dozens more, which showed up as 66 false "hallucinated package" flags
# when this scanner was run against the real Flask codebase.
if hasattr(sys, "stdlib_module_names"):
    _PY_STDLIB_SKIP = set(sys.stdlib_module_names)
else:  # pragma: no cover -- fallback for Python < 3.10
    _PY_STDLIB_SKIP = {
        "os", "sys", "re", "json", "typing", "pathlib", "datetime", "collections",
        "itertools", "functools", "subprocess", "unittest", "logging", "math",
        "random", "time", "io", "abc", "enum", "dataclasses", "asyncio", "ast",
        "argparse", "hashlib", "base64", "uuid", "threading", "queue", "socket",
        "shutil", "tempfile", "copy", "csv", "sqlite3", "xml", "html", "http",
        "urllib", "email", "string", "textwrap", "traceback", "warnings", "weakref",
        "__future__", "inspect", "types", "errno", "operator", "platform", "code",
        "rlcompleter",
    }

# Typing-stub-only pseudo-modules: real under a type checker via typeshed,
# but never actually installed at runtime, so a PyPI lookup would always
# false-flag as "hallucinated".
_PY_STDLIB_SKIP |= {"_typeshed"}

_NEW_PACKAGE_THRESHOLD_DAYS = 90


def _cache_path() -> Path:
    return Path(".slopguard_cache.json")


def _load_cache() -> dict:
    p = _cache_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    try:
        _cache_path().write_text(json.dumps(cache, indent=2))
    except OSError:
        pass


def extract_python_imports(content: str) -> list[str]:
    """Top-level package names imported in a Python file (via ast, no false positives)."""
    names: set[str] = set()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                names.add(node.module.split(".")[0])
    return sorted(n for n in names if n and n not in _PY_STDLIB_SKIP)


_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[\w*{}\s,]+\s+from\s+)?|require\()\s*['"]([^./][^'"]*)['"]"""
)


def extract_js_imports(content: str) -> list[str]:
    """Package names imported/required in a JS/TS file (regex-based v1)."""
    names: set[str] = set()
    for match in _JS_IMPORT_RE.finditer(content):
        raw = match.group(1)
        if raw.startswith("@"):
            parts = raw.split("/")
            names.add("/".join(parts[:2]))
        else:
            names.add(raw.split("/")[0])
    return sorted(names)


def check_pypi_package(name: str, timeout: float = 5.0) -> tuple[bool, Optional[int]]:
    """Returns (exists, age_in_days_or_None)."""
    try:
        resp = requests.get(PYPI_URL.format(name=name), timeout=timeout)
    except requests.RequestException:
        return True, None
    if resp.status_code == 404:
        return False, None
    if resp.status_code != 200:
        return True, None
    try:
        data = resp.json()
        releases = data.get("releases", {})
        earliest = None
        for files in releases.values():
            for f in files:
                ts = f.get("upload_time_iso_8601")
                if ts:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if earliest is None or dt < earliest:
                        earliest = dt
        if earliest:
            age_days = (datetime.now(timezone.utc) - earliest).days
            return True, age_days
        return True, None
    except (ValueError, KeyError):
        return True, None


def check_npm_package(name: str, timeout: float = 5.0) -> tuple[bool, Optional[int]]:
    try:
        resp = requests.get(NPM_URL.format(name=name), timeout=timeout)
    except requests.RequestException:
        return True, None
    if resp.status_code == 404:
        return False, None
    if resp.status_code != 200:
        return True, None
    try:
        data = resp.json()
        created = data.get("time", {}).get("created")
        if created:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
            return True, age_days
        return True, None
    except (ValueError, KeyError):
        return True, None


def _finding_for(file_path: str, package: str, ecosystem: str, exists: bool, age_days: Optional[int]) -> Optional[Finding]:
    if not exists:
        return Finding(
            id=f"slop-{file_path}-{package}",
            source="slop_check",
            severity=Severity.HIGH,
            file=file_path,
            line=None,
            title=f"Possibly hallucinated package: {package}",
            explanation=(
                f"'{package}' does not exist on {ecosystem}. This may be an LLM-invented "
                "package name -- if it does get registered by someone else later "
                "(a 'slopsquat'), installing it could pull in malicious code."
            ),
            confidence=0.7,
            rule_id="dependency-hallucination",
        )
    if age_days is not None and age_days < _NEW_PACKAGE_THRESHOLD_DAYS:
        return Finding(
            id=f"slop-{file_path}-{package}-new",
            source="slop_check",
            severity=Severity.LOW,
            file=file_path,
            line=None,
            title=f"Recently published package: {package}",
            explanation=(
                f"'{package}' exists on {ecosystem} but was only published {age_days} days ago -- "
                "worth a quick sanity check that this is the package you actually meant."
            ),
            confidence=0.4,
            rule_id="recently-published-package",
        )
    return None


def check_files_for_hallucinations(files: list[FileToScan]) -> list[Finding]:
    cache = _load_cache()
    findings: list[Finding] = []

    for file in files:
        if file.language == "python":
            packages = [(p, "pypi") for p in extract_python_imports(file.content)]
        elif file.language in ("javascript", "typescript"):
            packages = [(p, "npm") for p in extract_js_imports(file.content)]
        else:
            packages = []

        for package, ecosystem in packages:
            cache_key = f"{ecosystem}:{package}"
            if cache_key in cache:
                exists, age_days = cache[cache_key]["exists"], cache[cache_key]["age_days"]
            else:
                if ecosystem == "pypi":
                    exists, age_days = check_pypi_package(package)
                else:
                    exists, age_days = check_npm_package(package)
                cache[cache_key] = {"exists": exists, "age_days": age_days}

            finding = _finding_for(file.path, package, ecosystem, exists, age_days)
            if finding:
                findings.append(finding)

    _save_cache(cache)
    return findings
