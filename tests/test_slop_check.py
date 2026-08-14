from slopguard.slop_check import (
    _finding_for,
    extract_js_imports,
    extract_python_imports,
)


def test_extract_python_imports_skips_stdlib():
    code = "import os\nimport requests\nfrom fastapi import FastAPI\nimport json\n"
    imports = extract_python_imports(code)
    assert "requests" in imports
    assert "fastapi" in imports
    assert "os" not in imports
    assert "json" not in imports


def test_extract_python_imports_skips_relative():
    code = "from . import helpers\nfrom .models import Thing\n"
    imports = extract_python_imports(code)
    assert imports == []


def test_extract_js_imports_basic():
    code = 'import express from "express";\nconst axios = require("axios");\n'
    imports = extract_js_imports(code)
    assert "express" in imports
    assert "axios" in imports


def test_extract_js_imports_scoped_package():
    code = 'import { thing } from "@scope/package/sub";\n'
    imports = extract_js_imports(code)
    assert "@scope/package" in imports


def test_finding_for_nonexistent_package_is_high():
    finding = _finding_for("app.py", "totally_fake_pkg_xyz", "pypi", exists=False, age_days=None)
    assert finding is not None
    assert finding.severity.value == "high"
    assert finding.rule_id == "dependency-hallucination"


def test_finding_for_existing_established_package_is_none():
    finding = _finding_for("app.py", "requests", "pypi", exists=True, age_days=3000)
    assert finding is None


def test_finding_for_recently_published_package_is_low():
    finding = _finding_for("app.py", "brand-new-pkg", "pypi", exists=True, age_days=5)
    assert finding is not None
    assert finding.severity.value == "low"
    assert finding.rule_id == "recently-published-package"
