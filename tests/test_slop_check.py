from slopguard.slop_check import (
    _finding_for,
    check_files_for_hallucinations,
    extract_js_imports,
    extract_python_imports,
)
from slopguard.static_scan import FileToScan


def test_extract_python_imports_skips_stdlib():
    code = "import os\nimport requests\nfrom fastapi import FastAPI\nimport json\n"
    imports = extract_python_imports(code)
    assert "requests" in imports
    assert "fastapi" in imports
    assert "os" not in imports
    assert "json" not in imports


def test_extract_python_imports_skips_lesser_known_stdlib():
    # These were missed by an earlier hand-maintained skip list and caused
    # real false-positive "hallucinated package" flags when tested against
    # the actual Flask codebase -- regression test for that fix.
    code = "from __future__ import annotations\nimport inspect\nimport types\nimport errno\nimport operator\n"
    imports = extract_python_imports(code)
    assert imports == []


def test_extract_python_imports_skips_typeshed_stub_only_module():
    code = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import _typeshed\n"
    imports = extract_python_imports(code)
    assert "_typeshed" not in imports


def test_import_alias_resolves_openssl_to_pyopenssl():
    from slopguard.slop_check import _IMPORT_NAME_TO_PYPI_NAME
    assert _IMPORT_NAME_TO_PYPI_NAME["OpenSSL"] == "pyOpenSSL"


def test_extract_python_imports_skips_py2_compat_modules():
    code = "try:\n    from cStringIO import StringIO\nexcept ImportError:\n    from io import StringIO\n"
    imports = extract_python_imports(code)
    assert "cStringIO" not in imports


def test_local_module_names_found_from_file_tree():
    from slopguard.slop_check import _local_module_names
    files = [
        FileToScan(path="tests/test_apps/blueprintapp/__init__.py", content="", language="python"),
        FileToScan(path="src/mypkg/core.py", content="", language="python"),
    ]
    names = _local_module_names(files)
    assert "blueprintapp" in names
    assert "tests" in names
    assert "mypkg" in names
    assert "core" in names


def test_check_files_skips_local_first_party_import(monkeypatch):
    # 'localthing' matches a directory in the scanned tree, so it should
    # never trigger a registry lookup or a finding, even though it isn't
    # a real PyPI package.
    def fail_if_called(*args, **kwargs):
        raise AssertionError("should not hit the registry for a local module")

    monkeypatch.setattr("slopguard.slop_check.check_pypi_package", fail_if_called)

    files = [
        FileToScan(path="localthing/__init__.py", content="", language="python"),
        FileToScan(path="app.py", content="import localthing\n", language="python"),
    ]
    findings = check_files_for_hallucinations(files)
    assert findings == []


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


def test_extract_js_imports_dynamic_import():
    code = 'import("some-lazy-package").then(m => m.default);\n'
    imports = extract_js_imports(code)
    assert "some-lazy-package" in imports


def test_extract_js_imports_export_from():
    code = 'export { default } from "re-exported-package";\n'
    imports = extract_js_imports(code)
    assert "re-exported-package" in imports


def test_extract_js_imports_export_star_from():
    code = 'export * from "another-package";\n'
    imports = extract_js_imports(code)
    assert "another-package" in imports


def test_extract_js_imports_side_effect_only():
    code = 'import "polyfill-package";\n'
    imports = extract_js_imports(code)
    assert "polyfill-package" in imports


def test_extract_js_imports_skips_node_builtins():
    code = 'import fs from "fs";\nimport path from "path";\nimport axios from "axios";\n'
    imports = extract_js_imports(code)
    assert "fs" not in imports
    assert "path" not in imports
    assert "axios" in imports


def test_extract_js_imports_skips_node_prefixed_builtins():
    # Modern Node code often imports builtins with an explicit "node:"
    # scheme -- caught as a real false-positive class when this scanner
    # was run against the real express.js codebase (87 false hallucination
    # flags, all "node:xxx" builtins).
    code = 'import assert from "node:assert";\nimport { Buffer } from "node:buffer";\n'
    imports = extract_js_imports(code)
    assert imports == []


def test_extract_js_imports_skips_relative():
    code = 'import { local } from "./local-file";\n'
    imports = extract_js_imports(code)
    assert imports == []


def test_finding_for_nonexistent_package_is_high():
    finding = _finding_for("app.py", "totally_fake_pkg_xyz", "pypi", exists=False, age_days=None)
    assert finding is not None
    assert finding.severity.value == "high"
    assert finding.rule_id == "dependency-hallucination"
    # No line number for a whole-file/whole-import finding -- correctly no snippet
    assert finding.line is None
    assert finding.snippet is None


def test_finding_for_existing_established_package_is_none():
    finding = _finding_for("app.py", "requests", "pypi", exists=True, age_days=3000)
    assert finding is None


def test_finding_for_recently_published_package_is_low():
    finding = _finding_for("app.py", "brand-new-pkg", "pypi", exists=True, age_days=5)
    assert finding is not None
    assert finding.severity.value == "low"
    assert finding.rule_id == "recently-published-package"
