from pathlib import Path

from slopguard.static_scan import FileToScan, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> FileToScan:
    path = FIXTURES / name
    return FileToScan(path=str(path), content=path.read_text(), language="python")


def test_hardcoded_secret_detected():
    findings = scan_file(_load("secret_example.py"))
    rule_ids = [f.rule_id for f in findings]
    assert "hardcoded-secret" in rule_ids

    finding = next(f for f in findings if f.rule_id == "hardcoded-secret")
    assert finding.snippet is not None
    assert any(s.is_target and s.line == finding.line for s in finding.snippet)


def test_eval_on_input_detected():
    findings = scan_file(_load("eval_example.py"))
    assert any(f.rule_id == "eval-on-input" for f in findings)
    assert any(f.severity.value == "high" for f in findings)


def test_sql_string_format_detected():
    findings = scan_file(_load("sql_example.py"))
    assert any(f.rule_id == "sql-string-concat" for f in findings)


def test_cors_allow_all_detected():
    findings = scan_file(_load("cors_example.py"))
    assert any(f.rule_id == "cors-allow-all" for f in findings)


def test_clean_file_has_no_findings():
    findings = scan_file(_load("clean_example.py"))
    assert findings == []


def test_unparseable_file_does_not_crash():
    broken = FileToScan(path="broken.py", content="def f(:\n  pass", language="python")
    findings = scan_file(broken)
    assert findings == []


def test_js_hardcoded_secret_detected():
    js = FileToScan(
        path="config.js",
        content='const apiKey = "sk-abcdefghijklmnopqrstuvwx";',
        language="javascript",
    )
    findings = scan_file(js)
    assert any(f.rule_id == "hardcoded-secret" for f in findings)


def test_js_eval_detected():
    js = FileToScan(path="app.js", content="eval(userInput);", language="javascript")
    findings = scan_file(js)
    assert any(f.rule_id == "eval-on-input" for f in findings)


def test_weak_crypto_md5_detected():
    findings = scan_file(_load("weak_crypto_example.py"))
    assert any(f.rule_id == "weak-crypto" for f in findings)


def test_unsafe_yaml_load_detected():
    findings = scan_file(_load("yaml_example.py"))
    assert any(f.rule_id == "unsafe-yaml-load" for f in findings)


def test_safe_yaml_load_not_flagged():
    safe = FileToScan(
        path="config.py",
        content="import yaml\ndata = yaml.load(raw, Loader=yaml.SafeLoader)\n",
        language="python",
    )
    findings = scan_file(safe)
    assert not any(f.rule_id == "unsafe-yaml-load" for f in findings)


def test_debug_mode_detected():
    findings = scan_file(_load("debug_example.py"))
    assert any(f.rule_id == "debug-mode-enabled" for f in findings)


def test_path_traversal_detected():
    findings = scan_file(_load("path_traversal_example.py"))
    assert any(f.rule_id == "path-traversal" for f in findings)


def test_missing_auth_decorator_flags_unprotected_route():
    findings = scan_file(_load("missing_auth_example.py"))
    auth_findings = [f for f in findings if f.rule_id == "missing-auth-decorator"]
    assert any("list_users" in f.title for f in auth_findings)
    assert not any("get_profile" in f.title for f in auth_findings)


def test_js_weak_crypto_detected():
    js = FileToScan(
        path="hash.js",
        content='const hash = crypto.createHash("md5").update(data).digest("hex");',
        language="javascript",
    )
    findings = scan_file(js)
    assert any(f.rule_id == "weak-crypto" for f in findings)
