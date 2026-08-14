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
