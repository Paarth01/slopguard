from unittest.mock import patch

from slopguard.report import render_html
from slopguard.scanner import run_scan


def test_full_scan_against_fixtures_finds_known_issues():
    # Mock out network calls in slop_check so this stays a fast unit test.
    with patch("slopguard.slop_check.check_pypi_package", return_value=(True, 3000)):
        result = run_scan("tests/fixtures")

    rule_ids = {f.rule_id for f in result.findings}
    assert "hardcoded-secret" in rule_ids
    assert "eval-on-input" in rule_ids
    assert "sql-string-concat" in rule_ids
    assert "cors-allow-all" in rule_ids
    assert result.files_scanned > 0


def test_report_renders_without_error():
    with patch("slopguard.slop_check.check_pypi_package", return_value=(True, 3000)):
        result = run_scan("tests/fixtures")
    html = render_html(result)
    assert "SlopGuard scan report" in html
    assert "tests/fixtures" in html


def test_run_scan_exclude_removes_findings_from_excluded_file():
    with patch("slopguard.slop_check.check_pypi_package", return_value=(True, 3000)):
        full_result = run_scan("tests/fixtures")
        excluded_result = run_scan("tests/fixtures", exclude=["secret_example.py"])

    full_files = {f.file for f in full_result.findings}
    excluded_files = {f.file for f in excluded_result.findings}
    assert any("secret_example.py" in f for f in full_files)
    assert not any("secret_example.py" in f for f in excluded_files)
    assert excluded_result.files_scanned == full_result.files_scanned - 1
