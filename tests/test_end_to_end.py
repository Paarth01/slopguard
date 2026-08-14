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
