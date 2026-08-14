from unittest.mock import patch

from slopguard.judge import judge_file
from slopguard.static_scan import FileToScan


def test_no_intent_returns_no_findings():
    file = FileToScan(path="app.py", content="def f(): pass", language="python")
    assert judge_file(file, "") == []


def test_falls_back_to_heuristic_without_api_key():
    file = FileToScan(
        path="app.py",
        content="def get_profile(user_id):\n    return db.get(user_id)\n",
        language="python",
    )
    with patch.dict("os.environ", {}, clear=True):
        findings = judge_file(file, "Add an endpoint that requires authentication")
    assert any(f.rule_id == "intent-drift" for f in findings)
    assert any("heuristic fallback" in f.explanation for f in findings)
