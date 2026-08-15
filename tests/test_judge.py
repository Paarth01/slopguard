from slopguard.judge import judge_file
from slopguard.static_scan import FileToScan


def test_no_intent_returns_no_findings():
    file = FileToScan(path="app.py", content="def f(): pass", language="python")
    assert judge_file(file, "") == []


def test_flags_missing_auth_when_intent_mentions_it():
    file = FileToScan(
        path="app.py",
        content="def get_profile(user_id):\n    return db.get(user_id)\n",
        language="python",
    )
    findings = judge_file(file, "Add an endpoint that requires authentication to view a profile")
    assert any(f.rule_id == "intent-drift-heuristic" for f in findings)
    assert any("authentication" in f.title for f in findings)


def test_does_not_flag_when_code_handles_the_concept():
    file = FileToScan(
        path="app.py",
        content=(
            "@login_required\n"
            "def get_profile(user_id):\n"
            "    return db.get(user_id)\n"
        ),
        language="python",
    )
    findings = judge_file(file, "Add an endpoint that requires authentication to view a profile")
    assert findings == []


def test_negation_in_intent_suppresses_finding():
    file = FileToScan(path="app.py", content="def get_profile(user_id):\n    return db.get(user_id)\n", language="python")
    findings = judge_file(file, "Add a public profile endpoint, no authentication needed")
    assert findings == []


def test_findings_are_low_confidence():
    file = FileToScan(path="app.py", content="def delete_all(): pass", language="python")
    findings = judge_file(file, "Validate input before deleting records")
    for f in findings:
        assert f.confidence <= 0.5
        assert f.severity.value == "low"
