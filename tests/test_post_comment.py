import json
import os
from unittest.mock import MagicMock, patch

import pytest

from action.post_comment import _get_pr_number, build_comment_body, post_comment


def test_build_comment_body_no_findings():
    report = {"target": "x", "files_scanned": 12, "findings": []}
    body = build_comment_body(report)
    assert "No findings" in body
    assert "12 files scanned" in body


def test_build_comment_body_with_findings():
    report = {
        "target": "x",
        "files_scanned": 5,
        "findings": [
            {"severity": "critical", "file": "app.py", "line": 10, "title": "Hardcoded secret"},
            {"severity": "high", "file": "app.py", "line": None, "title": "Hallucinated package"},
        ],
    }
    body = build_comment_body(report)
    assert "critical" in body
    assert "Hardcoded secret" in body
    assert "app.py:10" in body
    assert "`app.py`" in body  # the line-less finding shouldn't get a bogus ":None"


def test_build_comment_body_caps_table_rows():
    findings = [
        {"severity": "low", "file": f"f{i}.py", "line": i, "title": f"Finding {i}"}
        for i in range(30)
    ]
    report = {"target": "x", "files_scanned": 30, "findings": findings}
    body = build_comment_body(report)
    assert "and 10 more" in body


def test_get_pr_number_from_pull_request_event(tmp_path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"pull_request": {"number": 42}}))
    with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event_file)}):
        assert _get_pr_number() == 42


def test_get_pr_number_missing_event_path():
    with patch.dict(os.environ, {}, clear=True):
        assert _get_pr_number() is None


def test_post_comment_skips_when_not_in_pr_context(tmp_path):
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"findings": [], "files_scanned": 1}))
    with patch.dict(os.environ, {}, clear=True):
        result = post_comment(str(report_file))
    assert result == 0  # fails soft, doesn't raise


@patch("action.post_comment.requests.Session")
def test_post_comment_creates_new_comment_when_none_exists(mock_session_cls, tmp_path):
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"findings": [], "files_scanned": 3}))

    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"pull_request": {"number": 7}}))

    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.get.return_value = MagicMock(status_code=200, json=lambda: [])  # no existing comment
    mock_session.post.return_value = MagicMock(status_code=201)

    env = {
        "GITHUB_TOKEN": "fake-token",
        "GITHUB_REPOSITORY": "someuser/somerepo",
        "GITHUB_EVENT_PATH": str(event_file),
    }
    with patch.dict(os.environ, env, clear=True):
        result = post_comment(str(report_file))

    assert result == 0
    mock_session.post.assert_called_once()
    call_args = mock_session.post.call_args
    assert "issues/7/comments" in call_args[0][0]


@patch("action.post_comment.requests.Session")
def test_post_comment_updates_existing_comment(mock_session_cls, tmp_path):
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"findings": [], "files_scanned": 3}))

    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"pull_request": {"number": 7}}))

    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.get.return_value = MagicMock(
        status_code=200,
        json=lambda: [{"id": 999, "body": "<!-- slopguard-scan-comment -->\nold"}],
    )
    mock_session.patch.return_value = MagicMock(status_code=200)

    env = {
        "GITHUB_TOKEN": "fake-token",
        "GITHUB_REPOSITORY": "someuser/somerepo",
        "GITHUB_EVENT_PATH": str(event_file),
    }
    with patch.dict(os.environ, env, clear=True):
        result = post_comment(str(report_file))

    assert result == 0
    mock_session.patch.assert_called_once()
    mock_session.post.assert_not_called()
    call_args = mock_session.patch.call_args
    assert "issues/comments/999" in call_args[0][0]
