"""
Posts a SlopGuard scan summary as a comment on the triggering pull request.

Reads:
  - report path (argv[1]) -- the report.json written by `slopguard scan --report`
  - GITHUB_EVENT_PATH -- path to the GitHub Actions event payload, used to
    find the PR number (only present/relevant for pull_request events)
  - GITHUB_REPOSITORY -- "owner/repo", provided automatically by Actions
  - GITHUB_TOKEN -- provided automatically by Actions as ${{ github.token }}

Deliberately fails soft: if anything about the GitHub context is missing
(e.g. running outside a PR, or a non-Actions environment), this exits 0
without posting rather than breaking the scan job. The scan's own exit
code (from `slopguard scan --fail-on`) is what should gate the build --
this script's job is purely to leave a helpful comment when it can.
"""

from __future__ import annotations

import json
import os
import sys

import requests

_SEVERITY_EMOJI = {
    "critical": "\U0001f534",  # red circle
    "high": "\U0001f7e0",  # orange circle
    "medium": "\U0001f7e1",  # yellow circle
    "low": "\U000026aa",  # white circle
    "info": "\U0001f535",  # blue circle
}

_COMMENT_MARKER = "<!-- slopguard-scan-comment -->"


def _get_pr_number() -> int | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        return None
    try:
        with open(event_path, encoding="utf-8") as f:
            event = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    # pull_request events nest the PR under "pull_request"; some other
    # trigger types (e.g. issue_comment on a PR) nest it under "issue".
    pr = event.get("pull_request") or {}
    if "number" in pr:
        return pr["number"]
    issue = event.get("issue") or {}
    if issue.get("pull_request") and "number" in issue:
        return issue["number"]
    return None


def build_comment_body(report: dict) -> str:
    counts = {}
    for f in report.get("findings", []):
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    lines = [_COMMENT_MARKER, "## \U0001f6e1\ufe0f SlopGuard scan results", ""]

    if not report.get("findings"):
        lines.append(f"No findings across {report.get('files_scanned', 0)} files scanned. \u2705")
        return "\n".join(lines)

    summary_bits = [
        f"{_SEVERITY_EMOJI.get(sev, '')} {count} {sev}" for sev, count in counts.items() if count
    ]
    lines.append(f"**{report.get('files_scanned', 0)} files scanned** — " + ", ".join(summary_bits))
    lines.append("")
    lines.append("| Severity | File | Finding |")
    lines.append("|---|---|---|")

    # Cap the inline table so a huge finding count doesn't produce an
    # unreadable comment; point to the full artifact instead.
    max_rows = 20
    findings = report["findings"]
    for f in findings[:max_rows]:
        loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
        emoji = _SEVERITY_EMOJI.get(f["severity"], "")
        lines.append(f"| {emoji} {f['severity']} | `{loc}` | {f['title']} |")

    if len(findings) > max_rows:
        lines.append("")
        lines.append(
            f"_...and {len(findings) - max_rows} more. See the full report artifact for details._"
        )

    lines.append("")
    lines.append(
        "_Posted automatically by [SlopGuard](https://github.com/) — a security scanner for AI-generated code._"
    )
    return "\n".join(lines)


def _find_existing_comment(session: requests.Session, api_base: str, pr_number: int) -> int | None:
    """Look for a prior SlopGuard comment on this PR so we update it instead
    of spamming a new comment on every push."""
    resp = session.get(f"{api_base}/issues/{pr_number}/comments", params={"per_page": 100})
    if resp.status_code != 200:
        return None
    for comment in resp.json():
        if _COMMENT_MARKER in comment.get("body", ""):
            return comment["id"]
    return None


def post_comment(report_path: str) -> int:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr_number = _get_pr_number()

    if not token or not repo or pr_number is None:
        print(
            "Not in a PR context (or missing GITHUB_TOKEN/GITHUB_REPOSITORY) -- skipping PR comment."
        )
        return 0

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    body = build_comment_body(report)

    api_base = f"https://api.github.com/repos/{repo}"
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )

    existing_id = _find_existing_comment(session, api_base, pr_number)
    if existing_id:
        resp = session.patch(f"{api_base}/issues/comments/{existing_id}", json={"body": body})
    else:
        resp = session.post(f"{api_base}/issues/{pr_number}/comments", json={"body": body})

    if resp.status_code not in (200, 201):
        print(f"Warning: failed to post PR comment ({resp.status_code}): {resp.text[:300]}")
        return 0  # fail soft -- don't break the scan job over a comment failure

    print(f"Posted scan summary comment on PR #{pr_number}.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: post_comment.py <report.json path>", file=sys.stderr)
        sys.exit(0)  # fail soft even on misuse -- never break the calling scan job
    sys.exit(post_comment(sys.argv[1]))
