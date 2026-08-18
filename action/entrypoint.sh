#!/bin/sh
# Entrypoint for the SlopGuard GitHub Action container.
#
# Runs the scan, then (if we're in a pull_request context with a token)
# posts or updates a summary comment on the PR. The scan's own exit code
# is what gates the build -- the PR comment step always fails soft so a
# comment-posting hiccup never breaks CI over something cosmetic.

set -u

SCAN_PATH="${INPUT_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
EXCLUDE="${INPUT_EXCLUDE:-}"
REPORT_DIR="/tmp/slopguard-report"

echo "SlopGuard: scanning '$SCAN_PATH' (fail-on: $FAIL_ON, exclude: ${EXCLUDE:-none})"
if [ -n "$EXCLUDE" ]; then
    python -m slopguard scan "$SCAN_PATH" --report "$REPORT_DIR" --fail-on "$FAIL_ON" --exclude "$EXCLUDE"
else
    python -m slopguard scan "$SCAN_PATH" --report "$REPORT_DIR" --fail-on "$FAIL_ON"
fi
SCAN_EXIT=$?

if [ -f "$REPORT_DIR/report.json" ]; then
    if [ -n "${GITHUB_EVENT_PATH:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
        echo "SlopGuard: attempting to post PR comment..."
        python /app/action/post_comment.py "$REPORT_DIR/report.json"
    else
        echo "SlopGuard: not running in a PR context (or no GITHUB_TOKEN) -- skipping comment."
    fi
else
    echo "SlopGuard: no report.json produced -- skipping PR comment step."
fi

exit "$SCAN_EXIT"
