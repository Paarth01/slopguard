"""
Fetches a public GitHub repo as a zip for scanning, given a repo URL.

Security note: this endpoint is publicly deployed and accepts a
user-supplied URL, which is a classic SSRF vector if handled carelessly
(an attacker could otherwise use the server to make requests to internal
infrastructure). To avoid that:

- The input is never used directly as a fetch target. It's parsed with a
  strict regex into (owner, repo, ref), and only those three components
  -- validated against a narrow character allowlist -- are used to build
  a new URL against a hardcoded host (codeload.github.com).
- Only http(s)://github.com/... URLs are accepted as input.
- Redirects are not followed to arbitrary hosts (requests' default zip
  download from codeload.github.com does not redirect off-host).
"""

from __future__ import annotations

import re
from typing import Optional

import requests

CODELOAD_URL = "https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{ref}"

# Deliberately narrow: GitHub owner/repo names are alphanumeric plus
# hyphen/underscore/dot. Anything outside this is rejected outright
# rather than passed through.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")

_GITHUB_URL_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?"
    r"(?:/tree/(?P<branch>[A-Za-z0-9_./-]+))?/?$"
)

_DEFAULT_BRANCHES_TO_TRY = ("main", "master")


class InvalidRepoUrl(ValueError):
    pass


class RepoFetchError(RuntimeError):
    pass


def parse_github_url(url: str) -> tuple[str, str, Optional[str]]:
    """
    Parses a github.com URL into (owner, repo, branch_or_none).
    Raises InvalidRepoUrl for anything that doesn't match the strict
    expected shape -- this is the SSRF guard, not just a convenience parser.
    """
    url = url.strip()
    match = _GITHUB_URL_RE.match(url)
    if not match:
        raise InvalidRepoUrl(
            "Expected a URL like https://github.com/<owner>/<repo> "
            "(optionally .../tree/<branch>)."
        )
    owner, repo, branch = match.group("owner"), match.group("repo"), match.group("branch")
    if not (_SAFE_SEGMENT.match(owner) and _SAFE_SEGMENT.match(repo)):
        raise InvalidRepoUrl("Owner/repo contained unexpected characters.")
    if branch and not re.match(r"^[A-Za-z0-9_./-]+$", branch):
        raise InvalidRepoUrl("Branch name contained unexpected characters.")
    return owner, repo, branch


def fetch_repo_zip(url: str, timeout: float = 20.0) -> bytes:
    """
    Downloads a public GitHub repo as a zip archive. Tries the branch
    named in the URL (if any), then falls back to main, then master.
    """
    owner, repo, branch = parse_github_url(url)
    candidates = [branch] if branch else list(_DEFAULT_BRANCHES_TO_TRY)

    last_status: Optional[int] = None
    for ref in candidates:
        fetch_url = CODELOAD_URL.format(owner=owner, repo=repo, ref=ref)
        try:
            resp = requests.get(fetch_url, timeout=timeout)
        except requests.RequestException as e:
            raise RepoFetchError(f"Network error fetching {owner}/{repo}: {e}") from e
        if resp.status_code == 200:
            return resp.content
        last_status = resp.status_code

    raise RepoFetchError(
        f"Could not fetch {owner}/{repo} (tried: {', '.join(candidates)}, "
        f"last status: {last_status}). Is it a public repo?"
    )
