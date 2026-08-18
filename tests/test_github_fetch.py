from unittest.mock import MagicMock, patch

import pytest

from slopguard.github_fetch import (
    InvalidRepoUrl,
    RepoFetchError,
    fetch_repo_zip,
    parse_github_url,
)


def test_parse_basic_url():
    assert parse_github_url("https://github.com/psf/requests") == ("psf", "requests", None)


def test_parse_url_with_branch():
    assert parse_github_url("https://github.com/pallets/flask/tree/main") == (
        "pallets",
        "flask",
        "main",
    )


def test_parse_url_strips_git_suffix():
    assert parse_github_url("https://github.com/expressjs/express.git") == (
        "expressjs",
        "express",
        None,
    )


def test_parse_url_trailing_slash():
    assert parse_github_url("https://github.com/psf/requests/") == ("psf", "requests", None)


@pytest.mark.parametrize(
    "bad_url",
    [
        "https://evil.com/owner/repo",
        "https://github.com.evil.com/o/r",
        "ftp://github.com/o/r",
        "https://github.com/o/r/../../etc",
        "not-a-url-at-all",
        "https://github.com/",
        "javascript:alert(1)",
        "https://github.com/owner",  # missing repo
    ],
)
def test_parse_rejects_ssrf_and_malformed_urls(bad_url):
    with pytest.raises(InvalidRepoUrl):
        parse_github_url(bad_url)


def test_fetch_repo_zip_uses_only_codeload_host():
    """Confirms the outbound request always targets codeload.github.com,
    built from the parsed owner/repo -- never the raw input URL."""
    with patch("slopguard.github_fetch.requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200, content=b"fake-zip-bytes")
        fetch_repo_zip("https://github.com/psf/requests")
        called_url = mock_get.call_args[0][0]
        assert called_url.startswith("https://codeload.github.com/psf/requests/")


def test_fetch_repo_zip_tries_main_then_master():
    with patch("slopguard.github_fetch.requests.get") as mock_get:
        mock_get.side_effect = [
            MagicMock(status_code=404, content=b""),
            MagicMock(status_code=200, content=b"fake-zip-bytes"),
        ]
        result = fetch_repo_zip("https://github.com/some/repo")
        assert result == b"fake-zip-bytes"
        assert mock_get.call_count == 2
        assert "/main" in mock_get.call_args_list[0][0][0]
        assert "/master" in mock_get.call_args_list[1][0][0]


def test_fetch_repo_zip_raises_when_all_branches_fail():
    with patch("slopguard.github_fetch.requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=404, content=b"")
        with pytest.raises(RepoFetchError):
            fetch_repo_zip("https://github.com/some/nonexistent-repo")


def test_fetch_repo_zip_raises_on_network_error():
    import requests as requests_module

    with patch("slopguard.github_fetch.requests.get") as mock_get:
        mock_get.side_effect = requests_module.ConnectionError("boom")
        with pytest.raises(RepoFetchError):
            fetch_repo_zip("https://github.com/some/repo")
