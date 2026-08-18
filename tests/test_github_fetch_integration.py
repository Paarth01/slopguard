import zipfile
from io import BytesIO

import pytest

from slopguard.github_fetch import fetch_repo_zip


@pytest.mark.integration
def test_fetch_real_small_public_repo():
    # Deliberately picks a small, stable, well-known repo to keep this fast.
    data = fetch_repo_zip("https://github.com/octocat/Hello-World")
    assert len(data) > 0
    zf = zipfile.ZipFile(BytesIO(data))
    assert len(zf.namelist()) > 0
