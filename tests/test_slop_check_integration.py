import pytest

from slopguard.slop_check import check_npm_package, check_pypi_package


@pytest.mark.integration
def test_real_package_exists_on_pypi():
    exists, age_days = check_pypi_package("requests")
    assert exists is True
    assert age_days is not None and age_days > 100


@pytest.mark.integration
def test_hallucinated_package_does_not_exist_on_pypi():
    exists, _ = check_pypi_package("this-package-definitely-does-not-exist-zzz-12345")
    assert exists is False


@pytest.mark.integration
def test_real_package_exists_on_npm():
    exists, age_days = check_npm_package("express")
    assert exists is True
    assert age_days is not None and age_days > 100


@pytest.mark.integration
def test_hallucinated_package_does_not_exist_on_npm():
    exists, _ = check_npm_package("this-package-definitely-does-not-exist-zzz-12345")
    assert exists is False
