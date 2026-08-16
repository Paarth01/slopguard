import io
import zipfile

from fastapi.testclient import TestClient

from slopguard.api import app

client = TestClient(app)


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_scan_zip_with_vulnerabilities():
    zip_buf = _make_zip(
        {
            "app.py": 'def f(user_expr):\n    return eval(user_expr)\n',
        }
    )
    r = client.post("/scan", files={"file": ("test.zip", zip_buf, "application/zip")})
    assert r.status_code == 200
    data = r.json()
    assert data["files_scanned"] == 1
    assert any(f["rule_id"] == "eval-on-input" for f in data["findings"])


def test_scan_clean_zip_has_no_findings():
    zip_buf = _make_zip({"clean.py": "def add(a, b):\n    return a + b\n"})
    r = client.post("/scan", files={"file": ("clean.zip", zip_buf, "application/zip")})
    assert r.status_code == 200
    assert r.json()["findings"] == []


def test_scan_rejects_bad_zip():
    bad = io.BytesIO(b"not a zip file")
    r = client.post("/scan", files={"file": ("bad.zip", bad, "application/zip")})
    assert r.status_code == 400


def test_scan_with_exclude_param_skips_matching_files():
    zip_buf = _make_zip(
        {
            "app.py": "def add(a, b):\n    return a + b\n",
            "tests/test_app.py": 'def f(user_expr):\n    return eval(user_expr)\n',
        }
    )
    r = client.post(
        "/scan",
        files={"file": ("test.zip", zip_buf, "application/zip")},
        data={"exclude": "tests"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["files_scanned"] == 1
    assert data["findings"] == []
