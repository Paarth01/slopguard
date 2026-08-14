from slopguard.input_parser import collect_files


def test_collect_files_finds_fixtures():
    files = collect_files("tests/fixtures")
    paths = [f.path for f in files]
    assert any("secret_example.py" in p for p in paths)
    assert all(f.language == "python" for f in files)  # fixtures dir is all .py


def test_collect_files_skips_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("var x = 1;")
    (tmp_path / "real.js").write_text("var y = 2;")

    files = collect_files(str(tmp_path))
    paths = [f.path for f in files]
    assert not any("node_modules" in p for p in paths)
    assert any("real.js" in p for p in paths)
