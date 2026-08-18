from slopguard.input_parser import collect_files, parse_exclude_arg


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


def test_exclude_plain_name_excludes_whole_subtree(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_foo.py").write_text("x = 1")
    (tmp_path / "app.py").write_text("y = 2")

    files = collect_files(str(tmp_path), exclude=["tests"])
    paths = [f.path for f in files]
    assert not any("test_foo.py" in p for p in paths)
    assert any("app.py" in p for p in paths)


def test_exclude_glob_pattern_matches_relative_path(tmp_path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("var x = 1;")
    (tmp_path / "src.js").write_text("var y = 2;")

    files = collect_files(str(tmp_path), exclude=["dist/*"])
    paths = [f.path for f in files]
    assert not any("bundle.js" in p for p in paths)
    assert any("src.js" in p for p in paths)


def test_exclude_multiple_patterns(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_foo.py").write_text("x = 1")
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("z = 3")
    (tmp_path / "app.py").write_text("y = 2")

    files = collect_files(str(tmp_path), exclude=["tests", "legacy"])
    paths = [f.path for f in files]
    assert not any("test_foo.py" in p for p in paths)
    assert not any("old.py" in p for p in paths)
    assert any("app.py" in p for p in paths)


def test_exclude_does_not_affect_non_matching_files(tmp_path):
    (tmp_path / "app.py").write_text("y = 2")
    files = collect_files(str(tmp_path), exclude=["nonexistent_pattern"])
    assert any("app.py" in f.path for f in files)


def test_parse_exclude_arg_splits_and_strips():
    assert parse_exclude_arg("tests, dist/* ,legacy") == ["tests", "dist/*", "legacy"]


def test_parse_exclude_arg_empty_string_returns_empty_list():
    assert parse_exclude_arg("") == []
    assert parse_exclude_arg("   ") == []
