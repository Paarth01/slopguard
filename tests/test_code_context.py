from slopguard.code_context import extract_snippet


def test_extract_snippet_basic():
    content = "line1\nline2\nline3\nline4\nline5"
    snippet = extract_snippet(content, target_line=3)
    assert [s.line for s in snippet] == [2, 3, 4]
    assert [s.text for s in snippet] == ["line2", "line3", "line4"]
    assert [s.is_target for s in snippet] == [False, True, False]


def test_extract_snippet_at_start_of_file():
    content = "line1\nline2\nline3"
    snippet = extract_snippet(content, target_line=1)
    # no line 0 to include -- starts at line 1
    assert [s.line for s in snippet] == [1, 2]
    assert snippet[0].is_target is True


def test_extract_snippet_at_end_of_file():
    content = "line1\nline2\nline3"
    snippet = extract_snippet(content, target_line=3)
    assert [s.line for s in snippet] == [2, 3]
    assert snippet[-1].is_target is True


def test_extract_snippet_single_line_file():
    content = "only_line"
    snippet = extract_snippet(content, target_line=1)
    assert [s.line for s in snippet] == [1]
    assert snippet[0].is_target is True


def test_extract_snippet_out_of_range_returns_none():
    content = "line1\nline2"
    assert extract_snippet(content, target_line=10) is None


def test_extract_snippet_none_line_returns_none():
    content = "line1\nline2"
    assert extract_snippet(content, target_line=None) is None


def test_extract_snippet_custom_context():
    content = "\n".join(f"line{i}" for i in range(1, 11))
    snippet = extract_snippet(content, target_line=5, context=2)
    assert [s.line for s in snippet] == [3, 4, 5, 6, 7]
