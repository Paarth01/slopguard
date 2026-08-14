from slopguard.models import Finding, Severity
from slopguard.scorer import aggregate


def _f(source, severity, file, line, title):
    return Finding(
        id=f"{source}-{file}-{line}-{title}",
        source=source,
        severity=severity,
        file=file,
        line=line,
        title=title,
        explanation="test",
    )


def test_dedup_across_sources():
    a = [_f("static", Severity.HIGH, "app.py", 10, "Bad thing")]
    b = [_f("judge", Severity.MEDIUM, "app.py", 10, "Bad thing")]  # same file/line/title
    result = aggregate("target", 1, a, b)
    assert len(result.findings) == 1


def test_sorted_by_severity_descending():
    a = [
        _f("static", Severity.LOW, "app.py", 1, "Low issue"),
        _f("static", Severity.CRITICAL, "app.py", 2, "Critical issue"),
        _f("static", Severity.MEDIUM, "app.py", 3, "Medium issue"),
    ]
    result = aggregate("target", 1, a)
    severities = [f.severity for f in result.findings]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_summary_counts():
    a = [
        _f("static", Severity.HIGH, "app.py", 1, "A"),
        _f("static", Severity.HIGH, "app.py", 2, "B"),
        _f("static", Severity.LOW, "app.py", 3, "C"),
    ]
    result = aggregate("target", 1, a)
    counts = result.summary_counts()
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0
