"""Merges findings from all scanner components, deduplicates overlaps, and
produces the final ScanResult."""

from __future__ import annotations

from slopguard.models import Finding, ScanResult


def aggregate(target: str, files_scanned: int, *finding_lists: list[Finding]) -> ScanResult:
    all_findings: list[Finding] = []
    seen_keys: set[str] = set()

    for findings in finding_lists:
        for f in findings:
            key = f.dedup_key()
            if key in seen_keys:
                continue  # same file+line+title already reported by another source
            seen_keys.add(key)
            all_findings.append(f)

    # Sort by severity (highest first), then by file/line for readability
    all_findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line or 0))

    return ScanResult(target=target, findings=all_findings, files_scanned=files_scanned)
