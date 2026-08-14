"""Top-level orchestrator: runs all scan components and aggregates results."""

from __future__ import annotations

from slopguard.input_parser import collect_files
from slopguard.judge import judge_file
from slopguard.models import ScanResult
from slopguard.scorer import aggregate
from slopguard.slop_check import check_files_for_hallucinations
from slopguard.static_scan import scan_files


def run_scan(target: str, stated_intent: str = "", run_judge: bool = False) -> ScanResult:
    """
    Run the full scan pipeline against a folder or file.

    run_judge defaults to False since it's an opt-in extra pass. The judge
    layer is fully local (no API key, no network call) -- see
    slopguard/judge.py -- so enabling it costs nothing but a little time.
    """
    files = collect_files(target)

    static_findings = scan_files(files)
    slop_findings = check_files_for_hallucinations(files)

    judge_findings = []
    if run_judge and stated_intent:
        for f in files:
            judge_findings.extend(judge_file(f, stated_intent))

    return aggregate(target, len(files), static_findings, slop_findings, judge_findings)
