"""Command-line interface: python -m slopguard scan <path>"""

from __future__ import annotations

import argparse
import sys

from slopguard.models import Severity
from slopguard.report import write_reports
from slopguard.scanner import run_scan

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[90m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def _print_table(result) -> None:
    if not result.findings:
        print(f"\n✅ No findings across {result.files_scanned} files scanned.\n")
        return

    print(f"\nSlopGuard — {result.target} ({result.files_scanned} files scanned)\n")
    for f in result.findings:
        color = _SEVERITY_COLOR.get(f.severity, "")
        loc = f"{f.file}:{f.line}" if f.line else f.file
        print(f"{color}[{f.severity.value.upper():8}]{_RESET} {loc}")
        print(f"           {f.title}")
        print(f"           {f.explanation}")
        print(f"           source={f.source} confidence={f.confidence:.2f}\n")

    counts = result.summary_counts()
    print("Summary: " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="slopguard")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a folder or file")
    scan_p.add_argument("path", help="Path to scan")
    scan_p.add_argument("--report", help="Write reports to this directory", default=None)
    scan_p.add_argument("--fail-on", default=None, choices=[s.value for s in Severity])
    scan_p.add_argument(
        "--intent", default="", help="Stated intent/PR description for the judge layer"
    )
    scan_p.add_argument("--judge", action="store_true", help="Enable the intent/judge layer")

    args = parser.parse_args(argv)

    if args.command == "scan":
        result = run_scan(args.path, stated_intent=args.intent, run_judge=args.judge)
        _print_table(result)

        if args.report:
            html_path, json_path = write_reports(result, args.report)
            print(f"\nReports written to {html_path} and {json_path}")

        if args.fail_on:
            threshold = Severity(args.fail_on)
            if result.findings_at_or_above(threshold):
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
