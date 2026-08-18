"""Core data models shared across all scanner components."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


SourceType = Literal["static", "slop_check", "judge"]


class SnippetLine(BaseModel):
    """One line of source context shown around a finding."""

    line: int
    text: str
    is_target: bool = False


class Finding(BaseModel):
    """A single scanner finding, regardless of which component produced it."""

    id: str
    source: SourceType
    severity: Severity
    file: str
    line: int | None = None
    title: str
    explanation: str = Field(
        ..., description="One plain-English sentence a non-security-engineer can understand."
    )
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    rule_id: str | None = None
    snippet: list[SnippetLine] | None = Field(
        default=None,
        description="A few lines of source context around the finding, when a line "
        "number is available. None if the finding has no specific line (e.g. a "
        "dependency-hallucination finding, which applies to the whole file).",
    )

    def dedup_key(self) -> str:
        # Findings on the same file+line with the same title are treated as duplicates
        # across sources (e.g. static scan and judge both flagging the same line).
        return f"{self.file}:{self.line}:{self.title}"


class ScanResult(BaseModel):
    """Aggregated result of a full scan run."""

    target: str
    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = 0

    def findings_at_or_above(self, min_severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity.rank >= min_severity.rank]

    def summary_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts
