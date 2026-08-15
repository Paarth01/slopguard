"""
Intent/judge layer -- fully local, no API key required.

Earlier drafts of this module called the Anthropic API for an LLM-as-judge
approach. That's been removed by request: this module now never makes a
network call and needs no ANTHROPIC_API_KEY or any other credential.

What runs instead is a rule-based heuristic judge that checks the code
against its stated intent (a docstring, commit message, or PR description)
using pattern matching across a set of common "intent concepts" (auth,
validation, deletion, error handling, logging). It is intentionally
conservative -- it will miss subtle divergences a real LLM or NLI judge
would catch, and its findings are always marked lower-confidence than the
static-scan and dependency-hallucination findings.

If you later want a stronger local judge without an API key, the natural
upgrade path is a small NLI model (e.g. DeBERTa, as used in the Veritas
project) run entirely on-device via `sentence-transformers` /
`transformers` -- see ARCHITECTURE.md for that tradeoff. That wasn't wired
up here because pulling model weights requires network access to
huggingface.co, which isn't guaranteed in every environment this project
might run in; the heuristic below has zero extra dependencies and always
works offline.
"""

from __future__ import annotations

import re

from slopguard.models import Finding, Severity
from slopguard.static_scan import FileToScan

# Each concept: keywords that would signal the concept is mentioned in the
# stated intent, and keywords that would signal it's actually handled in
# the code. If the intent mentions it and the code shows no trace of it,
# that's a (weak, heuristic) signal worth a human's attention.
_INTENT_CONCEPTS: dict[str, dict[str, list[str]]] = {
    "authentication/authorization": {
        "intent": ["auth", "login", "permission", "authoriz", "access control", "role"],
        "code": [
            "auth",
            "login",
            "permission",
            "role",
            "is_admin",
            "current_user",
            "@login_required",
            "depends(",
        ],
    },
    "input validation": {
        "intent": ["valid", "sanitiz", "check input", "input check"],
        "code": [
            "valid",
            "sanitiz",
            "assert ",
            "raise ",
            "if not ",
            "isinstance(",
            "pydantic",
            "basemodel",
        ],
    },
    "deletion/removal": {
        "intent": ["delete", "remove", "drop"],
        "code": ["delete", "remove", "drop", ".pop(", "del "],
    },
    "error handling": {
        "intent": ["error", "exception", "fail gracefully", "handle failure"],
        "code": ["try:", "except", "raise", "error", "exception"],
    },
    "logging/audit": {
        "intent": ["log", "audit", "track"],
        "code": ["log", "logger", "logging", "audit"],
    },
    "rate limiting": {
        "intent": ["rate limit", "throttle", "quota"],
        "code": ["rate", "limit", "throttle", "quota"],
    },
}

_NEGATION_RE = re.compile(r"\b(no|not|without|skip|disable|remove)\b", re.IGNORECASE)


def _mentions_any(text: str, keywords: list[str]) -> bool:
    return any(k in text for k in keywords)


def judge_file(file: FileToScan, stated_intent: str) -> list[Finding]:
    """
    Compare a file's code against its stated intent using local keyword
    heuristics only. No network calls, no API key.
    """
    if not stated_intent.strip():
        return []

    intent_lower = stated_intent.lower()
    code_lower = file.content.lower()
    findings: list[Finding] = []

    for concept, kw in _INTENT_CONCEPTS.items():
        mentioned = _mentions_any(intent_lower, kw["intent"])
        if not mentioned:
            continue
        handled = _mentions_any(code_lower, kw["code"])
        if handled:
            continue

        # Weak extra signal: if the intent text negates the concept right
        # next to the keyword ("no auth needed"), don't flag it -- the
        # absence is probably intentional.
        idx = next((intent_lower.find(k) for k in kw["intent"] if k in intent_lower), -1)
        nearby = intent_lower[max(0, idx - 20) : idx + 20] if idx >= 0 else ""
        if _NEGATION_RE.search(nearby):
            continue

        findings.append(
            Finding(
                id=f"judge-{file.path}-{concept.replace('/', '-').replace(' ', '-')}",
                source="judge",
                severity=Severity.LOW,
                file=file.path,
                line=None,
                title=f"Stated intent mentions {concept}, but code shows no matching logic",
                explanation=(
                    f"The description references {concept}, but no related keyword "
                    f"appears in the code -- this is a low-confidence heuristic signal, "
                    f"not a confirmed bug. Worth a manual check."
                ),
                confidence=0.3,
                rule_id="intent-drift-heuristic",
            )
        )

    return findings
