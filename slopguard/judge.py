"""
Intent/judge layer.

Per ARCHITECTURE.md's Option A/B decision: this implements Option B
(LLM-as-judge) since it's far less engineering than training/adapting an
NLI model, and is good enough for a v1 demo.

If ANTHROPIC_API_KEY is set, this calls the real Claude API with a
structured prompt and parses the JSON response. If no key is set (e.g.
running in a sandbox with no credentials), it falls back to a small,
clearly-labeled heuristic judge so the rest of the pipeline still works
end-to-end -- this fallback is NOT a substitute for the real judge and
should never be presented as equivalent accuracy in the README.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import requests

from slopguard.models import Finding, Severity
from slopguard.static_scan import FileToScan

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"

_JUDGE_SYSTEM_PROMPT = """You review a code change against its stated intent \
(a docstring, commit message, or PR description) and report ONLY genuine \
divergences between what the code claims to do and what it actually does -- \
missing checks, inverted conditions, silently swallowed errors, or logic \
that doesn't match the description. Do not report style issues or \
things static analysis would already catch (secrets, injection, eval).

Respond with ONLY a JSON array (no prose, no markdown fences). Each element:
{"line": <int or null>, "title": "<short title>", "explanation": "<one plain-English sentence>", "confidence": <0.0-1.0>}

If there are no divergences, respond with an empty array: []
"""


def _call_llm_judge(code: str, stated_intent: str, timeout: float = 30.0) -> list[dict]:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")

    payload = {
        "model": MODEL,
        "max_tokens": 1000,
        "system": _JUDGE_SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": f"Stated intent:\n{stated_intent}\n\nCode:\n```\n{code}\n```",
            }
        ],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    resp = requests.post(ANTHROPIC_API_URL, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    raw = "".join(text_blocks).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def _heuristic_judge(code: str, stated_intent: str) -> list[dict]:
    """
    Extremely simple keyword-based heuristic used only as a fallback when
    no ANTHROPIC_API_KEY is configured -- exists so the pipeline runs
    end-to-end without an API key -- it is intentionally conservative and
    will miss almost everything a real judge would catch.
    """
    intent_keywords = {
        "auth": ["auth", "login", "permission", "authoriz"],
        "validate": ["valid", "sanitiz", "check"],
        "delete": ["delete", "remove", "drop"],
    }
    findings = []
    intent_lower = stated_intent.lower()
    code_lower = code.lower()
    for concept, keywords in intent_keywords.items():
        mentioned_in_intent = any(k in intent_lower for k in keywords)
        present_in_code = any(k in code_lower for k in keywords)
        if mentioned_in_intent and not present_in_code:
            findings.append(
                {
                    "line": None,
                    "title": f"Stated intent mentions '{concept}' but code has no matching logic",
                    "explanation": (
                        f"The description references {concept}-related behavior, but no "
                        f"matching keyword appears in the code -- worth a manual check."
                    ),
                    "confidence": 0.3,
                }
            )
    return findings


def judge_file(file: FileToScan, stated_intent: str) -> list[Finding]:
    if not stated_intent.strip():
        return []

    try:
        raw_findings = _call_llm_judge(file.content, stated_intent)
        used_fallback = False
    except (RuntimeError, requests.RequestException):
        raw_findings = _heuristic_judge(file.content, stated_intent)
        used_fallback = True

    findings: list[Finding] = []
    for i, rf in enumerate(raw_findings):
        title = rf.get("title", "Possible intent/behavior divergence")
        explanation = rf.get("explanation", "")
        if used_fallback:
            explanation += " (heuristic fallback judge -- no ANTHROPIC_API_KEY configured, verify manually)"
        findings.append(
            Finding(
                id=f"judge-{file.path}-{i}",
                source="judge",
                severity=Severity.MEDIUM,
                file=file.path,
                line=rf.get("line"),
                title=title,
                explanation=explanation,
                confidence=float(rf.get("confidence", 0.5)),
                rule_id="intent-drift",
            )
        )
    return findings
