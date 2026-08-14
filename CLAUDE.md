# CLAUDE.md — Project Context for Claude Code

This file is read automatically by Claude Code. It defines what we're building, how, and the conventions to follow. Keep this file updated as decisions change.

## Project Name
**SlopGuard** — a security scanner purpose-built for AI-generated code (Copilot, Cursor, Claude Code, ChatGPT, etc.)

## One-line pitch
Catches the two failure modes unique to LLM-written code — invented ("hallucinated") package names that attackers can slopsquat, and subtle logic/security flaws that slip past a human skimming AI output — before it merges.

## Why this project exists
- 45%+ of AI-generated code carries a known security flaw (Veracode 2025), and the rate isn't improving as models get bigger.
- LLMs regularly invent plausible-but-nonexistent package names ("slopsquatting"); attackers register those names on PyPI/npm and wait.
- Existing tools (Semgrep, Snyk, Dependabot) don't specifically target the AI-authorship failure mode — they weren't built to ask "did an LLM plausibly hallucinate this?"
- This sits at the intersection of two 2026 hiring-hot tracks: applied AI engineering and security engineering.

## Author context (for tone/decisions, not for the app itself)
Built by Paarth Agl (github.com/Paarth01), a CS undergrad who previously built:
- **Veritas** — LLM hallucination detection service (FastAPI, DeBERTa NLI, sentence-transformers, Docker Compose, GitHub Actions)
- **Plagiarism Detector** — Winnowing/GST/AST/PDG-based code similarity system (FastAPI, HTML reports, 34/34 tests passing, deployed on Render)

This project reuses architecture patterns and, where sensible, actual code/model choices from Veritas (the NLI-based judge layer) and the plagiarism detector (the HTML report generator, FastAPI service shape, test discipline).

## Scope (v1 — what we are building)
1. **Static vulnerability scan** — wrap Semgrep with a curated ruleset targeting patterns common in AI-generated code (hardcoded secrets, missing input validation, unsafe eval/exec, SQL string concatenation, missing auth checks, overly-permissive CORS, etc.)
2. **Dependency hallucination checker ("slop check")** — parse imports/requires from a diff or file, check each package name against the real PyPI/npm registry, flag anything that doesn't exist (hallucination risk) and anything that exists but was registered very recently or has near-zero downloads (typosquat/slopsquat risk).
3. **Intent/judge layer** — given the code + (optionally) the prompt or PR description that generated it, use a fully local keyword-heuristic judge (no API key, no network call) to flag cases where the code's actual behavior may diverge from its stated intent.
4. **Reporting** — generate a single HTML report per scan (reuse plagiarism-detector report style) with severity-ranked findings, plus a machine-readable JSON output for CI.
5. **Delivery surface** — a GitHub Action that runs on PRs and posts a summary comment, backed by the same FastAPI service so it can also run as a standalone CLI/API.

## Explicitly out of scope for v1
- Auto-fixing code (flag only, don't patch)
- Support for languages beyond Python and JavaScript/TypeScript
- A hosted SaaS product / billing / multi-tenant auth
- Any LLM API dependency in the judge layer — it must run fully offline with no credentials (this was an explicit decision, not an oversight)

## Tech stack
- **Backend**: Python 3.11+, FastAPI
- **Static analysis**: Semgrep (via subprocess/CLI), custom rules in `rules/`
- **Registry checks**: `requests` against PyPI JSON API (`pypi.org/pypi/<pkg>/json`) and npm registry API (`registry.npmjs.org/<pkg>`)
- **Judge layer**: fully local keyword-heuristic matcher, no API key, no network call — see `slopguard/judge.py` and `ARCHITECTURE.md` for the reasoning and the documented upgrade path (a local NLI model) if stronger accuracy is needed later
- **Reports**: Jinja2 → static HTML (same approach as the plagiarism detector)
- **Testing**: pytest, target >90% coverage on core logic (scoring, parsing, registry lookups)
- **CI/CD**: GitHub Actions — one workflow to test/lint this repo, one reusable workflow (`action.yml`) that other repos can consume
- **Packaging**: Docker Compose for local dev; the GitHub Action itself should run in a container for reproducibility

## Conventions
- Python: `black` + `ruff`, type hints everywhere, `mypy` in CI
- Commit style: Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
- Every new feature ships with tests in the same PR — no exceptions, this mirrors the 34/34 discipline from the plagiarism detector
- Config over hardcoding: severity thresholds, ruleset selection, and registry-lookup timeouts all live in `config.yaml`, not in code
- No network calls in unit tests — mock the PyPI/npm HTTP layer; keep a small set of `integration` tests (marked `@pytest.mark.integration`) that hit the real registries and are excluded from the default `pytest` run

## Current phase
See `ROADMAP.md`. Always check it before starting work and update the checkboxes as you complete items.

## How to run things
```bash
# local dev
docker compose up --build

# run the scanner CLI directly on a folder
python -m slopguard scan ./path/to/code

# run tests
pytest                      # unit only (fast, no network)
pytest -m integration       # includes real registry lookups
```

## When in doubt
- Prefer a smaller, working v1 over a feature-complete but untested v2.
- If a design decision isn't obvious, write it down as a short ADR-style note in `ARCHITECTURE.md` rather than silently picking one.
- Every scan result should be explainable in one sentence a non-security-engineer could understand — this is a resume/demo project, so clarity of output matters as much as detection accuracy.
