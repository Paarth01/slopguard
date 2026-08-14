# Starter prompts for Claude Code

Copy these in order into Claude Code, one at a time, letting each finish (and its tests pass) before moving to the next. Claude Code will already have `CLAUDE.md`, `ARCHITECTURE.md`, and `ROADMAP.md` as context if they're in the repo root.

---

### 1. Scaffold
```
Read CLAUDE.md, ARCHITECTURE.md, and ROADMAP.md. Set up Phase 0 of the roadmap:
the repo structure, pyproject.toml with pinned dependencies, Dockerfile,
docker-compose.yml, and a GitHub Actions workflow that runs lint + pytest on
push and PR. Check off completed items in ROADMAP.md as you go.
```

### 2. Static scan
```
Implement Phase 1 from ROADMAP.md: the Semgrep wrapper and custom ruleset.
Create rules/ai-patterns.yml with rules for the patterns listed in
ARCHITECTURE.md. Write one fixture file with a deliberate vulnerability per
rule and a test asserting it's caught with exactly one finding. Update the
CLI so `python -m slopguard scan <path>` prints results as a table.
```

### 3. Dependency hallucination checker
```
Implement Phase 2 from ROADMAP.md: import extraction for Python and JS/TS,
a PyPI/npm registry client with a local cache, and the hallucination/
slopsquat scoring logic. Mock the registry HTTP calls in unit tests; add a
small number of tests marked @pytest.mark.integration that hit the real
registries. Wire the results into the CLI output alongside the static scan.
```

### 4. Judge layer (already built — reference only)
```
The judge layer in slopguard/judge.py is a local keyword-heuristic matcher
with no API key and no network call, per ARCHITECTURE.md. If you want to
extend it, add new "intent concepts" to _INTENT_CONCEPTS with intent/code
keyword lists, and add a test case per new concept in tests/test_judge.py
following the existing pattern.
```

### 5. Reporting
```
Implement Phase 4: the scorer/aggregator that merges and deduplicates
findings from all three sources, an HTML report template, and JSON output.
Look at how my plagiarism-detector project generates its HTML report and
follow a similar style/structure if you have access to that repo, otherwise
build a clean minimal report with severity-colored findings grouped by file.
```

### 6. Service + Action
```
Implement Phase 5: a FastAPI /scan endpoint, the action.yml GitHub Action
that runs the CLI in a container and posts a PR comment with findings above
a configurable severity threshold, linking to the full HTML report as an
artifact.
```

### 7. Polish
```
Help me work through Phase 6: run the scanner against 2-3 real repos I'll
point you to, capture the findings, and help me write an honest README
section with real accuracy numbers and before/after examples. No inflated
claims — I want numbers I can defend in an interview.
```

---

## Tips while working with Claude Code on this
- After each phase, ask it to run the full test suite before moving on — don't let failures accumulate.
- If a phase is taking too long or the judge-layer accuracy is bad, it's fine to descope (e.g., fewer Semgrep rules, regex-only JS parsing) — a smaller working v1 beats a stalled ambitious one.
- Ask Claude Code to keep `ROADMAP.md` checkboxes current — it's a good running record of what's actually done when you write your resume bullet later.
