# Architecture

## High-level flow

```
                     ┌────────────────────┐
   diff / folder ──▶ │   Input Parser      │  (git diff, or raw folder walk)
                     └─────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
   ┌───────────────┐  ┌────────────────┐ ┌───────────────────┐
   │ Static Scan    │  │ Dependency      │ │ Intent/Judge Layer │
   │ (Semgrep +     │  │ Hallucination   │ │ (NLI or LLM-based) │
   │ custom rules)  │  │ Checker         │ │                    │
   └───────┬───────┘  └────────┬────────┘ └─────────┬──────────┘
           │                   │                     │
           └───────────────────┼─────────────────────┘
                               ▼
                     ┌────────────────────┐
                     │  Aggregator/Scorer  │  (dedupe, severity, confidence)
                     └─────────┬──────────┘
                               │
                     ┌─────────┴──────────┐
                     ▼                    ▼
             ┌───────────────┐   ┌────────────────┐
             │  HTML Report   │   │  JSON output    │  ──▶ GitHub PR comment
             └───────────────┘   └────────────────┘
```

## Components

### 1. Input Parser (`slopguard/input_parser.py`)
- Accepts either a folder path or a `git diff` (for CI use — only scan changed lines/files, not the whole repo every time)
- Produces a normalized list of `FileToScan(path, content, language, changed_lines)`

### 2. Static Scan (`slopguard/static_scan.py`)
- **Decision made**: implemented as a lightweight, dependency-free rule
  engine rather than shelling out to Semgrep — Python's own `ast` module
  for Python files (reliable, no false positives from string matching),
  regex for JS/TS (v1, see open question below). This keeps install time
  fast and avoids learning Semgrep's YAML rule DSL for a small ruleset.
  If the ruleset grows past ~15-20 rules, revisit Semgrep — its pattern
  matching handles complex multi-line patterns better than hand-rolled AST
  walks.
- v1 ships 10 rules, each with a fixture + test in `tests/`:
  - `hardcoded-secret` — assignment of a key/secret/token-named variable to
    a string that looks like a credential
  - `eval-on-input` — `eval()`/`exec()` calls
  - `pickle-loads` — unpickling data (arbitrary code execution risk)
  - `sql-string-concat` — `.execute()` called with an f-string, `+`, or
    `%`-formatted argument instead of parameterized placeholders
  - `cors-allow-all` — `allow_origins=["*"]`
  - `weak-crypto` — `hashlib.md5`/`hashlib.sha1` (Python) or
    `crypto.createHash('md5'/'sha1')` (JS)
  - `unsafe-yaml-load` — `yaml.load()` without `Loader=yaml.SafeLoader`
  - `debug-mode-enabled` — `app.run(debug=True)`
  - `path-traversal` — `open()`/`os.path.join()` called with a
    dynamically-built path (f-string or `+` concatenation)
  - `missing-auth-decorator` — route handler with no auth-suggestive
    decorator or `Depends()`-style dependency (INFO severity, low
    confidence by design — this one produces real noise on codebases with
    intentionally public routes, see REAL_WORLD_TESTING.md)
- Remaining stretch goals: none critical for v1; ruleset expansion beyond
  this set is a "nice to have," not a known gap.

### 3. Dependency Hallucination Checker (`slopguard/slop_check.py`)
- Extracts import statements (Python `ast` module) / `require`/`import` (JS, via a lightweight regex or `esprima` if needed) from changed files
- For each package name:
  - Check PyPI (`https://pypi.org/pypi/<pkg>/json`) or npm (`https://registry.npmjs.org/<pkg>`)
  - `404` → **hallucination candidate**, severity HIGH
  - Exists but registered <90 days ago and near-zero weekly downloads → **slopsquat candidate**, severity MEDIUM
  - Exists, established → clean
- Cache lookups locally (`.slopguard_cache.json`) to avoid hammering the registries on repeated runs

### 4. Intent/Judge Layer (`slopguard/judge.py`)
- **Decision made: fully local keyword-heuristic judge, no API key, no
  network call.** An earlier draft used the Anthropic API for an
  LLM-as-judge approach; that was removed by request so the project has
  zero external credential requirements.
- How it works: for each of ~6 "intent concepts" (auth, input validation,
  deletion, error handling, logging, rate limiting), check whether the
  stated intent (docstring/commit message/PR description) mentions the
  concept and whether the code shows any keyword trace of handling it. A
  mismatch produces a LOW severity, 0.3-confidence finding — deliberately
  conservative, since keyword matching alone cannot understand what code
  actually does.
- **Honest limitation**: this will miss most real intent/behavior
  divergences a real LLM or NLI judge would catch, and it will occasionally
  flag things that are handled but with different vocabulary than the
  intent text used (e.g. code uses `permitted` instead of `permission`).
  Report this limitation plainly in the README rather than implying
  stronger accuracy than the approach can deliver.
- **If you later want a stronger local judge**: the natural upgrade is a
  small NLI model (e.g. DeBERTa, as used in Veritas) run entirely
  on-device via `sentence-transformers`/`transformers` — no API key
  needed, but it does require downloading model weights once (a few
  hundred MB from huggingface.co) and adds `torch` as a dependency. Not
  wired up in v1 to keep install size and time small; a reasonable Phase 3
  stretch goal if the heuristic's false-negative rate proves too high in
  practice.

### 5. Aggregator/Scorer (`slopguard/scorer.py`)
- Merges findings from all three sources into one list
- Assigns severity (`critical`/`high`/`medium`/`low`) and a short human-readable explanation for each
- Deduplicates overlapping findings (e.g., Semgrep and the judge layer both flagging the same line)

### 6. Reporting (`slopguard/report.py`)
- `report.html` via Jinja2 template (adapt the plagiarism-detector's report generator)
- `report.json` for machine consumption (CI gating, GitHub Action PR comments)

### 7. GitHub Action (`action.yml` + `action/entrypoint.sh`)
- Runs the scanner in a container on `pull_request`
- Posts a PR comment summarizing findings (via `GITHUB_TOKEN`)
- Exits non-zero if findings ≥ configured `fail-on` severity, to allow CI gating

## Data model (`slopguard/models.py`)
```python
class Finding(BaseModel):
    id: str
    source: Literal["static", "slop_check", "judge"]
    severity: Literal["critical", "high", "medium", "low"]
    file: str
    line: int | None
    title: str
    explanation: str          # one plain-English sentence, always required
    confidence: float         # 0-1
```

## Open questions to resolve during build (log answers here as ADR-style notes)
- [ ] NLI vs LLM-as-judge for the intent layer — see Option A/B above
- [ ] Which LLM API (if Option B) — prefer whichever is cheapest/fastest for short structured outputs; avoid hardcoding to one vendor, use an adapter
- [ ] JS/TS import parsing — regex-based v1 vs proper AST parser — start regex, upgrade only if false-positive rate is too high
- [ ] Registry lookup rate limits — confirm PyPI/npm public API limits before running against large diffs in CI
