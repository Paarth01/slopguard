# SlopGuard

**A security scanner built specifically for AI-generated code.**

[![CI](https://github.com/<your-username>/slopguard/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-username>/slopguard/actions/workflows/ci.yml)
[![Live demo](https://img.shields.io/badge/demo-live-brightgreen)](https://slopguard-nhri.onrender.com/docs)
[![Tests](https://img.shields.io/badge/tests-101%20passing-brightgreen)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](#license)

SlopGuard catches the two failure modes that are unique to — or heavily
amplified by — LLM code generation, on top of a curated static-analysis
pass for the vulnerability classes most common in AI-generated code:

1. **Hallucinated dependencies.** LLMs frequently invent plausible-sounding
   package names that don't exist. Attackers register those names
   ("slopsquatting") so the next person who blindly `pip install`s the
   hallucinated package pulls in malware.
2. **Intent-vs-behavior drift.** Code that looks reasonable but quietly
   does something other than what was asked for — a missing auth check,
   a swallowed exception, logic that doesn't match its own docstring.

**Live demo:** https://slopguard-nhri.onrender.com/docs (interactive API
docs — upload a zip and see real findings)

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it actually does](#what-it-actually-does)
- [Architecture](#architecture)
- [The 10 static rules](#the-10-static-rules)
- [Quickstart](#quickstart)
- [Using it as a GitHub Action](#using-it-as-a-github-action)
- [Web UI](#web-ui)
- [Using the API](#using-the-api)
- [Real-world validation](#real-world-validation)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Development workflow](#development-workflow)
- [Deployment](#deployment)
- [Honest limitations](#honest-limitations)
- [Roadmap](#roadmap)
- [Related projects](#related-projects)
- [License](#license)

---

## Why this exists

Veracode's 2025 State of Software Security report found **45%+ of
AI-generated code contains at least one known security flaw**, and the
rate doesn't improve with larger models. Most existing scanners (Semgrep,
Snyk, Dependabot) weren't designed around "this code was likely written
by an LLM" as a threat model — they don't specifically check for
hallucinated package names, and they don't compare code against its
stated intent.

SlopGuard is a narrow, opinionated tool built around exactly that threat
model, designed to sit in a PR as a fast, explainable second pair of eyes
on AI-assisted code.

## What it actually does

On every scan, three independent components run and their findings are
merged into one report:

| Component | What it checks | How |
|---|---|---|
| **Static scanner** | 10 vulnerability patterns common in AI-generated code | AST-based rules for Python, regex-based for JS/TS |
| **Dependency hallucination checker** | Imported packages that don't actually exist, or were just published | Live PyPI/npm registry lookups |
| **Intent/judge layer** | Code that doesn't match its stated intent (docstring, PR description) | Local keyword heuristic — no API key, no network call |

All three run in a single pass, get deduplicated against each other, and
come out as one severity-ranked report (HTML for humans, JSON for CI).

## Architecture

```
                     ┌────────────────────┐
   diff / folder ──▶ │   Input Parser      │  walks a folder into
                     └─────────┬──────────┘  scannable FileToScan objects
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
   ┌───────────────┐  ┌────────────────┐ ┌───────────────────┐
   │ Static Scan    │  │ Dependency      │ │ Intent/Judge Layer │
   │ (AST + regex)  │  │ Hallucination   │ │ (local heuristic,  │
   │                │  │ Checker (PyPI/  │ │  no API key)       │
   │                │  │ npm, live)      │ │                    │
   └───────┬───────┘  └────────┬────────┘ └─────────┬──────────┘
           │                   │                     │
           └───────────────────┼─────────────────────┘
                               ▼
                     ┌────────────────────┐
                     │  Aggregator/Scorer  │  dedupe + severity sort
                     └─────────┬──────────┘
                               │
                     ┌─────────┴──────────┐
                     ▼                    ▼
             ┌───────────────┐   ┌────────────────┐
             │  HTML Report   │   │  JSON output    │ ──▶ GitHub PR comment
             └───────────────┘   └────────────────┘
```

**Design decisions worth knowing about:**

- **No Semgrep.** The static scanner is a hand-rolled rule engine
  (Python's own `ast` module, regex for JS/TS) instead of shelling out to
  Semgrep — faster to install, no YAML rule DSL to learn for a ruleset
  this size. Revisit if the ruleset grows past ~15-20 rules.
- **No LLM API for the judge layer.** An earlier version called the
  Anthropic API for an LLM-as-judge approach. It was deliberately
  replaced with a pure keyword-heuristic matcher — the project has zero
  external credential requirements and runs fully offline. Weaker
  accuracy, explicit tradeoff (see [Honest limitations](#honest-limitations)).
- **Same Docker image serves both the API and the GitHub Action.**
  `action.yml` points at the root `Dockerfile` and overrides its default
  `CMD` via `runs.entrypoint` — this was a real fix after a separate
  `action/Dockerfile` turned out to have the wrong build context (Docker
  build context is the directory *containing* the Dockerfile, not the
  directory containing `action.yml` — see [Development workflow](#development-workflow)
  for the full story).

Full component-by-component design notes: [ARCHITECTURE.md](./ARCHITECTURE.md).

## The 10 static rules

| Rule ID | Severity | Catches |
|---|---|---|
| `hardcoded-secret` | Critical | API keys/secrets assigned as string literals |
| `eval-on-input` | High | `eval()` / `exec()` calls |
| `pickle-loads` | High | Unpickling data (arbitrary code execution risk) |
| `sql-string-concat` | High | SQL built via f-string/`+`/`%` instead of parameterized queries |
| `unsafe-yaml-load` | High | `yaml.load()` without `Loader=yaml.SafeLoader` |
| `dependency-hallucination` | High | Imported package doesn't exist on PyPI/npm |
| `cors-allow-all` | Medium | `allow_origins=["*"]` |
| `weak-crypto` | Medium | `md5`/`sha1` used for hashing |
| `debug-mode-enabled` | Medium | `app.run(debug=True)` |
| `path-traversal` | Medium | `open()`/`os.path.join()` with a dynamically-built path |
| `recently-published-package` | Low | Package exists but was published <90 days ago |
| `missing-auth-decorator` | Info | Route handler with no visible auth check (may be a false positive if auth is middleware-based) |
| `intent-drift-heuristic` | Low | Stated intent mentions a concept (auth, validation, etc.) the code shows no trace of handling |

Python rules are AST-based (zero false positives from string matching);
JS/TS rules are regex-based (faster to write, can't distinguish code from
string literals — see [Honest limitations](#honest-limitations)).

## Quickstart

```bash
git clone https://github.com/<your-username>/slopguard.git
cd slopguard
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -e ".[dev]"

# scan a folder, print findings, write an HTML+JSON report
python -m slopguard scan ./path/to/code --report out

# fail (exit code 1) if anything high severity or above is found -- for CI
python -m slopguard scan ./path/to/code --fail-on high

# exclude paths from the scan -- plain names exclude the whole subtree,
# globs match against the relative path
python -m slopguard scan ./path/to/code --exclude "tests,dist/*"

# enable the intent/judge layer -- fully local, no API key needed
python -m slopguard scan ./path/to/code --judge --intent "Add input validation to the login form"
```

Or run the FastAPI service locally:
```bash
docker compose up --build
# or without Docker:
uvicorn slopguard.api:app --reload
```

### Example output

Running against the bundled test fixtures (`tests/fixtures/`, which
contain deliberate vulnerabilities):

```
SlopGuard — tests/fixtures (11 files scanned)

[CRITICAL] secret_example.py:2
           Hardcoded credential-like value
           'api_key' is assigned a hardcoded string that looks like a secret
           or API key -- move it to an environment variable instead.
           source=static confidence=0.75

[HIGH    ] imports_example.py
           Possibly hallucinated package: this_package_definitely_does_not_exist_zzz_12345
           This package does not exist on pypi -- may be an LLM-invented name.
           source=slop_check confidence=0.70

Summary: critical=1, high=4, medium=3, info=1
```

That hallucination finding comes from a real, live query against the
PyPI registry — not a mock. [Confirmed against the deployed instance](#real-world-validation).

## Using it as a GitHub Action

```yaml
name: SlopGuard Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  slopguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # required for SlopGuard to post/update the PR comment
    steps:
      - uses: actions/checkout@v4
      - uses: <your-username>/slopguard@v1.0.0
        with:
          path: .
          fail-on: high
          exclude: "tests,dist/*"   # optional
        env:
          # action.yml's own runs.env can't reference the github context
          # (only 'inputs' is available there) -- the token is passed in
          # explicitly here, at the step level, where 'github' is valid.
          GITHUB_TOKEN: ${{ github.token }}
```

Posts (and updates, on later pushes to the same PR — matched via an HTML
marker so it doesn't spam a new comment every time) a severity-ranked
summary comment on the triggering pull request. Full example:
[action/example-consumer-workflow.yml](./action/example-consumer-workflow.yml).

**Before this works on your repo**, check Settings → Actions → General →
Workflow permissions is set to "Read and write permissions" — otherwise
the PR-comment step will fail even though the scan itself succeeds.

## Web UI

The live instance has a browser UI at https://slopguard-nhri.onrender.com/
— paste a public GitHub repo URL or drag in a zip, see findings rendered
live with source-line code snippets, no `curl` required.

**Scanning a GitHub repo works entirely server-side**: paste a URL like
`https://github.com/owner/repo` (optionally `.../tree/branch`), and the
server fetches it directly from GitHub's codeload endpoint, extracts it,
and scans it — nothing to download or zip yourself. Since this endpoint
is public, repo URLs are parsed with a strict allowlist (only
`github.com` URLs, only alphanumeric/`-`/`_`/`.` in the owner/repo/branch
segments) before ever being used to build the actual outbound request —
see [`slopguard/github_fetch.py`](./slopguard/github_fetch.py) for the
full SSRF-safety reasoning.

## Using the API

```bash
# health check
curl https://slopguard-nhri.onrender.com/health

# scan a zipped codebase
zip -r code.zip your-project/
curl -X POST https://slopguard-nhri.onrender.com/scan -F "file=@code.zip"

# scan a public GitHub repo directly, server-side -- no zip needed
curl -X POST https://slopguard-nhri.onrender.com/scan-repo \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo", "exclude": "tests,dist/*"}'
```

Interactive docs (Swagger UI, generated automatically by FastAPI):
https://slopguard-nhri.onrender.com/docs

Note: the live instance runs on Render's free tier, which spins down
after 15 minutes of inactivity — the first request after idle time can
take 30-60s to wake back up. That's expected, not a bug.

## Real-world validation

Rather than trusting only the bundled test fixtures, this scanner was run
against three real, well-known open-source repositories to catch false
positives that only show up on actual code:

| Repo | Language | False hallucination flags, before fixes | After |
|---|---|---|---|
| [pallets/flask](https://github.com/pallets/flask) | Python | 66 | 5 (documented, unfixable without running the target's own test suite) |
| [psf/requests](https://github.com/psf/requests) | Python | 7 | 0 |
| [expressjs/express](https://github.com/expressjs/express) | JavaScript | 87 | 0 |

Each round of testing found and fixed a real bug: an incomplete
hand-maintained Python stdlib list, a type-checking-only pseudo-module
(`_typeshed`), import-name-vs-PyPI-name mismatches (`OpenSSL` →
`pyOpenSSL`), Python 2 compat shims, first-party local test modules, and
the modern `node:`-prefixed Node builtin scheme.

Full write-up, including what's still an open, honestly-documented
limitation: **[REAL_WORLD_TESTING.md](./REAL_WORLD_TESTING.md)**.

## Testing

```bash
pytest -m "not integration"   # fast, no network, 96 tests
pytest -m integration          # hits real PyPI/npm APIs, 4 tests
pytest                          # everything, 101 tests
```

CI runs both `ruff check` (with an explicitly pinned rule selection —
`E4, E7, E9, F, B, SIM, ASYNC` — after a CI run once caught issues that
hadn't fired locally due to unpinned defaults), `black --check`, and the
full test suite on every push/PR: [.github/workflows/ci.yml](./.github/workflows/ci.yml).

## Project structure

```
slopguard/
├── slopguard/              # core package
│   ├── models.py           # Finding, ScanResult, Severity
│   ├── static_scan.py      # AST/regex rule engine (10 rules)
│   ├── slop_check.py       # dependency hallucination checker
│   ├── judge.py            # local intent/judge heuristic
│   ├── scorer.py           # aggregation + dedup
│   ├── input_parser.py     # folder -> scannable files
│   ├── report.py           # HTML/JSON report generation
│   ├── scanner.py          # top-level orchestrator
│   ├── cli.py               # python -m slopguard scan ...
│   └── api.py               # FastAPI service (/scan, /health)
├── action/                 # GitHub Action
│   ├── entrypoint.sh        # runs the scan, posts the PR comment
│   └── post_comment.py      # PR comment formatting + GitHub API calls
├── templates/report.html   # Jinja2 HTML report template
├── tests/                  # 101 tests, fixtures for every rule
├── rules/ai-patterns.yml   # historical Semgrep-style sketch (superseded)
├── action.yml               # Action metadata (reuses root Dockerfile)
├── Dockerfile               # serves both the API and the Action
├── render.yaml               # Render Blueprint deploy config
└── docs: README (this file), ARCHITECTURE.md, ROADMAP.md,
    REAL_WORLD_TESTING.md, DEPLOYMENT.md, CLAUDE.md
```

## Development workflow

This project went through several real deploy/CI failures that are worth
knowing about if you're extending it — each was reproduced locally before
being called "fixed," not just patched blind:

1. **Ruleset built incrementally** (5 rules → 10), each with a fixture +
   test, validated against real repos rather than only hand-written
   fixtures.
2. **Judge layer rewritten** from an LLM-API-based approach to a fully
   local heuristic, verified working under `env -i` (a completely empty
   environment) to confirm zero hidden credential dependency.
3. **CI caught real lint issues** (`B008`, `ASYNC230`, two `SIM102`s, one
   `SIM105`) that hadn't fired locally — traced to an unpinned ruff rule
   selection, fixed by pinning `[tool.ruff.lint] select = [...]`
   explicitly in `pyproject.toml`.
4. **Render deploy failed twice**, for two different real reasons:
   - The Dockerfile hardcoded port 8000 instead of Render's dynamic
     `$PORT` — fixed by switching to shell-form `CMD` so `${PORT:-8000}`
     expands.
   - `pip install -e .` failed with `package directory 'action' does not
     exist` — `pyproject.toml` declared `action` as an installable
     package, but the Dockerfile never copied that folder into the build
     context. Fixed by adding the missing `COPY`.
5. **The GitHub Action failed twice**, for two different real reasons:
   - `action.yml`'s `runs.env` referenced `${{ github.token }}`, but the
     `github` context isn't available at that scope — only `inputs` is.
     Fixed by moving the token to a step-level `env:` in the *calling*
     workflow instead.
   - A separate `action/Dockerfile` failed every `COPY` with "not found"
     — the real build log showed Docker's build context is the
     *directory containing the Dockerfile*, not the directory containing
     `action.yml`. Fixed by pointing `action.yml` at the already-working
     root `Dockerfile` and overriding its entrypoint via
     `runs.entrypoint` instead of maintaining a second, structurally
     broken Dockerfile.

Each of these is a real commit with a real diff — see `git log` for the
full, honest history.

## Deployment

Full step-by-step guide, including exact commands and a verification
checklist: **[DEPLOYMENT.md](./DEPLOYMENT.md)**.

Short version:
- **API**: one-click Render Blueprint deploy using the included
  `render.yaml`
- **Action**: tag a release (`v1.0.0`+), reference
  `uses: <you>/slopguard@v1.0.0` from any other repo's workflow

## Honest limitations

- **JS/TS rules are regex-based, not AST-based** — confirmed false
  positive on express.js: a string literal containing the text `eval(`
  as XSS test data got flagged as a real `eval()` call. The Python rules
  don't have this problem (they use the real `ast` module). Fixing this
  properly needs a real JS parser.
- **The dependency-hallucination checker's import-name/PyPI-name alias
  table is not exhaustive** (~18 common cases covered) — expect
  occasional false positives on packages not in it.
- **The judge layer is a local keyword heuristic, not an LLM or NLI
  model.** No API key required, runs fully offline, but it can only catch
  cases where the stated intent and the code use noticeably different
  vocabulary around a known concept. Findings are always LOW severity /
  0.3 confidence to reflect this.
- **`missing-auth-decorator` produces real noise** on codebases with
  intentionally public routes (287 findings on Flask's own test suite) —
  intentionally the lowest-severity, lowest-confidence rule for exactly
  this reason.
- No support yet for languages beyond Python and JS/TS.

Full detail on every limitation found through real-repo testing:
[REAL_WORLD_TESTING.md](./REAL_WORLD_TESTING.md).

## Roadmap

See **[ROADMAP.md](./ROADMAP.md)** for the full phase-by-phase status.
Short version: core scanner, API, deployment, and the GitHub Action are
all built, tested, and confirmed working in production. Remaining items
are polish (expanding the JS/TS parser to a real AST, growing the
alias table) rather than missing functionality.

## Related projects

- **Veritas** — LLM hallucination detection for chat/RAG outputs (an
  earlier version of this project's judge layer was adapted from it)
- **Code Plagiarism Detector** — Winnowing/GST/AST-based similarity
  detection (this project's HTML report style is adapted from it)

## License

MIT
