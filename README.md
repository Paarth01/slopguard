# SlopGuard

A security scanner built specifically for AI-generated code. It catches the two failure modes that are unique (or heavily amplified) by LLM code generation:

1. **Hallucinated dependencies** — LLMs frequently invent plausible-sounding package names that don't exist. Attackers register those names ("slopsquatting") so the next person who blindly `pip install`s the hallucinated package pulls in malware.
2. **Intent-vs-behavior drift** — code that looks reasonable but quietly does something other than what was asked for (missing auth check, wrong comparison operator, swallowed exception, etc.)

On top of that, it runs a static-analysis pass for the vulnerability classes most common in AI-generated code: hardcoded secrets, `eval`/`exec` on untrusted input, unsafe deserialization, SQL built via string concatenation, and permissive CORS.

## Status
✅ **v1 built, tested, and validated against real code.** 63/63 tests passing (59 unit, 4 integration against real PyPI/npm). CLI, FastAPI service, HTML/JSON reporting, and the GitHub Action (including PR-comment posting) all built and locally verified. Also run against three real open-source repos (Flask, requests, express.js) to catch false positives the bundled test fixtures couldn't — see [REAL_WORLD_TESTING.md](./REAL_WORLD_TESTING.md). **Not yet deployed to a live URL or run on a real GitHub Actions workflow** — see [DEPLOYMENT.md](./DEPLOYMENT.md) for the exact remaining steps. See [ROADMAP.md](./ROADMAP.md) for the full status.

## Why
Veracode's 2025 State of Software Security report found 45%+ of AI-generated code contains at least one known security flaw, and the rate doesn't improve with larger models. Most existing scanners weren't designed around "this code was likely written by an LLM" as a threat model. SlopGuard is.

## Quickstart

```bash
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -e ".[dev]"

# scan a folder, print findings, write an HTML+JSON report
python -m slopguard scan ./path/to/code --report out

# scan and fail (exit code 1) if anything high severity or above is found
python -m slopguard scan ./path/to/code --fail-on high

# enable the intent/judge layer -- fully local, no API key needed
python -m slopguard scan ./path/to/code --judge --intent "Add input validation to the login form"
```

Or run the FastAPI service:
```bash
uvicorn slopguard.api:app --reload
# POST a zipped codebase to http://localhost:8000/scan
```

Or with Docker:
```bash
docker compose up --build
```

## Example output
Running against the bundled test fixtures (`tests/fixtures/`, which contain deliberate vulnerabilities):

```
SlopGuard — tests/fixtures (6 files scanned)

[CRITICAL] secret_example.py:2
           Hardcoded credential-like value
           'api_key' is assigned a hardcoded string that looks like a secret
           or API key -- move it to an environment variable instead.
           source=static confidence=0.75

[HIGH    ] imports_example.py
           Possibly hallucinated package: this_package_definitely_does_not_exist_zzz_12345
           This package does not exist on pypi -- may be an LLM-invented name.
           source=slop_check confidence=0.70

Summary: critical=1, high=3, medium=1
```

That hallucination finding came from a real, live query against the PyPI registry — not a mock.

## Running tests
```bash
pytest -m "not integration"   # fast, no network, 26 tests
pytest -m integration          # hits real PyPI/npm APIs, 4 tests
pytest                         # everything, 30 tests
```

## Architecture
See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design, including the static-analysis-engine tradeoff (custom AST rules vs. Semgrep) and the judge-layer decision (LLM-as-judge vs. NLI).

## Using it as a GitHub Action
```yaml
- uses: <your-github-username>/slopguard@main
  with:
    path: .
    fail-on: high
```
Posts (and updates, on later pushes to the same PR) a summary comment on
the triggering pull request. See [action/example-consumer-workflow.yml](./action/example-consumer-workflow.yml)
for a full example, and [DEPLOYMENT.md](./DEPLOYMENT.md) for how to wire
this up on a real repo.

## Honest limitations (v1)
- Static ruleset covers 10 rule types (hardcoded secrets, eval/exec, unsafe pickle/YAML, SQL string-building, CORS wildcard, weak crypto, debug mode, path traversal, missing-auth heuristic) — broader than the original 5, still not comprehensive.
- **JS/TS rules are regex-based, not AST-based**, so they can't tell code from string literals — confirmed on express.js, where a string containing the text "eval(" as XSS test data was flagged as a real eval() call. The Python rules don't have this problem (they use the real `ast` module).
- **The dependency-hallucination checker has been validated against three real repos** (Flask, requests, express.js) and had several real false-positive classes found and fixed in the process — see [REAL_WORLD_TESTING.md](./REAL_WORLD_TESTING.md) for the full list. The import-name/PyPI-name alias table (`OpenSSL`→`pyOpenSSL`, etc.) is not exhaustive; expect occasional false positives on packages not in it.
- **The judge layer is a local keyword heuristic, not an LLM or NLI model** — no API key required, runs fully offline, but it can only catch cases where the stated intent and the code use noticeably different vocabulary around a known concept (auth, validation, deletion, etc.). Its findings are always LOW severity / 0.3 confidence to reflect this.
- No support yet for languages beyond Python and JS/TS.

## Related projects
- **Veritas** — LLM hallucination detection for chat/RAG outputs (the judge layer's LLM-as-judge pattern is adapted from it)
- **Code Plagiarism Detector** — Winnowing/GST/AST-based similarity detection (the HTML report style is adapted from it)

## License
MIT
