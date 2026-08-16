# Roadmap

## Phase 0 — Scaffold ✅ DONE
- [x] Repo structure, `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, CI workflow
- [x] `Finding`/`ScanResult` data models with tests

## Phase 1 — Static scan ✅ DONE, ruleset expanded
- [x] AST-based rules for Python, regex-based for JS/TS
- [x] 10 rule types: hardcoded-secret, eval-on-input, pickle-loads,
      sql-string-concat, cors-allow-all, weak-crypto, unsafe-yaml-load,
      debug-mode-enabled, path-traversal, missing-auth-decorator
- [x] Fixture + test per rule (17 static-scan tests, all passing)
- [x] CLI: `python -m slopguard scan <path>` prints a colored table
- [ ] **Known gap, documented**: JS/TS rules are regex-based and can't
      distinguish code from string literals (confirmed false positive on
      express.js — see REAL_WORLD_TESTING.md). Would need a real JS
      parser to fix properly; not done to avoid a fragile regex patch.

## Phase 2 — Dependency hallucination checker ✅ DONE, hardened on real code
- [x] Python import extraction via `ast`, JS/TS via regex (now handles
      dynamic `import()`, `export ... from`, and `node:`-prefixed builtins)
- [x] Real PyPI + npm registry clients with local JSON caching
- [x] Uses `sys.stdlib_module_names` for a complete, accurate Python
      stdlib list (an earlier hand-maintained list was missing dozens of
      modules — found by testing against Flask, see REAL_WORLD_TESTING.md)
- [x] Import-name/PyPI-name alias table for common mismatches (OpenSSL,
      cv2, bs4, sklearn, etc.)
- [x] Python 2 compat-shim module skip list (StringIO, cStringIO, etc.)
- [x] Cross-references imports against the scanned repo's own file tree
      to skip first-party local modules (e.g. test fixture packages)
      without a wasted registry lookup
- [x] Validated against 3 real repos (Flask, requests, express.js) —
      false-positive counts went 66→5, 7→0, 87→0 across those repos after
      the fixes above. Full details in REAL_WORLD_TESTING.md.
- [x] 4 integration tests hit the real PyPI/npm APIs and pass

## Phase 3 — Intent/judge layer ✅ DONE — fully local, no API key
- [x] Pure keyword-heuristic matcher across ~6 "intent concepts" — zero
      network calls, zero credentials, works offline (verified under
      `env -i`, a completely empty environment)
- [x] 5 tests covering the core behavior
- [ ] **Known limitation, documented not hidden**: keyword matching can't
      understand what code actually does. Local NLI model (DeBERTa via
      sentence-transformers, same approach as Veritas) is the documented
      upgrade path if stronger accuracy is wanted later without an API
      key — not built in v1 to avoid the extra ~1GB of model weights.

## Phase 4 — Reporting + aggregation ✅ DONE
- [x] Scorer/aggregator merges + dedupes findings across all three sources
- [x] HTML report (styled, severity-colored), JSON report for CI/API
- [x] End-to-end tests against fixtures, dedup verified

## Phase 5 — FastAPI service + GitHub Action ✅ CODE DONE, deploy pending
- [x] `POST /scan` accepts a zipped codebase, returns JSON `ScanResult`
- [x] Verified end-to-end with a real zip upload via TestClient
- [x] `action.yml` (reuses the root Dockerfile via `runs.entrypoint`,
      after a real build confirmed a separate `action/Dockerfile` can't
      reach repo-root files -- see fix commit for details),
      `action/entrypoint.sh` built —
      entrypoint tested locally outside Docker (scan runs, exit code is
      correct, report is generated)
- [x] **PR-comment posting built and tested.** `action/post_comment.py`
      posts (or updates, to avoid comment spam across pushes) a markdown
      summary table on the triggering PR. 8 tests cover comment
      formatting, PR-number extraction from the event payload, and both
      the create-new and update-existing code paths (mocked at the HTTP
      layer). Verified locally with a real (correctly-rejected, since the
      token was fake) call to api.github.com — confirms the request is
      built correctly, only a real token is missing.
- [x] Fixed a real deploy-blocking bug while preparing this: the main
      Dockerfile hardcoded port 8000 instead of respecting Render's
      `$PORT` env var, which would have caused the deploy to fail
      silently. Fixed and verified locally by binding to a custom port.
- [x] `render.yaml` (Blueprint config) added
- [ ] **Not yet done — needs your accounts, see DEPLOYMENT.md**: actually
      push to GitHub, actually deploy on Render, actually run the Action
      in a real workflow. All three are "should work" based on local
      testing, not "confirmed working in production."

## Phase 6 — Polish for portfolio/resume — MOSTLY DONE
- [x] Ran SlopGuard against 3 real open-source repos (Flask, requests,
      express.js), captured real before/after false-positive counts —
      see REAL_WORLD_TESTING.md for the full, honest writeup including
      what's still broken
- [x] README's "Honest limitations" section reflects real, tested gaps
      rather than guessed ones
- [ ] Architecture diagram, quickstart GIF
- [ ] Tag `v1.0.0`

## What to do next (recommended order)
1. **Follow DEPLOYMENT.md** — push to GitHub, deploy to Render, run the
   Action on a real PR. This is the only remaining work; everything else
   is built, tested, and waiting on your accounts.
2. If the JS eval-in-string-literal false positive bothers you, consider
   swapping the JS rules for a real parser — documented as the fix in
   REAL_WORLD_TESTING.md but not built to avoid scope creep.
3. Consider expanding the import-name/PyPI-name alias table if you hit
   more mismatches in practice.
