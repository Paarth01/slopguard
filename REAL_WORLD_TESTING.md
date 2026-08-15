# Real-world testing notes

This scanner has been run against three real, well-known open-source
repositories (not just the bundled test fixtures) to catch the kind of
false positives that only show up on actual codebases. This document
records what was found and fixed, honestly, including the bugs it exposed
in SlopGuard itself.

## Repos tested
| Repo | Language | Files scanned |
|---|---|---|
| [pallets/flask](https://github.com/pallets/flask) | Python | 83 |
| [psf/requests](https://github.com/psf/requests) | Python | 37 |
| [expressjs/express](https://github.com/expressjs/express) | JavaScript | 141 |

## What this testing found (bugs in SlopGuard, now fixed)

**1. Incomplete Python stdlib list caused mass false hallucination flags.**
An earlier hand-maintained stdlib skip-list was missing `__future__`,
`inspect`, `types`, `errno`, `operator`, `platform`, and dozens more.
Running against Flask alone produced **66 false "hallucinated package"**
flags on completely standard imports. Fixed by switching to
`sys.stdlib_module_names` (Python 3.10+), which gives the full, accurate
list instead of a hand-picked guess.

**2. `_typeshed` (a type-checking-only pseudo-module) isn't installed at
runtime**, so it 404'd against PyPI and looked hallucinated. Added to the
skip list as a special case.

**3. Import name ≠ PyPI package name for several common packages.**
`requests`' own codebase imports `OpenSSL` (from the real `pyOpenSSL`
package) — a correct import that 404'd against PyPI under its import
name. Added a small alias table (`OpenSSL`→`pyOpenSSL`, `cv2`→
`opencv-python`, `bs4`→`beautifulsoup4`, etc.) covering the most common
mismatches. This table is deliberately not exhaustive — see "Known
remaining limitations" below.

**4. Python 2-era compat shims** (`StringIO`, `cStringIO`,
`BaseHTTPServer`, `SimpleHTTPServer`) found in `requests`' own
`tests/compat.py` aren't part of the Python 3 stdlib, so they also
false-flagged. Added a small Python-2-stdlib skip set.

**5. First-party local test modules looked identical to hallucinations.**
Flask's test suite does `import blueprintapp` where `blueprintapp` is a
local test fixture package, not something from PyPI. Fixed by
cross-referencing every import against the file tree actually being
scanned — if a name matches a directory or module already present in the
target, it's treated as local and skipped (no registry lookup needed,
which is also a small performance win).

**6. Modern `node:`-prefixed builtin imports weren't recognized.**
Running against express.js produced **87 false hallucination flags**, all
of them `node:assert`, `node:path`, `node:buffer`, etc. — the modern
explicit-scheme way of importing Node builtins. Fixed by stripping the
`node:` prefix before checking against the builtin skip list.

## Net effect of these fixes

| Repo | False hallucination flags before | After |
|---|---|---|
| Flask | 66 | 5 (see below) |
| requests | 7 | 0 |
| express | 87 | 0 |

## Known remaining limitations (documented, not hidden)

- **Flask's remaining 5 flags** are test-fixture package names
  (`site_app`, `installed_package`, etc.) created dynamically at pytest
  runtime via temp directories — they don't exist as files in the
  scanned tree, so the local-module cross-reference can't catch them.
  This is a real, honest gap: catching these would require actually
  running the test suite, which is out of scope for a static scanner.
- **The import-name/PyPI-name alias table is not exhaustive.** It covers
  ~18 common cases found through testing and general knowledge, not a
  comprehensive mapping of the whole ecosystem. Expect occasional false
  positives on packages not in the table.
- **The JS/TS rules are regex-based, not AST-based**, so they can't
  distinguish real code from string literals. Confirmed on express.js:
  a test file contains the string `'javascript:eval(...)'` as XSS test
  data (not an actual `eval()` call), and the static scanner flagged it
  as a real one. The Python rules don't have this problem since they use
  the real `ast` module. Fixing this properly would mean writing (or
  adopting) a real JS parser — noted as a Phase 1/5 stretch goal in
  ROADMAP.md, not fixed here to avoid a fragile regex patch that could
  introduce new bugs.
- **`pickle-loads` findings don't know about trust context.** `requests`'
  own test suite legitimately pickles and unpickles trusted data within
  the same test; the scanner correctly flags every `pickle.loads()` call
  since it can't determine data provenance statically. This is intended,
  conservative behavior, not a bug — the finding is meant as "worth a
  glance," not "confirmed vulnerability."
- **`missing-auth-decorator` produces a lot of INFO-level noise** (287 on
  Flask) since Flask's own test suite is full of tiny unauthenticated demo
  routes by design. This rule is intentionally the lowest-confidence,
  lowest-severity one in the ruleset for exactly this reason — useful as
  a checklist during review, not as something to gate CI on.

## How to reproduce this testing
```bash
git clone --depth 1 https://github.com/pallets/flask.git
git clone --depth 1 https://github.com/psf/requests.git
git clone --depth 1 https://github.com/expressjs/express.git

python -m slopguard scan ./flask --report out/flask
python -m slopguard scan ./requests --report out/requests
python -m slopguard scan ./express --report out/express
```
