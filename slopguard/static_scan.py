"""
Static vulnerability scan.

Implemented as a lightweight, dependency-free rule engine (Python AST +
regex for JS/TS) rather than shelling out to Semgrep. This keeps the
scanner fast and installable anywhere, at the cost of being less
comprehensive than a full Semgrep ruleset. See ARCHITECTURE.md if you
later want to swap this module for a real Semgrep subprocess call --
the Finding-producing interface (`scan_file`) is designed to make that
swap a drop-in replacement.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from slopguard.models import Finding, Severity


@dataclass
class FileToScan:
    path: str
    content: str
    language: str  # "python" | "javascript" | "typescript" | "unknown"


def detect_language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in (".js", ".jsx", ".mjs"):
        return "javascript"
    if suffix in (".ts", ".tsx"):
        return "typescript"
    return "unknown"


# ---------------------------------------------------------------------------
# Python rules (AST-based -- reliable, no false positives from string matching)
# ---------------------------------------------------------------------------

_SECRET_KEY_PATTERN = re.compile(r"(?i)(key|secret|token|password|passwd|api_key)")
_SECRET_VALUE_PATTERN = re.compile(r"^(sk-|AKIA|ghp_|xox[baprs]-|AIza)")


def _scan_python(file: FileToScan) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(file.content, filename=file.path)
    except SyntaxError:
        # Can't parse -- skip AST rules for this file rather than crash the scan.
        return findings

    for node in ast.walk(tree):
        # Rule: hardcoded-secret
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and _SECRET_KEY_PATTERN.search(target.id):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if _SECRET_VALUE_PATTERN.match(val) or len(val) >= 20:
                            findings.append(
                                Finding(
                                    id=f"static-{file.path}-{node.lineno}-secret",
                                    source="static",
                                    severity=Severity.CRITICAL,
                                    file=file.path,
                                    line=node.lineno,
                                    title="Hardcoded credential-like value",
                                    explanation=(
                                        f"'{target.id}' is assigned a hardcoded string that looks "
                                        "like a secret or API key -- move it to an environment "
                                        "variable instead."
                                    ),
                                    confidence=0.75,
                                    rule_id="hardcoded-secret",
                                )
                            )

        # Rule: eval-exec-on-input
        if isinstance(node, ast.Call):
            func_name = _call_name(node)
            if func_name in ("eval", "exec"):
                findings.append(
                    Finding(
                        id=f"static-{file.path}-{node.lineno}-eval",
                        source="static",
                        severity=Severity.HIGH,
                        file=file.path,
                        line=node.lineno,
                        title=f"Use of {func_name}()",
                        explanation=(
                            f"{func_name}() executes arbitrary code -- if any part of its "
                            "argument can come from user input, this is a code-injection risk."
                        ),
                        confidence=0.6,
                        rule_id="eval-on-input",
                    )
                )
            elif func_name == "pickle.loads" or func_name == "loads" and _is_pickle_module(node):
                findings.append(
                    Finding(
                        id=f"static-{file.path}-{node.lineno}-pickle",
                        source="static",
                        severity=Severity.HIGH,
                        file=file.path,
                        line=node.lineno,
                        title="Unpickling untrusted data",
                        explanation=(
                            "pickle.loads() can execute arbitrary code if the data being "
                            "deserialized isn't fully trusted."
                        ),
                        confidence=0.6,
                        rule_id="pickle-loads",
                    )
                )

            # Rule: sql-string-format -- .execute() called with an f-string or %-formatted string
            if _is_execute_call(node) and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.JoinedStr):  # f-string
                    findings.append(_sql_finding(file.path, node.lineno, "an f-string"))
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    findings.append(_sql_finding(file.path, node.lineno, "string concatenation"))
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                    findings.append(_sql_finding(file.path, node.lineno, "%-style formatting"))

            # Rule: cors-allow-all
            for kw in node.keywords:
                if kw.arg == "allow_origins" and isinstance(kw.value, ast.List):
                    if any(
                        isinstance(elt, ast.Constant) and elt.value == "*" for elt in kw.value.elts
                    ):
                        findings.append(
                            Finding(
                                id=f"static-{file.path}-{node.lineno}-cors",
                                source="static",
                                severity=Severity.MEDIUM,
                                file=file.path,
                                line=node.lineno,
                                title="CORS allows all origins",
                                explanation=(
                                    "allow_origins=['*'] lets any website call this API from a "
                                    "browser -- fine for a demo, risky in production."
                                ),
                                confidence=0.9,
                                rule_id="cors-allow-all",
                            )
                        )

            # Rule: weak-crypto -- md5/sha1 used for hashing (fine for checksums,
            # weak for passwords/tokens; flagged at medium confidence since we
            # can't always tell the intent from the call site alone)
            if func_name in ("hashlib.md5", "hashlib.sha1"):
                algo = func_name.split(".")[1]
                findings.append(
                    Finding(
                        id=f"static-{file.path}-{node.lineno}-weakcrypto",
                        source="static",
                        severity=Severity.MEDIUM,
                        file=file.path,
                        line=node.lineno,
                        title=f"Weak hash algorithm ({algo})",
                        explanation=(
                            f"{algo.upper()} is broken for security purposes (password hashing, "
                            "signing, tokens). Fine for non-security checksums; use bcrypt/"
                            "argon2/scrypt for passwords or sha256+ for integrity checks."
                        ),
                        confidence=0.5,
                        rule_id="weak-crypto",
                    )
                )

            # Rule: unsafe-yaml-load -- yaml.load() without a safe Loader can
            # execute arbitrary Python objects during deserialization.
            if func_name == "yaml.load":
                loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
                is_safe = False
                if loader_kw is not None:
                    loader_name = _attribute_chain(loader_kw.value)
                    if "SafeLoader" in loader_name or "safe_load" in loader_name:
                        is_safe = True
                if not is_safe:
                    findings.append(
                        Finding(
                            id=f"static-{file.path}-{node.lineno}-yaml",
                            source="static",
                            severity=Severity.HIGH,
                            file=file.path,
                            line=node.lineno,
                            title="Unsafe YAML deserialization",
                            explanation=(
                                "yaml.load() without Loader=yaml.SafeLoader can construct "
                                "arbitrary Python objects from the input, which can lead to "
                                "code execution. Use yaml.safe_load() instead."
                            ),
                            confidence=0.65,
                            rule_id="unsafe-yaml-load",
                        )
                    )

            # Rule: debug-mode-enabled -- app.run(debug=True) should never ship
            if func_name.endswith(".run") or func_name == "run":
                for kw in node.keywords:
                    if (
                        kw.arg == "debug"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        findings.append(
                            Finding(
                                id=f"static-{file.path}-{node.lineno}-debug",
                                source="static",
                                severity=Severity.MEDIUM,
                                file=file.path,
                                line=node.lineno,
                                title="Debug mode enabled",
                                explanation=(
                                    "debug=True exposes an interactive debugger and stack traces "
                                    "to anyone who can trigger an error -- fine for local dev, "
                                    "must be off in production."
                                ),
                                confidence=0.8,
                                rule_id="debug-mode-enabled",
                            )
                        )

            # Rule: path-traversal -- open()/os.path.join() called with a
            # dynamically-built path (f-string or concatenation), which can
            # allow '../' traversal if the input isn't validated.
            if func_name in ("open", "os.path.join") and node.args:
                arg = node.args[0] if func_name == "open" else node.args[-1]
                if isinstance(arg, (ast.JoinedStr,)) or (
                    isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add)
                ):
                    findings.append(
                        Finding(
                            id=f"static-{file.path}-{node.lineno}-pathtraversal",
                            source="static",
                            severity=Severity.MEDIUM,
                            file=file.path,
                            line=node.lineno,
                            title="Possible path traversal",
                            explanation=(
                                f"{func_name}() is called with a dynamically-built path -- if "
                                "any part of it comes from user input without validation, "
                                "'../' sequences could escape the intended directory."
                            ),
                            confidence=0.4,
                            rule_id="path-traversal",
                        )
                    )

        # Rule: missing-auth-decorator -- a route handler (@app.get/post/etc)
        # with no auth-suggestive decorator and no Depends()-style default
        # argument. Deliberately INFO severity and low confidence: auth may
        # well be enforced via middleware, which this heuristic can't see.
        if isinstance(node, ast.FunctionDef):
            route_decorator = _find_route_decorator(node)
            if route_decorator is not None and not _looks_auth_protected(node):
                findings.append(
                    Finding(
                        id=f"static-{file.path}-{node.lineno}-authcheck",
                        source="static",
                        severity=Severity.INFO,
                        file=file.path,
                        line=node.lineno,
                        title=f"Route handler '{node.name}' has no visible auth check",
                        explanation=(
                            "No auth-related decorator or Depends()-style dependency was found "
                            "on this route. May be a false positive if auth is enforced via "
                            "middleware -- worth a quick manual check."
                        ),
                        confidence=0.3,
                        rule_id="missing-auth-decorator",
                    )
                )

    return findings


_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "route"}
_AUTH_HINTS = re.compile(r"(?i)(auth|login|permission|current_user|require|protected)")


def _find_route_decorator(node: ast.FunctionDef) -> ast.expr | None:
    for dec in node.decorator_list:
        call = dec if isinstance(dec, ast.Call) else None
        func = call.func if call else dec
        name = _call_name(call) if call else (func.attr if isinstance(func, ast.Attribute) else "")
        if name and name.split(".")[-1] in _ROUTE_METHODS:
            return dec
    return None


def _looks_auth_protected(node: ast.FunctionDef) -> bool:
    # Any decorator mentioning auth/login/permission/etc.
    for dec in node.decorator_list:
        src = ast.dump(dec)
        if _AUTH_HINTS.search(src):
            return True
    # Any default argument value that looks like FastAPI's Depends(get_current_user)
    for default in node.args.defaults:
        if isinstance(default, ast.Call) and _AUTH_HINTS.search(ast.dump(default)):
            return True
    return False


def _call_name(node: ast.Call) -> str:
    return _attribute_chain(node.func)


def _attribute_chain(node: ast.expr) -> str:
    """Extract a dotted name like 'yaml.SafeLoader' from an arbitrary expr node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _is_pickle_module(node: ast.Call) -> bool:
    return _call_name(node) == "pickle.loads"


def _is_execute_call(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Attribute) and node.func.attr == "execute"


def _sql_finding(path: str, line: int, technique: str) -> Finding:
    return Finding(
        id=f"static-{path}-{line}-sql",
        source="static",
        severity=Severity.HIGH,
        file=path,
        line=line,
        title="Possible SQL injection",
        explanation=(
            f"A SQL query is built using {technique} instead of parameterized "
            "query placeholders -- this is a classic injection risk that AI "
            "assistants reproduce often."
        ),
        confidence=0.65,
        rule_id="sql-string-concat",
    )


# ---------------------------------------------------------------------------
# JS/TS rules (regex-based v1 -- see ARCHITECTURE.md open question)
# ---------------------------------------------------------------------------

_JS_SECRET_RE = re.compile(
    r"(?i)(const|let|var)\s+(\w*(key|secret|token|password)\w*)\s*=\s*[\"'](sk-|AKIA|ghp_|xox)[^\"']{10,}[\"']"
)
_JS_EVAL_RE = re.compile(r"\beval\s*\(")
_JS_CORS_RE = re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"']")
_JS_WEAK_CRYPTO_RE = re.compile(r"createHash\(\s*[\"'](md5|sha1)[\"']\s*\)")


def _scan_js(file: FileToScan) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(file.content.splitlines(), start=1):
        if _JS_SECRET_RE.search(line):
            findings.append(
                Finding(
                    id=f"static-{file.path}-{i}-secret",
                    source="static",
                    severity=Severity.CRITICAL,
                    file=file.path,
                    line=i,
                    title="Hardcoded credential-like value",
                    explanation="This line assigns a hardcoded string that looks like a secret or API key.",
                    confidence=0.7,
                    rule_id="hardcoded-secret",
                )
            )
        if _JS_EVAL_RE.search(line):
            findings.append(
                Finding(
                    id=f"static-{file.path}-{i}-eval",
                    source="static",
                    severity=Severity.HIGH,
                    file=file.path,
                    line=i,
                    title="Use of eval()",
                    explanation="eval() executes arbitrary code -- risky if any input reaches it.",
                    confidence=0.55,
                    rule_id="eval-on-input",
                )
            )
        if _JS_CORS_RE.search(line):
            findings.append(
                Finding(
                    id=f"static-{file.path}-{i}-cors",
                    source="static",
                    severity=Severity.MEDIUM,
                    file=file.path,
                    line=i,
                    title="CORS allows all origins",
                    explanation="Access-Control-Allow-Origin is set to '*' -- review before production.",
                    confidence=0.8,
                    rule_id="cors-allow-all",
                )
            )
        match = _JS_WEAK_CRYPTO_RE.search(line)
        if match:
            algo = match.group(1)
            findings.append(
                Finding(
                    id=f"static-{file.path}-{i}-weakcrypto",
                    source="static",
                    severity=Severity.MEDIUM,
                    file=file.path,
                    line=i,
                    title=f"Weak hash algorithm ({algo})",
                    explanation=(
                        f"{algo.upper()} is broken for security purposes. Fine for non-security "
                        "checksums; avoid it for passwords, tokens, or signatures."
                    ),
                    confidence=0.5,
                    rule_id="weak-crypto",
                )
            )
    return findings


def scan_file(file: FileToScan) -> list[Finding]:
    """Entry point: dispatch to the right rule set for the file's language."""
    if file.language == "python":
        return _scan_python(file)
    if file.language in ("javascript", "typescript"):
        return _scan_js(file)
    return []


def scan_files(files: list[FileToScan]) -> list[Finding]:
    findings: list[Finding] = []
    for f in files:
        findings.extend(scan_file(f))
    return findings
