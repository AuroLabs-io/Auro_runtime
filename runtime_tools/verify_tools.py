"""
Source-checkout verification: verify_code_static, verify_code_dynamic,
verify_security, and verify_output over the three of them.

These are operator functions, called directly, and are deliberately NOT
registered as tools. They were reachable by a model through the `verify_project`
directive until 2026-08-13. That path was cut because it inverted when it worked:
driving it requires the registries to load, the policies to validate, and a model
to follow a multi-step protocol, so the runs it could report on were the runs
that were already fine. A broken checkout refused the directive instead of
explaining itself. Called directly, these still run and still report.

Static checks are safe (no code execution). Dynamic checks run in a temporary
project copy with a sanitized environment.
Each returns a structured report with passed (bool), checks (list), and errors/warnings.
"""

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from auro_runtime.paths import (
    get_directives_dir,
    get_policies_dir,
    get_source_checkout_root,
)
from auro_runtime.sensitive_paths import classify_text

_PROJECT_ROOT = None

# What the sandbox copies. Everything the copied suite READS has to be here,
# not merely everything it imports, and that has now been learned three times:
# "tests" because verify_code_dynamic runs pytest inside the temporary copy,
# "docs" because the copied suite validates its generated catalogue, and
# ".github" because test_support_claims reads the CI workflow to check the
# support matrix. Each was added after the copied suite failed without it.
#
# The failure is quiet in the direction that matters: the suite passes in CI,
# which runs against the real checkout, and fails only under
# verify_code_dynamic, which nothing in CI calls. A test that reads a path
# this list does not carry is invisible until someone runs the verifier by
# hand. Nothing keeps the two in sync -- see the open thread on the class.
_SOURCE_DIRS = ["auro_runtime", "runtime_tools", "tests", "docs", ".github"]

# Currently identical to _SOURCE_DIRS, and kept separate because they answer
# different questions: what a faithful copy needs, versus what a whole-tree
# scan walks. ".github" was appended here alone until it turned out the
# copied suite needed it too.
_SCAN_DIRS = [*_SOURCE_DIRS]

_SANITIZED_ENV_KEYS = {
    "PATH", "SYSTEMROOT", "TEMP", "TMP", "COMSPEC",
    "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
}

# Set inside the verification sandbox so the dynamic verifier does not re-enter itself.
_SANDBOX_MARKER = "AURO_VERIFY_SANDBOX"


def _root() -> Path:
    global _PROJECT_ROOT
    if _PROJECT_ROOT is None:
        _PROJECT_ROOT = get_source_checkout_root().resolve()
    return _PROJECT_ROOT


def _inside_named_sandbox() -> bool:
    """
    True only when the marker names a directory this module was loaded from.

    The sandbox copies the source tree and points PYTHONPATH at the copy, so a
    genuine re-entry imports this very file from under the sandbox root. That
    is the fact an ambient setting cannot fake: exporting the variable names
    no such directory, so the guard does not fire and the dynamic phase runs.

    The marker used to be a bare "1", which made the two cases identical to
    the reader below. Anyone who set the name got a `recursion_guard` check
    reporting `passed: True` and a dynamic phase that had run nothing --
    vacuous success, reachable from the environment, and named in no shipped
    document. Containment is checked here rather than trusted from the value
    for the same reason `egress` resolves an address instead of reading a
    string: the assertion and the fact it asserts have to be the same thing.
    """
    marker = os.environ.get(_SANDBOX_MARKER)
    if not marker:
        return False
    try:
        root = Path(marker).resolve()
        here = Path(__file__).resolve()
    except (OSError, ValueError):
        return False
    return root.is_dir() and here.is_relative_to(root)


def _source_checkout_failure() -> dict | None:
    """Return a structured refusal when a verifier has no source checkout."""
    try:
        _root()
    except RuntimeError as exc:
        finding = _make_finding(
            SEVERITY_ERROR,
            "SOURCE_CHECKOUT_REQUIRED",
            str(exc),
        )
        result = _summarize([finding])
        result["checks"] = [{
            "name": "source_checkout",
            "passed": False,
            "detail": str(exc),
        }]
        return result
    return None


# ---------------------------------------------------------------------------
# Sandbox helper
# ---------------------------------------------------------------------------

class _Sandbox:
    """
    Copy source directories to a temp location for safe dynamic execution.
    The real project root is never the cwd of a dynamic check.
    """

    def __init__(self):
        self._tmpdir = None
        self._path = None

    def __enter__(self) -> Path:
        self._tmpdir = tempfile.mkdtemp(prefix="auro_verify_")
        sandbox = Path(self._tmpdir)

        for src_dir in _SOURCE_DIRS:
            src = _root() / src_dir
            if src.exists():
                shutil.copytree(src, sandbox / src_dir, dirs_exist_ok=True)

        # Root files that make the sandbox a faithful snapshot of the project,
        # not just enough to import it — tests may legitimately assert on them.
        for config_file in ["pyproject.toml", "setup.py", "setup.cfg",
                            "LICENSE", ".gitignore", "README.md",
                            "release_evidence.py"]:
            src = _root() / config_file
            if src.exists():
                shutil.copy2(src, sandbox / config_file)

        self._path = sandbox
        return sandbox

    def __exit__(self, *exc):
        if self._tmpdir:
            try:
                shutil.rmtree(self._tmpdir, ignore_errors=True)
            except Exception:
                pass

    def env(self) -> dict:
        """Sanitized environment for subprocess execution."""
        clean = {k: v for k, v in os.environ.items() if k in _SANITIZED_ENV_KEYS}
        clean["PYTHONPATH"] = str(self._path)
        clean["PYTHONDONTWRITEBYTECODE"] = "1"
        clean["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        # Recursion guard. The sandbox copies tests/, so a test that calls
        # verify_code_dynamic would spawn a sandbox that runs that same test,
        # nesting until the timeouts cascade. Inside the sandbox the dynamic
        # verifier refuses to recurse.
        #
        # The marker carries the sandbox root rather than "1" so the read site
        # can tell a real re-entry from an ambient setting. A bare flag made
        # the two indistinguishable, which meant anyone who exported this name
        # turned the whole dynamic phase into a pass that ran nothing.
        clean[_SANDBOX_MARKER] = str(self._path)
        return clean


SEVERITY_ERROR = "error"    # blocks promotion / merge / export
SEVERITY_WARN = "warn"      # visible but allowed
SEVERITY_INFO = "info"      # informational


_PYTEST_SUMMARY_RE = re.compile(
    r"^\s*=*\s*\d+\s+(passed|failed|error|skipped|xfailed|xpassed|deselected)",
    re.IGNORECASE,
)


def _pytest_summary(stdout: str, tail: int = 400) -> str:
    """
    Lead the detail with pytest's own count line.

    Truncating blindly to the tail can leave only progress bars, and a caller
    handed dots and percentages will infer a test count rather than admit it
    cannot see one. Surface the counts explicitly.
    """
    lines = [ln.strip() for ln in (stdout or "").strip().splitlines() if ln.strip()]
    summary = next(
        (ln for ln in reversed(lines) if _PYTEST_SUMMARY_RE.match(ln)),
        None,
    )
    if summary:
        return summary
    if lines:
        return f"[no pytest summary line found] {' '.join(lines)[-tail:]}"
    return "[pytest produced no output]"


_SCANNABLE_SUFFIXES = frozenset({
    ".py", ".md", ".yaml", ".yml", ".toml", ".txt", ".json", ".cfg", ".ini", ".env", "",
})
_SCAN_SKIP_DIRS = frozenset({"__pycache__", ".git", ".pytest_cache", ".auro_archive", "node_modules"})


def _iter_scannable_files():
    """Every text file that ships, for whole-tree scans.

    Deliberately not driven by `git diff`: a diff-scoped scan silently covers
    nothing outside a git repo, on a clean tree, or in a fresh clone.
    """
    root = _root()
    for src_dir in _SCAN_DIRS:
        base = root / src_dir
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if any(part in _SCAN_SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() in _SCANNABLE_SUFFIXES:
                yield path
    for name in (
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "LICENSE",
        "README.md",
        "MANIFEST.in",
        ".gitignore",
        "release_evidence.py",
    ):
        p = root / name
        if p.is_file():
            yield p


class _SubcheckRecorded(Exception):
    """
    Raised by a subcheck that has already appended its own failure.

    Lets a check bail out of its try block without the generic handler
    recording the same failure a second time under a different detail.
    """


def _make_finding(severity: str, code: str, message: str, file: str = "", line: int = 0) -> dict:
    finding = {"severity": severity, "code": code, "message": message}
    if file:
        finding["file"] = file
    if line:
        finding["line"] = line
    return finding


def _summarize_with_checks(findings: list[dict], checks: list[dict]) -> dict:
    """
    Build a result whose headline verdict cannot contradict its own checks list.

    The two used to be assembled independently: `_summarize` derived `passed`
    from findings alone and `checks` was attached afterwards. A subcheck that
    recorded `passed: False` — because it examined nothing, or because it
    crashed and its handler recorded the failure without raising a finding —
    still returned an object reporting `passed: True`. One artifact, two
    readers, no agreement: a caller reading `result["passed"]` and a caller
    reading `result["checks"]` got opposite answers from the same value.

    Deriving the aggregate from the checks is what makes that state
    unconstructible. Fixing each subcheck that happened to reach it would leave
    the next one free to reach it again, and a subcheck added later would not
    know the rule existed.

    A check with no `passed` key counts as failed: a result that did not say
    whether it passed has not said that it did.
    """
    result = _summarize(findings)
    result["checks"] = checks
    result["passed"] = result["passed"] and all(c.get("passed", False) for c in checks)
    return result


def _summarize(findings: list[dict]) -> dict:
    """Return severity counts and pass/fail from a findings list."""
    counts = {SEVERITY_ERROR: 0, SEVERITY_WARN: 0, SEVERITY_INFO: 0}
    for f in findings:
        sev = f.get("severity", SEVERITY_ERROR)
        if sev in counts:
            counts[sev] += 1
    return {
        "passed": counts[SEVERITY_ERROR] == 0,
        "error_count": counts[SEVERITY_ERROR],
        "warn_count": counts[SEVERITY_WARN],
        "info_count": counts[SEVERITY_INFO],
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Strict YAML loader — duplicate key detection
# ---------------------------------------------------------------------------

class _DuplicateKeyError(Exception):
    def __init__(self, key, first_mark, second_mark):
        self.key = key
        self.first_mark = first_mark
        self.second_mark = second_mark
        super().__init__(f"Duplicate key '{key}' at line {second_mark.line + 1}")


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that raises on duplicate keys instead of silently overwriting."""
    pass


def _strict_construct_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node, deep=deep)
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKeyError(key, seen[key], node.start_mark)
        seen[key] = node.start_mark
    return dict(pairs)


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _strict_construct_mapping,
)


def _strict_yaml_load(text: str) -> dict:
    """Parse YAML with duplicate key detection. Raises on duplicates."""
    return yaml.load(text, Loader=_StrictSafeLoader)


# ---------------------------------------------------------------------------
# verify_code_static — safe, no code execution
# ---------------------------------------------------------------------------

def verify_code_static() -> dict:
    """
    Static code checks: syntax parsing, AST inspection, directive frontmatter
    parsing, file layout validation. No code is executed, so this is safe to run
    on untrusted input.
    """
    if failure := _source_checkout_failure():
        return failure

    checks = []
    errors = []
    warnings = []

    # 1. Syntax check on all project Python files
    py_files = []
    for src_dir in ["auro_runtime", "runtime_tools"]:
        src_path = _root() / src_dir
        if src_path.exists():
            py_files.extend(src_path.rglob("*.py"))

    syntax_errors = []
    for pf in py_files:
        rel = pf.relative_to(_root()).as_posix()
        try:
            raw = pf.read_bytes()
            if raw.startswith(b"\xef\xbb\xbf"):
                syntax_errors.append(_make_finding(
                    "error",
                    "SOURCE_BOM",
                    "UTF-8 byte-order marks are not allowed in Python source",
                    file=rel,
                    line=1,
                ))
                continue
            source = raw.decode("utf-8")
            ast.parse(source, filename=rel)
        except UnicodeDecodeError as e:
            syntax_errors.append(_make_finding(
                "error",
                "SOURCE_ENCODING",
                str(e),
                file=rel,
                line=1,
            ))
        except SyntaxError as e:
            syntax_errors.append(_make_finding("error", "SYNTAX_ERROR", e.msg, file=rel, line=e.lineno or 0))

    checks.append({
        "name": "syntax_check",
        "passed": len(syntax_errors) == 0,
        "detail": f"{len(py_files)} Python files parsed" if not syntax_errors else syntax_errors,
    })
    if syntax_errors:
        errors.extend(syntax_errors)

    # 2. Directive frontmatter validation (YAML parse only, no imports)
    #
    # The subject is the packaged authority, which is what the runtime loads.
    # Absence is a failure rather than a skip: an `if exists()` guard here would
    # delete the check silently the moment the directory moved, which is exactly
    # how this check would have vanished when the top-level mirrors were dropped.
    directives_dir = get_directives_dir()
    if not directives_dir.is_dir():
        checks.append({
            "name": "directive_frontmatter",
            "passed": False,
            "detail": f"packaged directives directory not found at {directives_dir}",
        })
        errors.append(_make_finding(
            "error", "MISSING_DIRECTORY",
            f"Packaged authority directives not found at {directives_dir}",
        ))
    else:
        bad_directives = []
        directive_count = 0
        for md_file in sorted(directives_dir.glob("*.md")):
            directive_count += 1
            try:
                content = md_file.read_text(encoding="utf-8")
                if not content.strip().startswith("---"):
                    bad_directives.append(_make_finding(
                        "error", "DIRECTIVE_NO_FRONTMATTER",
                        "No YAML frontmatter", file=md_file.name,
                    ))
                    continue

                parts = content.split("---", 2)
                if len(parts) < 3:
                    bad_directives.append(_make_finding(
                        "error", "DIRECTIVE_BAD_FRONTMATTER",
                        "Malformed frontmatter (no closing ---)", file=md_file.name,
                    ))
                    continue

                try:
                    meta = _strict_yaml_load(parts[1])
                except _DuplicateKeyError as dke:
                    bad_directives.append(_make_finding(
                        "error", "DIRECTIVE_DUPLICATE_KEY",
                        str(dke), file=md_file.name,
                    ))
                    continue
                if not isinstance(meta, dict):
                    bad_directives.append(_make_finding(
                        "error", "DIRECTIVE_BAD_YAML",
                        "Frontmatter is not a mapping", file=md_file.name,
                    ))
                    continue

                if not meta.get("id"):
                    bad_directives.append(_make_finding(
                        "error", "DIRECTIVE_MISSING_ID",
                        "Missing 'id' in frontmatter", file=md_file.name,
                    ))
                if not meta.get("tools"):
                    warnings.append(_make_finding(
                        "warn", "DIRECTIVE_NO_TOOLS",
                        "No tools listed — directive will have no tool access", file=md_file.name,
                    ))

            except Exception as e:
                bad_directives.append(_make_finding(
                    "error", "DIRECTIVE_PARSE_ERROR",
                    str(e), file=md_file.name,
                ))

        checks.append({
            "name": "directive_validation",
            "passed": len(bad_directives) == 0,
            "detail": f"{directive_count} directives valid" if not bad_directives else bad_directives,
        })
        if bad_directives:
            errors.extend(bad_directives)

    # 3. Policy YAML parse check (no imports, just YAML structure)
    policies_dir = get_policies_dir()
    if not policies_dir.is_dir():
        checks.append({
            "name": "policy_yaml_parse",
            "passed": False,
            "detail": f"packaged policies directory not found at {policies_dir}",
        })
        errors.append(_make_finding(
            "error", "MISSING_DIRECTORY",
            f"Packaged authority policies not found at {policies_dir}",
        ))
    else:
        bad_policies = []
        policy_count = 0
        for yaml_file in sorted(policies_dir.glob("*.yaml")):
            policy_count += 1
            try:
                data = _strict_yaml_load(yaml_file.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    bad_policies.append(_make_finding(
                        "error", "POLICY_BAD_YAML",
                        "Policy file is not a mapping", file=yaml_file.name,
                    ))
                elif not data.get("id"):
                    bad_policies.append(_make_finding(
                        "warn", "POLICY_MISSING_ID",
                        "Missing 'id' field", file=yaml_file.name,
                    ))
            except Exception as e:
                bad_policies.append(_make_finding(
                    "error", "POLICY_PARSE_ERROR",
                    str(e), file=yaml_file.name,
                ))

        checks.append({
            "name": "policy_yaml_parse",
            "passed": len([p for p in bad_policies if p["severity"] == "error"]) == 0,
            "detail": f"{policy_count} policy files valid" if not bad_policies else bad_policies,
        })
        errors.extend([p for p in bad_policies if p["severity"] == "error"])

    # 4. File layout check
    layout_issues = []
    expected_dirs = {"auro_runtime", "runtime_tools"}
    for d in expected_dirs:
        if not (_root() / d).is_dir():
            layout_issues.append(_make_finding(
                "error", "MISSING_DIRECTORY",
                f"Expected directory '{d}/' not found",
            ))

    # Authority lives in the package, not at the top level, so the layout check
    # asks the package for it rather than looking for a sibling directory.
    for authority_dir in (get_directives_dir(), get_policies_dir()):
        if not authority_dir.is_dir():
            layout_issues.append(_make_finding(
                "error", "MISSING_DIRECTORY",
                f"Packaged authority directory '{authority_dir}' not found",
            ))

    if not (_root() / "runtime_tools" / "__init__.py").exists():
        layout_issues.append(_make_finding(
            "error", "MISSING_INIT",
            "runtime_tools/__init__.py not found — tool registration will fail",
        ))

    checks.append({
        "name": "file_layout",
        "passed": len(layout_issues) == 0,
        "detail": "All expected directories present" if not layout_issues else layout_issues,
    })
    if layout_issues:
        errors.extend(layout_issues)

    all_findings = errors + warnings
    result = _summarize_with_checks(all_findings, checks)
    return result


# ---------------------------------------------------------------------------
# verify_code_dynamic — executes code in a temporary project copy
# ---------------------------------------------------------------------------

def verify_code_dynamic() -> dict:
    """
    Dynamic code checks: tool imports, policy validation against the registries,
    and the test suite. Runs in a temporary project copy with a sanitized
    environment. Never executes against the real project root.
    """
    if failure := _source_checkout_failure():
        return failure

    checks = []
    errors = []
    python = sys.executable

    if _inside_named_sandbox():
        # Already inside a verification sandbox — see the guard in _Sandbox.env().
        checks.append({
            "name": "recursion_guard",
            "passed": True,
            "detail": "Already running inside a verification sandbox; dynamic checks not re-entered.",
        })
        result = _summarize_with_checks(errors, checks)
        return result

    if os.environ.get(_SANDBOX_MARKER):
        # Set, but not naming a sandbox this process is running inside. The
        # dynamic phase runs anyway; record that the marker was disregarded
        # rather than honouring it silently, because the value that reaches
        # here is the one an operator exported by hand.
        checks.append({
            "name": "recursion_guard",
            "passed": True,
            "detail": (
                f"{_SANDBOX_MARKER} is set but does not name a sandbox this "
                "process is running inside; ignored, dynamic checks run."
            ),
        })

    with _Sandbox() as sandbox:
        sandbox_env = _Sandbox()
        sandbox_env._path = sandbox
        env = sandbox_env.env()

        # 1. Import check
        try:
            result = subprocess.run(
                [python, "-c", "import runtime_tools; from auro_runtime.executor import list_tools; print(len(list_tools()))"],
                capture_output=True, text=True, timeout=30,
                cwd=str(sandbox),
                env=env,
            )
            if result.returncode == 0:
                count = result.stdout.strip()
                checks.append({"name": "tool_imports", "passed": True, "detail": f"{count} tools registered"})
            else:
                checks.append({"name": "tool_imports", "passed": False, "detail": result.stderr[:500]})
                errors.append(_make_finding("error", "IMPORT_FAILURE", result.stderr[:200]))
        except subprocess.TimeoutExpired:
            checks.append({"name": "tool_imports", "passed": False, "detail": "Import check timed out (30s)"})
            errors.append(_make_finding("error", "IMPORT_TIMEOUT", "Import check timed out after 30s"))
        except Exception as e:
            checks.append({"name": "tool_imports", "passed": False, "detail": str(e)})
            errors.append(_make_finding("error", "IMPORT_ERROR", str(e)))

        # 2. Policy validation against registries
        try:
            result = subprocess.run(
                [python, "-c", (
                    "import runtime_tools; "
                    "from auro_runtime.policy import load_policies, validate_policies; "
                    "from auro_runtime.guards import get_guard_registry; "
                    "from auro_runtime.executor import get_registry; "
                    "from auro_runtime.paths import get_policies_dir; "
                    "policies = load_policies(str(get_policies_dir())); "
                    "validate_policies(policies, get_guard_registry(), get_registry()); "
                    "print('OK')"
                )],
                capture_output=True, text=True, timeout=30,
                cwd=str(sandbox),
                env=env,
            )
            if result.returncode == 0 and "OK" in result.stdout:
                checks.append({"name": "policy_validation", "passed": True, "detail": "All policies valid against registries"})
            else:
                checks.append({"name": "policy_validation", "passed": False, "detail": result.stderr[:500]})
                errors.append(_make_finding("error", "POLICY_VALIDATION_FAILURE", result.stderr[:200]))
        except subprocess.TimeoutExpired:
            checks.append({"name": "policy_validation", "passed": False, "detail": "Policy validation timed out (30s)"})
            errors.append(_make_finding("error", "POLICY_TIMEOUT", "Policy validation timed out after 30s"))
        except Exception as e:
            checks.append({"name": "policy_validation", "passed": False, "detail": str(e)})
            errors.append(_make_finding("error", "POLICY_ERROR", str(e)))

        # 3. Test suite
        try:
            result = subprocess.run(
                # -o addopts= clears the target project's own addopts. Without it the
                # project's config is inherited: a project that already sets -q gives
                # pytest -q twice, and -qq suppresses the summary line entirely — leaving
                # a caller with nothing but progress bars to infer a result from.
                [python, "-m", "pytest", "-o", "addopts=", "--tb=short", "-q", "-p", "no:cacheprovider"],
                capture_output=True, text=True, timeout=120,
                cwd=str(sandbox),
                env=env,
            )
            if "No module named pytest" in result.stderr:
                detail = "pytest is not installed; the test suite did not run"
                checks.append({"name": "test_suite", "passed": False, "detail": detail})
                errors.append(_make_finding("error", "PYTEST_MISSING", detail))
            elif result.returncode == 0:
                checks.append({"name": "test_suite", "passed": True, "detail": _pytest_summary(result.stdout)})
            elif result.returncode == 5:
                detail = "No tests collected"
                checks.append({"name": "test_suite", "passed": False, "detail": detail})
                errors.append(_make_finding("error", "NO_TESTS_COLLECTED", detail))
            else:
                checks.append({"name": "test_suite", "passed": False, "detail": result.stdout.strip()[-500:]})
                errors.append(_make_finding("error", "TEST_FAILURE", "Test suite failed"))
        except subprocess.TimeoutExpired:
            checks.append({"name": "test_suite", "passed": False, "detail": "Test suite timed out (120s)"})
            errors.append(_make_finding("error", "TEST_TIMEOUT", "Test suite timed out after 120s"))
        except Exception as e:
            checks.append({"name": "test_suite", "passed": False, "detail": str(e)})

    result = _summarize_with_checks(errors, checks)
    return result


# ---------------------------------------------------------------------------
# verify_security
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("aws_key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")),
    ("slack_token", re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}")),
    ("generic_key_assignment", re.compile(
        r"(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)"
        r"\s*[:=]\s*['\"][A-Za-z0-9_\-./+]{20,}['\"]",
        re.IGNORECASE,
    )),
]

# The sensitive-file inventory that used to sit here -- `.env`,
# `auro_secrets.yaml`, `.auro_secrets.yaml` -- was the third hand-maintained
# copy of a list that also lived in the policy guard and the file tool, all
# three drifting independently. It is gone; this check consumes the single
# definition in auro_runtime.sensitive_paths.
#
# That is a widening as well as a deduplication. The old check compared the
# *basename* exactly and case-sensitively, so a staged `.ssh/id_rsa` -- a
# private key, the thing this check exists to stop reaching a commit -- passed
# it. Classifying the repo-relative path catches the directory families too.


def verify_security() -> dict:
    """
    Security checks: secret scanning over the shipped tree, sensitive files
    staged for commit, guard coverage of enforceable rules, and tool schema
    coverage. Returns a structured pass/fail report.
    """
    if failure := _source_checkout_failure():
        return failure

    checks = []
    errors = []

    # 1. Secret scan over the whole shipped tree.
    #
    # This used to scan only `git diff --name-only HEAD`. That silently scans
    # NOTHING in three common situations — not a git repo, a clean working
    # tree, or a fresh clone — and then reports "0 files scanned clean" as a
    # pass. A security check that proves nothing must not look like one that
    # passed, so scan everything that ships and report the count.
    try:
        scanned_files = list(_iter_scannable_files())
        secrets_found = []

        for full_path in scanned_files:
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                for kind, pattern in _SECRET_PATTERNS:
                    if pattern.search(content):
                        secrets_found.append(_make_finding(
                            "error", "SECRET_DETECTED",
                            f"Possible {kind} detected",
                            file=str(full_path.relative_to(_root())),
                        ))
            except Exception:
                continue

        if secrets_found:
            checks.append({"name": "secret_scan", "passed": False, "detail": secrets_found})
            errors.extend(secrets_found)
        elif not scanned_files:
            # Nothing scanned is not a clean result.
            checks.append({
                "name": "secret_scan",
                "passed": False,
                "detail": "No files were scanned — the secret scan verified nothing.",
            })
            errors.append(_make_finding(
                SEVERITY_WARN, "SECRET_SCAN_EMPTY",
                "Secret scan found no files to scan; this is not a clean result.",
            ))
        else:
            checks.append({
                "name": "secret_scan",
                "passed": True,
                "detail": f"{len(scanned_files)} files scanned clean",
            })
    except Exception as e:
        checks.append({"name": "secret_scan", "passed": False, "detail": str(e)})

    # 2. Sensitive files not staged
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=15,
            cwd=str(_root()),
        )
        if result.returncode != 0:
            # git exits non-zero and prints nothing to stdout when the tree is
            # not a repository. The loop below then finds no lines and the check
            # reported "No sensitive files staged" — an inspection that failed,
            # scored as an inspection that found nothing.
            checks.append({
                "name": "sensitive_files",
                "passed": False,
                "detail": f"git status failed (exit {result.returncode}): "
                          f"{result.stderr.strip()[:200]}",
            })
            errors.append(_make_finding(
                SEVERITY_ERROR, "SOURCE_CONTROL_UNAVAILABLE",
                "git status failed; staged-file inspection verified nothing.",
            ))
            raise _SubcheckRecorded

        staged_sensitive = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            status = line[:2]
            filepath = line[3:].strip().strip('"')
            match = classify_text(filepath)
            if match is not None and status[0] in ("A", "M"):
                staged_sensitive.append(_make_finding(
                    "error", "SENSITIVE_FILE_STAGED",
                    f"Sensitive file staged for commit ({match.category})",
                    file=filepath,
                ))

        if staged_sensitive:
            checks.append({"name": "sensitive_files", "passed": False, "detail": staged_sensitive})
            errors.extend(staged_sensitive)
        else:
            checks.append({"name": "sensitive_files", "passed": True, "detail": "No sensitive files staged"})
    except _SubcheckRecorded:
        pass
    except Exception as e:
        checks.append({"name": "sensitive_files", "passed": False, "detail": str(e)})

    # 3. Guard registry completeness
    try:
        from auro_runtime.policy import load_policies, get_enforceable_rules
        from auro_runtime.guards import get_guard_registry

        policies = load_policies(get_policies_dir())
        enforceable = get_enforceable_rules(policies)
        guard_reg = get_guard_registry()
        missing_guards = [r.id for r in enforceable if r.guard not in guard_reg]
        # The reverse direction, which this check never asked about: a guard that
        # is registered but bound by no rule reads as protection on review and
        # never runs. Proving one direction and describing it as completeness is
        # how the unbound half stayed invisible.
        bound = {r.guard for r in enforceable if r.guard}
        unbound_guards = sorted(set(guard_reg) - bound)

        if not enforceable:
            # Zero rules satisfied "all guards present" vacuously, and reported
            # it in those words.
            checks.append({"name": "guard_completeness", "passed": False,
                           "detail": "No enforceable rules loaded — guard coverage verified nothing."})
            errors.append(_make_finding(
                SEVERITY_ERROR, "NO_ENFORCEABLE_RULES",
                "Policy set contains no enforceable rules; guard coverage examined nothing.",
            ))
        elif missing_guards or unbound_guards:
            checks.append({"name": "guard_completeness", "passed": False,
                           "detail": {"rules_naming_absent_guards": missing_guards,
                                      "registered_but_unbound_guards": unbound_guards}})
            if missing_guards:
                errors.append(_make_finding("error", "MISSING_GUARD", f"Missing guards: {missing_guards}"))
            if unbound_guards:
                errors.append(_make_finding(
                    SEVERITY_ERROR, "UNBOUND_GUARD",
                    f"Registered guards bound by no rule: {unbound_guards}",
                ))
        else:
            checks.append({"name": "guard_completeness", "passed": True,
                           "detail": f"{len(enforceable)} enforceable rules, "
                                     f"{len(guard_reg)} guards, bound in both directions"})
    except Exception as e:
        checks.append({"name": "guard_completeness", "passed": False, "detail": str(e)})

    # 4. Tool schema coverage
    try:
        from auro_runtime.executor import get_registry
        registry = get_registry()
        no_schema = [name for name, (fn, doc, schema) in registry.items() if schema is None]

        if not registry:
            checks.append({"name": "tool_schemas", "passed": False,
                           "detail": "No tools registered — schema coverage verified nothing."})
            errors.append(_make_finding(
                SEVERITY_ERROR, "TOOL_REGISTRY_EMPTY",
                "Tool registry is empty; schema coverage examined no tools.",
            ))
        elif no_schema:
            # Both branches used to report passed: True, so the only False this
            # check could produce came from its own except handler — it reported
            # failure when it crashed and never when the condition it examines
            # was violated.
            checks.append({"name": "tool_schemas", "passed": False,
                           "detail": f"{len(no_schema)} tools without schemas: {', '.join(sorted(no_schema))}"})
            errors.append(_make_finding(
                SEVERITY_ERROR, "TOOL_SCHEMA_MISSING",
                f"Tools without args_schema: {', '.join(sorted(no_schema))}",
            ))
        else:
            checks.append({"name": "tool_schemas", "passed": True, "detail": f"All {len(registry)} tools have schemas"})
    except Exception as e:
        checks.append({"name": "tool_schemas", "passed": False, "detail": str(e)})

    result = _summarize_with_checks(errors, checks)
    return result


# ---------------------------------------------------------------------------
# verify_output — orchestrated gate with execution ordering
# ---------------------------------------------------------------------------

def verify_output() -> dict:
    """
    Execution order:
    1. verify_code_static  — syntax, frontmatter, layout (safe, fast)
    2. verify_security     — secret scan, guard completeness (safe, reads files)
    3. verify_code_dynamic — imports, policy validation, pytest (sandboxed, executes code)

    If phases 1-2 produce errors, phase 3 is skipped.
    """
    if failure := _source_checkout_failure():
        failure["phases"] = [{
            "phase": "source_checkout",
            "passed": False,
            "error_count": failure["error_count"],
            "warn_count": failure["warn_count"],
            "checks": failure["checks"],
        }]
        return failure

    phases = []
    all_findings = []
    static_errors = 0
    # Tracked separately from the error count because a phase can fail without
    # raising an error finding — an evidence-empty subcheck is the case that
    # matters. Gating on the count alone let the dynamic phase run on top of a
    # static phase that had already reported failure.
    static_failed = []

    # Phase 1: Static code checks
    r = verify_code_static()
    phases.append({"phase": "code_static", "passed": r["passed"], "error_count": r["error_count"],
                   "warn_count": r["warn_count"], "checks": r.get("checks", [])})
    all_findings.extend(r.get("findings", []))
    static_errors += r["error_count"]
    if not r["passed"]:
        static_failed.append("code_static")

    # Phase 2: Security
    r = verify_security()
    phases.append({"phase": "security", "passed": r["passed"], "error_count": r["error_count"],
                   "warn_count": r["warn_count"], "checks": r.get("checks", [])})
    all_findings.extend(r.get("findings", []))
    static_errors += r["error_count"]
    if not r["passed"]:
        static_failed.append("security")

    # Phase 3: Dynamic code checks — only if static phases are clean
    if static_errors > 0 or static_failed:
        reason = (
            f"Skipped — {static_errors} error(s) in static phases must be resolved first"
            if static_errors
            else f"Skipped — static phase(s) reported failure: {', '.join(static_failed)}"
        )
        phases.append({
            "phase": "code_dynamic",
            "passed": False,
            "skipped": True,
            "reason": reason,
        })
        all_findings.append(_make_finding(
            SEVERITY_WARN, "DYNAMIC_SKIPPED", reason,
        ))
    else:
        r = verify_code_dynamic()
        # Per-check detail remains part of the result so callers can report what
        # the test phase covered, not just its pass/fail verdict.
        phases.append({"phase": "code_dynamic", "passed": r["passed"], "error_count": r["error_count"],
                       "warn_count": r["warn_count"], "checks": r.get("checks", [])})
        all_findings.extend(r.get("findings", []))

    result = _summarize(all_findings)
    result["phases"] = phases
    # Same rule as _summarize_with_checks, one level up: the orchestrator's
    # verdict must not contradict the phases it reports. A skipped dynamic phase
    # is not a passed one.
    result["passed"] = result["passed"] and all(ph.get("passed", False) for ph in phases)
    return result
