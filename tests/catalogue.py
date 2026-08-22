"""
Generate docs/TESTS.md from the test suite itself.

A test count is a verdict; a catalogue is coverage. Written by hand it would
drift within a week, so this reads the test files directly (AST, no execution)
and regenerates the document.

    python -m tests.catalogue           # write docs/TESTS.md
    python -m tests.catalogue --check   # exit 1 if the committed doc is stale
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
OUTPUT = REPO_ROOT / "docs" / "TESTS.md"

# What each file is responsible for. Keyed by filename; collect() refuses to
# run for any test_*.py file with no entry here, rather than publishing it
# unlabelled.
FILE_PURPOSE = {
    "test_policy_validation.py":
        "Policy loading and fail-hard validation. The regression barrier for the "
        "defect that once made the runtime unable to run any directive: a policy "
        "naming a tool that no longer exists.",
    "test_guard_bindings.py":
        "Every registered guard is bound by some policy rule, and every rule names "
        "a guard that exists. A registered-but-unbound guard reads as protection "
        "while never running.",
    "test_classifier_pins.py":
        "Law 10's enforcement: every caller-supplied locator argument is inspected "
        "or exempt on the record, and every security inventory declares whether it "
        "names places or matches secret values. A classifier that judges a string "
        "the filesystem or socket will read differently is the class these pin.",
    "test_enforcement.py":
        "The executor's refusal pipeline: registry check, directive scope, argument "
        "schema, then policy guards across block/warn/advisory and "
        "fail_closed/fail_open.",
    "test_sensitive_resource_classification.py":
        "The single sensitive-resource inventory and both layers that consume it. "
        "Covers that the policy guard and the file tool agree on every family and "
        "category, that the tool classifies the resolved path rather than the "
        "basename, and that normalisation is host-independent.",
    "test_credentials.py":
        "Alias resolution and delivery. The property under test throughout is that "
        "a resolved secret never appears in a tool result, an error message, or the "
        "audit trail.",
    "test_registry.py":
        "Tool registry shape, project-root and import wiring, the CLI surface, "
        "model-backend selection, and two source-hygiene invariants: loggers stay "
        "under the auro_runtime namespace, and no absolute home path reaches "
        "shipped source.",
    "test_directives.py":
        "Shipped directive integrity. A directive naming a tool that no longer "
        "exists parses fine, ships fine, and fails only at execution.",
    "test_end_to_end.py":
        "Full runs through the real CLI against a stub model server. Only inference "
        "is stubbed; orchestrator, executor, guards, tools and audit are real.",
    "test_security_p0.py":
        "Regression tests for the package-owned authority split: zero-policy refusal, "
        "workspace resolution, protected-path writes, directive exposure sets, MCP "
        "startup enforcement, and the static verifier's source-checkout and encoding "
        "contracts. Every case proves a seam that is closed in shipped code.",
    "test_mcp_auth.py":
        "Bearer-token admission on the streamable-HTTP transport, the runtime's only "
        "network-exposed authentication surface. Covers the verifier's decision across "
        "token shapes and both key states, the header parsing one layer above it, and "
        "the startup checks the comparison depends on. Refusing a caller and crashing "
        "on one are scored as different outcomes.",
    "test_audit_disclosure.py":
        "Public contracts for the versioned audit envelope and the shared sanitizer "
        "used at audit, executor, transcript, router, model-context, and logging "
        "boundaries. Uses only an ordinary synthetic marker.",
    "test_archive_integrity.py":
        "Soft delete keeps its promise: an archived file is never destroyed by a "
        "later one. Archive names carry the directory so same-named files cannot "
        "share an entry, an existing entry is never overwritten, restore refuses a "
        "name it cannot resolve to one original, and the retention caps govern the "
        "write path as well as the delete path.",
    "test_distribution_install.py":
        "Builds a real wheel and sdist, installs each into an isolated environment, "
        "and runs the installed package with no source checkout present. Proves the "
        "packaged authority split, the source-fallback refusal, and provenance "
        "checks hold from the artifact a user actually installs, not just from source.",
    "test_release_evidence.py":
        "Pins the publication gate to one explicit Git commit and tree. A dirty "
        "checkout, a different expected commit, or ambient source content must not "
        "produce release evidence for the reviewed tree.",
}

FILE_ORDER = list(FILE_PURPOSE)


def _first_line(node) -> str:
    doc = ast.get_docstring(node)
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _humanise(name: str) -> str:
    return name[len("test_"):].replace("_", " ") if name.startswith("test_") else name


class UnclassifiedTestFile(SystemExit):
    def __init__(self, names: list[str]):
        listed = "\n".join(f"  - {n}" for n in names)
        super().__init__(
            f"{len(names)} test file(s) have no FILE_PURPOSE entry in "
            f"tests/catalogue.py:\n{listed}\n\n"
            f"Every test file that ships is described in the catalogue, and what a "
            f"file covers is a decision rather than something to infer from its "
            f"name. Add an entry describing what it is responsible for."
        )


def collect() -> dict:
    """{filename: [(class_or_None, test_name, docstring_first_line), ...]}

    A file with no FILE_PURPOSE entry halts generation rather than being
    published under a placeholder purpose.
    """
    found = {}
    unclassified = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name not in FILE_PURPOSE:
            unclassified.append(path.name)
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        entries = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                entries.append((None, node.name, _first_line(node)))
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name.startswith("test_"):
                        entries.append((node.name, sub.name, _first_line(sub)))
        found[path.name] = entries

    if unclassified:
        raise UnclassifiedTestFile(unclassified)

    return found


def render(found: dict) -> str:
    # Every key in `found` has a FILE_PURPOSE entry by construction: collect()
    # refuses to run for a file that has none.
    total = sum(len(v) for v in found.values())
    ordered = [f for f in FILE_ORDER if f in found]

    out = [
        "# Test catalogue",
        "",
        f"**{total} test functions** across {len(found)} files.",
        "",
        "Generated from the test sources by `python -m tests.catalogue`. Do not edit by hand.",
        "",
        "A count on its own says nothing about what was checked, so this lists every",
        "test in the published suite and what it asserts. Parametrized tests are counted",
        "once here and expand to more cases at run time, so the number pytest reports is",
        "higher.",
        "",
        "## Summary",
        "",
        "| File | Tests |",
        "|---|---:|",
    ]
    for fname in ordered:
        out.append(f"| [`tests/{fname}`](../tests/{fname}) | {len(found[fname])} |")
    out.append(f"| **Total** | **{total}** |")
    out.append("")

    for fname in ordered:
        entries = found[fname]
        out.append("---")
        out.append("")
        out.append(f"## `tests/{fname}`")
        out.append("")
        purpose = FILE_PURPOSE.get(fname)
        if purpose:
            out.append(purpose)
        else:
            out.append("_No purpose recorded. Add an entry to `FILE_PURPOSE` in `tests/catalogue.py`._")
        out.append("")
        out.append(f"{len(entries)} tests.")
        out.append("")

        current_class = "___unset___"
        for cls, name, doc in entries:
            if cls != current_class:
                current_class = cls
                if cls:
                    out.append(f"### {cls}")
                    out.append("")
            label = _humanise(name)
            out.append(f"- **{label}**" + (f" — {doc}" if doc else ""))
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    found = collect()
    rendered = render(found)
    check_only = "--check" in sys.argv

    if check_only:
        if not OUTPUT.exists():
            print(f"MISSING: {OUTPUT.relative_to(REPO_ROOT)} has not been generated.")
            return 1
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"STALE: {OUTPUT.relative_to(REPO_ROOT)} does not match the test sources.")
            print("Regenerate with: python -m tests.catalogue")
            return 1
        print(f"current: {OUTPUT.relative_to(REPO_ROOT)}")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    total = sum(len(v) for v in found.values())
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} — {total} tests across {len(found)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
