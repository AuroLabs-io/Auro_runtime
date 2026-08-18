"""Pins for law 10: validation and action must agree on what the input means.

Law 10 has named this class since roughly 2026-07-27 -- its own worked example
is the `http_request` parser differential, and its body already unifies the
path and URL cases. It had no enforcement mechanism, and in the three weeks
after it was ratified the pattern was written or discovered twice more: the
trailing-space bypass that returned live credentials through both enforcement
layers, and `_is_read_blocked`'s two checks disagreeing about which path they
were judging inside a single function. Every other matured control here
acquired a mechanism -- inventories generated or pinned (law 2b), the
enforcement opt-out surface failing the build on an unclassified name (law
16c), counts derived. This is law 10's.

Two pins, because the class has two halves:

    Coverage -- is a caller-supplied locator inspected at all? `archive_name`
    was not, and nothing said so.

    Method -- does the classifier judge the same thing the filesystem or the
    socket will act on? That is the half law 10 is actually about.

Neither pin decides anything. Both force the decision to be explicit and
recorded, the same way tests/catalogue.py refuses to run for an unclassified
test file. See OT-law-10-is-named-but-unpinned.
"""

from __future__ import annotations

import ast
import re

import pytest

# ---------------------------------------------------------------------------
# Half one: coverage. Which caller-supplied locators are inspected.
# ---------------------------------------------------------------------------

# Scope, stated so it is falsifiable against the implementation rather than
# describing intent (law 16c): every field on a registered tool's args schema
# whose NAME is shaped like a filesystem or network location.
_LOCATOR_FIELD = re.compile(
    r"(^|_)(path|dir|directory|file|url|uri|dest|destination|source|src|target|to)($|_)"
    r"|_name$",
    re.IGNORECASE,
)

# Locator-shaped arguments that `check_sensitive_paths` deliberately does not
# inspect. Each needs a reason, and the reason needs to survive review.
_UNINSPECTED_LOCATOR_ARGS = {
    "archive_name": (
        "Names an entry inside the soft-delete archive, not an arbitrary "
        "filesystem path. Containment is enforced separately and provably: "
        "restore_file resolves it and calls _path_under_base, with two tests "
        "in the safety corpus mutation-proved against that check on "
        "2026-08-16. Adding it to _PATH_ARG_KEYS would refuse restoring a "
        "file the operator legitimately deleted -- an archived `.env` is the "
        "obvious case -- for no containment gain, because the *destination* "
        "argument `restore_to` IS inspected. Source contained, destination "
        "classified; the composition is what makes this safe, not the "
        "argument on its own."
    ),
}

# _PATH_ARG_KEYS entries that no registered tool currently produces. Law 16c:
# a control's stated scope must be falsifiable against its actual reach, and
# a key that matches nothing makes the guard look broader than it is. These
# are retained deliberately -- they pre-cover the obvious names a future tool
# would choose, so coverage is fail-safe rather than an afterthought -- but
# they are recorded as anticipatory rather than counted as reach.
_ANTICIPATORY_PATH_ARG_KEYS = {
    "dest_path",
    "directory",
    "file_path",
    "source_path",
}


def _locator_fields(registry) -> dict[str, str]:
    """{field_name: tool_name} for every locator-shaped registered tool field."""
    found: dict[str, str] = {}
    for tool, (_fn, _doc, schema) in registry.items():
        if schema is None:
            continue
        for field in schema.model_fields:
            if _LOCATOR_FIELD.search(field):
                found.setdefault(field, tool)
    return found


class TestLocatorArgumentsAreClassified:
    """Every caller-supplied locator is inspected, or exempt on the record."""

    def test_every_locator_argument_is_inspected_or_exempt(self, registry):
        from auro_runtime.guards import _PATH_ARG_KEYS

        unclassified = {
            field: tool
            for field, tool in _locator_fields(registry).items()
            if field not in _PATH_ARG_KEYS and field not in _UNINSPECTED_LOCATOR_ARGS
        }
        assert unclassified == {}, (
            f"locator-shaped tool argument(s) no guard inspects: {unclassified}. "
            f"Add the name to _PATH_ARG_KEYS so check_sensitive_paths sees it, "
            f"or to _UNINSPECTED_LOCATOR_ARGS with the reason it does not need "
            f"to. Leaving it unclassified is how archive_name stayed invisible."
        )

    def test_pinned_keys_are_falsifiable_against_actual_reach(self, registry):
        """Law 16c. A key matching no tool field is reach the guard does not have.

        Not a defect on its own -- the anticipatory set is deliberate -- but an
        unrecorded one lets `_PATH_ARG_KEYS` read as broader coverage than it
        delivers, which is the camouflage 16c exists to strip.
        """
        from auro_runtime.guards import _PATH_ARG_KEYS

        live = {
            field
            for _tool, (_fn, _doc, schema) in registry.items()
            if schema is not None
            for field in schema.model_fields
        }
        unmatched = set(_PATH_ARG_KEYS) - live - _ANTICIPATORY_PATH_ARG_KEYS
        assert unmatched == set(), (
            f"_PATH_ARG_KEYS names {sorted(unmatched)}, which no registered tool "
            f"produces and which is not recorded as anticipatory. Either a tool "
            f"was removed and the key is now dead, or the key is a typo that has "
            f"been silently inspecting nothing."
        )

    def test_exempt_arguments_still_exist(self, registry):
        """Negative control: exempting arguments nothing declares proves nothing."""
        live = {
            field
            for _tool, (_fn, _doc, schema) in registry.items()
            if schema is not None
            for field in schema.model_fields
        }
        stale = set(_UNINSPECTED_LOCATOR_ARGS) - live
        assert stale == set(), (
            f"{sorted(stale)} is pinned as a deliberately-uninspected locator but "
            f"no registered tool declares it. Remove the exemption rather than "
            f"leaving a reason for a decision nothing depends on."
        )

    def test_the_scan_reports_an_unclassified_locator_argument(self, registry):
        """Negative control for the scan itself.

        With `archive_name` exempt and everything else pinned, the test above
        passes whether or not the scan can see anything at all. This drives the
        real regex over a synthetic schema and asserts the new field is
        reported, so narrowing _LOCATOR_FIELD fails here instead of quietly
        reducing coverage.
        """
        from pydantic import BaseModel

        class _SyntheticArgs(BaseModel):
            output_path: str
            reason: str

        probe = dict(registry)
        probe["_synthetic_tool"] = (lambda: None, "", _SyntheticArgs)

        found = _locator_fields(probe)
        assert found.get("output_path") == "_synthetic_tool", (
            f"the scan did not report a locator-shaped field added to a schema; "
            f"reported {sorted(found)}. The pin cannot catch what it cannot see."
        )
        assert "reason" not in found, (
            "the scan matched a field that is not a locator; _LOCATOR_FIELD is "
            "too broad and will train people to exempt things reflexively."
        )


# ---------------------------------------------------------------------------
# Half two: method. How each classifier obtains the thing it judges.
# ---------------------------------------------------------------------------

# Modules that classify a caller-supplied locator, or hold an inventory used to.
_CLASSIFIER_MODULES = (
    "auro_runtime/guards.py",
    "auro_runtime/egress.py",
    "runtime_tools/file_tools.py",
    "runtime_tools/verify_tools.py",
)

_INVENTORY_NAME = re.compile(
    r"SENSITIVE|BLOCKLIST|BLOCKED|DENIED|RESTRICTED|PROTECTED|_PATTERNS$|_FILES$|_KEYS$",
    re.IGNORECASE,
)

# Every module-level inventory in those modules, classified as LOCATOR (names
# places -- law 10 applies) or CONTENT (matches secret values -- a different
# concern, law 11's territory). The distinction is the point: a scan cannot
# make it, and getting it wrong in the CONTENT direction is how a locator
# inventory would slip in unexamined.
_INVENTORY_KIND = {
    "auro_runtime/guards.py::_SENSITIVE_PATH_PATTERNS": "LOCATOR",
    "auro_runtime/guards.py::_PATH_ARG_KEYS": "LOCATOR",
    "auro_runtime/guards.py::_REDACT_KEYS": "CONTENT",
    "auro_runtime/guards.py::_SECRET_PATTERNS": "CONTENT",
    "auro_runtime/guards.py::_RAW_CREDENTIAL_KEYS": "CONTENT",
    "auro_runtime/egress.py::_EXTRA_DENIED": "LOCATOR",
    "runtime_tools/file_tools.py::_PROTECTED_PATTERNS": "LOCATOR",
    "runtime_tools/file_tools.py::_READ_BLOCKLIST_DIRS": "LOCATOR",
    "runtime_tools/file_tools.py::_READ_BLOCKLIST_FILES": "LOCATOR",
    "runtime_tools/file_tools.py::_READ_BLOCKLIST_PREFIXES": "LOCATOR",
    "runtime_tools/file_tools.py::_READ_BLOCKLIST_SUFFIXES": "LOCATOR",
    "runtime_tools/verify_tools.py::_SENSITIVE_FILES": "LOCATOR",
    "runtime_tools/verify_tools.py::_SANITIZED_ENV_KEYS": "CONTENT",
    "runtime_tools/verify_tools.py::_SECRET_PATTERNS": "CONTENT",
}

# How each module carrying a LOCATOR inventory obtains the subject it judges.
# This records the state as it is, not as it should be.
#
#   shared   -- consumes auro_runtime.guards._canonicalize_path
#   resolved -- judges a resolved subject, so no string normalisation applies
#   inline   -- carries its own normalisation. OPEN. Law 15b's practice calls
#               for one shared canonicaliser both layers consume deliberately;
#               this is the duplication the shared-canonicalisation refactor
#               exists to close, tracked on
#               OT-sensitive-resource-inventory-is-duplicated-across-three-modules.
_LOCATOR_SUBJECT = {
    "auro_runtime/guards.py": "shared",
    "auro_runtime/egress.py": "resolved",
    "runtime_tools/file_tools.py": "inline",
    "runtime_tools/verify_tools.py": "inline",
}

_NORMALISATION_STILL_DUPLICATED = {"runtime_tools/file_tools.py", "runtime_tools/verify_tools.py"}


def _module_inventories(repo_root, module: str) -> set[str]:
    tree = ast.parse((repo_root / module).read_text(encoding="utf-8"))
    names = set()
    for node in tree.body:
        targets = (
            node.targets if isinstance(node, ast.Assign)
            else [node.target] if isinstance(node, ast.AnnAssign)
            else []
        )
        for target in targets:
            if isinstance(target, ast.Name) and _INVENTORY_NAME.search(target.id):
                names.add(target.id)
    return names


class TestLocatorClassifiersAreInventoried:
    """A new classifier cannot appear without someone declaring what it judges."""

    def test_every_security_inventory_is_classified(self, repo_root):
        unclassified = [
            f"{module}::{name}"
            for module in _CLASSIFIER_MODULES
            for name in sorted(_module_inventories(repo_root, module))
            if f"{module}::{name}" not in _INVENTORY_KIND
        ]
        assert unclassified == [], (
            f"unclassified security inventory: {unclassified}. Add it to "
            f"_INVENTORY_KIND as LOCATOR (it names places -- law 10 applies, and "
            f"its module must declare how it obtains its subject) or CONTENT (it "
            f"matches secret values). An inventory nobody classified is how the "
            f"same list ends up in three modules disagreeing with each other."
        )

    def test_classified_inventories_still_exist(self, repo_root):
        """Negative control: pinning names nothing defines proves nothing."""
        defined = {
            f"{module}::{name}"
            for module in _CLASSIFIER_MODULES
            for name in _module_inventories(repo_root, module)
        }
        stale = sorted(set(_INVENTORY_KIND) - defined)
        assert stale == [], (
            f"pinned inventories that no longer exist: {stale}. Remove them, or "
            f"the pin is describing a codebase that is not this one."
        )

    def test_every_locator_module_declares_how_it_obtains_its_subject(self, repo_root):
        locator_modules = {
            key.split("::")[0]
            for key, kind in _INVENTORY_KIND.items()
            if kind == "LOCATOR"
        }
        undeclared = sorted(locator_modules - set(_LOCATOR_SUBJECT))
        assert undeclared == [], (
            f"module(s) holding a locator inventory with no declared subject: "
            f"{undeclared}. State whether it normalises via the shared "
            f"canonicaliser, judges a resolved subject, or carries its own "
            f"normalisation -- law 10 is about which of those it is."
        )

    def test_the_shared_canonicaliser_is_actually_shared_where_claimed(self, repo_root):
        """Every module declaring `shared` must really CALL it.

        Deliberately an AST walk for call sites rather than a substring search.
        A substring search passes on the function's own `def` line, so removing
        every call in guards.py left this green -- caught by mutation 2026-08-17,
        and precisely the "declaration is not a mechanism" failure this test
        exists to prevent, committed inside the test meant to prevent it.
        """
        for module, subject in _LOCATOR_SUBJECT.items():
            if subject != "shared":
                continue
            tree = ast.parse((repo_root / module).read_text(encoding="utf-8"))
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            assert "_canonicalize_path" in calls, (
                f"{module} is declared as using the shared canonicaliser but "
                f"contains no call to it. A declaration is not a mechanism."
            )

    def test_the_duplication_is_recorded_and_has_not_grown(self, repo_root):
        """The honest half. This pin does not pretend the refactor happened.

        `_canonicalize_path` has exactly one consumer today; file_tools.py
        carries its own copy of the trailing-dot-and-space normalisation, and
        verify_tools.py compares exact names with none. That is law 15b's
        "two layers sharing an assumption" still open, and it is tracked on
        OT-sensitive-resource-inventory-is-duplicated-across-three-modules.

        What this asserts is that the set has not GROWN. A third module
        growing its own normalisation fails here. Doing the refactor also
        fails here -- deliberately -- because shrinking the set should require
        someone to come back and retire this pin rather than leave it
        describing a problem that no longer exists (law 16b).
        """
        actual = {m for m, subject in _LOCATOR_SUBJECT.items() if subject == "inline"}
        assert actual == _NORMALISATION_STILL_DUPLICATED, (
            f"the set of modules carrying their own locator normalisation "
            f"changed: expected {sorted(_NORMALISATION_STILL_DUPLICATED)}, found "
            f"{sorted(actual)}. If it grew, a new layer is repeating an "
            f"assumption instead of consuming the shared canonicaliser. If it "
            f"shrank, the refactor landed -- update this pin and the card."
        )

    def test_the_scan_reports_a_new_inventory(self, repo_root):
        """Negative control for the scan.

        With every inventory pinned, the classification test passes whether or
        not the AST walk sees anything. This drives the real walk over a
        mutated copy of a real module and asserts the synthetic inventory is
        reported.
        """
        module = "auro_runtime/guards.py"
        mutated = (repo_root / module).read_text(encoding="utf-8") + (
            '\n_SYNTHETIC_SENSITIVE_PATHS = frozenset({".ssh"})\n'
        )
        tree = ast.parse(mutated)
        names = {
            target.id
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and _INVENTORY_NAME.search(target.id)
        }
        unclassified = {
            name for name in names if f"{module}::{name}" not in _INVENTORY_KIND
        }
        assert unclassified == {"_SYNTHETIC_SENSITIVE_PATHS"}, (
            f"the walk did not report an inventory added to {module}; reported "
            f"{unclassified or 'nothing'}. The pin cannot catch what it cannot see."
        )
