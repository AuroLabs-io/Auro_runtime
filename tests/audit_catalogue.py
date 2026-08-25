"""
Generate docs/AUDIT_EVENTS.md from the write_audit_event call sites.

    python -m tests.audit_catalogue           # regenerate
    python -m tests.audit_catalogue --check   # exit 1 if the committed doc is stale

Why this exists: docs/API.md tells an integrator that `event` is "the grouping
key" and then never says what the keys are. So the documented contract was
"group by a vocabulary we will not give you", and anyone who inferred a name
from the tool that emits it could be wrong without a way to find out. That
happened on 2026-08-08, when `file_deleted` was renamed to `file_soft_deleted`
because the old name claimed a destruction that had not occurred.

Two deliberate properties, matching tests/directive_catalogue.py:

* **Read from the emitting source, not from a hand-kept list.** The names here
  are the string literals the runtime actually passes to `write_audit_event`.
  A separate list maintained by hand is exactly the thing that drifted.
* **Refuses rather than guesses.** An event name that is not a literal string,
  or that is not passed positionally at all, cannot be catalogued and halts
  generation. So does a module that emits events and has no MODULE_BLURB entry,
  because the alternative is publishing a document that is missing a whole
  section and says nothing about the omission. An audit event nobody can name is
  an audit event nobody can alert on.

Field lists are best-effort by design and say so in the output: a call that
splats an unresolvable mapping is reported as having undocumented fields rather
than being silently printed as though the list were complete.

Lives in tests/ rather than the package because it is development tooling:
`tests/` is pruned from both the wheel and the sdist, while the generated
`docs/AUDIT_EVENTS.md` ships.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "docs" / "AUDIT_EVENTS.md"

# Packages that ship. build/ is a stale artifact of a previous packaging run and
# must not be scanned: it would resurrect names the source no longer emits.
SOURCE_DIRS = ("auro_runtime", "runtime_tools")

EMITTER = "write_audit_event"

# The envelope is documented in docs/API.md and is present on every record, so
# it is not repeated per event here.
ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "run_id",
        "sequence",
        "step_index",
        "timestamp",
        "event",
        "redacted_fields",
    }
)

# The one part of this generator kept by hand rather than read from source, and
# so the one part that can fall behind it. render() refuses to publish a module
# that is missing from here rather than dropping its section, which makes that
# drift loud instead of invisible. The reverse is harmless and stays: policy.py
# emits nothing today, and an unused line costs less than rediscovering it.
MODULE_BLURB = {
    "auro_runtime/executor.py": "Refusals and failures from the tool-call pipeline.",
    "auro_runtime/orchestrator.py": "Model-loop and directive-resolution failures.",
    "auro_runtime/mcp_server.py": "Server-side exposure refusals.",
    "auro_runtime/policy.py": "Policy-loading outcomes.",
    "auro_runtime/resource_plan.py": "Resolved-path classification, before the tool acts.",
    "runtime_tools/file_tools.py": "Changes the runtime made to files on disk.",
}


class UncatalogableEvent(SystemExit):
    def __init__(self, problems: list[str]) -> None:
        listed = "\n".join(f"  - {p}" for p in problems)
        super().__init__(
            f"{len(problems)} audit event(s) cannot be catalogued:\n{listed}\n\n"
            f"An event name must be a literal string, passed as the first positional "
            f"argument. A name assembled at runtime, or reachable only through a "
            f"keyword or a ** splat, cannot be documented, grouped on, or alerted on. "
            f"Pass a literal, positionally."
        )


class UndescribedModule(SystemExit):
    """A module emits events and MODULE_BLURB has nothing to say about it."""

    def __init__(self, modules: list[str]) -> None:
        listed = "\n".join(f"  - {m}" for m in modules)
        super().__init__(
            f"{len(modules)} module(s) emit audit events with no MODULE_BLURB entry:\n"
            f"{listed}\n\n"
            f"Add one line per module to MODULE_BLURB in tests/audit_catalogue.py "
            f"saying what its events are about. Without an entry the module's whole "
            f"section is absent from the catalogue while its events still appear in "
            f"the table above, so the document reads as complete and is not."
        )


def _splatted_names(node: ast.AST) -> tuple[list[str], bool]:
    """(field names, resolvable) for the value of a ** keyword.

    Three shapes occur in the source and all three are resolvable:
    **sanitize_fields_with_report(a=1), **{"a": x}, and the conditional
    **({"a": x} if cond else {}) used for fields that appear only sometimes.
    A conditionally present field is still a field, so both branches count.
    """
    if isinstance(node, ast.Call):
        names = [kw.arg for kw in node.keywords if kw.arg is not None]
        nested = [kw.value for kw in node.keywords if kw.arg is None]
        resolvable = True
        for inner in nested:
            more, ok = _splatted_names(inner)
            names.extend(more)
            resolvable = resolvable and ok
        return names, resolvable

    if isinstance(node, ast.Dict):
        names = [
            key.value
            for key in node.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        return names, len(names) == len(node.keys)

    if isinstance(node, ast.IfExp):
        left, ok_left = _splatted_names(node.body)
        right, ok_right = _splatted_names(node.orelse)
        return left + right, ok_left and ok_right

    return [], False


def _field_names(call: ast.Call) -> tuple[list[str], bool]:
    """(event-specific field names, fields_are_complete) for one emitter call."""
    fields: list[str] = []
    complete = True

    for keyword in call.keywords:
        if keyword.arg is not None:
            fields.append(keyword.arg)
            continue
        names, resolvable = _splatted_names(keyword.value)
        fields.extend(names)
        complete = complete and resolvable

    ordered = [f for f in dict.fromkeys(fields) if f not in ENVELOPE_FIELDS]
    return ordered, complete


def collect() -> list:
    """[(event, module, fields, complete)] for every emitted event, sorted."""
    found: list[tuple[str, str, list[str], bool]] = []
    problems: list[str] = []

    paths: list[Path] = []
    for package in SOURCE_DIRS:
        paths.extend(sorted((REPO_ROOT / package).rglob("*.py")))

    for path in paths:
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name != EMITTER:
                continue
            # No positional at all: the name is in `event=` or inside a ** splat.
            # That is an emitter call this generator cannot read, not a call that
            # isn't one, and the two must not share an exit. Skipping it would
            # drop the event from the catalogue with nothing said about it, which
            # is the exact failure this generator exists to prevent.
            if not node.args:
                problems.append(
                    f"{rel}:{node.lineno}: event name is not a positional argument"
                )
                continue
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                problems.append(f"{rel}:{node.lineno}: event name is not a literal string")
                continue
            fields, complete = _field_names(node)
            found.append((first.value, rel, fields, complete))

    if problems:
        raise UncatalogableEvent(problems)

    # One name can be emitted from several sites; merge their fields.
    merged: dict[str, tuple[set[str], list[str], bool]] = {}
    for event, rel, fields, complete in found:
        names, modules, ok = merged.get(event, (set(), [], True))
        names.update(fields)
        if rel not in modules:
            modules.append(rel)
        merged[event] = (names, modules, ok and complete)

    return sorted(
        (event, modules, sorted(names), complete)
        for event, (names, modules, complete) in merged.items()
    )


def render(found: list) -> str:
    by_module: dict[str, list] = {}
    for event, modules, fields, complete in found:
        by_module.setdefault(modules[0], []).append((event, modules, fields, complete))

    out = [
        "# Audit event catalogue",
        "",
        f"**{len(found)} event names** are emitted by the runtime.",
        "",
        "Generated from the `write_audit_event` call sites by",
        "`python -m tests.audit_catalogue`. Do not edit by hand.",
        "",
        "`event` is the grouping key in every audit record. These are its values.",
        "Each record also carries the eight-field envelope described in",
        "[`docs/API.md`](API.md); the fields listed here are the event-specific ones",
        "that sit beside it.",
        "",
        "Two things this list does not cover. Records passed to `write_audit_records`",
        "by an embedding application carry whatever `event` that caller chose. And an",
        "event appears here because the runtime can emit it, not because it will:",
        "a guard that approves returns `None` and writes nothing.",
        "",
        "| Event | Emitted from | Event-specific fields |",
        "|---|---|---|",
    ]
    for event, modules, fields, complete in found:
        where = "<br>".join(f"`{m}`" for m in modules)
        if fields:
            shown = ", ".join(f"`{f}`" for f in fields)
        else:
            shown = "none"
        if not complete:
            shown += " _(and others not resolvable from source)_"
        out.append(f"| `{event}` | {where} | {shown} |")
    out.append("")

    # by_module is keyed on the module a section is written under, so these are
    # exactly the modules whose sections would go missing. A module that emits
    # only events first seen elsewhere heads no section and so needs no blurb.
    # A blank entry counts as missing: it would render an empty paragraph under
    # a heading, which describes the module no better than omitting it did.
    undescribed = [m for m in sorted(by_module) if not MODULE_BLURB.get(m, "").strip()]
    if undescribed:
        raise UndescribedModule(undescribed)

    for module in sorted(by_module):
        out.append("---")
        out.append("")
        out.append(f"## `{module}`")
        out.append("")
        out.append(MODULE_BLURB[module])
        out.append("")
        for event, _modules, _fields, _complete in sorted(by_module[module]):
            out.append(f"- `{event}`")
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
            print(f"STALE: {OUTPUT.relative_to(REPO_ROOT)} does not match the source.")
            print("Regenerate with: python -m tests.audit_catalogue")
            return 1
        print(f"current: {OUTPUT.relative_to(REPO_ROOT)}")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} — {len(found)} event names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
