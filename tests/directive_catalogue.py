"""
Generate docs/DIRECTIVES.md from the shipped directives.

    python -m tests.directive_catalogue           # regenerate
    python -m tests.directive_catalogue --check   # exit 1 if the committed doc is stale

Why this exists: the README used to state a directive count with nothing behind
it. A count is not a catalogue — it reads as verified while nothing checks it,
and adding or removing a directive broke the claim silently. The test suite had
the same defect and it was closed the same way (see tests/catalogue.py).

Two deliberate properties:

* **Parsed by the runtime's own loader.** `load_directive` is what the executor
  uses, so the declared tool scope printed here is the scope actually enforced.
  A second, independent parser could drift from enforcement and publish a
  reassuring lie; this cannot.
* **Refuses rather than guesses.** A directive whose front matter does not parse,
  or whose filename does not match its declared `id`, halts generation. Silence
  is not an acceptable outcome for a file that grants tool authority.

Lives in tests/ rather than the package because it is development tooling:
`tests/` is pruned from both the wheel and the sdist, while the generated
`docs/DIRECTIVES.md` ships.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIRECTIVES_DIR = REPO_ROOT / "auro_runtime" / "resources" / "directives"
OUTPUT = REPO_ROOT / "docs" / "DIRECTIVES.md"

# Rendering order. Categories are a closed set in schemas.DirectiveCategory; an
# unrecognised one halts generation rather than being dropped from the output.
CATEGORY_ORDER = ("system", "security", "task", "debug")

CATEGORY_BLURB = {
    "system": "Setup, orientation, and authoring.",
    "security": "Credential handling and policy review.",
    "task": "General workflows.",
    "debug": "Diagnostics and investigation.",
}


class UnparsableDirective(SystemExit):
    def __init__(self, problems: list[str]) -> None:
        listed = "\n".join(f"  - {p}" for p in problems)
        super().__init__(
            f"{len(problems)} directive file(s) cannot be catalogued:\n{listed}\n\n"
            f"A directive grants tool authority. It must not ship undescribed or "
            f"unparsed. Fix the front matter, or remove the file."
        )


def collect() -> list:
    """[(id, category, description, tools)] for every shipped directive, id-sorted."""
    from auro_runtime.directive import load_directive

    found = []
    problems = []

    for path in sorted(DIRECTIVES_DIR.glob("*.md")):
        meta, _body = load_directive(path)
        if meta is None:
            problems.append(f"{path.name}: no parsable YAML front matter")
            continue
        if meta.id != path.stem:
            problems.append(
                f"{path.name}: declares id '{meta.id}', which does not match the filename"
            )
            continue
        if not meta.description.strip():
            problems.append(f"{path.name}: no description in front matter")
            continue
        if meta.category not in CATEGORY_ORDER:
            problems.append(
                f"{path.name}: category '{meta.category}' is not one of {list(CATEGORY_ORDER)}"
            )
            continue
        found.append((meta.id, meta.category, meta.description.strip(), list(meta.tools)))

    if problems:
        raise UnparsableDirective(problems)
    return found


def render(found: list) -> str:
    total = len(found)
    present = [c for c in CATEGORY_ORDER if any(f[1] == c for f in found)]

    out = [
        "# Directive catalogue",
        "",
        f"**{total} directives** ship with the runtime.",
        "",
        "Generated from `directives/` by `python -m tests.directive_catalogue`. Do not",
        "edit by hand.",
        "",
        "The `tools` column is the directive's entire authority. The runtime checks every",
        "proposed call against it before dispatch, so a tool absent from that list is",
        "refused whether the model was told about the boundary or not. This catalogue is",
        "generated with the same loader the executor uses, so what you see here is what",
        "is enforced.",
        "",
        "## Summary",
        "",
        "| Directive | Category | Tools granted |",
        "|---|---|---:|",
    ]
    for did, cat, _desc, tools in found:
        out.append(f"| [`{did}`](#{did.replace('_', '-')}) | {cat} | {len(tools)} |")
    out.append("")

    for cat in present:
        out.append("---")
        out.append("")
        out.append(f"## {cat}")
        out.append("")
        blurb = CATEGORY_BLURB.get(cat)
        if blurb:
            out.append(blurb)
            out.append("")
        for did, c, desc, tools in found:
            if c != cat:
                continue
            out.append(f"### {did}")
            out.append("")
            out.append(desc)
            out.append("")
            if tools:
                out.append("Authorized tools: " + ", ".join(f"`{t}`" for t in sorted(tools)))
            else:
                out.append(
                    "Authorized tools: **none declared.** An empty scope grants nothing; "
                    "the directive cannot call any tool."
                )
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
            print(f"STALE: {OUTPUT.relative_to(REPO_ROOT)} does not match directives/.")
            print("Regenerate with: python -m tests.directive_catalogue")
            return 1
        print(f"current: {OUTPUT.relative_to(REPO_ROOT)}")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} — {len(found)} directives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
