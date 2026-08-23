"""Messages a shipped document quotes are published claims, and must be pinned.

A refusal message printed in `README.md` or `docs/API.md` is a contract: a reader
checks it, and an integrator may match on it. Nothing previously connected the
two, so a message could be reworded in the source and the document would go
false with the suite still green.

The set of messages is derived from the source at check time rather than listed
here. A list would be a second copy of what the modules already say, correct when
written and silently wrong afterwards — the failure this pin exists to prevent,
one level up.

**What this does not reach.** The unit is the *fragment a document cites*, not
the whole message. A message whose cited fragment is pinned still has the rest
of its text unheld, and rewording only that remainder passes here. Two mutations
in the campaign that proved this file survived on the first attempt for exactly
that reason: they were aimed at an assertion the pin never reads. The pin answers
"is this documented sentence connected to any test", not "is every word of this
message asserted somewhere" — and the second question is the claims registry that
this project does not yet have.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SHIPPED_DOCS = ("README.md", "docs/API.md")
_MESSAGE_PACKAGES = ("auro_runtime", "runtime_tools")

# Anchors that survive extraction but are not published message claims. Each
# needs a reason, and the reason is what a later reader checks rather than the
# entry itself.
_NOT_A_MESSAGE = {
    "current working directory": (
        "a `source=` keyword argument in paths.py naming where a root was "
        "resolved from, not text any caller is shown; the identical phrase in "
        "docs/API.md is ordinary prose about resolution order"
    ),
}


def _emitted_templates() -> dict[str, set[str]]:
    """Message templates the packages return or raise, keyed to their module.

    Walked from the source rather than enumerated, so a module added to either
    package is covered without this file being edited.
    """
    found: dict[str, set[str]] = {}
    for package in _MESSAGE_PACKAGES:
        for path in sorted((_REPO_ROOT / package).rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Return, ast.Raise)):
                    continue
                for sub in ast.walk(node):
                    if isinstance(sub, ast.JoinedStr):
                        literal = "".join(
                            part.value
                            for part in sub.values
                            if isinstance(part, ast.Constant)
                            and isinstance(part.value, str)
                        )
                    elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        literal = sub.value
                    else:
                        continue
                    literal = literal.strip()
                    if len(literal) < 15 or literal.count(" ") < 2:
                        continue
                    if "\n" in literal:
                        continue
                    rel = path.relative_to(_REPO_ROOT).as_posix()
                    found.setdefault(literal, set()).add(rel)
    return found


def _fragments(template: str) -> list[str]:
    """The quotable pieces of a message.

    Split first on interpolation, since no document can quote across a `{}`, and
    then on sentence boundaries, since a two-sentence message is routinely cited
    by one of its sentences. Taking only the longest run instead would span the
    full stop and match neither the document nor the test — the message
    `Policy guard error [id]: guard 'x' raised an exception. Failing closed.`
    is cited by either half and by neither whole.
    """
    pieces: list[str] = []
    for run in re.split(r"\{[^}]*\}", template):
        for sentence in run.split(". "):
            cleaned = sentence.strip(" :'\".,[]()")
            if len(cleaned) >= 20:
                pieces.append(cleaned)
    return pieces


def _read(*relative: str) -> str:
    return "\n".join(
        (_REPO_ROOT / name).read_text(encoding="utf-8", errors="ignore")
        for name in relative
    )


def _tracked_test_sources() -> str:
    """Every tracked test except this file.

    Excluding self is load-bearing: the exemption reasons above quote the very
    anchors they exempt, so a pin that read itself would report coverage for
    anything it names.
    """
    return "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in sorted((_REPO_ROOT / "tests").glob("test_*.py"))
        if path.name != pathlib.Path(__file__).name
    )


def _documented_messages() -> list[tuple[str, str, str]]:
    """(cited fragment, template, module) for each emitted message a doc quotes.

    A message counts as documented when any one of its quotable fragments
    appears in a shipped document, and the fragment carried forward is the one
    the document actually used — so the pin asks the tests for the same text a
    reader would check.
    """
    docs = _read(*_SHIPPED_DOCS)
    out = []
    for template, modules in sorted(_emitted_templates().items()):
        for fragment in _fragments(template):
            if fragment in _NOT_A_MESSAGE:
                continue
            if fragment in docs:
                out.append((fragment, template, sorted(modules)[0]))
                break
    return out


def test_the_extraction_finds_messages_at_all():
    """Negative control for every case below.

    If the AST walk silently stopped matching — a package renamed, a node type
    changed — `_documented_messages()` would return an empty list and each
    parametrized case would vanish rather than fail. An empty sweep is the
    vacuous pass this whole file exists to prevent.
    """
    emitted = _emitted_templates()
    assert len(emitted) > 50, (
        f"only {len(emitted)} message templates extracted from "
        f"{_MESSAGE_PACKAGES}; the walk is not reaching the source"
    )
    assert _documented_messages(), (
        "no emitted message matched any shipped document, which cannot be true "
        "while README.md quotes refusal text"
    )


@pytest.mark.parametrize(
    "anchor, module",
    [(a, m) for a, _t, m in _documented_messages()],
    ids=[m.rsplit("/", 1)[-1] + ":" + a[:28] for a, _t, m in _documented_messages()],
)
def test_a_message_quoted_in_shipped_docs_is_pinned_by_a_test(anchor, module):
    """A documented message with no test is a claim rather than a control.

    Reword it in the source and the document goes false with the suite green.
    """
    assert anchor in _tracked_test_sources(), (
        f"{module} emits a message quoted in the shipped documentation, and no "
        f"tracked test asserts it: {anchor!r}. Either pin it, or stop quoting "
        f"it in README.md / docs/API.md."
    )


def test_every_exemption_still_describes_something_the_source_emits():
    """An exemption outlives its subject unless something checks.

    If the phrase an entry exempts stops being emitted, the entry is stale and
    is quietly widening what this pin ignores.
    """
    emitted = {f for t in _emitted_templates() for f in _fragments(t)}
    stale = sorted(set(_NOT_A_MESSAGE) - emitted)
    assert not stale, (
        f"exempted anchors no longer emitted by the source: {stale}. Remove the "
        f"entry rather than leaving the pin ignoring a phrase that is gone."
    )
