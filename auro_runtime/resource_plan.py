r"""
Tools submit what they are about to touch, resolved, before they touch it.

The policy guard runs in the executor, before the tool, and can only see the
string the model sent. That is not always the resource the tool acts on:

  * `read_file("directives/x.md")` opens `auro_runtime/resources/directives/x.md`,
    because `directives/` and `policies/` are reserved virtual mounts;
  * `restore_file(archive_name=...)` with no `restore_to` takes its destination
    from the archive manifest, so **no caller argument contributes to the target
    at all** and there is nothing for an argument-inspecting guard to look at;
  * on Windows an 8.3 alias such as `SSH~1/config` names `.ssh/config`, and no
    string normalisation can discover that -- only the filesystem can.

So the tool resolves once, submits the resolved source and destination set, and
acts on the same objects it submitted. This mirrors `auro_runtime.egress`, which
validates inside the connection routine and dials the address it just vetted,
for the same reason: validation and action must agree on what the input means,
and the only reliable way to make them agree is to validate where the action
happens.

Why this layer is not policy-configurable
-----------------------------------------
`check_sensitive_paths` honours `enforcement: block|warn` because it is the
policy tier and an operator tuning policy is tuning it. This layer does not.

It is the tool's own floor, and it has always been one: `_is_read_blocked` has
refused `.env` regardless of policy since long before this module existed. If
`warn` could downgrade it, then setting `warn` -- which reads like "log it and
carry on" -- would silently remove the *only* layer that sees resolved paths,
which is the layer that catches every case in the list above. A configuration
knob whose real effect is to disable the stronger of two checks is a trap, so
the knob is not offered. Defense in depth is not per-layer configurable; you do
not disable the deadbolt from the doorknob's settings.

What the policy context is for, then, is attribution: which directive was
running when this refusal happened. That belongs in the audit record and cannot
be recovered from inside a tool function any other way.
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from auro_runtime.audit import write_audit_event
from auro_runtime.sanitization import sanitize_fields_with_report
from auro_runtime.sensitive_paths import UNCONTAINED, classify_resolved

SOURCE = "source"
DESTINATION = "destination"

ARGUMENT = "argument"
MANIFEST = "manifest"


@dataclass(frozen=True)
class ResourceSubject:
    """One resolved thing a tool is about to read, write, delete or restore."""

    resolved: Path
    base: Path
    role: str = SOURCE
    origin: str = ARGUMENT


@dataclass(frozen=True)
class ResourcePlan:
    """Everything one tool call will touch, after resolution and containment."""

    tool: str
    subjects: tuple[ResourceSubject, ...]


@dataclass(frozen=True)
class _PolicyContext:
    directive_id: str | None


_POLICY_CONTEXT: contextvars.ContextVar[_PolicyContext | None] = contextvars.ContextVar(
    "auro_resource_policy_context", default=None
)


@contextmanager
def policy_context(directive_id: str | None):
    """Set by the executor around a tool invocation, for audit attribution only.

    Absence is normal rather than exceptional -- tools are called directly by
    tests and by embedders -- and absence never changes the verdict. If it did,
    the check would be weaker exactly where it is least supervised.
    """
    token = _POLICY_CONTEXT.set(_PolicyContext(directive_id=directive_id))
    try:
        yield
    finally:
        _POLICY_CONTEXT.reset(token)


def _relative(subject: ResourceSubject) -> str:
    """Workspace-relative posix form for the audit record.

    Never the absolute path: it carries the operator's directory layout off the
    machine, which `file_restored` was corrected for on 2026-08-08.
    """
    try:
        return subject.resolved.resolve().relative_to(subject.base).as_posix()
    except ValueError:
        return subject.resolved.name


def check_resource_plan(plan: ResourcePlan) -> str | None:
    """Classify every subject. Return an error string to refuse, or None to allow.

    Emits one audit event per plan, on approval as well as refusal. The approval
    record is the point: without it "the guard approved" and "the guard never
    ran" look identical in the log, and an operator asking whether a control was
    active during an incident gets silence either way. One event per plan rather
    than per subject keeps a recursive `list_dir` from flooding the trail.
    """
    ctx = _POLICY_CONTEXT.get()
    directive_id = ctx.directive_id if ctx is not None else None

    refused: ResourceSubject | None = None
    match = None
    for subject in plan.subjects:
        found = classify_resolved(subject.resolved, subject.base)
        if found is not None:
            refused, match = subject, found
            break

    write_audit_event(
        "resource_classification",
        **sanitize_fields_with_report(
            tool=plan.tool,
            directive_id=directive_id,
            outcome="refused" if match is not None else "approved",
            category=match.category if match is not None else None,
            role=refused.role if refused is not None else None,
            origin=refused.origin if refused is not None else None,
            subjects=[
                {
                    "path": _relative(s),
                    "role": s.role,
                    "origin": s.origin,
                }
                for s in plan.subjects
            ],
        ),
    )

    if match is None:
        return None

    if match.category == UNCONTAINED:
        return "Path is outside the allowed project directory."

    # The category is deliberately not in the message. It tells the caller which
    # class of secret it just probed for, which is a free oracle; the audit
    # record carries it for the operator instead.
    return f"Access to '{refused.resolved.name}' is blocked (sensitive file)."
