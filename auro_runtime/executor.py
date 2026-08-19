"""
Tool registry and deterministic execution. Only pre-registered functions are invoked.
Per-tool argument schemas validate args before invocation so side-effectful tools
are never called with malformed arguments.
"""

import logging
from collections.abc import Callable
from typing import Any, Type

from pydantic import BaseModel, ValidationError

from auro_runtime.audit import write_audit_event
from auro_runtime.sanitization import (
    sanitize_fields_with_report,
    sanitize_value,
    scrub_text,
)
from auro_runtime.resource_plan import policy_context
from auro_runtime.schemas import PERMISSIVE_ENFORCEMENT, ToolCallOutput, ToolCallResult

logger = logging.getLogger("auro_runtime.executor")


# Registry: tool_name -> (callable, docstring, optional args schema)
_REGISTRY: dict[str, tuple[Callable[..., Any], str, type[BaseModel] | None]] = {}


def register(name: str, doc: str = "", args_schema: type[BaseModel] | None = None):
    """Decorator to register a function as a callable tool. args_schema validates args before invocation."""

    def decorator(fn: Callable[..., Any]):
        _REGISTRY[name] = (fn, doc or (fn.__doc__ or ""), args_schema)
        return fn

    return decorator


def get_registry() -> dict[str, tuple[Callable[..., Any], str, type[BaseModel] | None]]:
    """Return a copy of the tool registry (read-only)."""
    return dict(_REGISTRY)


def _redacted_args(args: Any) -> Any:
    """
    Redact secret-shaped values before args reach the audit log.

    Needed on the failure paths that fire BEFORE the secret guard runs — schema
    validation failure in particular — where raw model-supplied args would
    otherwise be recorded verbatim. Imported lazily to keep executor's import
    graph free of guards at module load.
    """
    return sanitize_value(args)


def _safe_text(value: object) -> str:
    """Render caller-visible or logged text without secret-shaped substrings."""
    return scrub_text(str(value))


def _tool_reported_error(result: object) -> str | None:
    """
    The tool's own failure message, or None if it did not report one.

    Tools in this package signal a domain failure by returning a dict with a
    top-level `error` alongside a falsy status flag (`written: False`,
    `sent: False`, `resolved: False`, `content: None`) rather than by raising.
    The executor previously only inspected exceptions, so those returns became
    `success=True, error=None` and the refusal survived solely inside `result`.

    The `error` key is the failure signal, never a data field: that holds for
    all 45 error-returns across the four tool modules that have any, and a tool
    wanting to report an error as *content* must nest it rather than put it at
    the top level. Falsy values (`None`, `""`) are not failures, so a tool may
    return `error: None` on its success path without being marked failed.

    Pass the already-sanitized result: the message is surfaced to the caller,
    so it must not be lifted out of the raw value.
    """
    if isinstance(result, dict):
        err = result.get("error")
        if err:
            return _safe_text(err)
    return None


# Verdict codes whose arguments get a targeted redaction pass before the audit
# record is written. A guard emitting one of these MUST supply
# metadata["matched_fields"]: the name-based pass alone does not know a bespoke
# credential sitting under an innocuous key, so a guard that finds one and does
# not say where logs it in the clear. Pinned by a test over every guard that can
# emit one, so a third code cannot join this set silently.
REDACTING_VERDICT_CODES = ("secret_detected", "raw_credential")


class _Unrestricted:
    """
    Explicit opt-out of one of the executor's security boundaries.

    Never a default. A caller that genuinely wants no capability boundary or no
    guard evaluation has to name it, so the permissive path is visible at the
    call site and in review rather than reachable by leaving an argument out.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNRESTRICTED"


UNRESTRICTED = _Unrestricted()


def _incomplete_context(
    allowed_tools: object,
    policy_rules: object,
    run_history: object,
) -> list[str]:
    """
    Name the security inputs a direct caller failed to supply.

    execute() is public, so a partially supplied context must not read as
    permission to proceed. Note the deliberate asymmetry between the two
    collections: an empty `allowed_tools` is a real answer, because a directive
    declaring no tools may call none (see allowed_tools_for). An empty
    `policy_rules` is not, because zero rules means zero guards run, which is
    indistinguishable from omitting the argument. An unguarded run has to say
    UNRESTRICTED out loud.
    """
    missing = []
    if allowed_tools is None:
        missing.append("allowed_tools")
    if policy_rules is None or (
        not isinstance(policy_rules, _Unrestricted) and len(policy_rules) == 0
    ):
        missing.append("policy_rules")
    if run_history is None:
        missing.append("run_history")
    return missing


def execute(
    tool_call: ToolCallOutput,
    allowed_tools: set[str] | _Unrestricted | None = None,
    directive_id: str | None = None,
    policy_rules: list | _Unrestricted | None = None,
    run_history: list[dict] | None = None,
) -> ToolCallResult:
    """
    Execute a single tool call. Validates tool name, allowed_tools, args schema,
    and policy guards before invocation. Returns ToolCallResult.

    The three security inputs are required. Omitting one refuses the call rather
    than skipping that boundary. Pass UNRESTRICTED to opt out on purpose, or
    `set()` / `[]` where empty is the real answer.
    """
    missing = _incomplete_context(allowed_tools, policy_rules, run_history)
    if missing:
        error = (
            f"Incomplete execution context: {', '.join(missing)} not supplied. "
            f"execute() refuses rather than skipping a security boundary. Supply "
            f"the value, or executor.UNRESTRICTED to proceed without it on purpose."
        )
        write_audit_event(
            "incomplete_execution_context",
            **sanitize_fields_with_report(
                tool=tool_call.tool,
                directive_id=directive_id,
                error=error,
                missing=missing,
            ),
        )
        return ToolCallResult(success=False, result=None, error=error)

    safe_tool = _safe_text(tool_call.tool)
    safe_reason = _safe_text(tool_call.reason) if tool_call.reason else None
    if tool_call.tool not in _REGISTRY:
        safe_registered = sanitize_value(list(_REGISTRY.keys()))
        logger.warning(
            "unknown_tool: tool=%s registered=%s",
            safe_tool,
            safe_registered,
            extra={"tool": safe_tool, "registered": safe_registered},
        )
        write_audit_event(
            "unknown_tool",
            **sanitize_fields_with_report(
                tool=tool_call.tool,
                directive_id=directive_id,
                error=f"Unknown tool: {tool_call.tool}",
                reason=tool_call.reason or None,
                registered=list(_REGISTRY.keys()),
            ),
        )
        return ToolCallResult(
            success=False,
            result=None,
            error=f"Unknown tool: {safe_tool}. Registered: {safe_registered}",
        )
    if not isinstance(allowed_tools, _Unrestricted) and tool_call.tool not in allowed_tools:
        safe_allowed = sanitize_value(sorted(allowed_tools))
        logger.warning(
            "tool_not_allowed: tool=%s allowed=%s",
            safe_tool,
            safe_allowed,
            extra={"tool": safe_tool, "allowed_tools": safe_allowed},
        )
        write_audit_event(
            "tool_not_allowed",
            **sanitize_fields_with_report(
                tool=tool_call.tool,
                directive_id=directive_id,
                error="Tool not allowed",
                reason=tool_call.reason or None,
                allowed_tools=sorted(allowed_tools),
            ),
        )
        return ToolCallResult(
            success=False,
            result=None,
            error=f"Tool '{safe_tool}' is not allowed by the current directive. Allowed: {safe_allowed}",
        )

    fn, _, args_schema = _REGISTRY[tool_call.tool]

    if args_schema is not None:
        try:
            validated = args_schema.model_validate(tool_call.args)
            args_to_use = validated.model_dump()
        except ValidationError as e:
            errs = e.errors()
            msg = errs[0].get("msg", str(e)) if errs else str(e)
            loc = errs[0].get("loc", ())
            if loc:
                msg = f"{loc[0]}: {msg}"
            logger.warning(
                "argument_validation_failed: tool=%s error=%s",
                safe_tool,
                _safe_text(msg),
                extra={
                    "tool": safe_tool,
                    # NOT "args": logging.LogRecord reserves that attribute and
                    # makeRecord() raises KeyError if an extra dict tries to shadow it.
                    "tool_args": _redacted_args(tool_call.args),
                    "validation_error": _safe_text(msg),
                    "reason": safe_reason,
                },
            )
            write_audit_event(
                "argument_validation_failed",
                **sanitize_fields_with_report(
                    tool=tool_call.tool,
                    directive_id=directive_id,
                    error=msg,
                    reason=tool_call.reason or None,
                    validation_error=msg,
                    args=tool_call.args,
                ),
            )
            return ToolCallResult(
                success=False,
                result=None,
                error=f"Invalid arguments for {safe_tool} — {_safe_text(msg)}",
            )
    else:
        args_to_use = tool_call.args if isinstance(tool_call.args, dict) else {}

    # --- Policy guard checks ---
    if not isinstance(policy_rules, _Unrestricted):
        from auro_runtime.guards import GuardContext, get_guard_registry, redact_for_audit

        guard_registry = get_guard_registry()
        ctx = GuardContext(
            tool_name=tool_call.tool,
            raw_args=tool_call.args if isinstance(tool_call.args, dict) else {},
            args=args_to_use,
            reason=tool_call.reason or "",
            directive_id=directive_id,
            run_history=run_history or [],
        )

        for rule in policy_rules:
            if rule.tools is not None and tool_call.tool not in rule.tools:
                continue
            if rule.directives is not None and directive_id not in (rule.directives or []):
                continue

            guard_fn = guard_registry.get(rule.guard)
            if guard_fn is None:
                # A rule was written to enforce something and names a guard that
                # does not exist. Skipping silently makes it indistinguishable
                # from a guard that approved. Treat it as the guard failing:
                # honour on_error, and record it either way.
                write_audit_event(
                    "policy_guard_missing",
                    **sanitize_fields_with_report(
                        tool=tool_call.tool,
                        directive_id=directive_id,
                        rule_id=rule.id,
                        guard=rule.guard,
                        error=f"Guard '{rule.guard}' is not registered.",
                        on_error=rule.on_error,
                    ),
                )
                if rule.on_error != "fail_open":
                    return ToolCallResult(
                        success=False,
                        result=None,
                        error=(
                            f"Policy guard missing [{rule.id}]: guard "
                            f"'{rule.guard}' is not registered. Failing closed."
                        ),
                    )
                continue

            try:
                verdict = guard_fn(ctx)
            except Exception as e:
                write_audit_event(
                    "policy_guard_error",
                    **sanitize_fields_with_report(
                        tool=tool_call.tool,
                        directive_id=directive_id,
                        rule_id=rule.id,
                        guard=rule.guard,
                        error=e,
                        on_error=rule.on_error,
                    ),
                )
                # Fail closed unless the rule explicitly opts into failing open. A
                # fail-safe default must not depend on validate_policies having run:
                # execute() is public, so callers reach this code directly.
                if rule.on_error != "fail_open":
                    return ToolCallResult(
                        success=False,
                        result=None,
                        error=f"Policy guard error [{rule.id}]: guard '{rule.guard}' raised an exception. Failing closed.",
                    )
                continue

            if verdict is None:
                continue

            is_secret_guard = verdict.code in REDACTING_VERDICT_CODES
            audit_args = redact_for_audit(
                tool_call.args if isinstance(tool_call.args, dict) else {},
                verdict.metadata.get("matched_fields") if verdict.metadata else None,
            ) if is_secret_guard else None

            write_audit_event(
                "policy_guard_check",
                **sanitize_fields_with_report(
                    tool=tool_call.tool,
                    directive_id=directive_id,
                    rule_id=rule.id,
                    guard=rule.guard,
                    allowed=verdict.allowed,
                    enforcement=rule.enforcement,
                    message=verdict.message,
                    code=verdict.code,
                    verdict_metadata=verdict.metadata,
                    reason=tool_call.reason or None,
                    **(
                        {"redacted_args": audit_args}
                        if audit_args is not None
                        else {}
                    ),
                ),
            )

            if not verdict.allowed:
                # Refuse unless the rule explicitly opts into letting a denial
                # through. Comparing against "block" instead meant any typo or
                # case variant silently degraded a blocking rule to a warning,
                # the same defect already fixed on the sibling on_error field.
                if rule.enforcement not in PERMISSIVE_ENFORCEMENT:
                    return ToolCallResult(
                        success=False,
                        result=None,
                        error=f"Policy violation [{rule.id}]: {_safe_text(verdict.message)}",
                    )

    try:
        # Carries the directive id into the tools' own resolved-resource check,
        # which runs after they resolve and cannot otherwise attribute a refusal
        # to a run. It sets no verdict -- see auro_runtime.resource_plan.
        with policy_context(directive_id):
            result = fn(**args_to_use)
        safe_result = sanitize_value(result)
        tool_error = _tool_reported_error(safe_result)
        if tool_error is not None:
            # The tool ran and refused. Reporting that as success=True meant a
            # blocked 2 MiB write was recorded in the run transcript
            # (orchestrator.py, steps.append) as a successful step, with the
            # refusal visible only to something that knew to look inside
            # `result`. The payload is kept rather than blanked: it carries the
            # tool's own detail (`written: False`, and so on), and unlike the
            # executor's own refusals above there is a body worth reading.
            return ToolCallResult(
                success=False,
                result=safe_result,
                error=tool_error,
            )
        return ToolCallResult(
            success=True,
            result=safe_result,
            error=None,
        )
    except TypeError as e:
        safe_error = _safe_text(e)
        logger.warning(
            "tool_type_error: tool=%s error=%s",
            safe_tool,
            safe_error,
            extra={
                "tool": safe_tool,
                "tool_args": _redacted_args(tool_call.args),
                "error": safe_error,
            },
        )
        write_audit_event(
            "tool_type_error",
            **sanitize_fields_with_report(
                tool=tool_call.tool,
                directive_id=directive_id,
                error=e,
                reason=tool_call.reason or None,
                args=tool_call.args,
            ),
        )
        return ToolCallResult(
            success=False,
            result=None,
            error=f"Invalid arguments: {safe_error}",
        )
    except Exception as e:
        safe_error = _safe_text(e)
        logger.warning(
            "tool_execution_error: tool=%s error=%s",
            safe_tool,
            safe_error,
            extra={
                "tool": safe_tool,
                "tool_args": _redacted_args(tool_call.args),
                "error": safe_error,
            },
        )
        write_audit_event(
            "tool_execution_error",
            **sanitize_fields_with_report(
                tool=tool_call.tool,
                directive_id=directive_id,
                error=e,
                reason=tool_call.reason or None,
                args=tool_call.args,
            ),
        )
        return ToolCallResult(success=False, result=None, error=safe_error)


def list_tools() -> list[str]:
    """Return list of registered tool names."""
    return list(_REGISTRY.keys())
