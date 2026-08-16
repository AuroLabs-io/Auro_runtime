"""
Pydantic models for directive metadata, policy bindings, and LLM tool-call output.
"""

import json
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

DirectiveCategory = Literal["system", "task", "security", "debug"]


# --- Audit envelope ---


class AuditEvent(BaseModel):
    """Versioned envelope with flat, backward-compatible event details."""

    schema_version: Literal["1"] = "1"
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str | None = None
    sequence: int | None = None
    # Zero-based, matching RunMessage.step_index, so an audit line joins to the
    # transcript the run returns. None when no step owns the event.
    step_index: int | None = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    event: str
    redacted_fields: list[str] = Field(default_factory=list)

    # Existing JSONL readers and directives consume event-specific fields such
    # as tool, rule_id, allowed, and enforcement at the top level.  Schema v1
    # deliberately keeps that contract while making the envelope stable.
    model_config = {"extra": "allow"}


# --- Directive (from Markdown front matter) ---


class DirectiveMetadata(BaseModel):
    """Metadata parsed from directive Markdown front matter."""

    id: str = Field(..., description="Unique directive identifier")
    description: str = Field(default="", description="One-line summary for routing")
    tools: list[str] = Field(default_factory=list, description="Allowed tool names for this directive")
    category: DirectiveCategory = Field(
        default="task",
        description="Category for discovery: system (setup/debug), task (workflows), security (audit/bindings/credentials)",
    )


# --- Policy (from YAML) ---


# Enforcement levels that deliberately let a denied call proceed. The executor
# refuses anything outside this set, so an unrecognised value or a typo such as
# "Block" fails closed rather than degrading a blocking rule into a warning.
# Failing open is the exception and must be spelled out.
PERMISSIVE_ENFORCEMENT = frozenset({"warn", "advisory"})


class PolicyRule(BaseModel):
    """Single rule in a policy binding."""

    id: str = Field(..., description="Rule identifier")
    description: str = Field(..., description="Rule text")
    scope: str | None = Field(default=None, description="Optional scope, e.g. deletion, logging")
    guard: str | None = Field(default=None, description="Guard function name from registry")
    enforcement: str = Field(default="advisory", description="block | warn | advisory")
    enforcement_declared: bool = Field(
        default=True,
        description=(
            "False when the source YAML omitted `enforcement:`. Omission defaults to "
            "advisory, and advisory rules are dropped before execution, so a guarded "
            "rule that omits it would never run. Validation rejects that case."
        ),
    )
    tools: list[str] | None = Field(default=None, description="If set, guard only runs for these tool names")
    directives: list[str] | None = Field(default=None, description="If set, guard only runs for these directive_ids")
    on_error: str = Field(default="fail_closed", description="fail_closed | fail_open — behavior when guard raises")


class PolicyBinding(BaseModel):
    """Policy binding set loaded from YAML."""

    id: str = Field(..., description="Policy set name")
    rules: list[PolicyRule] = Field(default_factory=list, description="List of rules")


# --- LLM output (one tool call per turn) ---


class ToolCallOutput(BaseModel):
    """Structured output from the LLM: one tool call per turn."""

    tool: str = Field(..., description="Name of the tool to invoke")
    args: dict[str, Any] = Field(default_factory=dict, description="Arguments for the tool")
    reason: str = Field(default="", description="Brief reason for this action (for logging)")


class ToolCallResult(BaseModel):
    """Result returned to the orchestrator after executing a tool."""

    success: bool = Field(..., description="Whether the tool executed successfully")
    result: Any = Field(default=None, description="Return value or error message")
    error: str | None = Field(default=None, description="Error message if success is False")


class CompletionOutput(BaseModel):
    """When the LLM is done (no more tool calls), it returns this shape."""

    done: bool = Field(True, description="Always true when task is complete")
    summary: str = Field(default="", description="Final summary or result for the user")

    @field_validator("summary", mode="before")
    @classmethod
    def _coerce_summary(cls, v):
        """
        Accept a non-string summary rather than failing the whole run.

        `done: true` is an unambiguous completion signal and the summary is
        presentational. Smaller models routinely return a list of bullet points
        or a dict here; rejecting that discards a correctly-signalled completion
        and — because the caller then tries to parse it as a tool call — reports
        a misleading "invalid tool call shape" error.
        """
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        if isinstance(v, (list, tuple)):
            parts = []
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                else:
                    parts.append(json.dumps(item, default=str))
            return "\n".join(parts)
        if isinstance(v, dict):
            return json.dumps(v, default=str)
        return str(v)


# --- Orchestrator run() result: chat-style schema ---


RunMessageRole = Literal["system", "user", "assistant", "tool"]


class RunMessage(BaseModel):
    """Single message in a run() transcript, suitable for chat-style UIs."""

    role: RunMessageRole = Field(..., description='Chat role: system, user, assistant, or tool')
    content: str | None = Field(
        default=None,
        description="Natural-language text (summary, reasoning, explanation). None for purely structured entries.",
    )
    tool_call: dict[str, Any] | None = Field(
        default=None,
        description="When role=assistant and the model is requesting a tool, structured ToolCallOutput-like payload.",
    )
    tool_result: dict[str, Any] | None = Field(
        default=None,
        description="When role=tool, structured ToolCallResult-like payload or simplified view.",
    )
    step_index: int | None = Field(
        default=None,
        description="Optional index tying related assistant/tool messages back to the same logical step.",
    )
    timestamp: str | None = Field(
        default=None,
        description="Optional ISO 8601 timestamp for this message, when available.",
    )


class RunResult(BaseModel):
    """Top-level result from orchestrator.run(), optimized for chat-style consumption."""

    success: bool = Field(..., description="Overall success of the run.")
    messages: list[RunMessage] = Field(
        default_factory=list,
        description="Ordered conversation transcript suitable for chat-style UIs.",
    )
    final_summary: str | None = Field(
        default=None,
        description="Optional final summary or result for the user.",
    )
    error: str | None = Field(
        default=None,
        description="High-level error message, if any.",
    )
    meta: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata: directive_id, max_steps, timing, model name, etc.",
    )
    legacy_steps: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Legacy steps structure maintained for backward compatibility.",
    )


# --- Natural-language routing ---


RouterDecisionType = Literal["single", "multiple", "none"]


class RouterCandidate(BaseModel):
    """Candidate directive when the router is unsure between several options."""

    directive_id: str = Field(..., description="Suggested directive id.")
    reason: str = Field(..., description="Short explanation of why this directive may fit.")


class RouterDecision(BaseModel):
    """Structured decision from the natural-language router."""

    decision: RouterDecisionType = Field(
        ...,
        description='Routing decision: "single" (one directive), "multiple" (shortlist), or "none" (no good match).',
    )
    directive_id: str | None = Field(
        default=None,
        description="Chosen directive id when decision == 'single'.",
    )
    candidates: list[RouterCandidate] = Field(
        default_factory=list,
        description="Shortlist of candidate directives when decision == 'multiple'.",
    )
    reason: str | None = Field(
        default=None,
        description="Overall explanation for the routing decision.",
    )
