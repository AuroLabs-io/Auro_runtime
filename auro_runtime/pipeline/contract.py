"""
Pipeline contract: data types and plugin protocols for Intake -> Plan -> Execute -> Verify -> Persist.
Single internal contract so each stage is a pluggable component.
"""

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from auro_runtime.schemas import DirectiveMetadata, RunResult

# --- Intake ---

IntakeSource = Literal["voice", "text"]


class IntakeResult(BaseModel):
    """Normalized output from the Intake stage."""

    text: str = Field(..., description="Normalized text (e.g. transcribed or passthrough).")
    source: IntakeSource = Field(default="text", description="voice or text.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Optional intake metadata.")


# --- Plan ---


class Plan(BaseModel):
    """Resolved directive and context for execution. Produced by Plan when a single directive is chosen."""

    directive_id: str = Field(..., description="Directive id to run.")
    directive_meta: DirectiveMetadata = Field(..., description="Directive metadata from front matter.")
    directive_body: str = Field(..., description="Directive markdown body.")
    user_request: str = Field(..., description="User request text.")
    policies_text: str = Field(..., description="Formatted policy text for the prompt.")
    allowed_tools: set[str] = Field(default_factory=set, description="Tool names allowed for this directive.")
    max_steps: int = Field(default=20, description="Max execution steps.")
    override_directive: tuple[DirectiveMetadata, str] | None = Field(
        default=None,
        description="Optional override (e.g. approved user directive); when set, used instead of loading from file.",
    )
    intro_message: str | None = Field(
        default=None,
        description="Optional intro to prepend to transcript (e.g. when chosen by router).",
    )

    model_config = {"arbitrary_types_allowed": False}


RouterOutcomeKind = Literal[
    "multiple",
    "none",
    "no_directives",
    "parse_failed",
    "schema_failed",
    "backend_error",
    "missing_directive",
    "unknown_decision",
]


class RouterOutcome(BaseModel):
    """When Plan does not produce a single executable plan (shortlist, no match, or error)."""

    kind: RouterOutcomeKind = Field(..., description="Why no single plan.")
    run_result_dict: dict[str, Any] = Field(
        ...,
        description="Pre-built RunResult dict to return (messages, meta, error, etc.).",
    )


class PlanContext(BaseModel):
    """Context passed into the Plan stage."""

    directive_id: str | None = Field(default=None, description="If set, use this directive; else run router.")
    directives_dir: Any = Field(..., description="Path to directives directory.")
    policies_dir: Any = Field(..., description="Path to policies directory.")
    max_steps: int = Field(default=20, description="Max steps for execution.")
    override_directive: tuple[Any, str] | None = Field(
        default=None,
        description="Optional (metadata, body) for override directive (e.g. approved user directive); used when directive_id is set.",
    )
    allowed_directive_ids: set[str] | None = Field(
        default=None,
        description="If set, only these directive ids are visible — the server-wide MCP exposure set (deployment configuration), not a per-caller role. None = all.",
    )

    model_config = {"arbitrary_types_allowed": True}


# --- Execute: use RunResult from schemas as ExecuteResult ---

# RuntimeContext: what Execute needs (audit collector is set by runner; plugin just runs)


class RuntimeContext(BaseModel):
    """Context passed into the Execute stage."""

    request_secrets: dict[str, str] | None = Field(default=None, description="Request-scoped secrets.")
    directives_dir: Any = Field(..., description="Path to directives directory.")
    policies_dir: Any = Field(..., description="Path to policies directory.")
    max_steps: int = Field(default=20, description="Max execution steps.")

    model_config = {"arbitrary_types_allowed": True}


# --- Verify ---


class VerifyCheck(BaseModel):
    """Single verification check."""

    name: str = Field(..., description="Check name.")
    passed: bool = Field(..., description="Whether the check passed.")
    detail: str | None = Field(default=None, description="Optional detail.")


class VerifyResult(BaseModel):
    """Output from the Verify stage."""

    passed: bool = Field(..., description="Overall pass/fail.")
    checks: list[VerifyCheck] = Field(default_factory=list, description="Individual checks.")
    block_persist: bool = Field(default=False, description="If True, Persist may skip or downgrade.")


# --- Persist ---


class PersistResult(BaseModel):
    """Output from the Persist stage."""

    persisted: bool = Field(..., description="Whether persistence succeeded.")
    ids: list[str] = Field(default_factory=list, description="e.g. job ids, log ids.")
    errors: list[str] = Field(default_factory=list, description="Errors if any.")


# --- Plugin protocols ---


@runtime_checkable
class IntakePlugin(Protocol):
    """Pluggable Intake stage."""

    def intake(
        self,
        raw: str | bytes,
        *,
        content_type: str | None = None,
    ) -> IntakeResult:
        """Normalize raw input to IntakeResult."""
        ...


@runtime_checkable
class PlanPlugin(Protocol):
    """Pluggable Plan stage."""

    def plan(self, intake_result: IntakeResult, context: PlanContext) -> Plan | RouterOutcome:
        """Resolve directive (router + load) or return RouterOutcome for early exit."""
        ...


@runtime_checkable
class ExecutePlugin(Protocol):
    """Pluggable Execute stage."""

    def execute(self, plan: Plan, runtime: RuntimeContext) -> RunResult:
        """Run the directive (LLM + tools loop)."""
        ...


@runtime_checkable
class VerifyPlugin(Protocol):
    """Pluggable Verify stage. Receives intake, plan, and execute_result (full transcript with tool_call/tool_result per message).
    If request-scoped data is ever needed in Verify, the protocol can be extended with an optional
    runtime: RuntimeContext | None = None parameter; callers would pass it and implementations could use it for
    context-aware checks."""

    def verify(
        self,
        intake_result: IntakeResult,
        plan: Plan,
        execute_result: RunResult,
    ) -> VerifyResult:
        """Run confidence/completeness checks."""
        ...


@runtime_checkable
class PersistPlugin(Protocol):
    """Pluggable Persist stage."""

    def persist(
        self,
        intake_result: IntakeResult,
        plan: Plan,
        execute_result: RunResult,
        verify_result: VerifyResult,
        audit_events: list[dict[str, Any]],
    ) -> PersistResult:
        """Persist audit events, job memory, etc."""
        ...


class PipelinePlugins(BaseModel):
    """Bundle of the five pipeline plugins."""

    intake: Any = Field(..., description="IntakePlugin")
    plan: Any = Field(..., description="PlanPlugin")
    execute: Any = Field(..., description="ExecutePlugin")
    verify: Any = Field(..., description="VerifyPlugin")
    persist: Any = Field(..., description="PersistPlugin")

    model_config = {"arbitrary_types_allowed": True}
