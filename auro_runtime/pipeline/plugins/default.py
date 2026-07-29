"""
Default pipeline plugins: preserve current behavior.
Intake passthrough, Plan (router + load), Execute (_run_impl), Verify (pass if success), Persist (audit log).
"""

from auro_runtime.audit import write_audit_records
from auro_runtime.pipeline.contract import (
    IntakeResult,
    PipelinePlugins,
    Plan,
    PlanContext,
    PersistResult,
    RouterOutcome,
    RuntimeContext,
    VerifyResult,
)
from auro_runtime.schemas import RunResult


class DefaultIntake:
    """Passthrough: raw text -> IntakeResult. Bytes decoded as utf-8."""

    def intake(
        self,
        raw: str | bytes,
        *,
        content_type: str | None = None,
    ) -> IntakeResult:
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
            source = "voice" if content_type and "audio" in (content_type or "") else "text"
        else:
            text = raw
            source = "text"
        return IntakeResult(text=text, source=source, metadata={})


class DefaultPlan:
    """Router + load directive; returns Plan or RouterOutcome. Uses orchestrator helpers."""

    def plan(self, intake_result: IntakeResult, context: PlanContext) -> Plan | RouterOutcome:
        from auro_runtime.orchestrator import _plan_from_directive_id, _plan_from_router

        if context.directive_id:
            return _plan_from_directive_id(context, intake_result.text)
        return _plan_from_router(intake_result, context)


class DefaultExecute:
    """Runs _run_impl with Plan + RuntimeContext. Audit collector is set by the runner."""

    def execute(self, plan: Plan, runtime: RuntimeContext) -> RunResult:
        from auro_runtime.orchestrator import _run_impl

        # Execute the exact directive snapshot that passed planning and exposure
        # checks. Reloading the file here creates a Plan/Execute TOCTOU seam where
        # an allowlisted id can acquire a different body and tool scope.
        override = (plan.directive_meta, plan.directive_body)
        result_dict = _run_impl(
            directive_id=plan.directive_id,
            user_request=plan.user_request,
            directives_dir=runtime.directives_dir,
            policies_dir=runtime.policies_dir,
            max_steps=plan.max_steps,
            override_directive=override,
        )
        return RunResult.model_validate(result_dict)


class DefaultVerify:
    """Pass if execute_result.success; no extra checks."""

    def verify(
        self,
        intake_result: IntakeResult,
        plan: Plan,
        execute_result: RunResult,
    ) -> VerifyResult:
        return VerifyResult(passed=execute_result.success, checks=[], block_persist=False)


class DefaultPersist:
    """Write collected audit events to the audit file."""

    def persist(
        self,
        intake_result: IntakeResult,
        plan: Plan,
        execute_result: RunResult,
        verify_result: VerifyResult,
        audit_events: list[dict],
    ) -> PersistResult:
        errors = write_audit_records(audit_events)
        return PersistResult(
            persisted=len(errors) == 0,
            ids=[],
            errors=errors,
        )


def get_default_plugins() -> PipelinePlugins:
    """Return the default set of pipeline plugins."""
    return PipelinePlugins(
        intake=DefaultIntake(),
        plan=DefaultPlan(),
        execute=DefaultExecute(),
        verify=DefaultVerify(),
        persist=DefaultPersist(),
    )
