"""
Pipeline runner: runs Intake -> Plan -> Execute -> Verify -> Persist and returns RunResult dict.
"""

from pathlib import Path
from typing import Any

from auro_runtime.audit import (
    begin_audit_run,
    end_audit_run,
    set_audit_collector,
)
from auro_runtime.paths import get_directives_dir, get_policies_dir
from auro_runtime.secrets import clear_request_secrets, set_request_secrets

from auro_runtime.schemas import RunMessage

from auro_runtime.pipeline.contract import (
    IntakeResult,
    PipelinePlugins,
    Plan,
    PlanContext,
    RouterOutcome,
    RuntimeContext,
)


def run_pipeline(
    raw_input: str | bytes,
    *,
    directive_id: str | None = None,
    plugins: PipelinePlugins,
    directives_dir: Path | str | None = None,
    policies_dir: Path | str | None = None,
    max_steps: int = 20,
    request_secrets: dict[str, str] | None = None,
    override_directive: tuple[Any, str] | None = None,
    content_type: str | None = None,
    allowed_directive_ids: set[str] | None = None,
) -> dict:
    """
    Run the pipeline: Intake -> Plan -> Execute -> Verify -> Persist.
    Returns the same RunResult dict expected by the web app (success, messages, final_summary, error, meta, legacy_steps).
    """
    directives_dir = Path(directives_dir) if directives_dir is not None else get_directives_dir()
    policies_dir = Path(policies_dir) if policies_dir is not None else get_policies_dir()

    audit_context = begin_audit_run()
    try:
        set_request_secrets(request_secrets)
        # 1. Intake
        intake_result: IntakeResult = plugins.intake.intake(
            raw_input,
            content_type=content_type,
        )

        # 2. Plan
        plan_context = PlanContext(
            directive_id=directive_id,
            directives_dir=directives_dir,
            policies_dir=policies_dir,
            max_steps=max_steps,
            override_directive=override_directive,
            allowed_directive_ids=allowed_directive_ids,
        )
        outcome = plugins.plan.plan(intake_result, plan_context)
        if isinstance(outcome, RouterOutcome):
            result_dict = dict(outcome.run_result_dict)
            result_dict.setdefault("meta", {})
            result_dict["meta"]["audit_run_id"] = audit_context.run_id
            return result_dict

        plan: Plan = outcome

        # 3. Execute (with audit collector)
        audit_events: list[dict] = []
        set_audit_collector(audit_events)
        try:
            execute_result = plugins.execute.execute(
                plan,
                RuntimeContext(
                    request_secrets=request_secrets,
                    directives_dir=directives_dir,
                    policies_dir=policies_dir,
                    max_steps=plan.max_steps,
                ),
            )
        finally:
            set_audit_collector(None)

        # 4. Verify (intake, plan, execute_result only; if request-scoped data is ever needed,
        # extend the protocol with optional runtime: RuntimeContext | None = None — see VerifyPlugin docstring)
        verify_result = plugins.verify.verify(intake_result, plan, execute_result)

        # 5. Persist
        persist_result = plugins.persist.persist(
            intake_result,
            plan,
            execute_result,
            verify_result,
            audit_events,
        )

        # Prepend intro message when plan was chosen by router (single)
        if plan.intro_message and execute_result.messages:
            intro_msg = RunMessage(
                role="assistant",
                content=plan.intro_message,
                tool_call=None,
                tool_result=None,
                step_index=None,
                timestamp=None,
            )
            execute_result = execute_result.model_copy(
                update={
                    "messages": [execute_result.messages[0], intro_msg] + execute_result.messages[1:],
                }
            )
        result_dict = execute_result.model_dump()
        if "meta" not in result_dict:
            result_dict["meta"] = {}
        result_dict["meta"]["audit_run_id"] = audit_context.run_id
        result_dict["meta"]["pipeline_verify_passed"] = verify_result.passed
        # A run buffers its whole audit trail in memory and flushes once, here.
        # If that flush fails the trail is gone, and until this was surfaced the
        # caller had no way to know: the result looked identical either way.
        result_dict["meta"]["audit_persisted"] = persist_result.persisted
        if persist_result.errors:
            result_dict["meta"]["audit_errors"] = persist_result.errors
        if plan.intro_message:
            result_dict["meta"]["routed_via"] = "natural_language"
            result_dict["meta"]["directive_id"] = plan.directive_id
        return result_dict
    finally:
        try:
            clear_request_secrets()
        finally:
            end_audit_run(audit_context)
