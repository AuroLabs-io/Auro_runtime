"""
Orchestrator runtime: load directive + policies, build prompt, call LLM, parse output, execute tools.
One tool call per turn; loop until LLM returns done or max steps.
"""

import json
import logging
import os
import sys
from pathlib import Path

from auro_runtime.audit import set_audit_step, write_audit_event
from auro_runtime.directive import allowed_tools_for, list_directives, load_directive_by_id
from auro_runtime.executor import UNRESTRICTED, execute, get_registry
from auro_runtime.models import generate
from auro_runtime.paths import get_directives_dir, get_policies_dir
from auro_runtime.policy import load_policy, load_policies, format_policies_for_prompt, validate_policies, get_enforceable_rules, shipped_posture_drift
from auro_runtime.pipeline.contract import IntakeResult, Plan, PlanContext, RouterOutcome
from auro_runtime.sanitization import (
    sanitize_fields_with_report,
    sanitize_value,
    scrub_text,
)
from auro_runtime.schemas import (
    CompletionOutput,
    DirectiveMetadata,
    RouterDecision,
    RunMessage,
    RunResult,
    ToolCallOutput,
    ToolCallResult,
)
from auro_runtime.secrets import clear_request_secrets, set_request_secrets

logger = logging.getLogger("auro_runtime.orchestrator")


def _redacted(value):
    """
    Scrub secret-shaped content out of model-supplied data before it is audited,
    returned, or interpolated into an error string.

    The model's raw response reaches several failure paths here BEFORE any
    policy guard runs, so nothing else has scanned it. executor.py routes its
    equivalent paths through the same helper; these sites were missed when that
    fix was made, which is why a secret in a malformed response could reach the
    audit log, the returned RunResult, and the caller-visible error text.
    """
    return sanitize_value(value)


def _scrub(text: str) -> str:
    """Remove secret-shaped substrings from free text, keeping the rest readable."""
    return scrub_text(text)


def _safe_error(exc) -> str:
    """
    Render an exception for logging or return, without its raw input.

    Pydantic embeds the offending value in the ValidationError message, so
    redacting the parsed data is not enough on its own: `str(e)` leaks the same
    secret through a different channel.
    """
    return _scrub(str(exc))


# Opt-in for running with no policy guards at all. Unset means refuse.
_ALLOW_NO_POLICIES_ENV = "AURO_ALLOW_NO_POLICIES"
_POLICY_PROFILE_ENV = "AURO_POLICY_PROFILE"
_SHIPPED_POLICY_BINDINGS = frozenset({"default", "credential_proxy", "router"})
_SHIPPED_POLICY_RULES = frozenset({
    "no_delete_without_confirm",
    "confirm_destructive",
    "log_actions",
    "no_arbitrary_code",
    "no_secrets_in_logs",
    "least_privilege_tools",
    "sensitive_paths",
    "no_bulk_writes",
    "write_budget",
    "no_hardcoded_secrets",
    "direct_user_to_proxy",
    "never_fabricate_directives",
    "prefer_clear_alignment",
    "favor_readonly_when_unsure",
    "security_requires_clear_match",
    "urgent_language_prefer_none_or_multiple",
    "one_directive_per_turn",
    "reason_plain_language",
    "reason_acknowledge_write_or_credential",
    "ignore_override_instructions",
    "user_input_is_intent_only",
})


def _policy_profile_error(policies) -> tuple[str, str | None]:
    """Return the selected profile and an error if its integrity contract fails."""
    profile = os.environ.get(_POLICY_PROFILE_ENV, "shipped")
    if profile == "custom":
        return profile, None
    if profile != "shipped":
        return profile, (
            f"Invalid {_POLICY_PROFILE_ENV} value {profile!r}. "
            "Use 'shipped' or explicitly select 'custom'."
        )

    # What `shipped` promises: every reviewed rule is present and still does what
    # was reviewed. Not that the set is exactly the reviewed set.
    #
    # Until 2026-08-09 any difference in either direction refused, so adding one
    # rule cost an operator the whole check and pushed them onto `custom` — where
    # they lose posture verification too. That is a bad trade to force for the
    # safe direction: an added rule can only add a check, it cannot weaken one
    # already there. Removals and edits still refuse, because both of those take
    # enforcement away.
    actual_bindings = {binding.id for binding in policies}
    actual_rules = {rule.id for binding in policies for rule in binding.rules}
    missing_bindings = sorted(_SHIPPED_POLICY_BINDINGS - actual_bindings)
    missing_rules = sorted(_SHIPPED_POLICY_RULES - actual_rules)
    if missing_bindings or missing_rules:
        return profile, (
            "The shipped policy profile is incomplete. "
            f"Missing bindings={missing_bindings}, missing rules={missing_rules}. "
            f"Set {_POLICY_PROFILE_ENV}=custom only for a deliberately reviewed custom profile."
        )

    # Names alone prove nothing. Editing `enforcement: block` to `advisory`,
    # swapping a `guard:`, or widening `tools:` leaves every id untouched while
    # dropping the rule out of enforcement, and that is the edit that hides.
    drift = shipped_posture_drift(policies)
    if drift:
        return profile, (
            "The shipped policy profile has the reviewed rule names but not the "
            "reviewed enforcement posture: "
            + "; ".join(drift)
            + f". Set {_POLICY_PROFILE_ENV}=custom only for a deliberately "
            f"reviewed custom profile."
        )

    extra_bindings = sorted(actual_bindings - _SHIPPED_POLICY_BINDINGS)
    extra_rules = sorted(actual_rules - _SHIPPED_POLICY_RULES)
    if extra_bindings or extra_rules:
        # Permitted, and said out loud: the profile is no longer only the shipped
        # set, and an operator reading the log should not have to diff to find out.
        logger.info(
            "shipped_policy_profile_extended: bindings=%s rules=%s",
            extra_bindings,
            extra_rules,
        )
    return profile, None


def _add_to_path_if_needed(path: Path) -> None:
    """Prepend path to sys.path if not already present (resolve for comparison)."""
    resolved = str(path.resolve())
    try:
        existing = [str(Path(p).resolve()) for p in sys.path]
    except (OSError, RuntimeError):
        existing = list(sys.path)
    if resolved not in existing:
        sys.path.insert(0, resolved)


# Ensure tools are registered when orchestrator runs
def _ensure_tools():
    try:
        import runtime_tools  # noqa: F401
    except ImportError as e:
        logger.warning("runtime_tools package failed to import: %s", _safe_error(e))
        raise


TOOL_CALL_INSTRUCTION = """
Respond with a single JSON object. No other text.

If you need to call a tool, respond with:
{"tool": "<name>", "args": {...}, "reason": "<brief reason>"}

If the task is complete and you have nothing left to do, respond with:
{"done": true, "summary": "<final summary or result for the user>"}

You may only use tools that are listed in the directive. One tool call per message.
"""


ROUTER_SYSTEM_PROMPT = """
You are a routing assistant for Auro.

Given a USER REQUEST and a list of available directives (each with id, category, and description),
you MUST decide whether:
- there is one clearly best directive (decision = "single"),
- several directives could apply (decision = "multiple"), or
- no directive is a good match (decision = "none").

Respond with a single JSON object and no extra text. Use one of these shapes:

1) Clear choice:
{"decision": "single", "directive_id": "<id>", "reason": "<why this is the best choice>"}

2) Ambiguous between a few:
{"decision": "multiple", "candidates": [{"directive_id": "<id1>", "reason": "<why id1>"}, {"directive_id": "<id2>", "reason": "<why id2>"}], "reason": "<overall explanation>"}

3) No good match:
{"decision": "none", "reason": "<why nothing fits; what the user could try instead>"}

Never include markdown code fences or any additional commentary outside the JSON object.
"""


def _extract_json(text: str) -> dict | None:
    """Extract a JSON object from the LLM response.

    Scans for each `{` and attempts a strict decode from that point via
    `json.JSONDecoder.raw_decode`, rather than stripping markdown code
    fences first. Fence-stripping breaks when a JSON string *value*
    itself contains markdown content with triple backticks (e.g. a
    generated directive draft) — the naive fence search treats that
    inner backtick run as the closing fence and truncates the JSON
    mid-string. `raw_decode` parses balanced, quote-aware JSON tokens
    directly, so embedded backticks and arbitrary nesting depth inside
    string values can't confuse it; any leading/trailing markdown or
    commentary around the object is simply ignored.
    """
    if not isinstance(text, str):
        return None
    text = text.strip()
    decoder = json.JSONDecoder()
    start = 0
    while True:
        brace = text.find("{", start)
        if brace == -1:
            return None
        try:
            obj, _ = decoder.raw_decode(text, brace)
            return obj
        except json.JSONDecodeError:
            start = brace + 1


def _plan_from_directive_id(context: PlanContext, user_request: str) -> Plan | RouterOutcome:
    """Build a Plan when directive_id (and optional override_directive) is set. Returns RouterOutcome if the directive is not in the server's exposed set."""
    _ensure_tools()
    user_request = _scrub(user_request)
    if context.override_directive is not None:
        meta, directive_body = context.override_directive
        directive_id = meta.id
    else:
        directive_id = context.directive_id or ""
        if context.allowed_directive_ids is not None and directive_id not in context.allowed_directive_ids:
            result_model = RunResult(
                success=False,
                messages=[
                    RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                    RunMessage(
                        role="assistant",
                        content="This directive is not in this server's exposed directive set.",
                        tool_call=None,
                        tool_result=None,
                        step_index=None,
                        timestamp=None,
                    ),
                ],
                final_summary=None,
                error="This directive is not in this server's exposed directive set.",
                meta={"event": "router_missing_directive", "directive_id": directive_id},
                legacy_steps=[],
            )
            return RouterOutcome(kind="missing_directive", run_result_dict=result_model.model_dump())
        try:
            meta, directive_body = load_directive_by_id(context.directives_dir, directive_id)
        except (FileNotFoundError, ValueError) as e:
            # Unknown or malformed directive id is ordinary user error, not a crash.
            safe_directive_id = _scrub(directive_id)
            safe_error = _safe_error(e)
            logger.warning(
                "directive_load_failed: id=%s error=%s",
                safe_directive_id,
                safe_error,
            )
            write_audit_event(
                "directive_load_failed",
                **sanitize_fields_with_report(
                    directive_id=directive_id,
                    error=e,
                ),
            )
            result_model = RunResult(
                success=False,
                messages=[
                    RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                    RunMessage(
                        role="assistant",
                        content=f"Could not load directive '{safe_directive_id}': {safe_error}",
                        tool_call=None,
                        tool_result=None,
                        step_index=None,
                        timestamp=None,
                    ),
                ],
                final_summary=None,
                error=f"Could not load directive '{safe_directive_id}': {safe_error}",
                meta={
                    "event": "directive_load_failed",
                    "directive_id": safe_directive_id,
                },
                legacy_steps=[],
            )
            return RouterOutcome(kind="missing_directive", run_result_dict=result_model.model_dump())
    policies = load_policies(context.policies_dir)
    policy_text = format_policies_for_prompt(policies)
    allowed_tools = allowed_tools_for(meta)
    return Plan(
        directive_id=directive_id,
        directive_meta=meta,
        directive_body=directive_body,
        user_request=user_request,
        policies_text=policy_text,
        allowed_tools=allowed_tools,
        max_steps=context.max_steps,
        override_directive=context.override_directive,
    )


def _plan_from_router(intake_result: IntakeResult, context: PlanContext) -> Plan | RouterOutcome:
    """Run the router; return a single Plan or a RouterOutcome (shortlist/none/error)."""
    _ensure_tools()
    user_request = _scrub(intake_result.text)
    directives_dir = Path(context.directives_dir)
    policies_dir = Path(context.policies_dir)
    available = list_directives(directives_dir)
    if context.allowed_directive_ids is not None:
        available = [d for d in available if d.id in context.allowed_directive_ids]
    if not available:
        result_model = RunResult(
            success=False,
            messages=[
                RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                RunMessage(
                    role="assistant",
                    content="No directives are configured on this server, so I cannot route your request.",
                    tool_call=None,
                    tool_result=None,
                    step_index=None,
                    timestamp=None,
                ),
            ],
            final_summary=None,
            error="No directives available to handle this request.",
            meta={"event": "router_no_directives"},
            legacy_steps=[],
        )
        return RouterOutcome(kind="no_directives", run_result_dict=result_model.model_dump())

    lines = []
    for meta in available:
        desc = meta.description or ""
        lines.append(f"- id: {meta.id} | category: {meta.category} | description: {desc}")
    directives_overview = "\n".join(lines)
    router_user_message = f"""USER REQUEST:
{user_request}

AVAILABLE DIRECTIVES:
{directives_overview}
"""
    router_system_prompt = ROUTER_SYSTEM_PROMPT
    router_policy_path = policies_dir / "router.yaml"
    if router_policy_path.exists():
        try:
            router_binding = load_policy(router_policy_path)
            router_policy_text = format_policies_for_prompt([router_binding])
            router_system_prompt = ROUTER_SYSTEM_PROMPT + "\n\n# Router policy (you must follow these rules)\n\n" + router_policy_text
        except Exception:
            pass
    try:
        router_response = generate(
            system_prompt=_scrub(router_system_prompt),
            user_message=_scrub(router_user_message),
        )
    except Exception as e:
        safe_error = _safe_error(e)
        logger.warning("router_backend_error: %s", safe_error)
        write_audit_event(
            "router_backend_error",
            **sanitize_fields_with_report(error=e),
        )
        result_model = RunResult(
            success=False,
            messages=[
                RunMessage(
                    role="user",
                    content=user_request,
                    tool_call=None,
                    tool_result=None,
                    step_index=None,
                    timestamp=None,
                ),
                RunMessage(
                    role="assistant",
                    content="The routing model failed before a directive could be selected.",
                    tool_call=None,
                    tool_result={"error": safe_error},
                    step_index=None,
                    timestamp=None,
                ),
            ],
            final_summary=None,
            error=f"Natural-language routing backend failed: {safe_error}",
            meta={"event": "router_backend_error"},
            legacy_steps=[],
        )
        return RouterOutcome(
            kind="backend_error",
            run_result_dict=result_model.model_dump(),
        )
    data = _extract_json(router_response)
    if not data:
        safe_preview = _redacted(
            router_response[:500]
            if isinstance(router_response, str)
            else router_response
        )
        result_model = RunResult(
            success=False,
            messages=[
                RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                RunMessage(
                    role="assistant",
                    content="I could not route your request because the router output was not valid JSON. Please specify a directive explicitly.",
                    tool_call=None,
                    tool_result={"response_preview": safe_preview},
                    step_index=None,
                    timestamp=None,
                ),
            ],
            final_summary=None,
            error="Natural-language routing failed due to invalid JSON output.",
            meta={"event": "router_parse_failed"},
            legacy_steps=[],
        )
        return RouterOutcome(kind="parse_failed", run_result_dict=result_model.model_dump())
    try:
        decision = RouterDecision.model_validate(data)
    except Exception as e:
        result_model = RunResult(
            success=False,
            messages=[
                RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                RunMessage(
                    role="assistant",
                    content="I could not route your request because the router output did not match the expected schema. Please specify a directive explicitly.",
                    tool_call=None,
                    tool_result={"error": _safe_error(e), "response_data": _redacted(data)},
                    step_index=None,
                    timestamp=None,
                ),
            ],
            final_summary=None,
            error="Natural-language routing failed due to schema validation error.",
            meta={"event": "router_schema_failed"},
            legacy_steps=[],
        )
        return RouterOutcome(kind="schema_failed", run_result_dict=result_model.model_dump())
    by_id = {m.id: m for m in available}
    if decision.decision == "single" and decision.directive_id:
        chosen = by_id.get(decision.directive_id)
        if not chosen:
            safe_selected_id = _scrub(decision.directive_id)
            result_model = RunResult(
                success=False,
                messages=[
                    RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                    RunMessage(
                        role="assistant",
                        content=f"The router selected directive '{safe_selected_id}', but it is not available on this server.",
                        tool_call=None,
                        tool_result=None,
                        step_index=None,
                        timestamp=None,
                    ),
                ],
                final_summary=None,
                error=f"Directive '{safe_selected_id}' is not available.",
                meta={
                    "event": "router_missing_directive",
                    "directive_id": safe_selected_id,
                },
                legacy_steps=[],
            )
            return RouterOutcome(kind="missing_directive", run_result_dict=result_model.model_dump())
        meta, directive_body = load_directive_by_id(directives_dir, chosen.id)
        policies = load_policies(policies_dir)
        policy_text = format_policies_for_prompt(policies)
        allowed_tools = allowed_tools_for(meta)
        intro = (
            f"I'll run `{_scrub(chosen.id)}` — "
            f"{_scrub(chosen.description) if chosen.description else 'no description provided'} — "
            f"for this request because {_scrub(decision.reason) if decision.reason else 'it appears to be the best match.'}"
        )
        return Plan(
            directive_id=chosen.id,
            directive_meta=meta,
            directive_body=directive_body,
            user_request=user_request,
            policies_text=policy_text,
            allowed_tools=allowed_tools,
            max_steps=context.max_steps,
            override_directive=None,
            intro_message=intro,
        )
    if decision.decision == "multiple" and decision.candidates:
        lines = ["Your request matches several directives. Please specify one explicitly:"]
        for cand in decision.candidates:
            meta = by_id.get(cand.directive_id)
            desc = meta.description if meta else ""
            lines.append(
                f"- `{_scrub(cand.directive_id)}` — {_scrub(desc)} "
                f"(reason: {_scrub(cand.reason)})"
            )
        if decision.reason:
            lines.append("")
            lines.append(f"Why multiple: {_scrub(decision.reason)}")
        content = "\n".join(lines)
        result_model = RunResult(
            success=False,
            messages=[
                RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                RunMessage(role="assistant", content=content, tool_call=None, tool_result=None, step_index=None, timestamp=None),
            ],
            final_summary=None,
            error=None,
            meta={
                "event": "router_multiple",
                "candidates": [
                    {
                        "directive_id": _scrub(cand.directive_id),
                        "reason": _scrub(cand.reason),
                        "description": _scrub(
                            by_id.get(cand.directive_id).description
                            if by_id.get(cand.directive_id)
                            else ""
                        ),
                    }
                    for cand in decision.candidates
                ],
            },
            legacy_steps=[],
        )
        return RouterOutcome(kind="multiple", run_result_dict=result_model.model_dump())
    if decision.decision == "none":
        lines = [
            "I couldn't find a directive that clearly matches your request.",
        ]
        if decision.reason:
            lines.append("")
            lines.append(f"Reason: {_scrub(decision.reason)}")
        lines.append("")
        lines.append("Here are some available directives you could specify explicitly:")
        for meta in available[:5]:
            lines.append(f"- `{_scrub(meta.id)}` — {_scrub(meta.description)}")
        content = "\n".join(lines)
        result_model = RunResult(
            success=False,
            messages=[
                RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                RunMessage(role="assistant", content=content, tool_call=None, tool_result=None, step_index=None, timestamp=None),
            ],
            final_summary=None,
            error="No good directive match found for this request.",
            meta={"event": "router_none"},
            legacy_steps=[],
        )
        return RouterOutcome(kind="none", run_result_dict=result_model.model_dump())
    result_model = RunResult(
        success=False,
        messages=[
            RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
            RunMessage(
                role="assistant",
                content="I could not interpret the routing decision. Please specify a directive explicitly.",
                tool_call=None,
                tool_result={"raw_decision": _redacted(data)},
                step_index=None,
                timestamp=None,
            ),
        ],
        final_summary=None,
        error="Natural-language routing produced an unknown decision.",
        meta={"event": "router_unknown_decision"},
        legacy_steps=[],
    )
    return RouterOutcome(kind="unknown_decision", run_result_dict=result_model.model_dump())


def run(
    directive_id: str,
    user_request: str,
    *,
    directives_dir: Path | str | None = None,
    policies_dir: Path | str | None = None,
    max_steps: int = 20,
    override_directive: tuple[DirectiveMetadata, str] | None = None,
    request_secrets: dict[str, str] | None = None,
    allowed_directive_ids: set[str] | None = None,
) -> dict:
    """
    Run the orchestrator: load directive and policies, then loop (LLM -> parse -> execute) until done or max_steps.

    If override_directive is provided, use (metadata, body) instead of loading from directives_dir.
    If request_secrets is provided, resolve_secret will use it for this run only (cleared in finally).
    If allowed_directive_ids is set, a directive runs only when its id is in that set — the server-wide MCP exposure list (deployment configuration), not a per-caller role.

    Returns a dict with the chat-style run schema: success, messages, final_summary, error, meta, legacy_steps.
    """
    _ensure_tools()
    from auro_runtime.pipeline import run_pipeline
    from auro_runtime.pipeline.plugins import get_default_plugins

    return run_pipeline(
        user_request,
        directive_id=directive_id,
        plugins=get_default_plugins(),
        directives_dir=directives_dir,
        policies_dir=policies_dir,
        max_steps=max_steps,
        request_secrets=request_secrets,
        override_directive=override_directive,
        allowed_directive_ids=allowed_directive_ids,
    )


def route_and_run(
    user_request: str,
    *,
    directives_dir: Path | str | None = None,
    policies_dir: Path | str | None = None,
    max_steps: int = 20,
    request_secrets: dict[str, str] | None = None,
    allowed_directive_ids: set[str] | None = None,
) -> dict:
    """
    Natural-language router: choose a directive for the user_request, then run it.

    Returns the same chat-style RunResult dict as run(), with routing messages
    prepended to the directive's own messages when a single directive is chosen.
    If allowed_directive_ids is set, the router only sees directives in that set — the server-wide MCP exposure list (deployment configuration), not a per-caller role.
    """
    _ensure_tools()
    from auro_runtime.pipeline import run_pipeline
    from auro_runtime.pipeline.plugins import get_default_plugins

    return run_pipeline(
        user_request,
        directive_id=None,
        plugins=get_default_plugins(),
        directives_dir=directives_dir,
        policies_dir=policies_dir,
        max_steps=max_steps,
        request_secrets=request_secrets,
        allowed_directive_ids=allowed_directive_ids,
    )


def _run_impl(
    directive_id: str,
    user_request: str,
    *,
    directives_dir: Path | str | None = None,
    policies_dir: Path | str | None = None,
    max_steps: int = 20,
    override_directive: tuple[DirectiveMetadata, str] | None = None,
) -> dict:
    directives_dir = Path(directives_dir) if directives_dir else get_directives_dir()
    policies_dir = Path(policies_dir) if policies_dir else get_policies_dir()
    user_request = _scrub(user_request)

    if override_directive is not None:
        meta, directive_body = override_directive
        directive_id = meta.id
    else:
        try:
            meta, directive_body = load_directive_by_id(directives_dir, directive_id)
        except (FileNotFoundError, ValueError) as e:
            # Unknown or malformed directive id is ordinary user error, not a crash.
            safe_directive_id = _scrub(directive_id)
            safe_error = _safe_error(e)
            logger.warning(
                "directive_load_failed: id=%s error=%s",
                safe_directive_id,
                safe_error,
            )
            write_audit_event(
                "directive_load_failed",
                **sanitize_fields_with_report(
                    directive_id=directive_id,
                    error=e,
                ),
            )
            return RunResult(
                success=False,
                messages=[
                    RunMessage(role="user", content=user_request, tool_call=None, tool_result=None, step_index=None, timestamp=None),
                ],
                final_summary=None,
                error=f"Could not load directive '{safe_directive_id}': {safe_error}",
                meta={
                    "event": "directive_load_failed",
                    "directive_id": safe_directive_id,
                },
                legacy_steps=[],
            ).model_dump()
    public_directive_id = _scrub(directive_id)

    # A policies directory that is not there is a configuration error, not a
    # decision to run without policies. load_policies() returns [] for both, so
    # until this check the zero-rules gate below could not tell them apart: with
    # AURO_ALLOW_NO_POLICIES set, a mistyped path became an unguarded run rather
    # than a refusal. Checked before that gate and deliberately independent of
    # it, because no value of the opt-out makes a missing path the intent.
    if not Path(policies_dir).is_dir():
        msg = _scrub(
            f"Policies directory '{policies_dir}' does not exist. That is a "
            f"configuration error rather than a request to run without policies, "
            f"so {_ALLOW_NO_POLICIES_ENV} does not apply here. Check the path."
        )
        logger.error("policies_dir_missing: %s", msg)
        write_audit_event(
            "policies_dir_missing",
            directive_id=directive_id,
            error=msg,
            policies_dir=str(policies_dir),
        )
        return RunResult(
            success=False,
            messages=[RunMessage(role="assistant", content=msg, tool_call=None, tool_result=None, step_index=None, timestamp=None)],
            final_summary=None,
            error=msg,
            meta={"directive_id": public_directive_id, "event": "policies_dir_missing"},
            legacy_steps=[],
        ).model_dump()

    policies = load_policies(policies_dir)
    policy_text = format_policies_for_prompt(policies)
    allowed_tools = allowed_tools_for(meta)

    from auro_runtime.guards import get_guard_registry
    try:
        validate_policies(policies, guard_registry=get_guard_registry(), tool_registry=get_registry())
    except ValueError as e:
        safe_error = _safe_error(e)
        logger.warning("policy_validation_failed: %s", safe_error)
        write_audit_event(
            "policy_validation_failed",
            **sanitize_fields_with_report(
                directive_id=directive_id,
                error=e,
            ),
        )
        return RunResult(
            success=False,
            messages=[RunMessage(role="assistant", content=safe_error, tool_call=None, tool_result=None, step_index=None, timestamp=None)],
            final_summary=None,
            error=safe_error,
            meta={
                "directive_id": public_directive_id,
                "event": "policy_validation_failed",
            },
            legacy_steps=[],
        ).model_dump()

    enforceable_rules = get_enforceable_rules(policies)

    # Zero enforceable rules means every guard is absent, not that every guard
    # approved. The executor's guard loop simply never runs, so the call would
    # proceed unchecked and the audit log would look identical to a clean run.
    # A missing, mistyped, or deliberately custom policies directory can
    # produce exactly this state. Shipped installs use packaged policies.
    # Failing open here has to be a deliberate, spelled-out choice.
    allow_unguarded = os.environ.get(_ALLOW_NO_POLICIES_ENV) == "1"
    if not enforceable_rules and not allow_unguarded:
        msg = _scrub(
            f"No enforceable policy rules were loaded from '{policies_dir}'. Every policy "
            f"guard would be skipped, so this run is refused. Check the policies directory "
            f"exists and contains rules, or set {_ALLOW_NO_POLICIES_ENV}=1 to run unguarded "
            f"on purpose."
        )
        logger.error("no_enforceable_policies: %s", msg)
        write_audit_event("no_enforceable_policies", directive_id=directive_id, error=msg,
                          policies_dir=str(policies_dir))
        return RunResult(
            success=False,
            messages=[RunMessage(role="assistant", content=msg, tool_call=None, tool_result=None, step_index=None, timestamp=None)],
            final_summary=None,
            error=msg,
            meta={"directive_id": public_directive_id, "event": "no_enforceable_policies"},
            legacy_steps=[],
        ).model_dump()

    unguarded_mode = not enforceable_rules
    if unguarded_mode:
        policy_profile = "unguarded"
    else:
        policy_profile, profile_error = _policy_profile_error(policies)
        if profile_error:
            profile_error = _scrub(profile_error)
            logger.error("incomplete_policy_profile: %s", profile_error)
            write_audit_event(
                "incomplete_policy_profile",
                directive_id=directive_id,
                error=profile_error,
                policies_dir=str(policies_dir),
                policy_profile=policy_profile,
            )
            return RunResult(
                success=False,
                messages=[RunMessage(role="assistant", content=profile_error, tool_call=None, tool_result=None, step_index=None, timestamp=None)],
                final_summary=None,
                error=profile_error,
                meta={"directive_id": public_directive_id, "event": "incomplete_policy_profile"},
                legacy_steps=[],
            ).model_dump()

    if unguarded_mode:
        write_audit_event(
            "unguarded_mode_enabled",
            directive_id=directive_id,
            policies_dir=str(policies_dir),
            policy_profile=policy_profile,
        )

    system_prompt = _scrub(f"""# Policy Bindings (always apply)

{policy_text}

# Active Directive

{directive_body}

# Output format

{TOOL_CALL_INSTRUCTION}

Allowed tools for this directive: {', '.join(sorted(allowed_tools))}.
""")

    steps: list[dict] = []
    messages: list[RunMessage] = []
    # Initial user message for the transcript
    if user_request:
        messages.append(
            RunMessage(
                role="user",
                content=user_request,
                tool_call=None,
                tool_result=None,
                step_index=None,
                timestamp=None,
            )
        )

    user_message = user_request

    for step in range(max_steps):
        set_audit_step(step)
        try:
            response_text = generate(
                system_prompt=system_prompt,
                user_message=_scrub(user_message),
            )
        except Exception as e:
            safe_error = _safe_error(e)
            logger.warning(
                "model_backend_error: directive_id=%s error=%s",
                public_directive_id,
                safe_error,
            )
            write_audit_event(
                "model_backend_error",
                **sanitize_fields_with_report(
                    directive_id=directive_id,
                    error=e,
                ),
            )
            messages.append(
                RunMessage(
                    role="assistant",
                    content=f"The model backend failed: {safe_error}",
                    tool_call=None,
                    tool_result=None,
                    step_index=step,
                    timestamp=None,
                )
            )
            return RunResult(
                success=False,
                messages=messages,
                final_summary=None,
                error=f"Model backend failed: {safe_error}",
                meta={
                    "directive_id": public_directive_id,
                    "max_steps": max_steps,
                    "steps_count": len(steps),
                    "event": "model_backend_error",
                },
                legacy_steps=steps,
            ).model_dump()
        data = _extract_json(response_text)
        if not data:
            safe_preview = _redacted(
                response_text[:500]
                if isinstance(response_text, str)
                else response_text
            )
            response_length = (
                len(response_text)
                if isinstance(response_text, (str, bytes, list, tuple, dict))
                else None
            )
            logger.warning(
                "parse_json_failed: response_preview=%s",
                safe_preview,
                extra={
                    "directive_id": public_directive_id,
                    "response_length": response_length,
                },
            )
            write_audit_event(
                "parse_json_failed",
                directive_id=directive_id,
                error="Could not parse LLM response as JSON",
                response_length=response_length,
            )
            messages.append(
                RunMessage(
                    role="assistant",
                    content="I could not parse the model response as JSON for this step.",
                    tool_call=None,
                    tool_result={"response_preview": safe_preview},
                    step_index=step,
                    timestamp=None,
                )
            )
            result_model = RunResult(
                success=False,
                messages=messages,
                final_summary=None,
                error=f"Could not parse LLM response as JSON: {safe_preview}",
                meta={
                    "directive_id": public_directive_id,
                    "max_steps": max_steps,
                    "steps_count": len(steps),
                    "event": "parse_json_failed",
                },
                legacy_steps=steps,
            )
            return result_model.model_dump()

        if data.get("done"):
            try:
                completion = CompletionOutput.model_validate(data)
                # The completion summary is the model's own text on the success
                # path, so no guard has scanned it: guards inspect tool-call args
                # and reasons, not the final answer. A model that has seen a
                # secret-shaped string could otherwise echo it straight to the
                # caller as its result.
                safe_summary = _scrub(completion.summary)
                messages.append(
                    RunMessage(
                        role="assistant",
                        content=safe_summary,
                        tool_call=None,
                        tool_result=None,
                        step_index=step,
                        timestamp=None,
                    )
                )
                result_model = RunResult(
                    success=True,
                    messages=messages,
                    final_summary=safe_summary,
                    error=None,
                    meta={
                        "directive_id": public_directive_id,
                        "max_steps": max_steps,
                        "steps_count": len(steps),
                        "event": "done",
                        "policy_profile": policy_profile,
                        "unguarded_mode": unguarded_mode,
                    },
                    legacy_steps=steps,
                )
                return result_model.model_dump()
            except Exception as completion_error:
                # Do not swallow this. The model signalled `done`, so falling
                # through to tool-call parsing will fail on a missing `tool`
                # field and report "invalid tool call shape" — pointing at
                # entirely the wrong problem. Record the real reason.
                safe_data = _redacted(data)
                safe_error = _safe_error(completion_error)
                logger.warning(
                    "completion_shape_rejected: error=%s response=%s",
                    safe_error,
                    safe_data,
                    extra={"directive_id": public_directive_id, "response_data": safe_data},
                )
                write_audit_event(
                    "completion_shape_rejected",
                    **sanitize_fields_with_report(
                        directive_id=directive_id,
                        error=completion_error,
                        response_data=data,
                    ),
                )

        try:
            tool_call = ToolCallOutput.model_validate(data)
        except Exception as e:
            safe_data = _redacted(data)
            safe_error = _safe_error(e)
            logger.warning(
                "invalid_tool_call_shape: error=%s response=%s",
                safe_error,
                safe_data,
                extra={"directive_id": public_directive_id, "data": safe_data},
            )
            write_audit_event(
                "invalid_tool_call_shape",
                **sanitize_fields_with_report(
                    directive_id=directive_id,
                    error=e,
                    response_data=data,
                ),
            )
            messages.append(
                RunMessage(
                    role="assistant",
                    content="The model produced an invalid tool call shape.",
                    tool_call=None,
                    tool_result={"error": safe_error, "response_data": safe_data},
                    step_index=step,
                    timestamp=None,
                )
            )
            result_model = RunResult(
                success=False,
                messages=messages,
                final_summary=None,
                error=f"Invalid tool call shape: {safe_error}. Response: {safe_data}",
                meta={
                    "directive_id": public_directive_id,
                    "max_steps": max_steps,
                    "steps_count": len(steps),
                    "event": "invalid_tool_call_shape",
                },
                legacy_steps=steps,
            )
            return result_model.model_dump()

        result: ToolCallResult = execute(
            tool_call,
            allowed_tools=allowed_tools,
            directive_id=directive_id,
            # An empty rule list now reads as an incomplete context rather than
            # as "no guards apply". The unguarded opt-in was already made once,
            # loudly, at the AURO_ALLOW_NO_POLICIES gate above; carry it down as
            # an explicit sentinel instead of letting [] mean it silently.
            policy_rules=UNRESTRICTED if unguarded_mode else enforceable_rules,
            run_history=steps,
        )
        safe_tool = _scrub(tool_call.tool)
        safe_args = _redacted(tool_call.args)
        safe_reason = _scrub(tool_call.reason)
        safe_result = _redacted(result.result)
        safe_result_error = _scrub(result.error) if result.error else None
        steps.append(
            {
                "tool": safe_tool,
                "args": safe_args,
                "reason": safe_reason,
                "success": result.success,
                "result": safe_result,
                "error": safe_result_error,
            }
        )

        # Append assistant/tool messages for this step
        messages.append(
            RunMessage(
                role="assistant",
                content=safe_reason or f"Calling tool {safe_tool}.",
                tool_call={
                    "tool": safe_tool,
                    "args": safe_args,
                    "reason": safe_reason,
                },
                tool_result=None,
                step_index=step,
                timestamp=None,
            )
        )
        messages.append(
            RunMessage(
                role="tool",
                content=None,
                tool_call=None,
                tool_result={
                    "success": result.success,
                    "result": safe_result,
                    "error": safe_result_error,
                },
                step_index=step,
                timestamp=None,
            )
        )

        # Build next user message: previous request + history of tool calls and results
        if step == 0:
            next_user = user_request + "\n\n"
        else:
            next_user = user_message + "\n\n"
        next_user += f"Tool call: {safe_tool}(**{json.dumps(safe_args)})\n"
        next_user += (
            f"Result: {json.dumps(safe_result) if safe_result is not None else safe_result_error}\n\n"
        )
        next_user += "What do you do next? Respond with one JSON object (tool call or done)."
        user_message = next_user

    logger.warning(
        "max_steps_reached: directive_id=%s steps=%s",
        public_directive_id,
        len(steps),
        extra={"directive_id": public_directive_id, "max_steps": max_steps, "steps_count": len(steps)},
    )
    # The loop is over, so no step owns this. Attribute it to max_steps, matching
    # the RunMessage below, rather than leaving it on the last step that ran.
    set_audit_step(max_steps)
    write_audit_event(
        "max_steps_reached",
        directive_id=directive_id,
        error=f"Reached max steps ({max_steps}) without completion",
        max_steps=max_steps,
        steps_count=len(steps),
    )
    messages.append(
        RunMessage(
            role="assistant",
            content=f"Reached the maximum number of steps ({max_steps}) without completing the task.",
            tool_call=None,
            tool_result=None,
            step_index=max_steps,
            timestamp=None,
        )
    )
    result_model = RunResult(
        success=False,
        messages=messages,
        final_summary=None,
        error=f"Reached max steps ({max_steps}) without completion.",
        meta={
            "directive_id": public_directive_id,
            "max_steps": max_steps,
            "steps_count": len(steps),
            "event": "max_steps_reached",
        },
        legacy_steps=steps,
    )
    return result_model.model_dump()
