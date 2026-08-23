"""
Executor enforcement pipeline.

This is the security core: the runtime's central claim is that it refuses tool
calls that violate directive scope or policy. These tests are what make that
claim verifiable rather than asserted.

Layers exercised here, in the order execute() applies them:
  1. tool exists in the registry
  2. tool is within the active directive's allowed_tools
  3. arguments satisfy the tool's pydantic schema
  4. policy guards, subject to each rule's enforcement level and on_error mode
"""

import pytest

from auro_runtime.executor import UNRESTRICTED, execute
from auro_runtime.guards import GuardVerdict, get_guard_registry


# --- Layer 1: registry --------------------------------------------------------


def test_unknown_tool_is_refused(make_tool_call, registry, audit_events):
    result = execute(make_tool_call("no_such_tool_xyz"), allowed_tools=UNRESTRICTED, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is False
    assert "Unknown tool" in result.error
    assert any(e["event"] == "unknown_tool" for e in audit_events)


def test_known_tool_with_no_restrictions_succeeds(make_tool_call, registry):
    result = execute(make_tool_call("echo", {"message": "hello"}), allowed_tools=UNRESTRICTED, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is True
    assert result.error is None


# --- Layer 2: directive scope -------------------------------------------------


def test_tool_outside_allowed_tools_is_refused(make_tool_call, registry, audit_events):
    result = execute(make_tool_call("write_file", {"path": "output/x.txt", "content": "x"}),
                     allowed_tools={"echo", "list_dir"}, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is False
    assert "is not allowed by the current directive" in result.error
    assert any(e["event"] == "tool_not_allowed" for e in audit_events)


@pytest.mark.parametrize("omitted", ["allowed_tools", "policy_rules", "run_history"])
def test_omitted_security_input_refuses(make_tool_call, registry, audit_events, omitted):
    """
    Omission must not select the permissive branch. execute() is public, so a
    partially supplied context is the shape an embedding application reaches by
    accident; each of the three inputs has to refuse on its own rather than
    silently disabling its boundary.
    """
    ctx = {
        "allowed_tools": {"echo"},
        "policy_rules": UNRESTRICTED,
        "run_history": [],
    }
    del ctx[omitted]

    result = execute(make_tool_call("echo", {"message": "hi"}), **ctx)

    assert result.success is False
    assert omitted in result.error
    assert "Incomplete execution context" in result.error
    assert any(e["event"] == "incomplete_execution_context" for e in audit_events)


def test_complete_context_proceeds(make_tool_call, registry):
    """Positive control for the test above: the refusal is about the omission."""
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is True


def test_unrestricted_is_the_only_way_past_a_boundary(make_tool_call, registry):
    """
    The permissive behaviour still exists; it just has to be named. Without this
    the change above would be untestable as a *choice* rather than a removal.
    """
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools=UNRESTRICTED, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is True


def test_empty_policy_rules_is_not_a_way_to_run_unguarded(make_tool_call, registry):
    """
    An empty tool scope is a real answer (a directive declaring no tools may call
    none), but an empty rule list means no guard runs at all, which is exactly
    what omission meant. Only UNRESTRICTED may say that.
    """
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[], run_history=[])
    assert result.success is False
    assert "policy_rules" in result.error


def test_empty_allowed_tools_is_a_real_answer_not_an_omission(make_tool_call, registry):
    """The asymmetry above, from the other side: empty scope refuses the call
    on scope grounds, not as an incomplete-context error."""
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools=set(), policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is False
    assert "Incomplete execution context" not in result.error
    assert "is not allowed by the current directive" in result.error


def test_tool_inside_allowed_tools_proceeds(make_tool_call, registry):
    result = execute(make_tool_call("echo", {"message": "hi"}), allowed_tools={"echo"}, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is True


# --- Layer 3: argument schema -------------------------------------------------


def test_missing_required_argument_is_refused(make_tool_call, registry, audit_events):
    """write_file requires `content`; omitting it must fail cleanly, not crash."""
    result = execute(make_tool_call("write_file", {"path": "output/x.txt"}),
                     allowed_tools={"write_file"}, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is False
    assert "Invalid arguments" in result.error
    assert any(e["event"] == "argument_validation_failed" for e in audit_events)


def test_wrong_typed_argument_is_refused(make_tool_call, registry):
    result = execute(make_tool_call("list_dir", {"path": ".", "recursive": "not-a-bool"}),
                     allowed_tools={"list_dir"}, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is False
    assert "Invalid arguments" in result.error


def test_malformed_arguments_do_not_raise(make_tool_call, registry):
    """
    Regression: extra={"args": ...} collided with LogRecord's reserved `args`
    attribute, so makeRecord() raised KeyError from inside the warning call and
    crashed the whole process on any malformed tool call.
    """
    for bad in ({}, {"path": 123}, {"unexpected": ["a", "b"]}):
        result = execute(make_tool_call("write_file", bad), allowed_tools={"write_file"}, policy_rules=UNRESTRICTED, run_history=[])
        assert result.success is False, f"expected refusal for {bad}"


# --- Layer 4: guards, enforcement levels --------------------------------------


def test_block_rule_refuses_and_names_the_rule(make_tool_call, make_rule, registry):
    rule = make_rule(guard="check_destructive_action", enforcement="block",
                     tools=["delete_file"], rule_id="test_block_delete")
    result = execute(make_tool_call("delete_file", {"path": "output/x.txt"}),
                     allowed_tools={"delete_file"}, policy_rules=[rule], run_history=[])
    assert result.success is False
    assert "Policy violation [test_block_delete]" in result.error


def test_warn_rule_records_the_verdict_but_proceeds(make_tool_call, make_rule, registry,
                                                    audit_events, temp_output_file):
    """
    The heart of the enforcement model: a `warn` rule must audit the denial and
    still let execution through. A warn that blocks, or a block that warns,
    would both be silent governance failures.
    """
    path = temp_output_file("output/enforcement_warn_probe.txt")
    rule = make_rule(guard="check_reason_not_empty", enforcement="warn",
                     on_error="fail_open", rule_id="test_warn_reason")
    call = make_tool_call("write_file", {"path": path, "content": "x"}, reason="")
    result = execute(call, allowed_tools={"write_file"}, policy_rules=[rule], run_history=[])

    assert result.success is True, "warn must not block execution"
    checks = [e for e in audit_events if e["event"] == "policy_guard_check"]
    assert checks, "warn rule must still emit an audit record"
    assert checks[0]["enforcement"] == "warn"
    assert checks[0]["allowed"] is False


def test_advisory_rule_does_not_block(make_tool_call, make_rule, registry):
    rule = make_rule(guard="check_destructive_action", enforcement="advisory",
                     tools=["delete_file"], on_error="fail_open")
    result = execute(make_tool_call("delete_file", {"path": "output/nonexistent.txt"}),
                     allowed_tools={"delete_file"}, policy_rules=[rule], run_history=[])
    assert result.success is True or "Policy violation" not in (result.error or "")


# --- Layer 4: rule scoping ----------------------------------------------------


def test_rule_scoped_by_tools_does_not_fire_for_other_tools(make_tool_call, make_rule,
                                                            registry, audit_events):
    """
    The guard used here must NOT filter by tool name itself, or the executor's
    scoping decision becomes unobservable.

    The previous version of this test used check_destructive_action, which
    re-checks ctx.tool_name internally and returns None for echo no matter what.
    It therefore passed whether the executor scoped correctly, scoped wrongly, or
    had no scoping code at all: the entire tools-scoping block could be deleted
    from executor.py with the full suite still green. check_reason_not_empty
    fires on any tool with an empty reason, so scoping is the only thing that can
    suppress it.
    """
    rule = make_rule(guard="check_reason_not_empty", enforcement="block",
                     tools=["write_file"])

    # Out of scope: echo is not in the rule's tools, so the rule must be skipped
    # even though the empty reason would otherwise trip the guard.
    out_of_scope = execute(make_tool_call("echo", {"message": "hi"}, reason=""),
                           allowed_tools={"echo"}, policy_rules=[rule], run_history=[])
    assert out_of_scope.success is True, "a rule scoped to other tools must not block echo"
    assert not [e for e in audit_events if e["event"] == "policy_guard_check"]

    # Positive control. Without this half the assertions above would also pass if
    # the guard simply never fired, which is exactly how the old version failed.
    in_scope = execute(make_tool_call("write_file", {"path": "output/scoping_probe.txt",
                                                    "content": "x"}, reason=""),
                       allowed_tools={"write_file"}, policy_rules=[rule], run_history=[])
    assert in_scope.success is False, "the same rule must block the tool it is scoped to"
    assert "Policy violation" in in_scope.error


def test_rule_scoped_by_directives_only_fires_for_matching_directive(make_tool_call, make_rule,
                                                                     registry):
    rule = make_rule(guard="check_destructive_action", enforcement="block",
                     tools=["delete_file"], directives=["only_this_directive"])

    other = execute(make_tool_call("delete_file", {"path": "output/x.txt"}),
                    allowed_tools={"delete_file"}, directive_id="a_different_one",
                    policy_rules=[rule], run_history=[])
    assert "Policy violation" not in (other.error or "")

    matching = execute(make_tool_call("delete_file", {"path": "output/x.txt"}),
                       allowed_tools={"delete_file"}, directive_id="only_this_directive",
                       policy_rules=[rule], run_history=[])
    assert matching.success is False
    assert "Policy violation" in matching.error


def test_rule_naming_an_unregistered_guard_refuses(make_tool_call, make_rule, registry,
                                                   audit_events):
    """
    A rule was written to enforce something and names a guard that does not
    exist. Skipping it silently made that indistinguishable from a guard that
    approved. It is now treated as the guard failing: on_error decides, and the
    condition is recorded either way.

    Previously this asserted success is True, with validate_policies() at load
    time as the only thing between a typo and an absent protection. That is
    still the first line of defence; it is no longer the only one.
    """
    rule = make_rule(guard="check_guard_that_does_not_exist", enforcement="block")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule], run_history=[])
    assert result.success is False
    assert "is not registered" in result.error
    assert any(e["event"] == "policy_guard_missing" for e in audit_events)


def test_unregistered_guard_may_proceed_only_under_fail_open(make_tool_call, make_rule,
                                                             registry, audit_events):
    """
    Negative control for the test above: the refusal follows on_error rather than
    being unconditional, and the audit event is written on both branches so the
    permissive path is never silent.
    """
    rule = make_rule(guard="check_guard_that_does_not_exist", enforcement="block",
                     on_error="fail_open")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule], run_history=[])
    assert result.success is True
    assert any(e["event"] == "policy_guard_missing" for e in audit_events)


# --- Layer 2: directive scope is snapshotted, not re-read ---------------------


def test_directive_is_not_re_read_during_the_step_loop(monkeypatch, registry):
    """
    A run must not be able to widen its own authority.

    Executable directives are immutable to runtime tools, and the authority
    checked during Plan is the authority Execute must use. Pin both properties:
    exactly one authoritative load per run, independent of step count.
    """
    from auro_runtime import orchestrator

    load_calls: list[str] = []
    real_load = orchestrator.load_directive_by_id

    def counting_load(directives_dir, directive_id):
        load_calls.append(directive_id)
        return real_load(directives_dir, directive_id)

    monkeypatch.setattr(orchestrator, "load_directive_by_id", counting_load)

    def loads_for(n_tool_steps: int) -> int:
        load_calls.clear()
        scripted = ['{"tool": "list_tools", "args": {}, "reason": "probe"}'] * n_tool_steps
        scripted.append('{"done": true, "summary": "finished"}')
        responses = iter(scripted)
        monkeypatch.setattr(
            orchestrator, "generate",
            lambda system_prompt, user_message: next(responses),
        )
        result = orchestrator.run("tool_catalog", "list the available tools")
        assert result["success"] is True, f"run did not complete: {result.get('error')}"
        assert len(result["legacy_steps"]) == n_tool_steps
        return len(load_calls)

    one_step = loads_for(1)
    three_steps = loads_for(3)

    assert one_step == three_steps == 1, (
        f"expected one authoritative directive load per run, got {one_step} "
        f"for a 1-step run and {three_steps} for a 3-step run"
    )


# --- Layer 4: guard failure modes ---------------------------------------------


@pytest.fixture
def exploding_guard(monkeypatch):
    """Temporarily register a guard that raises, to exercise on_error handling."""
    def _boom(ctx):
        raise RuntimeError("guard exploded")

    reg = dict(get_guard_registry())
    reg["check_exploding_test_guard"] = _boom
    monkeypatch.setattr("auro_runtime.guards.get_guard_registry", lambda: reg)
    return "check_exploding_test_guard"


def test_guard_exception_fail_closed_refuses(make_tool_call, make_rule, registry,
                                             exploding_guard, audit_events):
    rule = make_rule(guard=exploding_guard, enforcement="block", on_error="fail_closed",
                     rule_id="test_failclosed")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule], run_history=[])
    assert result.success is False
    assert "Policy guard error" in result.error
    assert any(e["event"] == "policy_guard_error" for e in audit_events)


def test_a_rule_naming_an_unregistered_guard_refuses_with_the_documented_text(
    make_tool_call, make_rule, registry, audit_events
):
    """`docs/API.md` quotes this refusal: a rule whose guard is not in the
    registry counts as a guard that failed, not one that approved.

    The message text is the contract an integrator may match on, so it is
    asserted rather than the branch alone.
    """
    rule = make_rule(guard="check_no_such_guard_is_registered", enforcement="block",
                     on_error="fail_closed", rule_id="test_missing_guard")

    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule], run_history=[])

    assert result.success is False
    assert "Policy guard missing [test_missing_guard]" in result.error
    assert "is not registered. Failing closed." in result.error


def test_guard_exception_fail_open_proceeds(make_tool_call, make_rule, registry,
                                            exploding_guard, audit_events):
    rule = make_rule(guard=exploding_guard, enforcement="block", on_error="fail_open",
                     rule_id="test_failopen")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule], run_history=[])
    assert result.success is True
    assert any(e["event"] == "policy_guard_error" for e in audit_events)


@pytest.mark.parametrize("bad_on_error", ["fail_clsoed", "fail-closed", "FAIL_CLOSED", "closed", ""])
def test_guard_exception_fails_closed_for_any_unrecognised_on_error(
    make_tool_call, make_rule, registry, exploding_guard, audit_events, bad_on_error
):
    """
    Only the exact string "fail_open" may fail open. Anything else, including a
    typo, must refuse.

    execute() is public: embedders and tests call it without going through
    validate_policies, so the fail-safe default cannot rely on that validator
    having rejected the value upstream. Before this was inverted, on_error was
    compared against "fail_closed" and every other string fell through to
    `continue`, so a single transposed character silently allowed the call.
    """
    rule = make_rule(guard=exploding_guard, enforcement="block",
                     on_error=bad_on_error, rule_id="test_typo_on_error")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule], run_history=[])
    assert result.success is False, f"on_error={bad_on_error!r} must not fail open"
    assert "Policy guard error" in result.error
    assert any(e["event"] == "policy_guard_error" for e in audit_events)


# --- Specific guards ----------------------------------------------------------


def test_destructive_guard_fires_for_delete_and_restore_not_write(make_guard_context):
    guard = get_guard_registry()["check_destructive_action"]
    assert guard(make_guard_context("delete_file", {"path": "x"})) is not None
    assert guard(make_guard_context("restore_file", {"archive_name": "x"})) is not None
    assert guard(make_guard_context("write_file", {"path": "x", "content": "y"})) is None


def test_write_budget_blocks_once_the_budget_is_spent(make_tool_call, make_rule, registry,
                                                      temp_output_file):
    history = [{"tool": "write_file", "args": {"path": f"output/f{i}.txt"}} for i in range(10)]
    rule = make_rule(guard="check_write_budget", enforcement="block", rule_id="test_budget")
    path = temp_output_file("output/enforcement_budget_probe.txt")
    result = execute(make_tool_call("write_file", {"path": path, "content": "x"}),
                     allowed_tools={"write_file"}, policy_rules=[rule], run_history=history)
    assert result.success is False
    assert "Policy violation [test_budget]" in result.error


def test_write_budget_allows_under_the_limit(make_tool_call, make_rule, registry,
                                             temp_output_file):
    history = [{"tool": "write_file", "args": {"path": "output/f0.txt"}}]
    rule = make_rule(guard="check_write_budget", enforcement="block")
    path = temp_output_file("output/enforcement_budget_ok.txt")
    result = execute(make_tool_call("write_file", {"path": path, "content": "x"}),
                     allowed_tools={"write_file"}, policy_rules=[rule], run_history=history)
    assert result.success is True


def test_bulk_writes_guard_allows_rewriting_the_same_path(make_guard_context):
    guard = get_guard_registry()["check_no_bulk_writes"]
    history = [{"tool": "write_file", "args": {"path": "output/a.txt"}}]
    same = guard(make_guard_context("write_file", {"path": "output/a.txt"}, run_history=history))
    assert same is None, "rewriting the same path is not a bulk write"
    different = guard(make_guard_context("write_file", {"path": "output/b.txt"}, run_history=history))
    assert different is not None and different.allowed is False


# --- Secret handling ----------------------------------------------------------


def test_secret_in_args_is_detected(make_guard_context):
    guard = get_guard_registry()["check_no_secrets_in_args"]
    verdict = guard(make_guard_context("http_request", {"url": "https://x", "token": "sk-ant-" + "a" * 24}))
    assert verdict is not None
    assert verdict.allowed is False
    assert verdict.code == "secret_detected"


def test_secret_in_reason_is_detected(make_guard_context):
    guard = get_guard_registry()["check_no_secrets_in_args"]
    ctx = make_guard_context("echo", {"message": "hi"}, reason="use sk-ant-" + "d" * 24)
    verdict = guard(ctx)
    assert verdict is not None
    assert "reason" in verdict.metadata.get("matched_field_labels", [])


def test_a_secret_in_reason_is_labelled_but_not_given_to_the_targeted_pass(
    make_guard_context,
):
    """`reason` is not part of args, so it is not an addressable path.

    It used to be listed in `matched_fields` anyway, where the targeted
    redaction pass would look for a key called "reason" in the arguments, not
    find one, and skip silently. Harmless there — the reason string is scrubbed
    separately — but it is the same shape as the defect this contract change
    closes, and an unresolvable path now forces a full redaction rather than a
    quiet no-op. Labelling it without addressing it is the honest split.
    """
    ctx = make_guard_context("echo", {"message": "hi"}, reason="use sk-ant-" + "d" * 24)
    verdict = get_guard_registry()["check_no_secrets_in_args"](ctx)

    assert verdict.metadata["matched_fields"] == [], (
        "an unaddressable hit reached the targeted pass, which would now "
        "over-redact the whole record"
    )
    assert "reason" in verdict.metadata["matched_field_labels"]


def test_the_secret_scanner_emits_a_walkable_path_for_a_nested_list(
    make_guard_context,
):
    """The scanner's path must be one the redactor can actually walk.

    Asserted structurally rather than end to end, because it cannot be isolated
    end to end: the scanner and the name-and-pattern pass share
    `_SECRET_PATTERNS`, so anything the scanner detects the baseline pass would
    redact anyway, and a broken path would still produce a clean-looking record.
    The path itself is the only observable that distinguishes them.
    """
    secret = "sk-ant-" + "f" * 24
    ctx = make_guard_context("http_request", {"items": [{"note": secret}]})

    verdict = get_guard_registry()["check_no_secrets_in_args"](ctx)

    assert verdict is not None, "precondition: the scanner must fire"
    assert verdict.metadata["matched_fields"] == [["items", 0, "note"]], (
        f"expected structured segments, got "
        f"{verdict.metadata['matched_fields']!r} — a list index rendered into "
        f"the path string is exactly the shape the redactor cannot resolve"
    )
    assert verdict.metadata["matched_field_labels"] == ["items[0].note"]


def test_secret_guard_audit_redacts_the_value(make_tool_call, make_rule, registry, audit_events):
    """A secret must never reach the audit log in plaintext."""
    secret = "sk-ant-" + "e" * 24
    rule = make_rule(guard="check_no_secrets_in_args", enforcement="block", rule_id="test_secrets")
    execute(make_tool_call("http_request", {"url": "https://x", "token": secret}),
            allowed_tools={"http_request"}, policy_rules=[rule], run_history=[])
    serialized = repr(audit_events)
    assert secret not in serialized, "raw secret leaked into the audit trail"


def test_redaction_scrubs_a_secret_shaped_key():
    """The redaction pass covers key positions, not only values.

    The README states that a resolved value never enters the audit log. Arguments
    reach redaction as the model emitted them, so a key is as caller-controlled as
    a value, and detecting a hit without redacting it is a half-fix: the guard
    reports the secret while the record still carries it verbatim.
    """
    from auro_runtime.guards import redact_args_for_audit

    secret = "sk-ant-" + "i" * 24
    out = redact_args_for_audit({secret: "v", "nested": {secret: "v2"}})
    assert secret not in repr(out), "secret survived redaction in the key position"
    assert "[REDACTED_KEY]" in repr(out)


# --- Real policy integration --------------------------------------------------


def test_real_policies_block_sensitive_path_reads(make_tool_call, enforceable_rules, registry):
    """End of the chain: the actual shipped rules refuse a secrets-file read."""
    result = execute(make_tool_call("read_file", {"path": "auro_secrets.yaml"}),
                     allowed_tools={"read_file"}, policy_rules=enforceable_rules, run_history=[])
    assert result.success is False
    assert "sensitive_paths" in result.error


def test_real_policies_allow_a_benign_call(make_tool_call, enforceable_rules, registry):
    result = execute(make_tool_call("echo", {"message": "hello"}, reason="a benign call"),
                     allowed_tools={"echo"}, policy_rules=enforceable_rules, run_history=[])
    assert result.success is True


# --- Unknown arguments are refused, not dropped -------------------------------
#
# Pydantic's default is extra="ignore". Under it, `list_dir(path=...,
# recurse=True)` ran non-recursively, returned success and raised nothing: the
# call that reached the tool was not the call that was made, and nothing
# downstream could tell. Every schema now inherits _ToolArgs, which forbids
# extras.


def test_an_unknown_argument_is_refused_rather_than_dropped(
    make_tool_call, registry, tmp_path, monkeypatch
):
    """
    The whole point is that the tool must not run. A misspelled flag that is
    merely ignored produces a plausible wrong answer instead of an error.
    """
    result = execute(make_tool_call("list_dir", {"path": "output", "recurse": True}),
                     allowed_tools={"list_dir"}, policy_rules=UNRESTRICTED, run_history=[])

    assert result.success is False
    assert result.result is None, "the tool ran despite an argument it did not accept"
    assert "recurse" in result.error, (
        f"the refusal must name the offending key so the model can correct it; got {result.error!r}"
    )

    # Control: the correctly spelled argument is accepted, so the assertion
    # above is about the unknown key rather than about list_dir being broken.
    ok = execute(make_tool_call("list_dir", {"path": "output", "recursive": True}),
                 allowed_tools={"list_dir"}, policy_rules=UNRESTRICTED, run_history=[])
    assert ok.success is True, ok.error


def test_every_registered_tool_schema_forbids_unknown_arguments():
    """
    Stated over the registry rather than over a list of schemas, so a tool added
    later with a hand-rolled BaseModel schema fails here instead of silently
    reintroducing the permissive default.
    """
    from auro_runtime.executor import get_registry
    from auro_runtime.orchestrator import _ensure_tools

    _ensure_tools()
    permissive = sorted(
        name for name, (_fn, _doc, schema) in get_registry().items()
        if schema is not None and schema.model_config.get("extra") != "forbid"
    )
    assert not permissive, (
        f"{permissive} accept unknown argument keys and drop them silently"
    )


# --- A tool that refuses is not a successful call -----------------------------
#
# Tools signal domain failure by returning {"error": ...} rather than raising.
# The executor only inspected exceptions, so a refused call came back as
# success=True / error=None with the refusal readable only inside `result` —
# and the orchestrator copies `success` straight into the run transcript, so a
# blocked write was recorded as a step that worked.


def test_a_tool_reporting_an_error_is_not_reported_as_success(
    make_tool_call, registry, temp_output_file
):
    """End to end through a real refusal: write_file's own size cap."""
    from runtime_tools import file_tools

    rel = temp_output_file("output/__auro_successsemantics_probe__.txt")
    oversized = "x" * (file_tools._WRITE_MAX_SIZE_BYTES + 1)

    result = execute(make_tool_call("write_file", {"path": rel, "content": oversized}),
                     allowed_tools={"write_file"}, policy_rules=UNRESTRICTED, run_history=[])

    assert result.success is False, (
        "a refused write was reported as a successful call"
    )
    assert result.error and "max write size" in result.error, (
        "the tool's own message must reach ToolCallResult.error, not only result"
    )
    # The payload survives: it carries detail the bare message does not.
    assert result.result["written"] is False


def test_a_successful_tool_call_is_still_success(make_tool_call, registry):
    """
    Control. Without it, marking every call failed would satisfy the test above.
    """
    result = execute(make_tool_call("echo", {"message": "hello"}),
                     allowed_tools={"echo"}, policy_rules=UNRESTRICTED, run_history=[])
    assert result.success is True
    assert result.error is None


@pytest.mark.parametrize("payload", [None, ""])
def test_a_falsy_error_key_is_not_a_failure(make_tool_call, payload):
    """
    `error: None` on a success path must not be read as a refusal, or a tool
    that always includes the key for shape consistency could never succeed.
    """
    from auro_runtime.executor import _REGISTRY, register

    name = "__probe_falsy_error__"
    register(name, "probe")(lambda: {"ok": True, "error": payload})
    try:
        result = execute(make_tool_call(name, {}), allowed_tools={name},
                         policy_rules=UNRESTRICTED, run_history=[])
        assert result.success is True
        assert result.error is None
    finally:
        _REGISTRY.pop(name, None)


def test_a_nested_error_key_is_not_treated_as_a_refusal(make_tool_call):
    """
    Only a top-level `error` is the failure signal. A tool reporting errors as
    *content* — a validator listing what it found — nests them, and must still
    be able to succeed.
    """
    from auro_runtime.executor import _REGISTRY, register

    name = "__probe_nested_error__"
    register(name, "probe")(lambda: {"valid": False, "findings": {"error": "line 3 is bad"}})
    try:
        result = execute(make_tool_call(name, {}), allowed_tools={name},
                         policy_rules=UNRESTRICTED, run_history=[])
        assert result.success is True, (
            "a nested error key was mistaken for a tool-level refusal"
        )
    finally:
        _REGISTRY.pop(name, None)


# --- Sensitive paths: the directory itself, not only files inside it ----------


@pytest.mark.parametrize("path", [
    ".ssh", ".ssh/", ".aws", ".aws/", ".gnupg", ".gnupg/",
    "output/../.ssh",           # traversal reaching the bare directory
    "home/.aws/credentials",    # the file form, which always worked
])
def test_sensitive_directories_are_blocked_in_bare_and_trailing_slash_forms(
    path, make_tool_call, enforceable_rules, registry
):
    """
    The directory patterns required a trailing separator, and
    _canonicalize_path normalises through PurePosixPath, which strips one the
    caller did supply. So `.ssh/id_rsa` was blocked while `.ssh/` and `.ssh`
    were allowed, and list_dir would enumerate a credential directory.
    """
    result = execute(make_tool_call("list_dir", {"path": path}),
                     allowed_tools={"list_dir"}, policy_rules=enforceable_rules,
                     run_history=[])
    assert result.success is False, f"{path!r} was allowed"
    assert "sensitive_paths" in result.error


@pytest.mark.parametrize("path", [
    ".sshrc",            # a file whose name merely starts with .ssh
    "my.ssh",            # .ssh not at a path boundary
    ".awsome/notes.txt", # .aws is a prefix of this directory, not the directory
    "output/notes.txt",
])
def test_the_sensitive_path_widening_does_not_over_block(
    path, make_tool_call, enforceable_rules, registry, tmp_path
):
    """
    Control for the test above. Alternating the trailing separator with `$`
    must not turn the patterns into prefix matches — without this, blocking
    everything would pass the parametrized case.
    """
    result = execute(make_tool_call("list_dir", {"path": path}),
                     allowed_tools={"list_dir"}, policy_rules=enforceable_rules,
                     run_history=[])
    assert not (result.error and "sensitive_paths" in result.error), (
        f"{path!r} is not a sensitive directory but was refused as one"
    )


@pytest.mark.parametrize("path", [
    "output/.env ",             # trailing space
    "output/.env.",             # trailing dot
    "output/.env  ",            # several spaces
    "output/.env. ",            # dot then space
    "output/credentials.json ",
    "output/.htpasswd.",
])
def test_trailing_dots_and_spaces_do_not_bypass_the_sensitive_path_guard(
    path, make_tool_call, enforceable_rules, registry
):
    """
    Windows discards trailing dots and spaces when it opens a file, so
    `output/.env ` reaches the real `output/.env`. The guard compares strings,
    and `$` cannot follow a trailing space, so every `$`-anchored pattern was
    bypassable by appending one character.

    Verified live 2026-08-16 before the fix: this guard allowed the call, the
    tool's own blocklist allowed it too, and read_file returned the file's
    contents. Both layers shared one root cause -- comparing against a path the
    filesystem would not use -- so defense in depth counted for nothing.
    """
    result = execute(make_tool_call("read_file", {"path": path}),
                     allowed_tools={"read_file"}, policy_rules=enforceable_rules,
                     run_history=[])
    assert result.success is False, f"{path!r} was allowed"
    assert "sensitive_paths" in result.error


@pytest.mark.parametrize("path", [
    "output/%2eenv",            # %2e is a percent-encoded dot
    "output/%2Eenv",            # decoding is case-insensitive on the hex digit
    "output/%2essh/id_rsa",
])
def test_percent_encoded_dots_do_not_bypass_the_sensitive_path_guard(
    path, make_tool_call, enforceable_rules, registry
):
    """
    The canonicaliser decodes `%2e` to a dot before matching. Nothing in the
    filesystem tools percent-decodes, so on the read path this is deliberate
    over-classification in the fail-closed direction (D-038) -- `output/%2eenv`
    is a file legitimately named `%2eenv` and is refused as if it were `.env`.

    It is not decoration. `url` is in `_PATH_ARG_KEYS`, and a URL genuinely is
    percent-decoded before use, so a policy scoping this guard to `http_request`
    would need the decode to see `.env` in an encoded path segment.

    Added 2026-08-18 because a mutation deleting the decode survived: the
    transformation had shipped since the guard was written with no test naming
    it, which makes it indistinguishable from a line nobody would miss.
    """
    result = execute(make_tool_call("read_file", {"path": path}),
                     allowed_tools={"read_file"}, policy_rules=enforceable_rules,
                     run_history=[])
    assert result.success is False, f"{path!r} was allowed"
    assert "sensitive_paths" in result.error


@pytest.mark.parametrize("path", [
    "output/envelope.txt",     # begins with env, is not .env
    "output/notes.txt",
    "output/report.final.md",  # interior dots are ordinary
    "output/.environment",     # longer name, not .env
    "output/%252eenv",         # double-encoded: one pass must not reach .env
])
def test_the_trailing_character_strip_does_not_over_block(
    path, make_tool_call, enforceable_rules, registry
):
    """
    Control for the test above. Stripping trailing dots and spaces must not
    turn the patterns into prefix matches, and must not disturb names whose
    dots are interior -- without this, blocking everything would pass.
    """
    result = execute(make_tool_call("read_file", {"path": path}),
                     allowed_tools={"read_file"}, policy_rules=enforceable_rules,
                     run_history=[])
    assert not (result.error and "sensitive_paths" in result.error), (
        f"{path!r} is not sensitive but was refused as one"
    )
