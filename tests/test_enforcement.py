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

from auro_runtime.executor import execute
from auro_runtime.guards import GuardVerdict, get_guard_registry


# --- Layer 1: registry --------------------------------------------------------


def test_unknown_tool_is_refused(make_tool_call, registry, audit_events):
    result = execute(make_tool_call("no_such_tool_xyz"))
    assert result.success is False
    assert "Unknown tool" in result.error
    assert any(e["event"] == "unknown_tool" for e in audit_events)


def test_known_tool_with_no_restrictions_succeeds(make_tool_call, registry):
    result = execute(make_tool_call("echo", {"message": "hello"}))
    assert result.success is True
    assert result.error is None


# --- Layer 2: directive scope -------------------------------------------------


def test_tool_outside_allowed_tools_is_refused(make_tool_call, registry, audit_events):
    result = execute(make_tool_call("write_file", {"path": "output/x.txt", "content": "x"}),
                     allowed_tools={"echo", "list_dir"})
    assert result.success is False
    assert "is not allowed by the current directive" in result.error
    assert any(e["event"] == "tool_not_allowed" for e in audit_events)


def test_allowed_tools_none_means_unrestricted(make_tool_call, registry):
    result = execute(make_tool_call("echo", {"message": "hi"}), allowed_tools=None)
    assert result.success is True


def test_tool_inside_allowed_tools_proceeds(make_tool_call, registry):
    result = execute(make_tool_call("echo", {"message": "hi"}), allowed_tools={"echo"})
    assert result.success is True


# --- Layer 3: argument schema -------------------------------------------------


def test_missing_required_argument_is_refused(make_tool_call, registry, audit_events):
    """write_file requires `content`; omitting it must fail cleanly, not crash."""
    result = execute(make_tool_call("write_file", {"path": "output/x.txt"}),
                     allowed_tools={"write_file"})
    assert result.success is False
    assert "Invalid arguments" in result.error
    assert any(e["event"] == "argument_validation_failed" for e in audit_events)


def test_wrong_typed_argument_is_refused(make_tool_call, registry):
    result = execute(make_tool_call("list_dir", {"path": ".", "recursive": "not-a-bool"}),
                     allowed_tools={"list_dir"})
    assert result.success is False
    assert "Invalid arguments" in result.error


def test_malformed_arguments_do_not_raise(make_tool_call, registry):
    """
    Regression: extra={"args": ...} collided with LogRecord's reserved `args`
    attribute, so makeRecord() raised KeyError from inside the warning call and
    crashed the whole process on any malformed tool call.
    """
    for bad in ({}, {"path": 123}, {"unexpected": ["a", "b"]}):
        result = execute(make_tool_call("write_file", bad), allowed_tools={"write_file"})
        assert result.success is False, f"expected refusal for {bad}"


# --- Layer 4: guards, enforcement levels --------------------------------------


def test_block_rule_refuses_and_names_the_rule(make_tool_call, make_rule, registry):
    rule = make_rule(guard="check_destructive_action", enforcement="block",
                     tools=["delete_file"], rule_id="test_block_delete")
    result = execute(make_tool_call("delete_file", {"path": "output/x.txt"}),
                     allowed_tools={"delete_file"}, policy_rules=[rule])
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
    result = execute(call, allowed_tools={"write_file"}, policy_rules=[rule])

    assert result.success is True, "warn must not block execution"
    checks = [e for e in audit_events if e["event"] == "policy_guard_check"]
    assert checks, "warn rule must still emit an audit record"
    assert checks[0]["enforcement"] == "warn"
    assert checks[0]["allowed"] is False


def test_advisory_rule_does_not_block(make_tool_call, make_rule, registry):
    rule = make_rule(guard="check_destructive_action", enforcement="advisory",
                     tools=["delete_file"], on_error="fail_open")
    result = execute(make_tool_call("delete_file", {"path": "output/nonexistent.txt"}),
                     allowed_tools={"delete_file"}, policy_rules=[rule])
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
                           allowed_tools={"echo"}, policy_rules=[rule])
    assert out_of_scope.success is True, "a rule scoped to other tools must not block echo"
    assert not [e for e in audit_events if e["event"] == "policy_guard_check"]

    # Positive control. Without this half the assertions above would also pass if
    # the guard simply never fired, which is exactly how the old version failed.
    in_scope = execute(make_tool_call("write_file", {"path": "output/scoping_probe.txt",
                                                    "content": "x"}, reason=""),
                       allowed_tools={"write_file"}, policy_rules=[rule])
    assert in_scope.success is False, "the same rule must block the tool it is scoped to"
    assert "Policy violation" in in_scope.error


def test_rule_scoped_by_directives_only_fires_for_matching_directive(make_tool_call, make_rule,
                                                                     registry):
    rule = make_rule(guard="check_destructive_action", enforcement="block",
                     tools=["delete_file"], directives=["only_this_directive"])

    other = execute(make_tool_call("delete_file", {"path": "output/x.txt"}),
                    allowed_tools={"delete_file"}, directive_id="a_different_one",
                    policy_rules=[rule])
    assert "Policy violation" not in (other.error or "")

    matching = execute(make_tool_call("delete_file", {"path": "output/x.txt"}),
                       allowed_tools={"delete_file"}, directive_id="only_this_directive",
                       policy_rules=[rule])
    assert matching.success is False
    assert "Policy violation" in matching.error


def test_rule_naming_an_unregistered_guard_is_skipped(make_tool_call, make_rule, registry):
    """
    The executor silently continues past a guard name it cannot resolve, which is
    why validate_policies() at load time is the only thing standing between a
    typo and a silently absent protection. See test_policy_validation.py.
    """
    rule = make_rule(guard="check_guard_that_does_not_exist", enforcement="block")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule])
    assert result.success is True


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
                     allowed_tools={"echo"}, policy_rules=[rule])
    assert result.success is False
    assert "Policy guard error" in result.error
    assert any(e["event"] == "policy_guard_error" for e in audit_events)


def test_guard_exception_fail_open_proceeds(make_tool_call, make_rule, registry,
                                            exploding_guard, audit_events):
    rule = make_rule(guard=exploding_guard, enforcement="block", on_error="fail_open",
                     rule_id="test_failopen")
    result = execute(make_tool_call("echo", {"message": "hi"}),
                     allowed_tools={"echo"}, policy_rules=[rule])
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
                     allowed_tools={"echo"}, policy_rules=[rule])
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
    assert "reason" in verdict.metadata.get("matched_fields", [])


def test_secret_guard_audit_redacts_the_value(make_tool_call, make_rule, registry, audit_events):
    """A secret must never reach the audit log in plaintext."""
    secret = "sk-ant-" + "e" * 24
    rule = make_rule(guard="check_no_secrets_in_args", enforcement="block", rule_id="test_secrets")
    execute(make_tool_call("http_request", {"url": "https://x", "token": secret}),
            allowed_tools={"http_request"}, policy_rules=[rule])
    serialized = repr(audit_events)
    assert secret not in serialized, "raw secret leaked into the audit trail"


# --- Real policy integration --------------------------------------------------


def test_real_policies_block_sensitive_path_reads(make_tool_call, enforceable_rules, registry):
    """End of the chain: the actual shipped rules refuse a secrets-file read."""
    result = execute(make_tool_call("read_file", {"path": "auro_secrets.yaml"}),
                     allowed_tools={"read_file"}, policy_rules=enforceable_rules)
    assert result.success is False
    assert "sensitive_paths" in result.error


def test_real_policies_allow_a_benign_call(make_tool_call, enforceable_rules, registry):
    result = execute(make_tool_call("echo", {"message": "hello"}, reason="a benign call"),
                     allowed_tools={"echo"}, policy_rules=enforceable_rules)
    assert result.success is True
