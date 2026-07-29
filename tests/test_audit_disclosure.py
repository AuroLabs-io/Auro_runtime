"""Public contracts for the audit envelope and secret-safe outbound boundaries.

The fixtures use one ordinary synthetic marker and assert absence plus benign
positive controls.  Scanner-evasion techniques remain in the restricted suite.
"""

from __future__ import annotations

import asyncio
import json
import logging
from uuid import UUID

import pytest


SYNTHETIC_SECRET = "sk-" + ("A" * 32)


def _read_jsonl(path):
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_audit_envelope_is_correlated_idempotent_and_scrubbed(
    audit_events, monkeypatch, tmp_path
):
    """The live collector and persisted JSONL retain one safe event identity."""
    from auro_runtime.audit import (
        begin_audit_run,
        end_audit_run,
        write_audit_event,
        write_audit_records,
    )

    audit_path = tmp_path / "envelope.jsonl"
    monkeypatch.setenv("AURO_AUDIT_LOG", str(audit_path))
    context = begin_audit_run("run-contract")
    try:
        write_audit_event(
            "contract_probe",
            safe_detail="preserved",
            reason=f"diagnostic {SYNTHETIC_SECRET}",
            nested={"payload": SYNTHETIC_SECRET},
        )
    finally:
        end_audit_run(context)

    assert len(audit_events) == 1
    captured = audit_events[0]
    assert captured["schema_version"] == "1"
    UUID(captured["event_id"])
    assert captured["run_id"] == "run-contract"
    assert captured["sequence"] == 1
    assert captured["event"] == "contract_probe"
    assert captured["safe_detail"] == "preserved"
    assert set(captured["redacted_fields"]) == {
        "$.nested.payload",
        "$.reason",
    }
    assert SYNTHETIC_SECRET not in repr(captured)

    assert write_audit_records(audit_events) == []
    persisted = _read_jsonl(audit_path)
    assert len(persisted) == 1
    assert persisted[0]["event_id"] == captured["event_id"]
    assert persisted[0]["timestamp"] == captured["timestamp"]
    assert persisted[0]["run_id"] == captured["run_id"]
    assert persisted[0]["sequence"] == captured["sequence"]
    assert SYNTHETIC_SECRET not in repr(persisted)


def test_bulk_audit_sink_scrubs_legacy_records_independently(monkeypatch, tmp_path):
    """Persist is a security boundary even when a caller bypasses event creation."""
    from auro_runtime.audit import write_audit_records

    audit_path = tmp_path / "legacy.jsonl"
    monkeypatch.setenv("AURO_AUDIT_LOG", str(audit_path))
    records = [
        {
            "event": "legacy_probe",
            "reason": f"failed near {SYNTHETIC_SECRET}",
            "nested": {SYNTHETIC_SECRET: {"safe": "preserved"}},
        }
    ]

    assert write_audit_records(records) == []
    [persisted] = _read_jsonl(audit_path)
    assert persisted["schema_version"] == "1"
    UUID(persisted["event_id"])
    assert persisted["event"] == "legacy_probe"
    assert "preserved" in repr(persisted)
    assert SYNTHETIC_SECRET not in repr(persisted)
    assert SYNTHETIC_SECRET not in repr(persisted["redacted_fields"])


def test_nested_audit_runs_restore_outer_correlation(audit_events):
    """A nested run gets its own sequence without contaminating its caller."""
    from auro_runtime.audit import (
        begin_audit_run,
        end_audit_run,
        write_audit_event,
    )

    outer = begin_audit_run("outer-run")
    try:
        write_audit_event("outer_before")
        inner = begin_audit_run("inner-run")
        try:
            write_audit_event("inner")
        finally:
            end_audit_run(inner)
        write_audit_event("outer_after")
    finally:
        end_audit_run(outer)

    assert [
        (event["run_id"], event["sequence"])
        for event in audit_events
    ] == [
        ("outer-run", 1),
        ("inner-run", 1),
        ("outer-run", 2),
    ]


def test_plan_stage_audit_uses_the_pipeline_run_id(monkeypatch, registry, tmp_path):
    """Early Plan failures correlate with the result even before Execute collects."""
    from auro_runtime import orchestrator

    def model_must_not_run(**_kwargs):
        pytest.fail("model ran after directive planning had already failed")

    monkeypatch.setattr(orchestrator, "generate", model_must_not_run)
    result = orchestrator.run("missing_contract_directive", "benign request")
    events = _read_jsonl(tmp_path / "audit.jsonl")

    assert result["success"] is False
    assert result["meta"]["event"] == "directive_load_failed"
    assert len(events) == 1
    assert events[0]["event"] == "directive_load_failed"
    assert events[0]["run_id"] == result["meta"]["audit_run_id"]
    assert events[0]["sequence"] == 1


def test_bad_bulk_record_is_safe_and_does_not_block_later_events(
    monkeypatch, tmp_path
):
    """A malformed event fails closed while later valid records still persist."""
    from auro_runtime.audit import write_audit_records

    audit_path = tmp_path / "continue.jsonl"
    monkeypatch.setenv("AURO_AUDIT_LOG", str(audit_path))
    errors = write_audit_records(
        [
            {"not_event": f"unsafe {SYNTHETIC_SECRET}"},
            {"event": "valid_after_bad_record", "safe_detail": "preserved"},
        ]
    )

    assert errors == ["audit record could not be safely persisted"]
    [persisted] = _read_jsonl(audit_path)
    assert persisted["event"] == "valid_after_bad_record"
    assert persisted["safe_detail"] == "preserved"
    assert SYNTHETIC_SECRET not in repr(errors)
    assert SYNTHETIC_SECRET not in repr(persisted)


def test_structured_sanitizer_normalizes_supported_result_shapes():
    """Tuple, set, bytes, models, and exceptions become safe JSON primitives."""
    from pydantic import BaseModel

    from auro_runtime.sanitization import sanitize_value

    class Payload(BaseModel):
        label: str
        payload: str

    value = {
        "tuple": ("preserved", SYNTHETIC_SECRET),
        "set": {"preserved", SYNTHETIC_SECRET},
        "bytes": SYNTHETIC_SECRET.encode(),
        "model": Payload(label="preserved", payload=SYNTHETIC_SECRET),
        "error": RuntimeError(f"diagnostic {SYNTHETIC_SECRET}"),
    }
    safe = sanitize_value(value)

    encoded = json.dumps(safe)
    assert "preserved" in encoded
    assert "diagnostic" in encoded
    assert SYNTHETIC_SECRET not in encoded


def test_public_executor_scrubs_success_results_errors_and_logs(
    monkeypatch, make_tool_call, caplog
):
    """Direct execute() callers receive the same safe representation as the loop."""
    from auro_runtime import executor

    def return_payload():
        return {"status": "preserved", "payload": (SYNTHETIC_SECRET,)}

    def raise_payload():
        raise RuntimeError(f"preserved diagnostic {SYNTHETIC_SECRET}")

    monkeypatch.setitem(
        executor._REGISTRY,
        "contract_result_probe",
        (return_payload, "contract result probe", None),
    )
    monkeypatch.setitem(
        executor._REGISTRY,
        "contract_error_probe",
        (raise_payload, "contract error probe", None),
    )
    caplog.set_level(logging.WARNING, logger="auro_runtime.executor")

    success = executor.execute(
        make_tool_call("contract_result_probe"),
        allowed_tools={"contract_result_probe"},
    )
    failure = executor.execute(
        make_tool_call("contract_error_probe"),
        allowed_tools={"contract_error_probe"},
    )

    assert success.success is True
    assert success.result["status"] == "preserved"
    assert failure.success is False
    assert "preserved diagnostic" in failure.error
    assert SYNTHETIC_SECRET not in repr(success.model_dump())
    assert SYNTHETIC_SECRET not in repr(failure.model_dump())
    assert SYNTHETIC_SECRET not in caplog.text


def test_guard_verdicts_and_exceptions_are_safe(
    monkeypatch, make_tool_call, make_rule, audit_events
):
    """Custom guard output cannot escape through result or audit channels."""
    from auro_runtime import executor, guards

    monkeypatch.setitem(
        executor._REGISTRY,
        "contract_guard_probe",
        (lambda: {"status": "preserved"}, "contract guard probe", None),
    )

    def reject_with_payload(_context):
        return guards.GuardVerdict(
            allowed=False,
            message=f"preserved verdict {SYNTHETIC_SECRET}",
            code="contract_rejection",
            metadata={"payload": SYNTHETIC_SECRET, "status": "preserved"},
        )

    def raise_with_payload(_context):
        raise RuntimeError(f"preserved guard diagnostic {SYNTHETIC_SECRET}")

    monkeypatch.setitem(
        guards._GUARD_REGISTRY,
        "contract_reject_guard",
        reject_with_payload,
    )
    monkeypatch.setitem(
        guards._GUARD_REGISTRY,
        "contract_raise_guard",
        raise_with_payload,
    )
    rejected = executor.execute(
        make_tool_call("contract_guard_probe"),
        allowed_tools={"contract_guard_probe"},
        policy_rules=[
            make_rule(
                guard="contract_reject_guard",
                rule_id="contract_reject_rule",
            )
        ],
    )
    errored = executor.execute(
        make_tool_call("contract_guard_probe"),
        allowed_tools={"contract_guard_probe"},
        policy_rules=[
            make_rule(
                guard="contract_raise_guard",
                rule_id="contract_raise_rule",
            )
        ],
    )

    assert "preserved verdict" in rejected.error
    assert "Failing closed" in errored.error
    assert SYNTHETIC_SECRET not in repr(rejected.model_dump())
    assert SYNTHETIC_SECRET not in repr(errored.model_dump())
    assert {event["event"] for event in audit_events} == {
        "policy_guard_check",
        "policy_guard_error",
    }
    assert "preserved" in repr(audit_events)
    assert SYNTHETIC_SECRET not in repr(audit_events)
    guard_check = next(
        event for event in audit_events if event["event"] == "policy_guard_check"
    )
    guard_error = next(
        event for event in audit_events if event["event"] == "policy_guard_error"
    )
    assert "$.message" in guard_check["redacted_fields"]
    assert "$.verdict_metadata.payload" in guard_check["redacted_fields"]
    assert guard_error["redacted_fields"] == ["$.error"]


def test_classifier_limit_is_explicit_but_sensitive_key_provenance_still_scrubs():
    """Unknown shapes need provenance; pattern matching is not called omniscient."""
    from auro_runtime.sanitization import sanitize_value, secret_kind

    opaque_value = "opaque-short-format"
    assert secret_kind(opaque_value) is None
    safe = sanitize_value(
        {
            "token": opaque_value,
            "ordinary_note": opaque_value,
        }
    )
    assert safe["token"] == "[REDACTED]"
    assert safe["ordinary_note"] == opaque_value


def test_tool_call_and_result_are_safe_in_transcript_model_context_and_audit(
    monkeypatch, registry, tmp_path
):
    """Blocked inputs and successful outputs cannot cross any loop representation."""
    from auro_runtime import executor, orchestrator
    from auro_runtime.schemas import DirectiveMetadata

    def return_payload(message):
        return {"status": "preserved", "payload": SYNTHETIC_SECRET, "message": message}

    monkeypatch.setitem(
        executor._REGISTRY,
        "contract_loop_probe",
        (return_payload, "contract loop probe", None),
    )
    responses = iter(
        [
            json.dumps(
                {
                    "tool": "contract_loop_probe",
                    "args": {"message": "benign"},
                    "reason": "preserved reason",
                }
            ),
            json.dumps({"done": True, "summary": "preserved summary"}),
        ]
    )
    model_inputs = []

    def fake_generate(*, system_prompt, user_message):
        model_inputs.append({"system": system_prompt, "user": user_message})
        return next(responses)

    monkeypatch.setattr(orchestrator, "generate", fake_generate)
    meta = DirectiveMetadata(
        id="contract_loop",
        description="contract loop",
        tools=["contract_loop_probe"],
    )
    result = orchestrator.run(
        "contract_loop",
        "benign request",
        override_directive=(meta, "Run the contract probe."),
    )

    assert result["success"] is True
    assert result["final_summary"] == "preserved summary"
    assert result["legacy_steps"][0]["result"]["status"] == "preserved"
    assert "preserved" in model_inputs[1]["user"]
    assert SYNTHETIC_SECRET not in repr(result)
    assert SYNTHETIC_SECRET not in repr(model_inputs)
    assert SYNTHETIC_SECRET not in repr(_read_jsonl(tmp_path / "audit.jsonl"))


def test_raw_request_and_blocked_reason_are_scrubbed_before_outbound_use(
    monkeypatch, registry, tmp_path
):
    """A refused value is absent from model context, transcript, steps, and audit."""
    from auro_runtime import orchestrator
    from auro_runtime.schemas import DirectiveMetadata

    model_inputs = []
    responses = iter(
        [
            json.dumps(
                {
                    "tool": "echo",
                    "args": {"message": SYNTHETIC_SECRET},
                    "reason": f"attempt with {SYNTHETIC_SECRET}",
                }
            ),
            json.dumps({"done": True, "summary": "preserved summary"}),
        ]
    )

    def fake_generate(*, system_prompt, user_message):
        model_inputs.append({"system": system_prompt, "user": user_message})
        return next(responses)

    monkeypatch.setattr(orchestrator, "generate", fake_generate)
    meta = DirectiveMetadata(
        id="contract_block",
        description="contract block",
        tools=["echo"],
    )
    result = orchestrator.run(
        "contract_block",
        f"preserved request {SYNTHETIC_SECRET}",
        override_directive=(meta, "Run the contract probe."),
    )

    assert result["success"] is True
    assert "preserved request" in repr(result)
    assert SYNTHETIC_SECRET not in repr(result)
    assert SYNTHETIC_SECRET not in repr(model_inputs)
    events = _read_jsonl(tmp_path / "audit.jsonl")
    assert any(event["event"] == "policy_guard_check" for event in events)
    assert SYNTHETIC_SECRET not in repr(events)
    assert result["meta"]["audit_run_id"] == events[0]["run_id"]
    assert [event["sequence"] for event in events] == sorted(
        event["sequence"] for event in events
    )


def test_router_reason_and_backend_exception_are_safe(monkeypatch, registry, caplog):
    """Pre-tool router and backend failures use the same outbound scrub contract."""
    from auro_runtime import orchestrator
    from auro_runtime.schemas import DirectiveMetadata

    monkeypatch.setattr(
        orchestrator,
        "generate",
        lambda **_kwargs: json.dumps(
            {
                "decision": "multiple",
                "candidates": [
                    {
                        "directive_id": "tool_catalog",
                        "reason": f"preserved candidate {SYNTHETIC_SECRET}",
                    }
                ],
                "reason": f"preserved overall {SYNTHETIC_SECRET}",
            }
        ),
    )
    routed = orchestrator.route_and_run("benign routing request")
    assert routed["meta"]["event"] == "router_multiple"
    assert "preserved candidate" in repr(routed)
    assert SYNTHETIC_SECRET not in repr(routed)

    def fail_backend(**_kwargs):
        raise RuntimeError(f"preserved backend diagnostic {SYNTHETIC_SECRET}")

    monkeypatch.setattr(orchestrator, "generate", fail_backend)
    caplog.set_level(logging.WARNING, logger="auro_runtime.orchestrator")
    meta = DirectiveMetadata(
        id="contract_backend",
        description="contract backend",
        tools=[],
    )
    failed = orchestrator.run(
        "contract_backend",
        "benign request",
        override_directive=(meta, "Complete without tools."),
    )
    assert failed["success"] is False
    assert failed["meta"]["event"] == "model_backend_error"
    assert "preserved backend diagnostic" in failed["error"]
    assert SYNTHETIC_SECRET not in repr(failed)
    assert SYNTHETIC_SECRET not in caplog.text


def test_mcp_errors_use_the_same_safe_outbound_contract(monkeypatch):
    """MCP refusal and exception responses cannot bypass the runtime scrub."""
    from auro_runtime import mcp_server

    monkeypatch.setattr(mcp_server, "_ALLOWED_DIRECTIVE_IDS", frozenset())
    refused = asyncio.run(
        mcp_server.run_directive(SYNTHETIC_SECRET, "benign request")
    )
    assert refused["meta"]["event"] == "directive_not_exposed"
    assert SYNTHETIC_SECRET not in repr(refused)

    monkeypatch.setattr(
        mcp_server,
        "_ALLOWED_DIRECTIVE_IDS",
        frozenset({"contract_mcp"}),
    )

    def fail_runtime(*_args, **_kwargs):
        raise RuntimeError(f"preserved MCP diagnostic {SYNTHETIC_SECRET}")

    monkeypatch.setattr(mcp_server, "orchestrator_run", fail_runtime)
    failed = asyncio.run(
        mcp_server.run_directive("contract_mcp", "benign request")
    )
    assert "preserved MCP diagnostic" in failed["error"]
    assert SYNTHETIC_SECRET not in repr(failed)


@pytest.mark.slow
def test_cli_json_and_audit_are_safe(run_cli, repo_root):
    """The real CLI serialization and persisted JSONL share the scrub contract."""
    result, proc = run_cli(
        "create_directive",
        "benign CLI request",
        script=[
            {
                "tool": "echo",
                "args": {"message": SYNTHETIC_SECRET},
                "reason": f"preserved CLI reason {SYNTHETIC_SECRET}",
            },
            {"done": True, "summary": "preserved CLI summary"},
        ],
    )

    assert proc.returncode == 0
    assert result["success"] is True
    assert "preserved CLI reason" in repr(result)
    assert SYNTHETIC_SECRET not in proc.stdout
    assert SYNTHETIC_SECRET not in proc.stderr
    assert SYNTHETIC_SECRET not in repr(result)
    events = _read_jsonl(repo_root / "tests" / ".test_audit.jsonl")
    assert any(event["event"] == "policy_guard_check" for event in events)
    assert SYNTHETIC_SECRET not in repr(events)
