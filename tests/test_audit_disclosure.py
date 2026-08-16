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


def test_file_events_audit_relative_paths_that_correlate(repo_root, temp_output_file, audit_events):
    """The audit trail names a file the same way each time, and never absolutely."""
    from pathlib import Path

    from runtime_tools.file_tools import delete_file, restore_file, write_file

    rel = temp_output_file("output/__auro_restore_relpath__.txt")
    write_file(rel, "correlate me")
    deleted = delete_file(rel)
    restore_file(archive_name=deleted["archive_path"])

    by_event = {event["event"]: event for event in audit_events}
    restored_to = by_event["file_restored"]["restored_to"]
    # An absolute path here would disclose the deployment's filesystem layout to
    # anything consuming the log.
    assert not Path(restored_to).is_absolute()
    assert str(repo_root) not in restored_to
    # All three events describe one file, so an operator can follow it through.
    assert restored_to == Path(rel).as_posix()
    assert by_event["file_written"]["path"] == rel
    assert by_event["file_soft_deleted"]["path"] == rel


def test_a_failed_batch_write_is_reported_and_names_no_path(monkeypatch, tmp_path, caplog):
    """Losing the trail must be visible to the caller, without leaking the sink's path."""
    from auro_runtime.audit import write_audit_records

    # A directory cannot be opened for append, so the whole batch is lost.
    blocked = tmp_path / "not_a_file"
    blocked.mkdir()
    monkeypatch.setenv("AURO_AUDIT_LOG", str(blocked))

    with caplog.at_level(logging.WARNING, logger="auro_runtime.audit"):
        errors = write_audit_records([{"event": "probe_one"}, {"event": "probe_two"}])

    assert len(errors) == 1
    assert "2 of 2 record(s) not persisted" in errors[0]
    # This string reaches the caller in meta, so the sink's path must not be in it.
    assert str(blocked) not in errors[0]
    assert str(tmp_path) not in errors[0]
    # The operator's log is where the detail belongs.
    assert "audit_batch_write_failed" in caplog.text


def test_a_rejected_record_is_not_counted_as_a_lost_one(monkeypatch, tmp_path):
    """A record that was never valid is a different failure from one that is gone."""
    from auro_runtime.audit import write_audit_records

    audit_path = tmp_path / "mixed.jsonl"
    monkeypatch.setenv("AURO_AUDIT_LOG", str(audit_path))

    # An empty event name fails normalization; the other two are well-formed.
    errors = write_audit_records(
        [{"event": "good_one"}, {"event": ""}, {"event": "good_two"}]
    )

    assert errors == ["audit record could not be safely persisted"]
    # The valid records still reach the file: one bad entry does not sink the batch.
    assert [event["event"] for event in _read_jsonl(audit_path)] == ["good_one", "good_two"]


def test_a_swallowed_single_write_failure_reaches_the_operator_log(monkeypatch, tmp_path, caplog):
    """write_audit_event stays best-effort, but no longer fails invisibly."""
    from auro_runtime.audit import begin_audit_run, end_audit_run, write_audit_event

    blocked = tmp_path / "also_a_directory"
    blocked.mkdir()
    monkeypatch.setenv("AURO_AUDIT_LOG", str(blocked))

    context = begin_audit_run("run-lost")
    try:
        with caplog.at_level(logging.WARNING, logger="auro_runtime.audit"):
            # Must not raise: audit trouble cannot interrupt the run being audited.
            write_audit_event("policy_guard_check", tool="read_file", allowed=False)
    finally:
        end_audit_run(context)

    assert "audit_write_failed" in caplog.text
    assert "policy_guard_check" in caplog.text
    assert "run-lost" in caplog.text


def test_a_run_whose_audit_trail_was_lost_says_so_in_its_result(monkeypatch, tmp_path):
    """The reporting is only worth building if the caller actually receives it."""
    from auro_runtime.pipeline import PipelinePlugins, run_pipeline
    from auro_runtime.pipeline.contract import IntakeResult, Plan, VerifyResult
    from auro_runtime.pipeline.plugins.default import DefaultPersist
    from auro_runtime.schemas import DirectiveMetadata, RunResult

    blocked = tmp_path / "sink_is_a_directory"
    blocked.mkdir()
    monkeypatch.setenv("AURO_AUDIT_LOG", str(blocked))

    meta = DirectiveMetadata(id="probe", description="", tools=[], category="system")
    plan = Plan(
        directive_id="probe",
        directive_meta=meta,
        directive_body="",
        user_request="probe",
        policies_text="",
        allowed_tools=set(),
        max_steps=1,
    )

    class StubIntake:
        def intake(self, raw_input, content_type=None):
            return IntakeResult(text=str(raw_input), source="text", metadata={})

    class StubPlan:
        def plan(self, intake_result, context):
            return plan

    class StubExecute:
        def execute(self, plan, runtime):
            # One real audit event, so the flush has something to lose.
            write_audit_event("probe_event", tool="echo")
            return RunResult(success=True, messages=[], final_summary="ok", error=None, meta={})

    class StubVerify:
        def verify(self, intake_result, plan, execute_result):
            return VerifyResult(passed=True, checks=[], block_persist=False)

    from auro_runtime.audit import write_audit_event

    result = run_pipeline(
        "probe",
        directive_id="probe",
        plugins=PipelinePlugins(
            intake=StubIntake(),
            plan=StubPlan(),
            execute=StubExecute(),
            verify=StubVerify(),
            persist=DefaultPersist(),
        ),
    )

    assert result["meta"]["audit_persisted"] is False
    assert result["meta"]["audit_errors"], "a lost audit trail must reach the caller"
    assert "not persisted" in result["meta"]["audit_errors"][0]
    # The run itself still succeeded: audit trouble does not fail the run.
    assert result["success"] is True
    # And the sink's path stays out of the caller-visible result.
    assert str(blocked) not in json.dumps(result["meta"])


def test_a_healthy_run_reports_its_audit_trail_persisted(monkeypatch, tmp_path):
    """Negative control: audit_persisted must not be False for everyone."""
    from auro_runtime.pipeline import PipelinePlugins, run_pipeline
    from auro_runtime.pipeline.contract import IntakeResult, Plan, VerifyResult
    from auro_runtime.pipeline.plugins.default import DefaultPersist
    from auro_runtime.schemas import DirectiveMetadata, RunResult

    audit_path = tmp_path / "healthy.jsonl"
    monkeypatch.setenv("AURO_AUDIT_LOG", str(audit_path))

    meta = DirectiveMetadata(id="probe", description="", tools=[], category="system")
    plan = Plan(
        directive_id="probe",
        directive_meta=meta,
        directive_body="",
        user_request="probe",
        policies_text="",
        allowed_tools=set(),
        max_steps=1,
    )

    class StubIntake:
        def intake(self, raw_input, content_type=None):
            return IntakeResult(text=str(raw_input), source="text", metadata={})

    class StubPlan:
        def plan(self, intake_result, context):
            return plan

    class StubExecute:
        def execute(self, plan, runtime):
            return RunResult(success=True, messages=[], final_summary="ok", error=None, meta={})

    class StubVerify:
        def verify(self, intake_result, plan, execute_result):
            return VerifyResult(passed=True, checks=[], block_persist=False)

    result = run_pipeline(
        "probe",
        directive_id="probe",
        plugins=PipelinePlugins(
            intake=StubIntake(),
            plan=StubPlan(),
            execute=StubExecute(),
            verify=StubVerify(),
            persist=DefaultPersist(),
        ),
    )

    assert result["meta"]["audit_persisted"] is True
    assert "audit_errors" not in result["meta"]


def test_soft_delete_and_permanent_prune_are_distinct_events(repo_root, temp_output_file, audit_events):
    """The recoverable move and the irreversible unlink must not look alike in the log."""
    import os
    import time

    from runtime_tools import file_tools
    from runtime_tools.file_tools import delete_file, write_file

    rel = temp_output_file("output/__auro_prune_audit__.txt")
    write_file(rel, "prune me")
    deleted = delete_file(rel)
    archive_name = deleted["archive_path"]
    archive_path = repo_root / file_tools._ARCHIVE_DIR_NAME / archive_name

    soft = [event for event in audit_events if event["event"] == "file_soft_deleted"]
    assert len(soft) == 1
    # The file is still on disk: this event must not claim it was destroyed.
    assert archive_path.exists()
    assert soft[0]["retention_days"] == file_tools._ARCHIVE_MAX_AGE_DAYS
    assert not any(event["event"] == "archive_pruned" for event in audit_events)

    # Age the archive past the cutoff so the next prune genuinely unlinks it.
    stale = time.time() - ((file_tools._ARCHIVE_MAX_AGE_DAYS + 1) * 86400)
    os.utime(archive_path, (stale, stale))
    audit_events.clear()

    file_tools._prune_archive()

    assert not archive_path.exists(), "the probe must actually destroy the file"
    pruned = [event for event in audit_events if event["event"] == "archive_pruned"]
    assert len(pruned) == 1, "irreversible destruction must leave a record"
    assert archive_name in pruned[0]["expired"]
    assert pruned[0]["pruned"] >= 1


def test_a_prune_that_destroys_nothing_writes_nothing(repo_root, temp_output_file, audit_events):
    """Negative control: the event must mean destruction, not that prune ran."""
    from runtime_tools import file_tools
    from runtime_tools.file_tools import delete_file, write_file

    rel = temp_output_file("output/__auro_prune_quiet__.txt")
    write_file(rel, "keep me")
    delete_file(rel)
    audit_events.clear()

    file_tools._prune_archive()

    assert not any(event["event"] == "archive_pruned" for event in audit_events)


def test_audit_event_catalogue_is_current(repo_root):
    """
    docs/AUDIT_EVENTS.md is generated from the write_audit_event call sites.
    docs/API.md calls `event` the grouping key, so the set of keys is part of
    the contract; a stale list sends an integrator grouping on a name the
    runtime stopped emitting.

    Regenerate with: python -m tests.audit_catalogue
    """
    from tests.audit_catalogue import collect, render

    catalogue = repo_root / "docs" / "AUDIT_EVENTS.md"
    assert catalogue.is_file(), "docs/AUDIT_EVENTS.md missing — run: python -m tests.audit_catalogue"
    assert catalogue.read_text(encoding="utf-8") == render(collect()), (
        "docs/AUDIT_EVENTS.md is stale. Regenerate with: python -m tests.audit_catalogue"
    )


def test_audit_catalogue_would_detect_a_renamed_event(repo_root):
    """
    Negative control. A drift check that cannot fail proves nothing, and the
    change this exists to catch is exactly a rename: file_deleted became
    file_soft_deleted on 2026-08-08 because the old name claimed a destruction
    that had not happened.
    """
    from tests.audit_catalogue import collect, render

    committed = (repo_root / "docs" / "AUDIT_EVENTS.md").read_text(encoding="utf-8")
    catalogue = collect()
    renamed = [
        ("zz_probe_renamed", modules, fields, complete) if event == "file_soft_deleted"
        else (event, modules, fields, complete)
        for event, modules, fields, complete in catalogue
    ]
    assert any(event == "zz_probe_renamed" for event, _m, _f, _c in renamed), (
        "file_soft_deleted is no longer in the catalogue — this control needs updating"
    )
    assert render(renamed) != committed, (
        "renaming an event produced byte-identical output — "
        "the drift check cannot detect a renamed event"
    )


def test_audit_catalogue_refuses_a_non_literal_event_name(tmp_path, monkeypatch):
    """
    An event name assembled at runtime cannot be documented, grouped on, or
    alerted on. Generation must halt rather than emit a catalogue that silently
    omits it, which would read as complete while an event went unnamed.
    """
    from tests import audit_catalogue

    fake = tmp_path / "auro_runtime"
    fake.mkdir()
    (fake / "probe.py").write_text(
        "from auro_runtime.audit import write_audit_event\n"
        "def go(name):\n"
        "    write_audit_event(name, tool='echo')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(audit_catalogue, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(audit_catalogue, "SOURCE_DIRS", ("auro_runtime",))

    with pytest.raises(audit_catalogue.UncatalogableEvent) as excinfo:
        audit_catalogue.collect()
    assert "not a literal string" in str(excinfo.value)


def test_step_index_attributes_events_and_survives_persistence(monkeypatch, tmp_path, audit_events):
    """An event carries the step that owns it, and keeps it when flushed to file."""
    from auro_runtime.audit import (
        begin_audit_run,
        end_audit_run,
        set_audit_step,
        write_audit_event,
        write_audit_records,
    )

    audit_path = tmp_path / "steps.jsonl"
    monkeypatch.setenv("AURO_AUDIT_LOG", str(audit_path))
    context = begin_audit_run("run-steps")
    try:
        write_audit_event("before_any_step")
        set_audit_step(0)
        write_audit_event("first_step_guard")
        write_audit_event("first_step_result")
        set_audit_step(1)
        write_audit_event("second_step_guard")
    finally:
        end_audit_run(context)

    # Zero is a real step, so it must survive as 0 and not collapse to null.
    assert [event["step_index"] for event in audit_events] == [None, 0, 0, 1]
    # Several events share one step; sequence still separates them.
    assert [event["sequence"] for event in audit_events] == [1, 2, 3, 4]

    assert write_audit_records(audit_events) == []
    persisted = _read_jsonl(audit_path)
    assert [event["step_index"] for event in persisted] == [None, 0, 0, 1]


def test_step_index_does_not_leak_across_runs(audit_events):
    """A run that ends restores the step its caller was on, including None."""
    from auro_runtime.audit import (
        begin_audit_run,
        end_audit_run,
        get_audit_step,
        set_audit_step,
        write_audit_event,
    )

    outer = begin_audit_run("outer-steps")
    try:
        set_audit_step(4)
        inner = begin_audit_run("inner-steps")
        try:
            # A nested run starts unattributed rather than inheriting step 4.
            assert get_audit_step() is None
            write_audit_event("inner_before_step")
            set_audit_step(0)
            write_audit_event("inner_first_step")
        finally:
            end_audit_run(inner)
        assert get_audit_step() == 4
        write_audit_event("outer_after")
    finally:
        end_audit_run(outer)

    assert get_audit_step() is None
    by_event = {event["event"]: event for event in audit_events}
    assert by_event["inner_before_step"]["step_index"] is None
    assert by_event["inner_first_step"]["step_index"] == 0
    assert by_event["outer_after"]["step_index"] == 4


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
        allowed_tools={"contract_result_probe"}, policy_rules=executor.UNRESTRICTED, run_history=[],
    )
    failure = executor.execute(
        make_tool_call("contract_error_probe"),
        allowed_tools={"contract_error_probe"}, policy_rules=executor.UNRESTRICTED, run_history=[],
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
        ], run_history=[],
    )
    errored = executor.execute(
        make_tool_call("contract_guard_probe"),
        allowed_tools={"contract_guard_probe"},
        policy_rules=[
            make_rule(
                guard="contract_raise_guard",
                rule_id="contract_raise_rule",
            )
        ], run_history=[],
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
