"""Versioned, secret-safe JSONL audit events.

The sink remains best-effort local JSONL; it is not an immutable event store.
Every public write path normalizes through the same defensive boundary before
an event reaches a collector or a file.
"""

from __future__ import annotations

import json
import logging
import os
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from auro_runtime.paths import get_workspace_root
from auro_runtime.sanitization import sanitize_with_report, scrub_text
from auro_runtime.schemas import AuditEvent

logger = logging.getLogger("auro_runtime.audit")

_AUDIT_ENV = "AURO_AUDIT_LOG"
_DEFAULT_FILENAME = "auro_audit.jsonl"
_RESERVED_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "run_id",
        "sequence",
        "step_index",
        "timestamp",
        "event",
        "redacted_fields",
    }
)

_audit_collector: ContextVar[list[dict] | None] = ContextVar(
    "audit_collector", default=None
)
_audit_run_id: ContextVar[str | None] = ContextVar("audit_run_id", default=None)
_audit_sequence: ContextVar[int] = ContextVar("audit_sequence", default=0)
# Which orchestrator step the events being written belong to. Zero-based, to
# match RunMessage.step_index so audit lines join to the returned transcript.
# None when no step owns the event: outside a run, or on a direct execute().
_audit_step: ContextVar[int | None] = ContextVar("audit_step", default=None)


@dataclass(frozen=True)
class AuditRunContext:
    """Tokens needed to restore a possibly nested audit-run context."""

    run_id: str
    run_token: Any
    sequence_token: Any
    step_token: Any


def begin_audit_run(run_id: str | None = None) -> AuditRunContext:
    """Begin a correlated audit run and return a token-managed context."""
    resolved = run_id or str(uuid4())
    run_token = _audit_run_id.set(resolved)
    sequence_token = _audit_sequence.set(0)
    step_token = _audit_step.set(None)
    return AuditRunContext(
        run_id=resolved,
        run_token=run_token,
        sequence_token=sequence_token,
        step_token=step_token,
    )


def end_audit_run(context: AuditRunContext) -> None:
    """Restore the audit context that existed before ``begin_audit_run``."""
    _audit_step.reset(context.step_token)
    _audit_sequence.reset(context.sequence_token)
    _audit_run_id.reset(context.run_token)


def get_audit_run_id() -> str | None:
    """Return the active correlated run id, if this execution boundary set one."""
    return _audit_run_id.get()


def set_audit_step(step: int | None) -> None:
    """Attribute subsequent events to one orchestrator step. None clears it."""
    _audit_step.set(step)


def get_audit_step() -> int | None:
    """Return the step events are currently attributed to, if any."""
    return _audit_step.get()


def set_audit_collector(collector: list[dict] | None) -> None:
    """Set the collector used by the pipeline Execute stage."""
    _audit_collector.set(collector)


def get_audit_collector() -> list[dict] | None:
    """Return the current audit collector, if any."""
    return _audit_collector.get(None)


def _audit_path() -> Path:
    p = os.environ.get(_AUDIT_ENV)
    if p:
        return Path(p)
    return get_workspace_root() / _DEFAULT_FILENAME


def _next_sequence() -> int | None:
    if _audit_run_id.get() is None:
        return None
    sequence = _audit_sequence.get() + 1
    _audit_sequence.set(sequence)
    return sequence


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _normalize_audit_record(
    raw_record: object,
    *,
    runtime_owned_envelope: bool,
) -> dict[str, Any]:
    """Create an idempotent, JSON-safe v1 record without unsafe fallbacks."""
    safe_record, newly_redacted = sanitize_with_report(raw_record)
    if not isinstance(safe_record, dict):
        raise TypeError("audit record must be an object")

    existing_redacted = safe_record.get("redacted_fields", [])
    if not isinstance(existing_redacted, list):
        existing_redacted = [existing_redacted]
    redacted_fields = sorted(
        {
            str(path)
            for path in [*existing_redacted, *newly_redacted]
            if path is not None
        }
    )

    if runtime_owned_envelope:
        details = {
            key: value
            for key, value in safe_record.items()
            if key not in _RESERVED_FIELDS
        }
        event = safe_record.get("event")
        payload = {
            **details,
            "schema_version": "1",
            "event_id": str(uuid4()),
            "run_id": _audit_run_id.get(),
            "sequence": _next_sequence(),
            "step_index": _audit_step.get(),
            "timestamp": _now(),
            "event": event,
            "redacted_fields": redacted_fields,
        }
    else:
        payload = dict(safe_record)
        payload["schema_version"] = "1"
        payload["event_id"] = (
            safe_record.get("event_id")
            if isinstance(safe_record.get("event_id"), str)
            and safe_record.get("event_id")
            else str(uuid4())
        )
        payload["run_id"] = (
            safe_record.get("run_id")
            if isinstance(safe_record.get("run_id"), str)
            else _audit_run_id.get()
        )
        existing_sequence = safe_record.get("sequence")
        payload["sequence"] = (
            existing_sequence
            if isinstance(existing_sequence, int) and existing_sequence >= 1
            else _next_sequence()
        )
        # step_index is zero-based, so 0 is a real value and the floor is >= 0.
        existing_step = safe_record.get("step_index")
        payload["step_index"] = (
            existing_step
            if isinstance(existing_step, int) and existing_step >= 0
            else _audit_step.get()
        )
        payload["timestamp"] = (
            safe_record.get("timestamp")
            if isinstance(safe_record.get("timestamp"), str)
            and safe_record.get("timestamp")
            else _now()
        )
        payload["redacted_fields"] = redacted_fields

    if not isinstance(payload.get("event"), str) or not payload["event"]:
        raise ValueError("audit event must be a non-empty string")
    return AuditEvent.model_validate(payload).model_dump(mode="json")


def write_audit_event(event: str, **kwargs: object) -> None:
    """Append one normalized event to the collector or JSONL sink."""
    try:
        record = _normalize_audit_record(
            {"event": event, **kwargs},
            runtime_owned_envelope=True,
        )
    except Exception:
        # Never serialize the rejected raw value or its validation exception.
        return

    collector = _audit_collector.get(None)
    if collector is not None:
        collector.append(record)
        return

    try:
        with open(_audit_path(), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError as exc:
        # The sink stays best-effort: trouble writing the log must not interrupt
        # the run being logged. Failing silently, though, left a lost record and
        # a rejected one indistinguishable in the file -- both are just a gap in
        # sequence. The record's own fields are not logged: it may carry context
        # that is redacted but still sensitive, and the operator needs to know a
        # write failed rather than what was in it.
        logger.warning(
            "audit_write_failed: event=%s run_id=%s error=%s",
            record.get("event"),
            record.get("run_id"),
            scrub_text(str(exc)),
        )


def write_audit_records(records: list[dict]) -> list[str]:
    """Re-normalize and persist records; continue safely after bad entries."""
    path = _audit_path()
    errors: list[str] = []
    written = 0
    rejected = 0
    try:
        with open(path, "a", encoding="utf-8") as handle:
            for raw_record in records:
                # Normalization and the write are separated deliberately. Folding
                # them into one try treated a failed write as a malformed record,
                # which conflates the two cases this log is supposed to keep
                # apart: a record that was never valid, and one that was valid
                # and is now lost. A write failure belongs to the OSError branch.
                try:
                    record = _normalize_audit_record(
                        raw_record,
                        runtime_owned_envelope=False,
                    )
                except Exception:
                    rejected += 1
                    errors.append("audit record could not be safely persisted")
                    continue
                handle.write(json.dumps(record) + "\n")
                written += 1
    except OSError as exc:
        # This string reaches the caller through PersistResult and then the run
        # result, so it must not carry the sink's path: scrub_text removes secret
        # patterns, not filesystem layout. Full detail goes to the operator log.
        lost = len(records) - written - rejected
        logger.warning(
            "audit_batch_write_failed: lost=%d of=%d path_error=%s",
            lost,
            len(records),
            scrub_text(str(exc)),
        )
        errors.append(
            f"audit sink unavailable ({type(exc).__name__}); "
            f"{lost} of {len(records)} record(s) not persisted"
        )
    return errors
