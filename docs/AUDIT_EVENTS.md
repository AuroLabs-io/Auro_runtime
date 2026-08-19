# Audit event catalogue

**27 event names** are emitted by the runtime.

Generated from the `write_audit_event` call sites by
`python -m tests.audit_catalogue`. Do not edit by hand.

`event` is the grouping key in every audit record. These are its values.
Each record also carries the eight-field envelope described in
[`docs/API.md`](API.md); the fields listed here are the event-specific ones
that sit beside it.

Two things this list does not cover. Records passed to `write_audit_records`
by an embedding application carry whatever `event` that caller chose. And an
event appears here because the runtime can emit it, not because it will:
a guard that approves returns `None` and writes nothing.

| Event | Emitted from | Event-specific fields |
|---|---|---|
| `archive_pruned` | `runtime_tools/file_tools.py` | `expired`, `max_size_mb`, `over_capacity`, `pruned`, `retention_days` |
| `argument_validation_failed` | `auro_runtime/executor.py` | `args`, `directive_id`, `error`, `reason`, `tool`, `validation_error` |
| `completion_shape_rejected` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `response_data` |
| `directive_load_failed` | `auro_runtime/orchestrator.py` | `directive_id`, `error` |
| `directive_not_exposed` | `auro_runtime/mcp_server.py` | `allowed_directive_ids`, `directive_id`, `error` |
| `file_restored` | `runtime_tools/file_tools.py` | `archive`, `restored_to` |
| `file_soft_deleted` | `runtime_tools/file_tools.py` | `archive`, `path`, `retention_days` |
| `file_written` | `runtime_tools/file_tools.py` | `backed_up`, `path`, `size` |
| `incomplete_execution_context` | `auro_runtime/executor.py` | `directive_id`, `error`, `missing`, `tool` |
| `incomplete_policy_profile` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `policies_dir`, `policy_profile` |
| `invalid_tool_call_shape` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `response_data` |
| `max_steps_reached` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `max_steps`, `steps_count` |
| `model_backend_error` | `auro_runtime/orchestrator.py` | `directive_id`, `error` |
| `no_enforceable_policies` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `policies_dir` |
| `parse_json_failed` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `response_length` |
| `policies_dir_missing` | `auro_runtime/orchestrator.py` | `directive_id`, `error`, `policies_dir` |
| `policy_guard_check` | `auro_runtime/executor.py` | `allowed`, `code`, `directive_id`, `enforcement`, `guard`, `message`, `reason`, `redacted_args`, `rule_id`, `tool`, `verdict_metadata` |
| `policy_guard_error` | `auro_runtime/executor.py` | `directive_id`, `error`, `guard`, `on_error`, `rule_id`, `tool` |
| `policy_guard_missing` | `auro_runtime/executor.py` | `directive_id`, `error`, `guard`, `on_error`, `rule_id`, `tool` |
| `policy_validation_failed` | `auro_runtime/orchestrator.py` | `directive_id`, `error` |
| `resource_classification` | `auro_runtime/resource_plan.py` | `category`, `directive_id`, `origin`, `outcome`, `role`, `subjects`, `tool` |
| `router_backend_error` | `auro_runtime/orchestrator.py` | `error` |
| `tool_execution_error` | `auro_runtime/executor.py` | `args`, `directive_id`, `error`, `reason`, `tool` |
| `tool_not_allowed` | `auro_runtime/executor.py` | `allowed_tools`, `directive_id`, `error`, `reason`, `tool` |
| `tool_type_error` | `auro_runtime/executor.py` | `args`, `directive_id`, `error`, `reason`, `tool` |
| `unguarded_mode_enabled` | `auro_runtime/orchestrator.py` | `directive_id`, `policies_dir`, `policy_profile` |
| `unknown_tool` | `auro_runtime/executor.py` | `directive_id`, `error`, `reason`, `registered`, `tool` |

---

## `auro_runtime/executor.py`

Refusals and failures from the tool-call pipeline.

- `argument_validation_failed`
- `incomplete_execution_context`
- `policy_guard_check`
- `policy_guard_error`
- `policy_guard_missing`
- `tool_execution_error`
- `tool_not_allowed`
- `tool_type_error`
- `unknown_tool`

---

## `auro_runtime/mcp_server.py`

Server-side exposure refusals.

- `directive_not_exposed`

---

## `auro_runtime/orchestrator.py`

Model-loop and directive-resolution failures.

- `completion_shape_rejected`
- `directive_load_failed`
- `incomplete_policy_profile`
- `invalid_tool_call_shape`
- `max_steps_reached`
- `model_backend_error`
- `no_enforceable_policies`
- `parse_json_failed`
- `policies_dir_missing`
- `policy_validation_failed`
- `router_backend_error`
- `unguarded_mode_enabled`

---

## `runtime_tools/file_tools.py`

Changes the runtime made to files on disk.

- `archive_pruned`
- `file_restored`
- `file_soft_deleted`
- `file_written`
