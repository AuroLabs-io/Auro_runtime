---
id: debug_research
description: Analyze recent system failure logs and report where failures occur with statistics
tools: [list_dir, read_file]
category: system
---

# Debug research

## Purpose
Analyze the structured audit log of system failures (from the orchestrator and executor), identify where failures are happening, and produce a clear report with statistics. The report can be used by humans or fed to the active_debug directive for suggested fixes.

## Steps

1. **Locate the audit file** — The default path is `auro_audit.jsonl` in the project root. The path can be overridden by the environment variable `AURO_AUDIT_LOG`. The user may also specify a different path in their request. Use `list_dir` on the project root (e.g. `.` or the path the user gives) to confirm the file exists. If the user did not specify a path, use `auro_audit.jsonl` in the current or project root.

2. **Read and parse** — Use `read_file` to load the audit file. The format is JSONL: one JSON object per line. Each line has at least: `timestamp`, `event`, and often `tool`, `directive_id`, `error`, and other fields (e.g. `validation_error`, `allowed_tools`, `args`). Parse each line with JSON; skip or note any malformed lines.

3. **Aggregate** — Group events by:
   - **Event type** (e.g. `argument_validation_failed`, `tool_not_allowed`, `tool_execution_error`, `tool_type_error`, `parse_json_failed`, `invalid_tool_call_shape`, `max_steps_reached`, `model_refused`, `response_format_reminded`).
   - **Tool** (when the event has a `tool` field).
   - **Directive** (when the event has a `directive_id` field).

4. **Compute statistics** — For each group, count occurrences. Optionally restrict to a time window (e.g. last 24 hours or last N events) if the user asked. Produce simple stats: total events, count per event type, count per tool, count per directive_id, and top tools/directives by failure count.

5. **Output** — When done, respond with `{"done": true, "summary": "..."}`. The summary must be a clear, copy-pasteable report that includes:
   - Where failures are happening (which event types, which tools, which directives).
   - The relevant statistics (counts, top offenders).
   Structure the summary so it can be pasted into the active_debug directive or read by a human. Use plain language and optional section headers (e.g. "Failure types", "By tool", "By directive", "Recommendations" or "Summary").

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use to find the audit file or list the project root.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str, default "utf-8"). Use to read the audit file (e.g. `auro_audit.jsonl`).

## Notes
- If the audit file does not exist or is empty, say so in the summary and report zero events.
- Do not include secrets or raw user data in the summary; the audit file already avoids secrets.
- One tool call per message.
