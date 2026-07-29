---
id: active_debug
description: Use research results or run research, then suggest tool or directive changes to reduce system friction
tools: [list_dir, read_file]
category: system
---

# Active debug

## Purpose
Use failure research (from a prior run of debug_research or provided by the user) or perform that research when none is provided, then suggest concrete tool or directive changes to reduce system friction. Output is suggestions only; no file writes.

## Steps

1. **Obtain research** — If the user's request includes research output (e.g. "Here's the output from debug_research: …" or a pasted report) or a path to a saved report file, use that as the research summary. Otherwise, perform the research inline: locate the audit file (`auro_audit.jsonl` in the project root, or the path from env `AURO_AUDIT_LOG`, or a path the user gives). Use `read_file` to load it, parse each line as JSON (JSONL), aggregate events by failure type and by tool (and by directive_id if present), and produce a short research summary (same logic as the debug_research directive).

2. **Identify friction** — From the research summary, identify the main sources of friction. For example:
   - Repeated **argument_validation_failed** for a given tool → suggest tightening or documenting the args_schema or the directive's "Allowed tools" section.
   - **tool_not_allowed** → suggest adding the tool to the directive's `tools` list or fixing the directive.
   - **parse_json_failed** or **invalid_tool_call_shape** → suggest clarifying the directive's output-format instructions so the LLM emits valid JSON.
   - **max_steps_reached** → suggest simplifying the workflow or increasing max_steps.
   - **tool_execution_error** or **tool_type_error** → suggest fixing the tool implementation or its schema.

3. **Suggest changes** — For each identified issue, suggest concrete, actionable changes:
   - **Tool changes** — e.g. "Add or tighten args_schema for tool X in tool_schemas.py," "Document argument Y in the directive's Allowed tools section."
   - **Directive changes** — e.g. "Add tool Z to the `tools` list in directive D (front matter)," "Clarify step 2 in directive D so the LLM emits valid JSON."
   - **Policy changes** — Only if clearly relevant (e.g. a policy is causing repeated refusals); suggest with caution and reference the policy by id. Remind the user to review policy edits (e.g. with the update_policies directive) and confirm security impact.

4. **Output** — When done, respond with `{"done": true, "summary": "..."}`. The summary must list the suggestions in plain language. Optionally include minimal patch snippets or directive excerpts (as text) for the user to apply. No execution of writes; suggestions only.

## Allowed tools
- `list_dir` — List directory contents. Use to find the audit file or list directives/policies.
- `read_file` — Read file contents. Use to read the audit file when running research inline, or to read existing directives/policies so suggestions can reference specific files and sections.

## Notes
- If the user has not provided research results, first perform the research (locate and read the audit file, aggregate by type and tool, summarize); then suggest changes based on that summary.
- Read-only: do not write or edit files; only output suggestions in the summary.
- One tool call per message.
