---
id: tool_catalog
description: List all registered tools with name, description, and argument summary for writing directives
tools: [list_tools, read_file]
category: system
---

# Tool catalog

## Purpose
List all registered tools with their name, description, and (where available) a short argument summary. This helps users know what they can use when writing or choosing directives. Read-only; no secrets.

## Steps

1. **Get the tool list** — Use `list_tools` with `include_args` true to get every registered tool with name, description, and args summary. If the user asked for a compact list without args, you may call `list_tools` with `include_args` false.

2. **Format the catalog** — For each tool, include:
   - Tool name (e.g. `list_dir`, `read_file`).
   - One-line description (from the tool registry).
   - Short args summary (e.g. "path (str), recursive (bool)" or "—" if none). Use the `args_summary` returned by `list_tools` when available.

3. **Optional context** — If helpful, use `read_file` on one or two tool module files (e.g. under `runtime_tools/`) to add a brief note about usage (e.g. "Use list_dir to discover the policies folder before reading."). Do not include large code blocks; keep the catalog scannable.

4. **Complete** — When done, respond with `{"done": true, "summary": "..."}`. The summary must be a formatted catalog (e.g. alphabetically or by category) that the user can copy or reference when writing directives. Include a line like "Use these tool names in the `tools` front matter of a directive."

## Allowed tools
- `list_tools` — List registered tools with description and args summary. Args: optional `include_args` (bool, default true).
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Use optionally to add short usage notes from tool modules; do not expose secrets or large code blocks.

## Notes
- Read-only; no secrets. One tool call per message.
