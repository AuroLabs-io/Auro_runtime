---
id: health_check
description: Lightweight sanity check — directives dir, policies dir, audit file, and tool count
tools: [list_dir, read_file, list_tools]
category: system
---

# Health check

## Purpose
Run a quick sanity check of the environment: verify the directives and policies directories exist and have content, optionally that the audit file path exists, and that the tool registry has tools. Report OK, warning, or fail per item. No secrets; read-only. Use plain language.

## Steps

1. **Explain** — In one sentence: "This is a read-only check of the environment. No secrets are read; no files are written."

2. **Check directives** — Use `list_dir` on the `directives` folder (project root). Report: OK if the directory exists and contains at least one `*.md` file; warning if empty or missing; fail if the path cannot be listed. Optionally use `read_file` on one directive file to confirm it is readable (or note "could not parse" without failing the run).

3. **Check policies** — Use `list_dir` on the `policies` folder. Report: OK if it exists and contains at least one `*.yaml` or `*.yml`; warning if empty or missing; fail if the path cannot be listed. Optionally use `read_file` on one policy file to confirm it is readable.

4. **Check audit path** — The default audit file is `auro_audit.jsonl` in the project root; the path can be overridden by `AURO_AUDIT_LOG`. Use `list_dir` on the project root and note whether the default audit file exists (or state that the path is configurable via env). Report OK if the file exists or the user is aware of the path; warning if the default file is missing and no env is set (audit is optional).

5. **Check tools** — Use `list_tools` (with `include_args` true or false) to get the number of registered tools. Report: OK if at least one tool is registered; fail if zero.

6. **Complete** — When done, respond with `{"done": true, "summary": "..."}`. The summary must have one line per check with status (OK / warning / fail) and a single overall line at the end (e.g. "All checks passed" or "See warnings above"). Structure it so the user can scan quickly.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use for directives, policies, and project root.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Use optionally to verify one directive and one policy are readable.
- `list_tools` — List registered tools. Args: optional `include_args` (bool). Use to get the tool count.

## Notes
- No writes; no secrets. Do not read the real secrets file. One tool call per message.
