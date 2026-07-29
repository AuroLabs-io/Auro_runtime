---
id: policy_audit
description: Read all policy files, summarize rules in plain language, and note potential gaps or overlaps
tools: [list_dir, read_file]
category: security
---

# Policy audit

## Purpose
Policies are global guardrails that every script must follow. This directive reads all policy files, summarizes their rules in plain language, and highlights potential gaps or overlaps (e.g. two rules that might conflict, or a broad "no delete" vs "confirm before delete"). Read-only; no edits. Use plain language.

## Steps

1. **Explain policies** — In one sentence: "Policies are rules that apply to all your scripts. This audit lists them and checks for consistency."

2. **List and read policy files** — Use `list_dir` on the `policies` directory to see which files exist (e.g. `default.yaml`, `credential_proxy.yaml`). Use `read_file` on each `*.yaml` (and `*.yml` if present) to load the content.

3. **Summarize each policy** — For each policy file: state its `id` and list each rule with its `id` and `description` in plain language. Do not include raw YAML in the summary unless the user asks; focus on what each rule means.

4. **Consistency pass** — Note if any rules seem to overlap, contradict, or leave a clear gap. For example: two rules about the same topic with different wording; a rule that says "never X" and another that says "confirm before X"; or a missing topic (e.g. "no rule about credential handling" when another file like credential_proxy exists). Do not invent rules; only report what you see.

5. **Complete** — When done, respond with `{"done": true, "summary": "..."}`. The summary must contain the list of policies and rules in plain language and any notes about gaps or overlaps.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use to list the `policies` folder.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Use to read each policy YAML file.

## Notes
- Read-only; no edits. Same policy directory as used by the orchestrator (project root `policies/`). One tool call per message.
