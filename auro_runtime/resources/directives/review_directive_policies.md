---
id: review_directive_policies
description: Compare a directive's steps and tools to current policies and report alignment or conflicts
tools: [list_dir, read_file]
category: security
---

# Review directive vs policies

## Purpose
Given a directive id (or name), load that directive and all policies, then report whether the directive's described steps and allowed tools align with the policies. For example: "Directive X allows tool Y; policy Z restricts Y in sensitive paths." Suggestions only; no edits to files. Use plain language.

## Steps

1. **Identify the directive** — Ask for the directive id (or infer from the user's request). Use `list_dir` on the `directives` folder to see available `*.md` files. Use `read_file` on `directives/{id}.md` to load the directive. If the file does not exist (e.g. wrong id), state "Directive not found" in the summary and respond with `{"done": true, "summary": "Directive not found: <id>. Check the directives folder for valid ids."}`; do not proceed.

2. **Extract directive content** — From the directive file, note: the `tools` list (from front matter or body), the purpose, and the main steps. Do not invent tools or steps; use only what is in the file.

3. **Load policies** — Use `list_dir` on the `policies` folder and `read_file` on each policy `*.yaml` (and `*.yml` if present). Summarize each rule in plain language (id and description).

4. **Compare** — For each tool listed in the directive, check if any policy rule clearly restricts or cautions about that tool or similar actions (e.g. "avoid sensitive paths", "confirm before delete"). For each policy rule, note if the directive's steps or tools might conflict or need care. Use plain language (e.g. "Directive allows read_file; default policy says avoid sensitive paths—ensure paths in the directive are appropriate."). Do not invent conflicts; only report what is clearly stated or implied.

5. **Complete** — When done, respond with `{"done": true, "summary": "..."}`. The summary must include: a short compliance-style summary (aligned / potential conflicts / recommendations) and any recommended follow-ups (e.g. tighten directive steps, add a policy, or confirm with the user). Structure it so the user can act on it.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use for directives and policies folders.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Use to read the directive and each policy file.

## Notes
- Read-only; no changes to files. If the directive is not found, say so in the summary and exit. One tool call per message.
