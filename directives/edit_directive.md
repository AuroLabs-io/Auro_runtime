---
id: edit_directive
description: Walk the user through editing an existing workflow script (directive)
tools: [list_dir, read_file, write_file, echo]
category: system
---

# Edit an existing directive

## Purpose
Guide the user step by step to change an existing directive: find the script they want to edit, understand what to change, and produce an updated directive file they can save. Use simple language. Assume the user may have little or no coding experience.

## Steps

1. **Identify which directive to edit** — If the user hasn’t named it, use `list_dir` on the `directives` folder to list existing directive names and let them pick (e.g. by filename without .md). Once you know the file (e.g. `file_analysis`), use `read_file` to load that directive (e.g. `directives/file_analysis.md`).

2. **Understand what to change** — Ask in plain language: What do you want to change? (e.g. add a step, use a different tool, update the description). If they’re unsure what’s possible, briefly explain the structure (Purpose, Steps, Allowed tools) and suggest options.

3. **Inspect format** — Use the content you already read (or read another example) to keep the same format: YAML front matter with `id`, `description`, `tools`, then Markdown sections for Purpose, Steps, and Allowed tools.

4. **Apply the edit** — Draft the updated directive. If the change involves **API keys, passwords, or tokens**, remind the user to use the credential proxy (run **setup_credentials** if needed) and reference only the alias in the directive, never the actual secret.

5. **Security and requirements disclosure** — Before outputting the final directive, decide if the workflow involves: external API calls, authentication, or sensitive data. If yes, include a short "Requirements and security" section in plain language in your output.

6. **Save the updated candidate** — Use `write_file` to save the updated content to `drafts/directives/<id>.md`. Confirm the write succeeded with `read_file` on the saved path. Runtime tools cannot overwrite the executable copy; an operator reviews and promotes the candidate outside model execution.

7. **Confirm** — Use `echo` to report:
   - Candidate saved to: `drafts/directives/<id>.md`
   - What was changed (description, category, steps, tools, or combination)

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use to list the `directives` folder.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Use to read the directive being edited and optionally other examples. Use in step 6 to verify the saved file.
- `write_file` — Write content to a file. Args: `path` (str), `content` (str). Use in step 6 to save the updated candidate to `drafts/directives/<id>.md`.
- `echo` — Echo a message. Args: `message` (str). Use in step 7 for confirmation.

## Notes
- Keep steps concrete and tool-focused. If the user wants to create a brand-new directive instead, suggest the **create_directive** directive.
