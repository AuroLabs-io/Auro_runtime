---
id: update_policies
description: Walk the user through adding or changing policy rules (guardrails) that apply to every script
tools: [list_dir, read_file]
category: security
---

# Update policies

## Purpose
Policies are rules that **every script must follow**, like "always ask before deleting" or "never put secrets in logs." This directive walks the user through adding a new rule or changing an existing one. Use simple language. Assume the user may have little or no coding experience.

## Steps

1. **Explain what policies are** — In one sentence: "Policies are rules that apply to all your scripts, such as requiring confirmation before destructive actions or forbidding secrets in logs."

2. **List current policy files** — Use `list_dir` on the `policies` folder to show which policy files exist (e.g. `default.yaml`, `credential_proxy.yaml`). Read one or two with `read_file` so the user sees the format: each file has an `id` and a list of `rules`, each rule has an `id` and a `description`.

3. **Ask what to add or change** — In plain language: Do you want to add a new rule or change an existing one? Which policy file should it go in? What should the rule say? Draft the rule in plain language first (e.g. "Scripts must not delete files unless the user has said yes").

4. **Security check** — Before outputting any final policy YAML, assess whether the **edit would create a security risk**. For example:
   - Removing or weakening a rule that protects against destructive actions (e.g. "always confirm before delete").
   - Adding a rule that broadens what scripts can do in a risky way (e.g. allowing unconfirmed overwrites).
   - Removing or weakening a rule about secrets, logging, or sensitive data.
   If the edit would create a security risk:
   - **State the risk clearly in plain language** (e.g. "This change would remove the rule that requires confirmation before deleting files. Scripts could then delete files without asking.").
   - **Do not output the final policy YAML yet.** Tell the user they should confirm they understand and accept the risk. Only after the user has explicitly confirmed (e.g. by repeating the request or saying they accept the risk) should you output the full policy YAML in a follow-up.

5. **Impact note** — When outputting the policy, include a short "What this changes" or "Impact" in plain language (e.g. "This rule blocks any script from deleting or overwriting files without explicit user confirmation.").

6. **Output the full policy** — When done (and after any required security confirmation), respond with `{"done": true, "summary": "..."}`. In `summary`:
   - **First (if applicable):** A brief "Impact" or "What this changes" paragraph in plain language, then
   - **Then:** The full policy file content as YAML the user can copy into the chosen file (e.g. `policies/default.yaml`). Use the same structure: `id`, `rules` with `id` and `description` for each rule. No extra commentary inside the YAML block so the user can copy it as-is.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use to list the `policies` folder.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Use to read existing policy YAML files as examples.

## Notes
- If the user’s suggested edit creates a security risk, always convey the risk and require explicit confirmation before producing the final YAML. One tool call per message.
