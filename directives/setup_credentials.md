---
id: setup_credentials
description: Walk the user through storing a secret and referencing it by alias, so keys never appear in directives, transcripts, or logs
tools: [list_dir, list_tools, resolve_secret]
category: security
---

# Set up credentials

## Purpose
Secrets should never appear in a directive, a chat transcript, or a log. Instead the user stores each secret once in a place they control and gives it a **nickname** (an alias). Directives reference only the nickname; the runtime resolves the real value at the moment a tool runs and injects it directly into the outbound request.

Say this plainly to the user, because it is the part that matters: **the assistant never sees the secret.** It only ever knows the nickname.

Assume the user may have little coding experience.

## Steps

1. **Explain the model** — In plain language: "You store the secret once, somewhere on your machine. You give it a short nickname. From then on, scripts refer to the nickname. When a script actually needs the secret, the system looks it up and puts it straight into the outgoing request — it never passes through me, and it never appears in the logs."

2. **Be honest about where it will live** — auro-runtime does **not** store secrets. It reads them from a source the user chooses. Explain the two built-in options and their real tradeoff:
   - **OS keychain (for a configured personal machine).** The optional `keyring` package may delegate to macOS Keychain, Windows Credential Manager, or Linux Secret Service. Storage and unlock behavior depend on the backend selected by that package. Install with `pip install auro-runtime[keyring]` and set `AURO_SECRET_BACKEND=keyring`.
   - **Environment variables (default).** Set `AURO_SECRET_<ALIAS>`. The runtime does not encrypt these values, and child processes inherit them by default. Use this option when the deployment system already injects environment variables; that system remains responsible for storage and access control.

3. **Help them choose** — Personal laptop → keychain. Server, container, or CI → environment variables, ideally injected by an existing secret manager rather than typed into a shell profile. Do not recommend pasting secrets into files inside the project folder; the project directory gets copied, backed up, and committed.

4. **Guide them to store it** — Give the exact command for their chosen option:
   - Keychain: `python -c "import keyring; keyring.set_password('auro-runtime', 'ALIAS', 'VALUE')"`, or their OS keychain app.
   - Environment: `AURO_SECRET_ALIAS=value` in their shell profile, systemd unit, container env, or secret manager.

   **Never ask the user to paste the secret into the chat.** If they do anyway, tell them plainly that it is now in the transcript and should be rotated.

5. **Choose a good alias** — Lowercase letters, digits, and underscores only. Name it for what it opens, not what it is: `github_token`, `slack_hook`, `openai_key`.

6. **Verify** — Use `resolve_secret` with the alias. It reports only whether the alias resolves; it never returns the value. If it fails, check: the alias spelling, whether `AURO_SECRET_BACKEND` is set for keychain use, and — for environment variables — whether the shell that set it is the same one running the runtime.

7. **Show them how to use it** — This is the step that makes the setup worth anything. Use `list_tools` to point at the alias parameters:
   - `http_request` takes `auth_alias` (and optional `auth_scheme`: Bearer, Basic, or Token). Example: `http_request(url="https://api.github.com/user", auth_alias="github_token")`.
   - `send_notification` takes `webhook_url_alias`. Prefer it over `webhook_url` for Slack and Discord, because their webhook URLs contain the token in the path.
   - Explain the rule: **never put a raw token in `headers`.** A policy guard blocks it, and it would land in the transcript before the guard ever saw it.

8. **Complete** — Respond with `{"done": true, "summary": "..."}`. The summary must list the aliases configured, name the storage they chose and whether it is encrypted at rest, and show one concrete example of calling a tool with the alias parameter.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use only if the user needs orientation in the project; not required for setup.
- `list_tools` — List registered tools with argument summaries. Args: optional `include_args` (bool). Use in step 7 to show the alias parameters.
- `resolve_secret` — Check whether an alias resolves. Args: `alias` (str). Returns presence only, never the value.

## Notes
- Never display, log, or repeat a secret value. If the user pastes one into the chat, tell them to rotate it.
- Do not read any secrets file, and do not offer to.
- One tool call per message.
