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
   - **OS keychain (for a configured personal machine).** The optional `keyring` package may delegate to macOS Keychain, Windows Credential Manager, or Linux Secret Service. Storage and unlock behavior depend on the backend selected by that package. Install the extra the same way they installed the runtime — `pip install ".[keyring]"` from a source checkout, or `pip install "auro-runtime[keyring]"` if they installed from a package index — then set `AURO_SECRET_BACKEND=keyring`.
   - **Environment variables (default).** Set `AURO_SECRET_<ALIAS>`, uppercased. The runtime does not encrypt these values, and child processes inherit them by default. Use this option when the deployment system already injects environment variables; that system remains responsible for storage and access control.

3. **Help them choose** — Personal laptop → keychain. Server, container, or CI → environment variables injected by an existing secret manager. Do not recommend pasting secrets into files inside the project folder; the project directory gets copied, backed up, and committed. A shell profile is the same hazard in a different location: it is an unencrypted file, and dotfile repositories and backup tools collect it.

4. **Guide them to store it** — Give the exact command for their chosen option:
   - Keychain: `python -m keyring set auro-runtime ALIAS`. This prompts for the value, so the secret is typed at a prompt rather than written into the command line.
   - Environment: have their secret manager, systemd unit, or container runtime inject `AURO_SECRET_GITHUB_TOKEN=...` (uppercase, one variable per alias). Only fall back to a shell profile if they have no secret manager, and tell them what that costs.

   **Never put a secret value on a command line.** Anything typed as an argument lands in shell history and is visible in the process list to other users on that machine. Do not offer `keyring.set_password(...)` with the value inline, `export AURO_SECRET_X=value` typed directly at an interactive prompt, or any equivalent — even when the user asks for a one-liner. Prompt-based entry or secret-manager injection only.

   **Never ask the user to paste the secret into the chat.** If they do anyway, tell them plainly that it is now in the transcript and should be rotated.

5. **Choose a good alias** — Lowercase letters, digits, and underscores only. Name it for the thing it opens, so the alias stays meaningful if the credential type changes: `github_token`, `slack_hook`, `openai_key`.

6. **Verify — and be precise about what the check proves** — Use `resolve_secret` with the alias. It reports only whether the alias resolves; it never returns the value.

   If it fails, check: the alias spelling, whether `AURO_SECRET_BACKEND` is set for keychain use, and — for environment variables — whether the shell that set it is the same one running the runtime.

   If it succeeds, say what that does and does not establish. Resolution order is request-scoped secrets, then `AURO_SECRET_<ALIAS>` in the environment, then the configured backend. **The environment is consulted before the keychain and wins.** So a user who has just set up the keychain, but who still has an old `AURO_SECRET_<ALIAS>` exported from earlier experimentation, will get a successful result that came from the stale environment variable — not from the keychain they configured, and possibly an outdated value. `resolve_secret` cannot tell the two apart, and neither can you.

   For anyone using the keychain, have them confirm no `AURO_SECRET_<ALIAS>` is set for that alias before trusting the green result. Tell them a success proves the alias resolves *somewhere*; it does not prove it resolves from the store they chose.

7. **Show them how to use it** — This is the step that makes the setup worth anything. Use `list_tools` to point at the alias parameters:
   - `http_request` takes `auth_alias` (and optional `auth_scheme`: Bearer, Basic, or Token). Example: `http_request(url="https://api.github.com/user", auth_alias="github_token")`.
   - Explain the rule: **never put a raw token in `headers`.** A policy guard blocks it, and it would land in the transcript before the guard ever saw it.

8. **Complete** — Respond with `{"done": true, "summary": "..."}`. The summary must list the aliases configured, name the storage they chose, state whether `resolve_secret` confirmed each alias resolves, and show one concrete example of calling a tool with the alias parameter.

   **Do not characterize the security properties of their storage.** You cannot determine whether a keychain backend encrypts at rest, what unlocks it, or who else can read it — that depends on the backend `keyring` selected and how the machine is configured. Name the store; do not grade it. If the user asks whether their secret is "safe" or "encrypted," say plainly that it depends on the backend and the machine, and point them at that backend's own documentation rather than guessing.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use only if the user needs orientation in the project; not required for setup.
- `list_tools` — List registered tools with argument summaries. Args: optional `include_args` (bool). Use in step 7 to show the alias parameters.
- `resolve_secret` — Check whether an alias resolves. Args: `alias` (str). Returns presence only, never the value.

## Notes
- Never display, log, or repeat a secret value. If the user pastes one into the chat, tell them to rotate it.
- Do not read any secrets file, and do not offer to.
- One tool call per message.
