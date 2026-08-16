---
id: rotate_credentials
description: Guide the user to rotate a secret (same alias, new value) without changing directives
tools: [resolve_secret, list_tools]
category: security
---

# Rotate credentials

## Purpose
Guide the user to replace a secret's value while keeping the same alias, so no directive has to change. Only the store is updated; every directive that references the alias keeps working. Never ask the user to paste the new secret into chat. Use plain language.

## Steps

1. **Explain rotation** — In plain language: "Rotation means putting a new value behind the same nickname. Your directives reference the nickname, so they don't change at all — you only update the place the real value is stored."

2. **Identify the alias** — Ask which alias is being rotated. If the user is unsure of the exact name, use `resolve_secret` to test a candidate: it reports whether that alias resolves, without revealing anything about the value. Do not attempt to enumerate or display secrets.

3. **Confirm it resolves *before* the change** — Use `resolve_secret` on the alias first. This establishes a baseline: if it does not resolve now, the problem is the alias name or the backend configuration, not the rotation.

4. **Instruct where to update** — The new value goes in the same store as the old one:
   - **OS keychain** (`AURO_SECRET_BACKEND=keyring`): `python -m keyring set auro-runtime ALIAS`, or the OS keychain app. Prompts for the value and overwrites in place.
   - **Environment variable** (default): update `AURO_SECRET_<ALIAS>` through whatever injects it. Remind them that a change to a shell profile only takes effect in a **new** shell, and that a running server or container must be restarted to pick it up — a common reason rotation appears not to work.

   **Never put the new value on a command line.** Anything passed as an argument lands in shell history and is visible in the process list to other users on that machine. Do not offer `keyring.set_password(...)` with the value inline or any equivalent one-liner, even if asked. Prompt-based entry or secret-manager injection only.

   Never ask for the secret itself. If the user pastes it into the chat, tell them plainly that it is now in the transcript and must be rotated again.

5. **Check for a shadowing environment variable — do this before step 6** — Resolution order is request-scoped secrets, then `AURO_SECRET_<ALIAS>` in the environment, then the configured backend. **The environment is consulted before the keychain and wins.**

   This creates a specific and damaging failure during rotation. A user who rotates the value in their keychain while an old `AURO_SECRET_<ALIAS>` is still exported will keep resolving the *old* value. Verification appears to succeed, because the old credential is still live until it is revoked. They then revoke it at the provider, and everything breaks — with the cause now invisible, since the rotation itself looked correct.

   For anyone on the keychain backend, have them confirm no `AURO_SECRET_<ALIAS>` is set for this alias before proceeding. `resolve_secret` cannot detect this: it reports that the alias resolves, never which source answered.

6. **Verify after the change** — Use `resolve_secret` again. Be explicit about what this proves and what it does not: it confirms the alias **still resolves**, not that the value changed, and not which store it came from. The real confirmation is an actual call against the upstream service — for example `http_request` with `auth_alias` set to this alias, which will fail with an authentication error if the new value is wrong. That check is only trustworthy once step 5 has ruled out a shadowing environment variable, because a stale value that is still live will pass it.

7. **Revoke the old secret** — Rotation is not finished until the previous value is revoked at the provider. A rotated-but-not-revoked key is still a live credential. Say this explicitly; it is the step people skip. Do not advise revoking until steps 5 and 6 have both passed — revoking while a stale environment variable is still shadowing the new value is what turns a quiet misconfiguration into an outage.

8. **Complete** — Respond with `{"done": true, "summary": "..."}`. The summary must state the alias, where it is stored, that directives need no change, whether a shadowing environment variable was ruled out, whether a restart is required for the new value to take effect, and a reminder to revoke the old secret at the provider.

## Allowed tools
- `resolve_secret` — Check whether an alias resolves. Args: `alias` (str). Presence only; never the value, and never which source answered. Use before and after the change.
- `list_tools` — List registered tools with argument summaries. Args: optional `include_args` (bool). Use if the user wants to see which tools accept this alias (`auth_alias`, `webhook_url_alias`).

## Notes
- Never display, request, or repeat a secret value.
- `resolve_secret` cannot tell you whether a value changed — only that the alias resolves. Do not claim otherwise.
- One tool call per message.
