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
   - **OS keychain** (`AURO_SECRET_BACKEND=keyring`): `python -c "import keyring; keyring.set_password('auro-runtime', 'ALIAS', 'NEW_VALUE')"`, or the OS keychain app. Overwrites in place.
   - **Environment variable** (default): update `AURO_SECRET_<ALIAS>`. Remind them that a change to a shell profile only takes effect in a **new** shell, and that a running server or container must be restarted to pick it up — a common reason rotation appears not to work.

   Never ask for the secret itself. If the user pastes it into the chat, tell them plainly that it is now in the transcript and must be rotated again.

5. **Verify after the change** — Use `resolve_secret` again. Be explicit about what this proves and what it does not: it confirms the alias **still resolves**, not that the value changed. The real confirmation is an actual call against the upstream service — for example `http_request` with `auth_alias` set to this alias, which will fail with an authentication error if the new value is wrong.

6. **Revoke the old secret** — Rotation is not finished until the previous value is revoked at the provider. A rotated-but-not-revoked key is still a live credential. Say this explicitly; it is the step people skip.

7. **Complete** — Respond with `{"done": true, "summary": "..."}`. The summary must state the alias, where it is stored, that directives need no change, whether a restart is required for the new value to take effect, and a reminder to revoke the old secret at the provider.

## Allowed tools
- `resolve_secret` — Check whether an alias resolves. Args: `alias` (str). Presence only; never the value. Use before and after the change.
- `list_tools` — List registered tools with argument summaries. Args: optional `include_args` (bool). Use if the user wants to see which tools accept this alias (`auth_alias`, `webhook_url_alias`).

## Notes
- Never display, request, or repeat a secret value.
- `resolve_secret` cannot tell you whether a value changed — only that the alias resolves. Do not claim otherwise.
- One tool call per message.
