# Credentials

auro-runtime does not store your secrets. It resolves an *alias* to a value from a source you configure, and never returns that value to the model. The model can say "use the `github_token` credential" without ever seeing it.

This document covers setting that up, with a full walkthrough for Windows Credential Manager. For the short version, see the credential section of the [README](../README.md).

## How resolution works

When a tool asks for an alias, the runtime checks three sources in order and returns the first that has a non-empty value:

1. **Request-scoped secrets**, if an embedding application supplied them for this run. Never persisted.
2. **Environment variables**, `AURO_SECRET_<ALIAS>` with the alias uppercased. Always consulted, with no configuration and no dependencies.
3. **The backend named by `AURO_SECRET_BACKEND`**, if one is set.

> **The environment wins over your credential store.** Step 2 runs before step 3, by design, so a deployment system can override a stored value. The practical consequence is that a leftover `AURO_SECRET_MY_ALIAS` variable will silently shadow the entry you carefully saved in Credential Manager. If a credential resolves to the wrong value, check your environment first.

### Alias naming

Aliases are identifiers, not paths. Letters, digits, underscores and hyphens only. An alias containing anything else (a slash, a dot, a space) resolves to `None` without raising, so a malformed alias looks exactly like a missing one. Keep them boring: `github_token`, `anthropic_provider`, `stripe_live`.

## Backends

| `AURO_SECRET_BACKEND` | Behaviour |
|---|---|
| unset, or `env` | Environment variables only. Zero dependencies. |
| `keyring` | Adds the OS credential store. Requires the `[keyring]` extra. |
| anything else | Raises `ValueError` at startup rather than silently resolving nothing. |

The `env` backend is always active regardless of this setting. Choosing `keyring` adds a source, it does not replace the environment.

**What the runtime guarantees:** a resolved value is not returned to the model, does not appear in tool results, and is redacted from the audit log. **What it does not guarantee:** encryption at rest. With `env`, values sit in the process environment unencrypted and child processes inherit them. With `keyring`, storage and unlock behaviour belong to whichever backend the `keyring` package selects.

---

## Walkthrough: Windows Credential Manager

### 1. Install with the keyring extra

```bash
pip install ".[keyring]"
```

On Windows this pulls `pywin32-ctypes`, which is what `keyring` uses to reach the credential store. It does **not** need the full `pywin32` package.

### 2. Confirm which backend keyring selected

```bash
python -c "import keyring; k = keyring.get_keyring(); print(type(k).__module__ + '.' + type(k).__name__)"
```

You want `keyring.backends.Windows.WinVaultKeyring`. If you see `keyring.backends.fail.Keyring`, no usable store was found and nothing will resolve.

### 3. Store a secret

```bash
python -m keyring set auro-runtime my_alias
```

`auro-runtime` is the service name the runtime reads from, so use it exactly. `my_alias` is your choice, subject to the naming rules above.

The command prompts for the value, so the secret does not appear in your shell history or in the process list. Type it and press Enter.

> Use the `python -m keyring` form. Installing into a virtual environment often puts `keyring.exe` in a `Scripts` directory that is not on `PATH`, and the bare `keyring` command will appear to be missing.

### 4. Verify it resolves through the runtime

```bash
python -c "import os; os.environ['AURO_SECRET_BACKEND'] = 'keyring'; from auro_runtime.secrets import get_secret; print('resolved:', get_secret('my_alias') is not None)"
```

This prints whether the alias resolved, not the value. Never echo a secret to a terminal to check it.

### 5. Select the backend for real use

Set this wherever the runtime actually runs, whether that is your shell, a service definition, or an MCP client configuration:

```bash
set AURO_SECRET_BACKEND=keyring
```

### Where the entry lives

Entries appear in **Control Panel > User Accounts > Credential Manager > Windows Credentials**, under **Generic Credentials**. The target name contains `auro-runtime` and the user name is your alias. You can also list them from a terminal:

```bash
cmdkey /list
```

Credential Manager is per Windows user account, not per Python environment. A secret stored from one virtual environment is visible to every environment that same user runs.

### Rotating a secret

Store it again under the same alias. The write overwrites in place, so nothing referencing the alias needs to change.

```bash
python -m keyring set auro-runtime my_alias
```

### Deleting a secret

```bash
python -m keyring del auro-runtime my_alias
```

---

## Model provider keys

The same alias path can carry your model provider key, so the raw value stays out of configuration files.

```bash
python -m keyring set auro-runtime anthropic_provider
set AURO_SECRET_BACKEND=keyring
set AURO_ANTHROPIC_API_KEY_ALIAS=anthropic_provider
```

`AURO_ANTHROPIC_API_KEY_ALIAS` must match the alias you stored. If an alias is configured but cannot be resolved, the Anthropic backend **fails closed** rather than falling back to `ANTHROPIC_API_KEY`. Falling back would quietly use a different credential than the one you configured. `ANTHROPIC_API_KEY` remains available for compatibility only when no alias is selected.

## MCP client configuration

For a stdio MCP client, put the backend and alias in the server's environment. Only names appear here, never a secret.

```json
{
  "mcpServers": {
    "auro": {
      "command": "C:\\path\\to\\env\\python.exe",
      "args": ["-m", "auro_runtime", "mcp", "--transport", "stdio"],
      "env": {
        "AURO_WORKSPACE_ROOT": "C:\\path\\to\\auro-workspace",
        "AURO_MCP_ALLOWED_DIRECTIVE_IDS": "tool_catalog",
        "AURO_SECRET_BACKEND": "keyring",
        "AURO_ANTHROPIC_API_KEY_ALIAS": "anthropic_provider"
      }
    }
  }
}
```

Use the full path to the interpreter of the environment where auro-runtime is
installed. `AURO_WORKSPACE_ROOT` must name an existing writable workspace for
runtime output and audit state; it does not select executable directives or
policies. `AURO_MCP_ALLOWED_DIRECTIVE_IDS` is the server-wide exposure set.
Missing or empty configuration exposes no directives.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `keyring` is not recognised as a command | The `Scripts` directory is not on `PATH`. Use `python -m keyring`. |
| Backend reports `keyring.backends.fail.Keyring` | No usable OS store. On Windows, confirm `pywin32-ctypes` is installed. |
| `RuntimeError: OS keychain unavailable` | The store exists but could not be read, usually locked or a permissions problem. This is deliberately distinct from a missing alias. |
| An alias resolves to an unexpected value | An `AURO_SECRET_<ALIAS>` environment variable is shadowing the store. Unset it. |
| An alias resolves to nothing, but the entry exists | Check the service name is exactly `auro-runtime`, and that the alias contains only letters, digits, underscores and hyphens. |
| `ValueError: Unknown AURO_SECRET_BACKEND` | The value must be `env` or `keyring`. |
| A DLL or import error mentioning `pywin32` | Usually caused by installing into a temporary directory with `pip --target`, which breaks pywin32 DLL resolution. Install into a real environment instead. |
| `list_secret_aliases()` returns nothing | Expected. The keyring API has no portable way to enumerate entries, so the backend reports an empty list rather than guessing. Aliases are discovered from your configuration, not from the store. |

## Security notes

- A stored value is never returned to the model, never appears in a tool result, and is redacted from the audit log. Only the alias name is visible.
- Putting a raw token in a tool argument such as an HTTP header is refused by a policy guard. Reference the alias instead.
- A blank or whitespace-only stored value is treated as absent, so an empty entry cannot masquerade as a configured credential.
- Credential Manager entries are readable by anything running as your Windows user. The store protects against other users and offline disk access, not against code you run yourself.
