# auro-runtime

This project is a model-agnostic execution kernel. The entire premise of this project was to create a safe and trustworthy execution layer for skills. Primary access to this runtime kernel is via MCP. It can be used with Stdio to directly wire it into the Claude harness. To use, define a directive and a request, and the directive dictates which tool calls a model is allowed to make. Refusal is the whole point. If a model proposes an action or tool call that is not allowed, the runtime rejects it before it has a chance to execute. The guards then check each one against policy before anything runs, and writes an audit record.

```
Tool 'write_file' is not allowed by the current directive. Allowed: {'read_file', 'list_tools'}
Policy violation [sensitive_paths]: Path argument 'path' matches sensitive pattern.
```

## Directives

There are two different layers, the first is directive scope. A directive is essentially a skill with YAML frontmatter. The frontmatter lists the tools it is allowed to use, and the runtime checks every proposed call against that list before dispatch, so a tool outside it is refused whether the model was told about the boundary or not.

The front matter is enforced at runtime by the guards:

```yaml
---
id: tool_catalog
description: List all registered tools with name, description, and argument summary
tools: [list_tools, read_file]
category: system
---
```

The `tools` list here is not discretionary. The runtime enforces it before dispatch, regardless of what the model was told or what it attempts to do, resulting in the model only having access to the tools authorized for that execution.

The body of the markdown file provides the context the model needs: purpose, steps, requirements, handoff notes etc. but those instructions still depend on the model interpreting and following them correctly. A model can misunderstand a step, skip it, or respond in prose when the directive expects a tool call.

Fourteen directives ship with the runtime, covering credential setup, policy audits, directive drafting, and the quality gate. Runtime tools may write candidates under `drafts/directives/`, but executable files under `directives/` are immutable to model execution and require operator promotion.

## Policies

Policies provide the second layer. They inspect permitted calls outside the model, so enforcement does not depend on the model remembering an instruction or choosing to comply. They cannot guarantee correct behavior, but they make specific boundaries durable wherever a guard has been defined.

```yaml
- id: sensitive_paths
  description: Be cautious with paths that suggest sensitive locations.
  guard: check_sensitive_paths
  enforcement: block
  on_error: fail_closed
  tools: [read_file, write_file, delete_file, list_dir, restore_file]
```

Here, `sensitive_paths` applies to five file tools. If the guard rejects a call, `enforcement` determines what happens next. `block` refuses the call. `warn` records the verdict but allows the call to proceed.

`on_error` answers a different question: what should happen if the guard itself fails? `fail_closed` refuses the call; `fail_open` allows it to continue.

Two settings determine what happens when a guard does not return approval:

| Setting | Condition | Result |
| --- | --- | --- |
| `enforcement: advisory` | Policy is passed as context to the LLM | This is the default when a policy rule does not specify enforcement. The runtime does not execute a check for that rule. To make the rule executable, name a guard and set enforcement to `warn` or `block` |
| `enforcement: block` | The guard denies the call | Refuse the call and record the verdict |
| `enforcement: warn` | The guard denies the call | Record the verdict and allow the call to proceed |
| `on_error: fail_open` | The guard raises an error | Record the error and allow the call to proceed |
| `on_error: fail_closed` | The guard raises an error | Block the call and record the error |

The `enforcement` field dictates how decisions made by the guard are handled and `on_error` decides what happens if a guard fails to execute as expected. At startup, the runtime validates every policy against the live tool and guard registries. A rule that names something that does not exist fails immediately. It cannot sit quietly in a policy file looking active while protecting nothing.

That startup validation covers policies loaded through `run()`, the CLI, and the MCP server. It is not a property of the executor itself: calling `execute()` directly without passing `policy_rules` performs no guard evaluation at all, and an omitted tool scope is likewise permissive where an explicitly empty one refuses. Embedding applications that drive the executor directly are responsible for passing the full context.

## Policy Enforcement

Every guard receives an immutable snapshot of the proposed call. That context includes the tool name, its raw and validated arguments, the model's reason for making the call, the active directive, and the run history.

The guard returns one of two things:

- `None` when it has no objection to the call.
- A `GuardVerdict` containing a decision, message, code, and optional metadata.

Once complete, the guard reports what it found. The policy's `enforcement` and `on_error` settings determine what the runtime does next.

### Example: refusing a sensitive path

Suppose the active directive permits `read_file`, and the model proposes:

```
read_file(path="auro_secrets.yaml")
```

The call passes directive scope because `read_file` is allowed. The `sensitive_paths` policy applies to that tool, so the runtime passes the call to `check_sensitive_paths`.

The guard normalizes the path and compares it with a set of sensitive patterns. In this case, it returns a verdict resembling:

```
GuardVerdict(
    allowed=False,
    message="Path argument 'path' matches sensitive pattern.",
    code="sensitive_path",
    metadata={"key": "path"}
)
```

The complete path through the runtime looks like this:

```
Model proposes read_file("auro_secrets.yaml")
                    ↓
Directive permits read_file
                    ↓
sensitive_paths policy applies
                    ↓
check_sensitive_paths inspects the arguments
                    ↓
GuardVerdict(allowed=False)
                    ↓
enforcement: block
                    ↓
Call refused and verdict written to the audit log
```

The model does not need to remember that the path is sensitive, agree with the rule, or report its own violation. That decision is made outside the model before the tool executes.

## Credentials

The runtime does not maintain its own secret store. It resolves an alias to a value from a source you configure, and the value never reaches the model.

```python
http_request(url="https://api.github.com/user", auth_alias="github_token")
```

The model names the alias and it's resolved when the tool runs and puts it in the outgoing request. The raw value never appears in the transcript, the result, or the audit log. Attempting to put a token directly in `headers` instead will be refused by a guard.

Two built-in sources for credentials are available depending on your preferred configuration:

`env` is the default and reads `AURO_SECRET_<ALIAS>`. **The runtime does not encrypt these values.** Child processes inherit them by default. Use this backend when your deployment system already injects environment variables; that system remains responsible for storage and access control.

`keyring` delegates storage to the backend selected by Python's `keyring` package. On a configured desktop that may be macOS Keychain, Windows Credential Manager, or Linux Secret Service. Storage and unlock behavior depend on the selected backend. Install with `pip install ".[keyring]"` and set `AURO_SECRET_BACKEND=keyring`.

Resolution is ordered, and the environment is always consulted:

1. **Request-scoped secrets**, if an embedding application supplied them for this run. Never persisted.
2. **`AURO_SECRET_<ALIAS>`** in the process environment.
3. **The backend named by `AURO_SECRET_BACKEND`**, if one is set.

Selecting `keyring` adds a source, it does not replace the environment. That ordering lets a deployment system override a stored value, and it means a leftover `AURO_SECRET_<ALIAS>` will silently shadow an entry you saved in a credential store.

Embedding applications can resolve credentials in their own layer and supply them for a single run through the request-scoped API.

Model-provider credentials can use the same alias path. For Anthropic, store the key under the `auro-runtime` service and select its alias:

```bash
python -m keyring set auro-runtime anthropic_provider
export AURO_SECRET_BACKEND=keyring
export AURO_ANTHROPIC_API_KEY_ALIAS=anthropic_provider
```

The first command prompts for the value so it does not need to appear in shell history. Wherever the runtime is configured, only the backend and alias names are written down, never the secret. If an alias is explicitly configured but cannot be resolved, the Anthropic backend fails closed rather than falling back to `ANTHROPIC_API_KEY`. The environment key remains available for compatibility only when no alias is selected.

[docs/CREDENTIALS.md](docs/CREDENTIALS.md) walks through Windows Credential Manager step by step, covering storage, rotation, deletion, and the failure modes worth knowing about.

## Install

From a source checkout:

```bash
pip install .
pip install ".[anthropic]"           # Anthropic with an environment key
pip install ".[anthropic,keyring]"   # Anthropic with an OS credential store
```

Use `pip install -e ".[dev]"` for an editable development checkout.

Set a model backend. Anthropic is the default:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Or point it at anything speaking the OpenAI chat-completions API, including a local Ollama:

```bash
export AURO_MODEL_BACKEND=openai_compatible
export AURO_OPENAI_BASE_URL=http://localhost:11434/v1
export AURO_OPENAI_MODEL=llama3.2:3b
```

For this local Ollama example, no API key is needed. `AURO_OPENAI_API_KEY` is sent only when set.

## Run something

```bash
python -m auro_runtime run --directive tool_catalog "list the available tools"
```

Add `--json` for the full result: the message transcript, every step with its arguments and outcome, and the errors from any refused call.

As an MCP server, over stdio for local clients:

```bash
export AURO_WORKSPACE_ROOT=/srv/auro/workspace
export AURO_MCP_ALLOWED_DIRECTIVE_IDS=tool_catalog
python -m auro_runtime mcp
```

Or streamable HTTP with bearer auth, for remote use:

```bash
export AURO_MCP_API_KEY=...
export AURO_WORKSPACE_ROOT=/srv/auro/workspace
export AURO_MCP_ALLOWED_DIRECTIVE_IDS=tool_catalog
python -m auro_runtime mcp \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8001 \
  --public-url https://auro.example.com
```

Remote mode has no per-client identity. Every client shares this bearer token, and the audit log records what happened, not who requested it.

The MCP server exposes no directives unless `AURO_MCP_ALLOWED_DIRECTIVE_IDS` names them explicitly. Discovery and execution use the same server-wide set; this is deployment exposure configuration, not per-user RBAC.

MCP startup also requires an existing `AURO_WORKSPACE_ROOT` (or `--workspace`). The server will not inherit an incidental launcher directory as its writable file and audit scope.

The wheel carries reviewed default policies and directives as package resources. Runtime tools expose those resources through read-only `directives/` and `policies/` mounts; writes, restores, deletes, drafts, archives, and the default audit log remain in the workspace. `AURO_WORKSPACE_ROOT` selects that writable workspace and is frozen on first resolution. The deprecated `AURO_ROOT` name may still select workspace state for local compatibility, but neither variable can redirect executable directives, policies, or Python imports.

## Operational audit

The default operational sink is `auro_audit.jsonl` in the workspace; `AURO_AUDIT_LOG` can select a different path. Each line is a schema-v1 event with a stable flat envelope:

```json
{
  "schema_version": "1",
  "event_id": "8a33e75e-...",
  "run_id": "525cf4df-...",
  "sequence": 1,
  "timestamp": "2026-07-27T22:14:05.123456+00:00",
  "event": "policy_guard_check",
  "redacted_fields": ["$.reason"],
  "tool": "read_file",
  "rule_id": "sensitive_paths",
  "allowed": false
}
```

Event-specific fields remain top-level so the JSONL is easy to inspect and existing readers can group by `event`, `tool`, `directive_id`, or `rule_id`. Events emitted inside one pipeline run share `run_id`, increment `sequence`, and expose the same correlation value as `meta.audit_run_id` in the returned result. `event_id` identifies the individual record.

All event creation and bulk persistence pass through the same structured sanitizer. It removes supported secret-shaped values and values carried under sensitive keys before they reach a collector or file, normalizes nested result types to JSON-safe values, and records safe field paths in `redacted_fields`. Pattern recognition is not omniscient: embedding applications should still keep credentials out of prompts and tool payloads and use aliases for secret delivery.

This sink is best-effort, append-written JSONL. It is **not** an immutable event store, a tamper-evident ledger, or a durability guarantee. Domain events and durable application state belong behind a separate application-supplied persistence interface.

## Verification

`verify_project` is a developer/source-checkout gate, not an installed-wheel
self-test. It requires a complete checkout containing `pyproject.toml`,
`tests/`, `auro_runtime/`, and `runtime_tools/`. Run it from an editable
checkout, or point an installed command at the checkout explicitly:

```bash
export AURO_SOURCE_ROOT=/path/to/auro-runtime  # omit for an editable checkout
python -m auro_runtime run --directive verify_project "run the gate and tell me what it verified"
```

Three phases run in order. If the static or security checks find errors, the dynamic phase does not run. Static checks parse every source file and validate directive front matter. Security checks scan the whole tree for secret patterns and confirm every registered guard is bound by some policy rule. Dynamic checks import the tools, validate policies against the live registries, and run the test suite inside a temporary project copy with a sanitized environment.

One design note, because it took three separate bugs to learn: a check that examined nothing must not report success. An empty secret scan, a test phase with no tests collected, a guard registered but bound by no rule. Each of those was a green result hiding a gap. Checks here report what they covered, not just a verdict, and an empty scope is a failure.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite covers policy validation, guard bindings, the executor's refusal paths, workspace/authority separation and the read-only resource mount, credential resolution, registry integrity, and end-to-end runs against a stub model server.

A further regression pack exercises path-containment and secret-scanner edge cases whose payloads would themselves double as an attack corpus if published. It is **not part of this repository and does not run in CI** — it is maintained privately and run by hand. What you can clone is what CI runs; no green result here depends on a test you cannot see.

[`docs/TESTS.md`](docs/TESTS.md) lists every published test and what it asserts. A count tells you nothing about what was checked, so the catalogue is generated from the test sources rather than written by hand, and a test fails if it drifts:

```bash
python -m tests.catalogue           # regenerate
python -m tests.catalogue --check   # exit 1 if stale
```

## Current boundaries

`auro-runtime` has no state engine. Nothing here tracks what is true across runs, applies transitions, or resumes an interrupted thread. The five pipeline stages (Intake, Plan, Execute, Verify, Persist) are protocols, and the default `Persist` writes audit events. Anything that wants durable state implements its own.

Identity sits outside this kernel. There is no user or role model, and no per-caller attribution.

Nor is this a general agent framework. It permits one tool call per turn, with no parallel calls or sub-agents.

One result from local testing with Llama 3.2 3B through Ollama: it can drive a simple single-call directive, but it did not follow the multi-step `health_check` protocol. It answered in prose instead of returning a tool call, and the run ended with a parse failure. That is one tested configuration, not a claim about every small model. If you use a small model, start with short directives and test the behavior you need.

## Requirements

Python 3.10+. Core dependencies are `pyyaml`, `pydantic`, `mcp`, and `requests`. Model provider SDKs are optional extras, imported only when that backend is selected, so the package installs and runs with none of them present.

## License

MIT. Copyright (c) 2026 Chris Thurman.
