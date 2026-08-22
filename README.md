# auro-runtime

This is a security focused AI skills execution kernel. The entire premise of this project was to create a safe execution layer for an agentic system to run skills autonomously and provide consistently trustworthy results. If, during a given run, a model proposes an action or tool call that is not allowed, this runtime rejects it before it has a chance to execute. That verdict is then appended to auro_audit.jsonl, or to whatever path AURO_AUDIT_LOG names. Guards write events on refusal, but a guard that approves returns `None` and logs nothing in this version. (See Operational Audit for the record shape.) Primary access to this runtime kernel is via MCP in this version. It can be used with Stdio to directly wire into an AI harness.

## Directives

There are two defined layers to the kernel. The first layer is the directive. It lists the job, steps, and all of the registered tools the model is allowed to use during a given run. The body of the directive provides the context the model needs: purpose, steps, requirements, handoff notes etc. and the YAML frontmatter defines which tools are available for that particular directive along with a description, the directive ID, and which category of directive it belongs to. Directives with an empty tool list will still load in and run just fine but any attempt at calling a registered tool will be rejected.

example directive tool list:

```yaml
---
id: tool_catalog
description: List all registered tools with name, description, and argument summary
tools: [list_tools, read_file]
category: system
---
```

Thirteen directives ship with the runtime, covering credential setup, policy audits, and directive drafting. `docs/DIRECTIVES.md` lists every one with the tool authority it grants. The catalogue is generated from the directive sources by `python -m tests.directive_catalogue`, using the same loader the executor uses. The scope printed in the catalogue is the scope actually enforced at dispatch, not a second description maintained alongside it.

The catalogue will go stale the moment a directive is added, removed, or has its frontmatter changed, and it will stay that way until the generator is rerun. `python -m tests.directive_catalogue --check` runs in CI, and the test suite makes the same comparison, so a stale catalogue fails the build rather than shipping. The generator also refuses to guess. A directive with unparsable frontmatter, an `id` that disagrees with its filename, a missing description, or an unknown category halts generation instead of producing a plausible-looking entry.

---
#### Regenerate Directive Catalogue

From a clone of the repository:

```Python
python -m tests.directive_catalogue          # rewrite docs/DIRECTIVES.md
python -m tests.directive_catalogue --check  # reports any drift in the testing catalogue
```

Running it when nothing has changed rewrites the same bytes, so there is no harm in running it out of habit. The generator lives in `tests/`, which is not packaged, so ***regeneration is a repository task*** rather than something an installed copy can do.

---

#### Directive Drafting and Promotion

`write_file` accepts two destinations: `output` and `drafts`.

A model drafting a directive writes to `drafts/directives/<id>.md` and stops there. Point the same call at any other directory and it comes back with `Path is in protected directory. Cannot write.` This block also covers `delete_file`, so existing directives cannot be removed either, and `policies/`, `auro_runtime/`, `runtime_tools/`, and `.git` all sit behind the same blacklist list. Each path is resolved to its real target before it is checked, so a symlink, a Windows junction, or a `../` sequence pointing outside the writable area resolves to its true location and is refused there.

A directive's `tools:` list is the only thing that grants tool authority to a run. If a directive should list a tool that is missing from the registry, any attempted call to it is refused. If a run could write to directives/, it could add a line to its own tool list, re-enter, and arrive holding permissions no operator ever gave it. The protected path stops that loop from closing.

Example Log:

```
Tool 'write_file' is not allowed by the current directive. Allowed: ['read_file', 'list_tools']
```

Widening the allowlist doesn't open it either. `AURO_RUNTIME_WRITABLE_DIRS` overrides the two designated destinations, but naming a protected directory raises at import: `AURO_RUNTIME_WRITABLE_DIRS cannot include protected directories: directives`. The runtime refuses to start rather than run with the boundary quietly removed.

---
*note: One exception lives outside the directive layer: an embedding application calling `execute()` directly can pass `UNRESTRICTED` instead of a tool scope, bypassing this boundary. the Policies section below covers that path, and why it has to be named rather than reached by omission.*

---

Currently, the only way to promote a directive is to place the file in `directives/` by hand. Nothing inside a run can do it. That is deliberate. Any automated promotion path needs write access to `directives/`, which is exactly what the protected list denies. A later version will look at whether that step can move inside the runtime without handing the capability back to a run. Regenerate the catalogue once the file is in place.

## Tools

Only 2 of 12 tools carry authority beyond the local workspace, `http_request` and `generate_text`. `http_request` is the reference implementation of credential-alias delivery. `auth_alias` resolves at call time into the `Authorization` header and is the tool the shipped `credential_proxy.yaml` binds its `no_hardcoded_secrets` guard to. No registered tool spawns a subprocess.

| Tool                                        | Privilege                                                                                                            |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `echo`, `list_tools`                        | none (in-memory)                                                                                                     |
| `list_directives`, `validate_directive`     | read-only (packaged authority / workspace)                                                                           |
| `list_dir`, `read_file`                     | read filesystem; blocklist filters `.env`, `auro_secrets.yaml`, `.git`, `.pyc`; `read_file` 1 MiB cap                |
| `write_file`, `delete_file`, `restore_file` | write/soft-delete filesystem, only under `output/` and `drafts/`; protected dirs blocked                             |
| `resolve_secret`                            | reads secret store; never returns the value                                                                          |
| `http_request`                              | network egress + reads secret (`auth_alias`); SSRF filter is string-only, not enforced                               |
| `generate_text`                             | network egress + reads provider API key; per-run cap 10; high-cost gate is a soft speed-bump the model clears itself |
## Policies

Policies provide the second layer. They inspect permitted calls outside the model, so enforcement does not depend on the model remembering an instruction or choosing to comply. While they cannot guarantee correct model behavior, they do make specific boundaries durable wherever a guard has been defined.

The work splits into two components. The policy files hold rules which are a structured declaration that states which guard to run, which tools it covers, and what should happen when the check says no or fails. The check itself is a guard, a registered function in the runtime that receives the proposed call and returns a verdict. Any rule naming a guard that is not registered fails at startup, and a registered guard that has no rule references is caught by a test, because a guard nothing invokes reads as vacuous protection.

Policy Rules are defined by six fields: 
- `id` and `description` carry prose that reaches the model in the system prompt. 
- `guard` defines which guard function inspects calls with this rule enforced. 
- `enforcement` determines what happens when that function denies one.
- `on_error` decides what happens when the function itself raises. 
- `tools` scopes the rule to particular tools. An empty `tools` argument assumes the rule applies to all registered tools.

##### Example Rule:

```YAML
- id: sensitive_paths
  description: Be cautious with paths that suggest sensitive locations.
  guard: check_sensitive_paths
  enforcement: block
  on_error: fail_closed
  tools: [read_file, write_file, delete_file, list_dir, restore_file]
```

##### Rule Settings

| Setting                 | Condition                              | Result                                                                                                                                                                                                      |
| ----------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enforcement: advisory` | Policy is passed as context to the LLM | This is the default when a policy rule does not specify enforcement. The runtime does not execute a check for that rule. To make the rule executable, name a guard and set enforcement to `warn` or `block` |
| `enforcement: block`    | The guard denies the call              | Refuse the call and record the verdict                                                                                                                                                                      |
| `enforcement: warn`     | The guard denies the call              | Record the verdict and allow the call to proceed                                                                                                                                                            |
| `on_error: fail_open`   | The guard raises an error              | Record the error and allow the call to proceed                                                                                                                                                              |
| `on_error: fail_closed` | The guard raises an error              | Block the call and record the error                                                                                                                                                                         |

Seven guard-bound rules ship: six in `default.yaml` and one in `credential_proxy.yaml`. `router.yaml` carries ten rules with no guard at all, which is what the advisory enforcement role is for. Each of the seven has its guard, enforcement, `on_error`, and tool scope pinned by a test, so a silent downgrade fails the build.

When more than one rule covers a call, evaluation is deterministic and stops at the first refusal. Rules load in a fixed order (alphabetical by policy filename, then their order within the file) and are checked in that order. A `warn` verdict is recorded and evaluation continues; a `block`, or a guard that raises under `fail_closed`, refuses the call immediately and the rules after it do not run.

At startup the runtime validates every policy against the live tool and guard registries. A rule naming a guard that is not registered, is not callable, or does not accept exactly one argument fails the load. So does an `enforcement` or `on_error` value outside the accepted set, and so does `block` or `warn` with no guard named.

One case deserves calling out: A rule that names a guard but leaves out `enforcement:` defaults to advisory, and advisory rules are filtered out before execution, so the guard would never run and nothing would be audited. The runtime treats that as a load error rather than a default: `has guard 'check_sensitive_paths' but no enforcement key`. Declaring `advisory` explicitly is still allowed. What is not allowed is arriving there by silence.

The executor holds the same line at its own boundary. That validation runs for policies loaded through `run()`, the CLI, and the MCP server, and `execute()` is public, so an embedding application can drive the executor directly instead. It refuses any call whose tool scope, policy rules, or run history is missing rather than skipping that check, and a rule naming a guard the registry does not hold counts as a guard that failed rather than one that approved, with `on_error` deciding what follows. 
### Policy Customization

The shipped policy set is reviewed, and by default the runtime checks that it is the set actually loaded. If the bindings and rule ids do not match, the run is refused and the error names what is missing and what is extra.

The check covers what the reviewed rules do: 
- the guard each one runs
- its enforcement level
- how it behaves when that guard raises
- which tools it covers. 

**Adding your own rules needs nothing turned off.** Put a binding of your own beside the shipped ones and the check still applies to the reviewed rules. Removing a shipped rule, or editing one so it stops enforcing, is refused. That is the case `custom` exists for:

```
export AURO_POLICY_PROFILE=custom
```

This is not an opt-out from enforcement. Your rules still load, your guards still run, and every boundary above still applies. What you give up is the check itself: under `custom`, nothing verifies that the shipped rules you kept are still doing what they were reviewed to do. The default is `shipped`. Any other value is refused at startup rather than treated as custom. 
### Guards

A rule's `guard:` field is a lookup key. Guards register under that name, and every one has the same shape:

```Python
from auro_runtime.guards import GuardContext, GuardVerdict, register_guard
@register_guard("check_sensitive_paths")
def check_sensitive_paths(ctx: GuardContext) -> GuardVerdict | None:    
...
```

The one-argument signature is not a convention. `validate_policies()` checks it at load, alongside the guard existing and being callable, so a guard of the wrong shape fails startup rather than the first call that reaches it.

`GuardContext` is a frozen dataclass holding the snapshot of the proposed call:

```Python
tool_name: str            # the tool being called
raw_args: dict            # arguments as the model produced them
args: dict                # arguments after schema validation
reason: str               # the model's stated reason for the call
directive_id: str | None  # the directive it is running under
run_history: list[dict]   # prior calls this run, for stateful guards
```

`GuardVerdict` is also a frozen output. Two fields are required, two are optional:

```Python
allowed: bool                 # required: the decision
message: str                  # required: what the caller and the log are told
code: str | None = None       # optional: stable identifier for the verdict
metadata: dict | None = None  # optional: structured detail
```

Neither optional field is declared centrally. `code` is a free string and `metadata` a free dict, both written where the verdict is built. `code` earns its place by being stable where `message` is not. The executor keys behavior off it, redacting matched fields before writing the audit record for `secret_detected` or `raw_credential` verdicts.

The shipped guards use the following codes: 

| `empty_reason` | `secret_detected` | `sensitive_path` | `raw_credential` | `bulk_write` | `destructive_action` | `write_budget_exceeded`. 

---

*note: Returning `None` and returning `GuardVerdict(allowed=True, ...)` both let the call proceed, but they differ in one way. A verdict writes a `policy_guard_check` record carrying the decision, message, code, and metadata. `None` writes nothing at all. V1's shipped policies all default to `None` on passing checks, meaning only errors and violations are logged.*`

---

### Example: refusing a sensitive path

Suppose the active directive permits `read_file`, and the model proposes:

```Python
read_file(path="auro_secrets.py")
```

The call passes directive scope because `read_file` is allowed. The `sensitive_paths` policy applies to that tool, so the runtime passes the call to `check_sensitive_paths`.

The guard normalizes the path and compares it with a set of sensitive patterns. In this case, it returns a verdict resembling:

```Python
GuardVerdict(
    allowed=False,
    message="Path argument 'path' matches sensitive pattern.",
    code="sensitive_path",
    metadata={"key": "path"}
)
```

The complete path through the runtime looks like this:

```
Model proposes read_file("auro_secrets.py")
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

## Credentials

The runtime keeps no secret store of its own. A credential has two parts: an **alias**, a name the model may see and use, and a **value**, which it never does. Tools accept the alias, and the runtime resolves it at call time from a source you configure, injecting the result into the outgoing request.

```python
http_request(url="https://api.github.com/user", auth_alias="github_token")
```

The model's only job is to name the alias. That alias is resolved when the tool runs and puts it in the outgoing request. A resolved value never enters the model's context, the tool arguments, the returned result, or the audit log. Putting a raw token in `headers` is refused by the `no_hardcoded_secrets` guard before the request goes out, and the record of that refusal does not carry the credential either.

Two backends ship.

`env` is the default and reads `AURO_SECRET_<ALIAS>`. **The runtime does not encrypt these values**, and child processes inherit them. Use it where your deployment system already injects environment variables and stays responsible for their storage and access control.

`keyring` delegates to whatever backend Python's `keyring` package selects: macOS Keychain, Windows Credential Manager, Linux Secret Service. Storage and unlock behaviour belong to that backend, not to the runtime. Install with `pip install ".[keyring]"` and set `AURO_SECRET_BACKEND=keyring`.

The runtime tries three sources in order:

1. **Request-scoped secrets**, if an embedding application supplied them for this run. It resolves them in its own layer, from whatever store it already uses, and passes values rather than a source for the runtime to read.
2. **`AURO_SECRET_<ALIAS>`** in the process environment. This is where a deployment system injects credentials, so it is consulted even when a backend is configured and takes precedence over anything stored there.
3. **The backend named by `AURO_SECRET_BACKEND`**, if one is set. This is the durable store for a credential you saved once on a machine, rather than one supplied per run or injected per deployment.

Choosing `keyring` hands storage to your OS credential store, so the operations that matter most happen outside the runtime: saving a secret, rotating it, removing it. `docs/CREDENTIALS.md` covers that half for Windows Credential Manager, step by step, along with the failure modes worth knowing about.

---

*note: Selecting `keyring` adds a source rather than replacing the environment. That ordering lets a deployment system override a stored value, and it means a leftover `AURO_SECRET_<ALIAS>` silently shadows the entry you saved in a credential store. If a lookup surprises you, check the environment first.* 

---

Model-provider credentials can use the same alias path. For Anthropic, store the key under the `auro-runtime` service and select its alias:

```bash
python -m keyring set auro-runtime anthropic_provider
export AURO_SECRET_BACKEND=keyring
export AURO_ANTHROPIC_API_KEY_ALIAS=anthropic_provider
```

The first command prompts for the value so it does not need to appear in shell history. Wherever the runtime is configured, only the backend and alias names are written down, never the secret. If an alias is explicitly configured but cannot be resolved, the Anthropic backend fails closed rather than falling back to `ANTHROPIC_API_KEY`. The environment key remains available for compatibility only when no alias is selected.
## Threat model and trust boundary

The kernel's one job is to make a model's proposed actions refusable before they run. Everything else in the trust boundary follows from that one stance.

| Party                                 | Trusted?                            | Grounding                                                                                                                                                                                                                        |
| ------------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The model                             | **No** — primary adversary          | Its calls are the thing checked; sees only rule id/description in the prompt (`policy.py:308-316`); cannot set config (no model `os.environ` write); cannot reach a tool no directive grants (`allowed_tools_for` fails closed). |
| Tool output                           | **Partly**                          | Scrubbed for secret shapes before re-entering context (`sanitize_value`), but embedded instructions are not neutralized. Treat tool results as untrusted data.                                                                   |
| Directive / policy author             | **Yes** (trusted human, R2)         | A directive's `tools:` list is its authority; `write_file` refuses paths under `directives/`; activation is a deliberate human file move.                                                                                        |
| Embedding application via `execute()` | **Yes** (R3)                        | Must supply a complete security context; `UNRESTRICTED` is the only explicit opt-out. Publishing `docs/API.md` is what makes this tier reachable at all.                                                                         |
| Operator / deployment                 | **Yes**                             | Sets configuration, including knobs that deliberately weaken the default posture. The runtime does not defend against its own operator.                                                                                          |
| MCP client                            | **Authenticated, not individuated** | `AURO_MCP_API_KEY` gates streamable-http; the exposed directive set is server-wide and does not have a per-client deployment configuration; no per-caller RBAC.                                                                  |

**Settings that weaken the default posture.** All are operator-set; none is reachable by a model. `AURO_ALLOW_NO_POLICIES` is the environment form of the deliberate opt-out detailed under Opting out below; the rest are single switches.

- `AURO_ALLOW_NO_POLICIES=1` converts the zero-rules refusal into an unguarded run. The biggest single weakener.
- `AURO_POLICY_PROFILE=custom` drops the shipped-posture drift check (guards still run).
- `AURO_RUNTIME_WRITABLE_DIRS` / `AURO_RUNTIME_DELETE_ALLOWLISTED_DIRS` replace the write/delete sandbox allowlists (they raise at import if they name a protected dir).
- `AURO_OPENAI_BASE_URL` redirects LLM traffic.
### Opting out

Running without a boundary is possible at two scopes: per call, and per run. Both must be named explicitly. A missing argument, empty rule list, or missing directory all refuse by default. For a single call, `UNRESTRICTED` is a sentinel exported from `auro_runtime.executor`, and the only value `execute()` treats as "skip this check".

```Python
from auro_runtime.executor import UNRESTRICTED, execute

# every boundary enforced

execute(call, allowed_tools={"read_file"}, policy_rules=rules, run_history=steps)

# guards deliberately off, capability boundary still enforced

execute(call, allowed_tools={"read_file"}, policy_rules=UNRESTRICTED, run_history=[])
```

`UNRESTRICTED` applies per argument, so switching off guard evaluation does not also drop the tool scope. It is a distinct object rather than `None`, `[]`, or a boolean flag so only the application embedding the runtime can reach it. A model emits a tool name, arguments and a reason, and nothing else; the tool scope and the rule set are supplied by the orchestrator, so a tool call has no field a sentinel could occupy.

Leave an argument out instead and the call is refused, with the alternative named in the error:

```
Incomplete execution context: policy_rules not supplied. execute() refuses rather than skipping a security boundary. Supply the value, or executor.UNRESTRICTED to proceed without it on purpose.
```

---
*note: The two empty scopes (tools and rules) mean opposite things which is worth knowing before you run into it. An empty tool list is a real answer since a directive that declares no tools may run but call none. An empty rule list is not an answer. Zero rules means the guard evaluates nothing, which is indistinguishable from leaving the argument out. That case is what `UNRESTRICTED` exists for.*

---

The same choice exists one level up, for a whole run. A run that loads no enforceable rules is refused, because zero rules means every guard is skipped rather than every guard approving:

```
No enforceable policy rules were loaded from '<dir>'. Every policy guard would be skipped, so this run is refused. Check the policies directory exists and contains rules, or set AURO_ALLOW_NO_POLICIES=1 to run unguarded on purpose.
```

Setting `AURO_ALLOW_NO_POLICIES=1` takes that refusal off, and the run proceeds with `UNRESTRICTED` in place of its rules. It emits `unguarded_mode_enabled`, so the log records that the choice was made.

## Install

```bash
pip install auro-runtime
pip install "auro-runtime[anthropic]"           # Anthropic with an environment key
pip install "auro-runtime[anthropic,keyring]"   # Anthropic with an OS credential store
```

Or from a source checkout:

```bash
pip install .
pip install -e ".[dev]"    # editable, with test dependencies
```

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

---

_note: Installing puts an `auro-runtime` command on your path. Every `python -m auro_runtime …` example below works as `auro-runtime …` on an installed copy._

---

## Run something

A directive plus a request is the whole invocation. This one runs the shipped `tool_catalog` directive, which enumerates every registered tool, and it is the cheapest way to confirm a working install:

```bash
python -m auro_runtime run --directive tool_catalog "list the available tools"
```

The command prints the final summary followed by a numbered step list, and exits non-zero when the run fails. Add `--json` for the full result: the message transcript, every step with its arguments and outcome, and the errors from any refused call. `--max-steps` bounds the loop and defaults to 20.

### From Python

Two entry points. `run()` executes a directive you name; `route_and_run()` picks one from the request itself.

```Python
from auro_runtime import run
from auro_runtime.orchestrator import route_and_run

result = run("tool_catalog", "list the available tools")
result = route_and_run("what tools do I have?")
```

Only `run` is exported from the package root; `route_and_run` comes from `auro_runtime.orchestrator`.

Both return the same dict:

```Python
result["success"]         # bool
result["final_summary"]   # str | None
result["error"]           # str | None, set when the run failed
result["messages"]        # ordered transcript: role, content, tool_call, tool_result
result["meta"]            # directive id and run correlation
result["legacy_steps"]    # per-step detail
```

`route_and_run` prepends its routing messages to the transcript, so the record shows which directive was chosen before the directive's own turn begins.

The positional arguments differ, because naming a directive is the thing the router does for you. `run(directive_id, user_request)` takes both; `route_and_run(user_request)` takes only the request. Everything after that is keyword-only.

Shared keyword-only arguments:

|Argument|Type|Purpose|
|---|---|---|
|`directives_dir`|`Path \| str \| None`|Where directives load from. Defaults to the packaged set|
|`policies_dir`|`Path \| str \| None`|Same, for policies|
|`max_steps`|`int`|Step budget for the loop. Default 20|
|`request_secrets`|`dict[str, str] \| None`|Credentials for this run only, never persisted|
|`allowed_directive_ids`|`set[str] \| None`|Restrict which directive ids may run|

`run()` accepts one more that `route_and_run()` does not: `override_directive`, a `(DirectiveMetadata, str) | None` that runs a directive held in memory instead of loading one from disk. The router has no equivalent, because it chooses from what is on disk.

`execute()` sits one layer below and is deliberately not exported from the package root. It runs a single tool call and expects you to supply the directive scope, the enforceable rules, and the run history yourself. The policies section covers what it requires and what happens when something is missing.
### As an MCP server

Over stdio for local clients:

```bash
export AURO_WORKSPACE_ROOT=/srv/auro/workspace
export AURO_MCP_ALLOWED_DIRECTIVE_IDS=tool_catalog
python -m auro_runtime mcp
```

stdio has no authentication. It inherits whatever trust the launching process already holds, which is the right model for a client on the same machine and not for anything reachable beyond it.

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

`AURO_MCP_API_KEY` is mandatory on this transport, and must be ASCII. The process exits rather than start an unauthenticated listener, and exits rather than start one whose key cannot be compared: the `Authorization` header arrives decoded as latin-1 while the environment is decoded by the OS, so outside ASCII the two disagree and no token could ever match. Binding a non-loopback host additionally requires `--public-url`, since the auth metadata has to advertise an address a client can actually reach.

That URL says `https`, and the runtime does not terminate TLS. This example assumes a reverse proxy in front of it holding the certificate and forwarding to port 8001. Binding `0.0.0.0` without one puts the bearer token in cleartext on every request.

Remote mode has no per-client identity. Every client shares this bearer token, and the audit log records what happened, not who requested it. The server also clamps `max_steps` to 50 whatever a client asks for.

The MCP server exposes no directives unless `AURO_MCP_ALLOWED_DIRECTIVE_IDS` names them explicitly. Unset or empty exposes none, so a server that starts cleanly and returns an empty `list_directives` is configured, not broken. Discovery and execution use the same server-wide set; this is deployment exposure configuration, not per-user RBAC.

MCP startup also requires `AURO_WORKSPACE_ROOT` (or `--workspace`) to name a directory that already exists. The server will not create one, and will not inherit an incidental launcher directory as its writable file and audit scope.

The wheel carries reviewed default policies and directives as package resources. Runtime tools expose those resources through read-only `directives/` and `policies/` mounts; writes, restores, deletes, drafts, archives, and the default audit log remain in the workspace. `AURO_WORKSPACE_ROOT` selects that writable workspace and is frozen on first resolution. The deprecated `AURO_ROOT` name may still select workspace state for local compatibility, but neither variable can redirect executable directives, policies, or Python imports.
## Operational audit

The runtime records all call refusals, errors, and any changes made to disk. Each event is one line of JSON appended to `auro_audit.jsonl` in the workspace. `AURO_AUDIT_LOG` can be configured to point somewhere else if you prefer:

```json
{
  "schema_version": "1",
  "event_id": "8a33e75e-...",
  "run_id": "525cf4df-...",
  "sequence": 1,
  "step_index": 0,
  "timestamp": "2026-07-27T22:14:05.123456+00:00",
  "event": "policy_guard_check",
  "redacted_fields": ["$.reason"],
  "tool": "read_file",
  "rule_id": "sensitive_paths",
  "allowed": false
}
```

The first eight fields are always present, whatever the event was. Everything specific to that event sits beside them rather than nested underneath, so a whole file can be filtered on `event`, `tool`, `directive_id`, or `rule_id` without unwrapping anything first. 

Three fields serve to locate any given record or set of records: 
- `run_id` - shared by every record from one pipeline run and handed back as `meta.audit_run_id` 
- `step_index`- identifies which turn in the run the record was created.
	- This is the same number the returned transcript puts on its messages, so the log and the transcript join on it. 
- `event_id` - unique to each audit record, not to the step that produced it: a single proposed tool call can generate several records; one for each policy rule that returns a verdict, plus anything the tool logs on its own.

`sequence` is a per-run counter claimed once per event, at the moment the record is assembled. Starts at 1. Strictly increasing within a run. This field resets on `begin_audit_run` and is restored on `end_audit_run` so any nested runs get their own numbering, independent across concurrent runs, and the caller resumes where it left off after.

`sequence` starts at 1 within a run and is **not guaranteed to be contiguous**. A run that emitted five events can leave three lines behind, trimmed to the fields that matter:

```json
{"sequence": 1, "step_index": 0, "event": "policy_guard_check"}
{"sequence": 3, "step_index": 0, "event": "tool_not_allowed"}
{"sequence": 5, "step_index": 0, "event": "file_deleted"}
```

A number is claimed partway through building the record, before the record is known to be valid and long before it reaches disk. Two things can go wrong after that. A malformed event is rejected during assembly and never becomes a line. A well-formed event can still fail to be written, and the runtime swallows that `OSError` rather than let an issue that arises with writing the log interrupt the run it is logging.

From the file, those two are indistinguishable. Event two was never going to be a line; event four should have been one and is gone. So a gap is not evidence of tampering, and it is not proof that nothing was lost.

---

_note: `sequence` counts from 1 and `step_index` counts from 0. `sequence` is an ordinal, the nth event of the run; `step_index` is an index into the step loop, and it carries the value the transcript already uses._

---

Each of these fields return null when nothing owns it. An event emitted outside a run, e.g. an MCP server refusing a directive it doesn't expose, carries `"run_id": null` and `"sequence": null`. An event inside a run but before the step loop begins carries `"step_index": null`. 
## Sanitization

Every event is stripped of secrets on its way out, by the same sanitizer the rest of the runtime uses. `auro_runtime/sanitization.py` removes values that look like credentials, replaces values stored under a name that suggests one, converts anything not directly representable in JSON, and records where each redaction happened in `redacted_fields`, using the path form shown below.  It is a shared boundary, applied on the way to tool results, error messages, guard verdicts and the MCP surface as well.

example write log:

```json
{"sequence": 2, "step_index": 1, "event": "file_written", "path": "output/notes.md", "size": 21, "backed_up": "20260808_215231_output__notes.md"}
```

During a pipeline run, events accumulate in memory and are written once at the end, so each one passes through the sanitizer twice. `write_audit_records()` in `audit.py` is a public entry point that will accept records from any caller, so it cannot assume anything upstream cleaned them and scrubs unconditionally. On this path that work is wasted, which is the intended trade.

The scrubbing currently works from a fixed list. A value is removed if it matches one of the credential shapes defined in `auro_runtime/sanitization.py`, or if it sits under a key name like `token` or `password`. A secret that does neither will leak through. Keep credentials out of prompts and tool payloads and use aliases for delivery, rather than relying on this pass to catch them.

This log is best-effort and append-written. It does not hold any durability guarantees. It records what the runtime did but it does not address the application's own events or lasting state. Those need persistence at the embedding application layer.

A run buffers its audit events and writes them once at the end, so a failed write loses the whole run's trail rather than one line of it. `meta["audit_persisted"]` is false when that happens, and `meta["audit_errors"]` identifies how many records were lost out of how many were held. Neither field carries the sink's path as that would put the deployment's filesystem layout into a value the caller receives. The path and the underlying error go to Python's logging under `auro_runtime.audit`, which reaches stderr unless the embedding application routes it elsewhere.

---

_note: `audit_persisted` returning a true value just means that the run's buffered records reached the file. A record rejected while being assembled was never going to be written, and a run that produced no events at all reports true because nothing failed._

---

## Verification

The runtime ships with four verification scripts that validate a developer source checkout. They require a complete checkout containing `pyproject.toml`, `tests/`, `auro_runtime/`, and `runtime_tools/`. Without one they return a structured `SOURCE_CHECKOUT_REQUIRED` refusal rather than a pass. Run them from an editable checkout, or point an installed copy at a checkout explicitly:

```bash
export AURO_SOURCE_ROOT=/path/to/auro-runtime  # omit for an editable checkout
```

`verify_output` runs all three verification scripts in sequence and returns a structured verdict (`passed`, `error_count`, `warn_count`, `info_count`, `findings`, `phases`). 

```python
from runtime_tools.verify_tools import verify_output

result = verify_output()
print(result["passed"], result["error_count"], result["warn_count"])
```

 `passed` returns true only when no finding carries error severity **and** every subcheck in `checks` reported a pass. The second half matters because a subcheck can fail without raising an error finding — one that examined nothing, or one whose own inspection crashed — and those used to leave a headline `passed: true` sitting on top of a `checks` list that said the opposite. Warnings still do not fail a run on their own. Every `detail` reports what the check covered rather than only whether it passed, and a scope of zero is recorded as a failure rather than as a clean result: an empty secret scan, a policy set with no enforceable rules, an empty tool registry, or a `git status` that exits non-zero all fail the run. `tests/test_verifier_non_vacuity.py` is the gate that proves it, driving each evidence source to zero in turn. 

Example output:

```json
{
  "passed": true,
  "error_count": 0,
  "warn_count": 0,
  "info_count": 0,
  "findings": [],
  "phases": [
    {
      "phase": "code_static",
      "passed": true, "error_count": 0, "warn_count": 0,
      "checks": [
        {"name": "syntax_check", "passed": true, "detail": "37 Python files parsed"},
        {"name": "directive_validation", "passed": true, "detail": "13 directives valid"},
        {"name": "policy_yaml_parse", "passed": true, "detail": "3 policy files valid"},
        {"name": "file_layout", "passed": true, "detail": "All expected directories present"}
      ]
    },
    {
      "phase": "security",
      "passed": true, "error_count": 0, "warn_count": 0,
      "checks": [
        {"name": "secret_scan", "passed": true, "detail": "97 files scanned clean"},
        {"name": "sensitive_files", "passed": true, "detail": "No sensitive files staged"},
        {"name": "guard_completeness", "passed": true, "detail": "7 enforceable rules, all guards present"},
        {"name": "tool_schemas", "passed": true, "detail": "All 12 tools have schemas"}
      ]
    },
    {
      "phase": "code_dynamic",
      "passed": true, "error_count": 0, "warn_count": 0,
      "checks": [
        {"name": "tool_imports", "passed": true, "detail": "12 tools registered"},
        {"name": "policy_validation", "passed": true, "detail": "All policies valid against registries"},
        {"name": "test_suite", "passed": true, "detail": "409 passed, 7 skipped in 21.15s"}
      ]
    }
  ]
}
```

If either of the first two phases report an `error` severity finding, the dynamic phase does not run. `Warn` severity results or a check that crashes is recorded as failed in `checks` but contributes no finding does not stop the dynamic phase. In its place in `phases` it will be marked `skipped` with the reason instead of as a pass.

**Phases:**
- Static checks parse every source file and validate directive front matter. 
- Security checks scan the whole tree for secret patterns, confirm no sensitive file is staged for commit, and confirm that every enforceable policy rule names a guard the registry actually holds. 
- Dynamic checks import the tools, validate policies against the live registries, and run the test suite inside a temporary project copy with a sanitized environment.

---

_note: Only one direction of the guard check runs in the security phase. It catches a rule pointing at a guard that does not exist. The reverse case, a guard registered in code that no policy rule ever binds, is caught by the test suite, which runs in the dynamic phase: the phase that is skipped when an earlier one errors. Meaning that a tree with a static error can go a whole gate run without anything checking for orphaned guards._

---

### Commit-bound release evidence

`release_evidence.py` is the publication-candidate gate. It is a root-level operator script rather than a runtime tool, so it can report on a checkout even when the runtime package does not import. Install the development and release dependencies, then name the full commit that the candidate must come from:

```bash
pip install -e ".[dev]" twine
python -B release_evidence.py \
  --expected-commit "$(git rev-parse HEAD)" \
  --output-dir dist
```

The command refuses unless the supplied 40-character id is `HEAD`, the index tree equals that commit's tree, and `git status --porcelain --untracked-files=all` is empty. It exports that commit with `git archive`, builds one wheel and one sdist from the export, runs `twine check`, and drives the mandatory distribution matrix against those exact artifacts. A successful output directory contains the wheel, the sdist, and `release-evidence.json`; the record binds their filenames, sizes, and SHA-256 digests to the commit, commit/index tree ids, toolchain versions, clean-before-and-after state, and a non-zero pytest count.

CI supplies GitHub's workflow commit as `--expected-commit` and retains the three files together. The retained candidate is evidence for that workflow identity; it is not evidence for an artifact rebuilt later from a local checkout.

---

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The testing suite covers:
- policy validation
- guard bindings
- the executor's refusal paths
- workspace/authority separation
- the read-only resource mount
- credential resolution
- registry integrity
- the audit envelope and sanitizer contracts
- soft-delete archive integrity
- end-to-end runs against a stub model server.

[`docs/TESTS.md`](docs/TESTS.md) lists every published test and what it asserts. A count tells you nothing about what was checked, so the catalogue is generated from the test sources rather than written by hand, and a test fails if it drifts:

```bash
python -m tests.catalogue           # regenerate
python -m tests.catalogue --check   # exit 1 if stale
```

## Current boundaries

This is Alpha software (version 0.1.x). It is built for constrained, local, single-operator use behind controls you supply, and carries no compatibility or stability guarantee yet.

`auro-runtime` has no state engine. Nothing here tracks what is true across runs, applies transitions, or resumes an interrupted thread. The five pipeline stages (Intake, Plan, Execute, Verify, Persist) are protocols, and the default `Persist` writes audit events. Anything that wants durable state implements its own. Nor is this a general agent framework: it permits one tool call per turn, with no parallel calls or sub-agents.

The runtime bounds a run's length and little else. Its resource behavior:

| Concern                 | Behavior                                                           |
| ----------------------- | ------------------------------------------------------------------ |
| Steps per run           | Capped: 20 by default, 50 maximum over MCP                         |
| Model calls per run     | Capped                                                             |
| Model-call timeout      | None on the Anthropic path; 120s on the OpenAI-compatible path     |
| Tool-call timeout       | None; the step loop has no wall-clock guard                        |
| Retry / backoff         | None; a model-backend error ends the run                           |
| Cancellation / deadline | None                                                               |
| Concurrency             | No application cap; each MCP request runs on a default thread pool |
| Memory / CPU            | No limit                                                           |

Anything beyond the step and call caps (a model-call timeout, retry, cancellation, a concurrency limit) you must supply around the kernel.

## Requirements

Python 3.10+. Core dependencies are `pyyaml>=6.0`, `pydantic>=2.0`, `mcp>=1.26,<2`, and `requests>=2.28`. Model provider SDKs are optional extras, imported only when that backend is selected, so the package installs and runs with none of them present.

Both `mcp` bounds are load-bearing. mcp 2.0.0 removed `mcp.server.fastmcp`, which `mcp_server.py` imports, so an unbounded `mcp>=1.0` resolves to a version where the MCP server dies on import (the isolated-wheel install test is what catches it). The floor is the version this has actually been exercised against rather than the oldest that might work: the server passes `token_verifier=` to FastMCP, which early 1.x does not accept.

## License

MIT. Copyright (c) 2026 Chris Thurman.
