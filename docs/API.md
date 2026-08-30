# auro-runtime API

Reference for embedding the runtime, driving the executor directly, and extending it with tools or guards.

`auro_runtime` exports one name: `run`. Everything else in this document is reachable, but reaching for it means taking on work `run()` does for you. Each section says what that work is.

**Contents**

- [Running a directive](#running-a-directive) — the supported entry points
- [Driving the executor yourself](#driving-the-executor-yourself) — `execute()` and the context it requires
- [Adding a tool](#adding-a-tool)
- [Adding a guard](#adding-a-guard)
- [Embedding and operating](#embedding-and-operating) — policy profile, secrets, audit, paths
- [Tool reference](#tool-reference) — argument contracts for the 11 shipped tools
- [MCP server](#mcp-server)

---

## Running a directive

Two entry points. `run()` executes a directive you name; `route_and_run()` picks one from the request.

```python
from auro_runtime import run
from auro_runtime.orchestrator import route_and_run

result = run("tool_catalog", "list the available tools")
result = route_and_run("what tools do I have?")
```

Both return the same dict:

| Key | Type | Meaning |
|---|---|---|
| `success` | `bool` | Overall outcome. `False` also covers a run the model declined — see `RefusalOutput` under [Types](#types), where `error` is `None` |
| `messages` | `list[dict]` | Ordered transcript: `role`, `content`, `tool_call`, `tool_result`, `step_index`, `timestamp` |
| `final_summary` | `str \| None` | Closing summary, when the run produced one |
| `error` | `str \| None` | Set when the run failed |
| `meta` | `dict` | `directive_id` and `audit_run_id` for joining to audit events. A run that reached the execute stage also carries `pipeline_verify_passed` and `audit_persisted` — `False` when the run's audit records did not reach the file, with `audit_errors` alongside it. A run that ended earlier, such as a routing failure, carries neither: read them with `.get()`. See [Audit](#audit) |
| `legacy_steps` | `list[dict]` | Per-step detail |

`route_and_run` prepends its routing messages to the transcript, so the record shows which directive was chosen before that directive's own turns begin.

Shared keyword-only arguments:

| Argument | Type | Purpose |
|---|---|---|
| `directives_dir` | `Path \| str \| None` | Where directives load from. Defaults to the packaged set |
| `policies_dir` | `Path \| str \| None` | Same, for policies |
| `max_steps` | `int` | Step budget for the loop. Default 20 |
| `request_secrets` | `dict[str, str] \| None` | Credentials for this run only, cleared when it ends |
| `allowed_directive_ids` | `set[str] \| None` | Restrict which directives may run. On `route_and_run` the router only sees this set |

`run()` additionally accepts `override_directive: tuple[DirectiveMetadata, str] | None`, to run a directive held in memory rather than loaded from disk.

`route_and_run` is reached through `auro_runtime.orchestrator` rather than the package root.

---

## Driving the executor yourself

`execute()` runs a single tool call through the enforcement pipeline. It does not load directives, load or validate policies, drive a model, or maintain run history — you supply all of that.

```python
from auro_runtime.executor import execute

def execute(
    tool_call: ToolCallOutput,
    allowed_tools: set[str] | _Unrestricted | None = None,
    directive_id: str | None = None,
    policy_rules: list[PolicyRule] | _Unrestricted | None = None,
    run_history: list[dict] | None = None,
) -> ToolCallResult
```

### The security context is required

The three default to `None`, so omitting one refuses the call at runtime rather than raising `TypeError`. `policy_rules=[]` refuses as well. Either refusal writes an `incomplete_execution_context` audit event:

```
Incomplete execution context: policy_rules not supplied. execute() refuses rather
than skipping a security boundary. Supply the value, or executor.UNRESTRICTED to
proceed without it on purpose.
```

**Caveats**

- The empty collections are not symmetrical. `allowed_tools=set()` and `run_history=[]` are valid; `policy_rules=[]` is not, because zero rules means no guard evaluates — indistinguishable from leaving the argument out.
- `directive_id` is not part of the check. It defaults to `None`, which skips every rule that sets `directives:`, because the filter is `directive_id in rule.directives`. No shipped rule sets it.

### Opting out

`UNRESTRICTED` is a sentinel exported from `auro_runtime.executor`, and the only value `execute()` treats as "skip this check". It applies per argument.

| Argument | Effect of `UNRESTRICTED` |
|---|---|
| `allowed_tools` | Skips check 3. The tool must still be registered |
| `policy_rules` | Skips the guard loop entirely: no guard runs and no `policy_guard_*` event is written |
| `run_history` | Not supported. It satisfies check 1 but is not a list, so a stateful guard raises on it and a `fail_closed` rule then refuses the call. Pass `[]` |

**Caveats**

- It is a distinct object rather than `None`, `[]`, or a boolean flag, because those are the values a caller reaches by accident. The README carries the reasoning.
- There is a second, run-level route: `AURO_ALLOW_NO_POLICIES=1` turns a zero-enforceable-rules refusal into an unguarded run, in which `run()` passes `UNRESTRICTED` for you. See [Embedding and operating](#embedding-and-operating).

### Assembling the context

```python
import runtime_tools  # registers the 11 shipped tools

from auro_runtime.directive import allowed_tools_for, load_directive_by_id
from auro_runtime.paths import get_directives_dir, get_policies_dir
from auro_runtime.policy import get_enforceable_rules, load_policies, validate_policies

meta, _ = load_directive_by_id(get_directives_dir(), "file_analysis")
allowed_tools = allowed_tools_for(meta)          # {'list_dir', 'read_file'}

policies = load_policies(get_policies_dir())
validate_policies(policies)                      # raises ValueError on any problem
policy_rules = get_enforceable_rules(policies)   # required — see caveats
assert policy_rules, "zero enforceable rules: every guard would be skipped"

run_history: list[dict] = []                     # you own this; append after each call
```

**Caveats**

- Import `runtime_tools` before calling `validate_policies()`. It resolves both registries when it is called, not at import, so importing the tools afterwards leaves every `tools:` entry unregistered and unchecked.
- `get_enforceable_rules()` is not optional. It selects rules that have a guard and `enforcement != "advisory"`; a raw `PolicyBinding.rules` list also carries prose-only rules with `guard: None`, which the executor is not built to receive. Guarded rules declared `advisory` are dropped here and logged as `advisory_guarded_rules_not_enforced`.
- `validate_policies()` raises rather than returns: it accumulates every error and raises a single `ValueError` listing all of them. Its return value is always `[]` — do not branch on it.
- `allowed_tools_for()` fails closed: an undeclared or empty `tools:` grants nothing.

### Check order and error strings

`execute()` applies these in order; 6 and 7 are the tool invocation itself. Each returns `ToolCallResult(success=False)` with the message shown; none of them raises.

| # | Check | Audit event | Error |
|---|---|---|---|
| 1 | Context completeness | `incomplete_execution_context` | `Incomplete execution context: <names> not supplied. …` |
| 2 | Tool is registered | `unknown_tool` | `Unknown tool: <name>. Registered: [...]` |
| 3 | Tool is in scope | `tool_not_allowed` | `Tool '<name>' is not allowed by the current directive. Allowed: [...]` |
| 4 | Arguments match schema | `argument_validation_failed` | `Invalid arguments for <tool> — <field>: <reason>` |
| 5a | Named guard is registered | `policy_guard_missing` | `Policy guard missing [<rule>]: guard '<guard>' is not registered. Failing closed.` |
| 5b | Guard did not raise | `policy_guard_error` | `Policy guard error [<rule>]: guard '<guard>' raised an exception. Failing closed.` |
| 5c | Guard verdict | `policy_guard_check` | `Policy violation [<rule>]: <message>` |
| 6 | `fn(**args)` raises `TypeError` | `tool_type_error` | `Invalid arguments: <exception>` |
| 7 | `fn(**args)` raises anything else | `tool_execution_error` | `<exception>` |

**Caveats**

- 5a and 5b refuse unless the rule's `on_error` is exactly `"fail_open"`; 5c refuses unless `enforcement` is in `{"warn", "advisory"}`. Both are typo-resistant by construction — any unrecognised value fails closed.
- Rules are evaluated in list order and the first refusal returns. A rule is skipped when its `tools` or `directives` list is set and does not match the call.
- Check 4 reports only the first pydantic error, and only the first element of its location — three bad fields produce one message naming one field.

### Types

**`ToolCallOutput`** — the model's structured output, and the input to `execute()`.

| Field | Type | Required |
|---|---|---|
| `tool` | `str` | yes |
| `args` | `dict[str, Any]` | no, `{}` |
| `reason` | `str` | no, `""` |

**`CompletionOutput`** — the model's completion shape, the second thing it may emit.

| Field | Type | Required |
|---|---|---|
| `done` | `bool` | yes, always `true` |
| `summary` | `str` | no, `""` — a non-string value is rendered to text rather than rejected |

**`RefusalOutput`** — the model's refusal shape, the third and last thing it may emit.

| Field | Type | Required |
|---|---|---|
| `refused` | `bool` | yes, always `true` |
| `reason` | `str` | no, `""` — a non-string value is rendered to text rather than rejected |

A refusal is a terminal outcome of the run, not an error: `success` is `False`
because no result was produced, `error` is `None` because nothing failed, and
`meta["event"]` is `model_refused` with the stated reason in both
`final_summary` and `meta["refusal_reason"]`. A response carrying both `refused`
and `done` is read as a refusal.

When a response cannot be parsed at all, the runtime re-states the response
format once — naming the refusal shape — and parses the reply before giving up
with `parse_json_failed`. The reminder is recorded as `response_format_reminded`.
It never inspects unparseable prose to decide whether it was a refusal.

**`ToolCallResult`** — what `execute()` returns.

| Field | Type | Required |
|---|---|---|
| `success` | `bool` | yes |
| `result` | `Any` | no, `None` |
| `error` | `str \| None` | no, `None` |

**Caveats**

- `success` is `False` for every refusal, including one the tool itself made. Tools here signal a domain failure by returning a dict with a truthy **top-level** `error` rather than by raising, and the executor lifts that key into `error` — so no caller needs an individual tool's payload shape. That path writes no audit event.
- A tool may carry `error: None` on its success path, and a tool reporting errors as *content* — a validator listing what it found — must nest them under another key.
- `result` keeps the tool's payload on a tool refusal, since it holds detail the message alone does not, and is `None` on the executor's own. Both `result` and `error` are sanitized before return.

**`PolicyRule`** — the element type of `policy_rules`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | `str` | required | Rule identifier, used in refusal messages and audit records |
| `description` | `str` | required | Prose sent to the model in the system prompt |
| `guard` | `str \| None` | `None` | Guard name to invoke. A rule with no guard is prose only |
| `enforcement` | `str` | `"advisory"` | `block`, `warn`, or `advisory` |
| `enforcement_declared` | `bool` | `True` | `False` when the YAML omitted `enforcement:`. A guarded rule that omitted it is rejected at load |
| `on_error` | `str` | `"fail_closed"` | `fail_closed` or `fail_open`, when the guard raises |
| `tools` | `list[str] \| None` | `None` | Restrict to these tools. `None` means every tool; `[]` is rejected at load |
| `directives` | `list[str] \| None` | `None` | Restrict to these directive ids. `None` means every directive; `[]` is rejected at load |
| `scope` | `str \| None` | `None` | Descriptive only |

**`DirectiveMetadata`** — `id` (`str`, required), `description` (`str`, `""`), `tools` (`list[str]`, `[]`), `category` (`system`, `task`, `security`, `debug`; default `task`).

---

## Adding a tool

A tool is a function registered under a name, with an optional pydantic model describing its arguments.

```python
from pydantic import Field
from auro_runtime.executor import register
from auro_runtime.tool_schemas import _ToolArgs

class EchoArgs(_ToolArgs):
    message: str = Field(..., description="Message to echo back")

@register("echo", "Echo back a message (for testing).", args_schema=EchoArgs)
def echo(message: str) -> dict:
    return {"message": message}
```

`register(name: str, doc: str = "", args_schema: type[BaseModel] | None = None)` returns the function unchanged. What the executor does with `args_schema`:

1. `validated = args_schema.model_validate(tool_call.args)`
2. `args_to_use = validated.model_dump()`
3. `fn(**args_to_use)`

**Caveats**

- `model_dump()` fills in defaults, so the function receives *every* field in the schema, not only the ones the model supplied. It must accept all of them as keyword arguments.
- Inherit `_ToolArgs`, not `BaseModel`. `_ToolArgs` sets `extra="forbid"`; pydantic's default is `extra="ignore"`, which drops a misspelled key and runs the tool with that field's default, so the call that reaches the tool is not the call that was made. The refusal names the key: `recurse: Extra inputs are not permitted`.
- `args_schema` is optional. Without it the raw args go straight to the function — no validation, no coercion — and an unknown key surfaces as a caught `TypeError`: `Invalid arguments: <tool>() got an unexpected keyword argument '<key>'`. Every registered tool declares a schema, and a test enforces it; the schemaless path remains for callers who register their own tools.
- Registration is process-global and last-write-wins: registering a name that already exists replaces both the function and its schema.
- `doc` falls back to the function's docstring when omitted.
- The description does not reach the model through the system prompt, which carries the directive body and the allowed tool *names* only. It reaches a model when something calls `list_tools`, so state a tool's limits in the directive body as well.

`get_registry()` returns a copy mapping `name -> (fn, description, args_schema)`. `executor.list_tools()` returns the registered names.

---

## Adding a guard

A rule's `guard:` field is a lookup key. Guards register under that name and every one has the same shape. `validate_policies()` checks at load that the guard exists, is callable, and takes exactly one required parameter.

```python
from auro_runtime.guards import GuardContext, GuardVerdict, register_guard

@register_guard("check_no_widgets")
def check_no_widgets(ctx: GuardContext) -> GuardVerdict | None:
    if "widget" in str(ctx.raw_args):
        return GuardVerdict(
            allowed=False,
            message="Widgets are not permitted in tool arguments.",
            code="widget_found",
            metadata={"tool": ctx.tool_name},
        )
    return None
```

Both types are frozen dataclasses:

```python
class GuardContext:
    tool_name: str            # already registered and in scope
    raw_args: dict
    args: dict
    reason: str               # "" if the model gave none
    directive_id: str | None
    run_history: list[dict]

class GuardVerdict:
    allowed: bool                  # False refuses, unless enforcement is warn or advisory
    message: str                   # surfaced as `Policy violation [<rule>]: <message>`
    code: str | None = None
    metadata: dict | None = None   # recorded as `verdict_metadata`
```

**Caveats**

- Use `raw_args` for anything adversarial: `args` is the post-validation view, with defaults filled in and values coerced. `raw_args` is exactly what the model emitted. Both shipped secret guards scan `raw_args`. Every registered tool declares a schema and a test enforces that, so the two views differ for all of them; a tool registered without one would make `args` the same object. Use `args` for the values the tool will actually receive.
- `frozen=True` prevents rebinding a field; it does not deep-freeze the contents. Treat the context as read-only: guards run in rule order, so a mutation is visible to every later guard and to the tool itself.
- An unknown key never reaches a guard. `extra="forbid"` refuses it during validation, which is before the guard loop; that refusal is audited as `argument_validation_failed`, and no guard exists on that path to supply `matched_fields`, so name-and-pattern redaction is the only cover the rejected arguments get.
- Returning `None` and returning `GuardVerdict(allowed=True, …)` both let the call proceed. A verdict writes a `policy_guard_check` record; `None` writes nothing at all.
- `code` and `metadata` are a free string and a free dict, written where the verdict is built. Nothing declares them centrally except the codes below, which the executor keys behaviour off.

### The `matched_fields` contract

If a verdict's `code` is in `executor.REDACTING_VERDICT_CODES` — currently `("secret_detected", "raw_credential")` — the executor copies the call's **raw** args into the audit record as `redacted_args`, passing them through `redact_for_audit(raw_args, metadata["matched_fields"])` first.

**A guard emitting one of those codes must supply `metadata["matched_fields"]`**, as a list of **structured segment paths** — `[["headers", "Authorization"], ["items", 0, "api_key"]]`. A string segment indexes a dict, an integer segment indexes a list. Emitting the code without the paths is worse than emitting no code at all: the code is what causes the arguments to be recorded in the first place, and without the paths only the generic name-and-pattern scrub applies.

Segments rather than a dotted string, because the flattened form was ambiguous and could not be repaired. `{"a": {"b": …}}` and `{"a.b": …}` produce the identical string `a.b`, so no parser however careful could tell them apart, and a path holding a list index never resolved at all. Carrying the structure means there is no grammar for a producer and a consumer to disagree about. Use `guards.format_field_path(segments)` for anything a human reads; nothing reconstructs structure from that rendering.

**Caveats**

- The name-and-pattern pass (`sanitize_value`) always runs on the copied args. `matched_fields` adds a targeted pass on top of it; it does not replace it.
- **An unresolvable path redacts every string in the record**, rather than being skipped. A targeted pass that cannot find its target has not decided the value is safe, it has failed to look, and those two outcomes are otherwise indistinguishable in the output. This costs audit detail in a case that should not occur; the alternative cost is a credential in the log.
- Paths that are not argument paths are therefore **not** supplied as `matched_fields`. `check_no_secrets_in_args` reports a secret used as a key name, or one found in `reason`, under `metadata["matched_field_labels"]` instead — labelled for the reader, never handed to the walk.
- A path segment can itself be redacted in the audit record if the segment is an attacker-supplied key that looks secret-shaped. That happens after the targeted pass has run, so redaction still lands on the right value; the operator sees a path with `[REDACTED]` in it.

---

## Embedding and operating

### Policy profile

Two environment variables decide whether a run may proceed and how much of the loaded policy set is verified. Both are read per run inside `_run_impl`, not at import, so they apply to every entry point that reaches it: `run()`, `route_and_run()`, the CLI, and the MCP server.

| Variable | Default | Opt-in value | Effect |
|---|---|---|---|
| `AURO_ALLOW_NO_POLICIES` | unset | exactly `1` | Permits a run whose policy set yields zero enforceable rules. Unset, or any other value, refuses it |
| `AURO_POLICY_PROFILE` | `shipped` | `shipped` or `custom` | `shipped` verifies the reviewed policy set is present and unchanged; `custom` verifies nothing. Any other value refuses the run |

With `AURO_ALLOW_NO_POLICIES=1` and zero enforceable rules, the run proceeds with `executor.UNRESTRICTED` in place of its rule list, records `policy_profile: "unguarded"`, and emits `unguarded_mode_enabled` before the first model call.

**Gates**, in the order `_run_impl` applies them once the directive has loaded. Each returns `RunResult(success=False)` before the model is called, with `meta["event"]` set to the audit event name.

| Gate | Refuses when | Audit event |
|---|---|---|
| Policies directory | `policies_dir` is not an existing directory | `policies_dir_missing` |
| Policy validation | `validate_policies()` raises | `policy_validation_failed` |
| Zero enforceable rules | `get_enforceable_rules()` is empty and `AURO_ALLOW_NO_POLICIES != "1"` | `no_enforceable_policies` |
| Policy profile | `AURO_POLICY_PROFILE` is neither `shipped` nor `custom`, or is `shipped` and the set has drifted | `incomplete_policy_profile` |

**What `shipped` checks:**

| Check | Compared against | On a difference |
|---|---|---|
| Binding and rule ids are all present | the reviewed id sets in `orchestrator.py` (private) | Refused, naming the missing ids |
| `guard`, `enforcement`, `on_error`, `tools` still match | `SHIPPED_ENFORCEMENT_POSTURE` via `shipped_posture_drift()` — both public in `auro_runtime.policy` | Refused, naming each drifted field |
| Extra bindings or rules | — | Permitted, and logged at INFO on the `auro_runtime.orchestrator` logger as `shipped_policy_profile_extended` |

`shipped_posture_drift(policies) -> list[str]` is callable on its own; an empty list means no drift.

**Caveats**

- Both variables are matched as exact strings — no trimming, no case folding. `AURO_ALLOW_NO_POLICIES=" 1 "` does not opt in, and `AURO_POLICY_PROFILE=Shipped` refuses the run.
- `AURO_POLICY_PROFILE=` (set but empty) refuses too: only an unset variable gets the `shipped` default.
- Posture is verified only for the enforceable subset in `SHIPPED_ENFORCEMENT_POSTURE`. A prose rule with no guard is checked by id alone, and no rule's `description` is compared — so reviewed prose that reaches the model's system prompt can be rewritten without tripping the check.
- Adding your own rules keeps the `shipped` check; removing a reviewed rule or editing one so it stops enforcing refuses. An addition can only add a check, so it does not push an operator onto `custom`, where posture verification is lost on the reviewed rules too.
- `custom` verifies nothing, including on the shipped rules the operator kept. Guards still run; they are no longer checked to be the reviewed ones.
- An unguarded run skips the profile check entirely: `AURO_POLICY_PROFILE` is never read on that path, so an invalid value does not refuse there.
- A policies directory that does not exist is refused whatever `AURO_ALLOW_NO_POLICIES` says, because `load_policies()` returns `[]` for both a missing and an empty directory — without a separate path check a typo would become an unguarded run rather than a refusal.
- `meta["policy_profile"]` and `meta["unguarded_mode"]` are set on a run the model itself ended — a completion or a refusal. A run that fails or reaches `max_steps` does not report which profile it used.

### Secrets

```python
from auro_runtime.secrets import (
    clear_request_secrets,
    get_backend,
    get_secret,
    list_secret_aliases,
    set_request_secrets,
)
```

| Function | Signature | Notes |
|---|---|---|
| `get_secret` | `(alias: str) -> str \| None` | Resolves through the three sources below in order. Values are stripped; whitespace-only counts as absent |
| `set_request_secrets` | `(secrets: dict[str, str] \| None) -> None` | Highest-precedence source, for this run only. Never persisted |
| `clear_request_secrets` | `() -> None` | Drops them. Call in a `finally` |
| `list_secret_aliases` | `() -> list[str]` | Alias names only, never values |
| `get_backend` | `() -> SecretBackend \| None` | Constructs the backend named by `AURO_SECRET_BACKEND`. `None` when unset or `env` |

Resolution order for `get_secret(alias)`:

| # | Source | Notes |
|---|---|---|
| 1 | Request-scoped secrets | From `set_request_secrets` or `run(request_secrets=...)`. Never persisted |
| 2 | `AURO_SECRET_<ALIAS>` in the process environment | Alias is upper-cased for the lookup. Always consulted |
| 3 | The backend named by `AURO_SECRET_BACKEND` | Reached only when 1 and 2 miss |

| Backend | Selected by | Notes |
|---|---|---|
| `env` | the default; also `AURO_SECRET_BACKEND=env` | Reads `AURO_SECRET_<ALIAS>`. Not encrypted, and inherited by child processes |
| `keyring` | `AURO_SECRET_BACKEND=keyring` | Delegates to the OS store under service name `auro-runtime`. Needs the `[keyring]` extra |

The variable is stripped and lower-cased before matching, so `KEYRING` selects the same backend.

**Caveats**

- The environment is always consulted before any backend, so a stale `AURO_SECRET_<ALIAS>` shadows a value in a credential store.
- An alias that is not an identifier resolves to `None` rather than raising: aliases must be non-empty and alphanumeric apart from `_` and `-`, so `a/b` or `../etc/passwd` is indistinguishable from a missing alias.
- An unknown `AURO_SECRET_BACKEND` raises `ValueError`, and selecting `keyring` without the package raises `RuntimeError` — both from `get_backend()`, which `get_secret()` reaches only after the first two sources miss. An alias satisfied from the environment never surfaces the misconfiguration.
- `list_secret_aliases()` cannot see keyring entries — keyring has no portable enumeration, so its `list_aliases()` returns `[]` — and it swallows a broken backend's exception. A short list is not proof an alias is unconfigured.
- Neither `set_request_secrets` nor `clear_request_secrets` returns a restore token, so calls overwrite rather than nest, and clearing inside an outer caller's run drops that caller's secrets too. Pair them in a `try`/`finally`.
- The backend protocol is an internal seam: `get_backend()` recognises `env` and `keyring` only, and there is no registration point for a third. Inject your own credentials through `set_request_secrets` or `run(request_secrets=...)`.

### Audit

```python
from auro_runtime.audit import (
    begin_audit_run,
    end_audit_run,
    get_audit_run_id,
    get_audit_step,
    set_audit_collector,
    set_audit_step,
)
```

Every audit line is a JSON object with a stable envelope, then event-specific fields at the top level:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | `"1"` | Always present |
| `event_id` | `str` | UUID4, identifies the record. Not the step that produced it: one tool call can write several records |
| `run_id` | `str \| null` | `null` outside a run. Not required to be a UUID |
| `sequence` | `int \| null` | 1-based within a run. **Not guaranteed contiguous**; see below |
| `step_index` | `int \| null` | 0-based orchestrator step, the same number `messages[].step_index` carries, so the log and the transcript join on it. `null` when no step owns the event |
| `timestamp` | `str` | ISO-8601 UTC. **Not unique** — two events can share a microsecond, so do not order on it |
| `event` | `str` | The grouping key. Its values are catalogued in [`AUDIT_EVENTS.md`](AUDIT_EVENTS.md) |
| `redacted_fields` | `list[str]` | `$`-rooted paths where redaction occurred |

| Function | Signature | Notes |
|---|---|---|
| `begin_audit_run` | `(run_id: str \| None = None) -> AuditRunContext` | Sets the run id — UUID4 when omitted — and resets sequence and step. Pass the returned context to `end_audit_run` in a `finally` |
| `end_audit_run` | `(context: AuditRunContext) -> None` | Restores the identity, sequence and step that existed before, so a nested run restores the outer one's correlation rather than destroying it |
| `get_audit_run_id` | `() -> str \| None` | The active run id. `None` outside a run. Also returned as `meta["audit_run_id"]` |
| `set_audit_step` | `(step: int \| None) -> None` | Attributes subsequent events to one orchestrator step. `None` clears it. The orchestrator sets it per iteration |
| `get_audit_step` | `() -> int \| None` | Reads it back |
| `set_audit_collector` | `(collector: list[dict] \| None) -> None` | Diverts events into that list instead of the file. `None` restores file writing |

State lives in `ContextVar`s, per-context and safe across concurrent runs.

**Caveats**

- A `sequence` gap proves nothing in either direction. A rejected record and a failed write both consume a number and the file does not distinguish them. Use `meta["audit_persisted"]` for whether a run's records reached the file.
- `timestamp` is not unique. Do not order on it.
- `set_audit_collector` suppresses rather than duplicates and takes no restore token, so it cannot nest. Treat it as process-wide.
- An embedder driving `execute()` directly leaves `step_index` null unless it calls `set_audit_step`.
- The sink is best-effort. A failed write goes to the `auro_runtime.audit` logger and does not interrupt the run.
- `run()` and `route_and_run()` buffer the execute stage's events in memory and flush them once at the end, so a process that dies mid-run loses that run's trail entirely. Events written before that stage — routing and directive-load failures — go straight to the file.
- `meta["audit_persisted"]` is absent, not `False`, on a run that ended before the execute stage. Read it with `.get()`.

The sink is `$AURO_AUDIT_LOG` if set, otherwise `auro_audit.jsonl` in the workspace root.

[`AUDIT_EVENTS.md`](AUDIT_EVENTS.md) catalogues every `event` value the runtime emits and the event-specific fields each carries. It is generated from the `write_audit_event` call sites by `python -m tests.audit_catalogue`, and CI fails if the committed copy is stale.

### Paths

The distinction that matters: **authority is not environment-selectable, the workspace is.**

| Function | Resolves to | Environment |
|---|---|---|
| `get_authority_root()` | The packaged `resources/` directory holding the reviewed directives and policies | None, deliberately |
| `get_directives_dir()` | `authority_root / "directives"` | None |
| `get_policies_dir()` | `authority_root / "policies"` | None |
| `get_workspace_root()` | Writable workspace: files, archive, audit log | `AURO_WORKSPACE_ROOT`, then the legacy `AURO_ROOT` |
| `get_source_checkout_root()` | The source tree, for developer tooling only | `AURO_SOURCE_ROOT` |

**Caveats**

- With neither variable set, `get_workspace_root()` falls back to the source checkout containing the package when it has `pyproject.toml` and `tests/`, and otherwise to the current working directory. From an installed wheel the workspace is therefore wherever the process was started.
- `get_workspace_root()` is `lru_cache`d and frozen on the first successful resolution. Changing the environment afterwards has no effect; `get_workspace_root.cache_clear()` is the only reset.
- A path that is missing or not a directory raises `RuntimeError` rather than falling through to the next candidate, so an `AURO_WORKSPACE_ROOT` typo fails loudly instead of silently landing in the cwd.
- `get_authority_root()` raises `RuntimeError` if the packaged `resources/` is missing `directives/` or `policies/`. No environment variable selects it — there is no authority-root override.
- `get_source_checkout_root()` raises from an installed wheel by design: it requires `pyproject.toml`, `auro_runtime/__init__.py`, `runtime_tools/__init__.py` and `tests/`. Only the four `verify_*` functions call it — they are operator functions, not registered tools — and only when invoked, so nothing on the orchestration or enforcement path needs a checkout.

---

## Tool reference

**These functions are not an importable API.** Importing `write_file` from `runtime_tools.file_tools` and calling it bypasses directive scope, policy guards, argument validation, and the audit log. Every one of those boundaries lives in `execute()`, not in the tool.

A tool is reached by naming it in a directive's `tools:` list. What follows is therefore the **argument contract** — what may appear in a tool call — not a Python calling convention.

### Files

| Tool | Arguments | Limits |
|---|---|---|
| `write_file` | `path` str · `content` str · `encoding` str = `utf-8` | Writes only under `output/` or `drafts/`. 1 MiB per write, measured in encoded bytes. Existing file is archived first and named in `previous_version_archived` |
| `delete_file` | `path` str | Soft delete: moves to `.auro_archive/`, records a manifest entry, returns `archive_path`, `recoverable` and `retention_days`. **`recoverable` is bounded**: archived files are pruned after 30 days, or oldest-first once the archive passes 100 MB, and that prune is the only irreversible deletion the runtime performs. It emits `archive_pruned`. Same allowlist. Refuses protected paths and protected filenames |
| `restore_file` | `archive_name` str · `restore_to` str \| None | Moves a file back out of the archive. Destination must pass the write allowlist. Refuses if the destination already exists |
| `read_file` | `path` str · `encoding` str = `utf-8` | Blocks `.env`, `auro_secrets.yaml`, `.pyc`, and any path component under `.git`, `.auro_archive`, `__pycache__`. Relative paths beginning `directives/` or `policies/` resolve to the **packaged** authority copies. Refuses files over 1 MiB — the same cap as `write_file`, checked from `stat()` before the read. Whole-file only; there is no range or chunked mode, so an oversized file cannot be read at all |
| `list_dir` | `path` str · `recursive` bool = `False` | `recursive` descends exactly one level. Blocked entries are filtered from results rather than erroring |

`output/` and `drafts/` are the entire write allowlist. `AURO_RUNTIME_WRITABLE_DIRS` can change it but raises at import if it names a protected directory.

### Network

| Tool | Arguments | Limits |
|---|---|---|
| `http_request` | `url` str · `method` str = `GET` · `headers` dict \| None · `body` str \| None · `timeout` int = 30 (1–120) · `auth_alias` str \| None · `auth_scheme` str = `Bearer` | GET and POST only. Response body truncated at 10 000 characters, flagged by `truncated`. `auth_alias` is resolved at call time and injected; a raw token in `headers` is refused by the `no_hardcoded_secrets` guard. The destination is checked at connection time against the **resolved IP address**, on the initial request and again on every redirect hop; loopback, private, link-local and any address that is not globally routable are refused. A request is refused outright when an HTTP proxy is configured, because the check cannot see the real destination through one |

### Credentials

| Tool | Arguments | Limits |
|---|---|---|
| `resolve_secret` | `alias` str | Returns `{resolved: bool, alias}` and never the value. It is an existence oracle: it discloses which aliases are configured |

### Introspection

| Tool | Arguments | Notes |
|---|---|---|
| `list_tools` | `include_args` bool = `True` | Read-only |
| `list_directives` | `category` str \| None | Read-only. An unrecognised category returns an empty list rather than an error |
| `validate_directive` | `path` str | Parses without executing. Errors on a bad id, an id that disagrees with the filename, unknown tools, or an empty body; warns on a missing description or section |
| `echo` | `message` str | Testing |

Verification is not a registered tool: the `verify_*` functions are operator functions, called directly, never reachable by a model. See the README's Verification section.

**Mutating tools** are `write_file`, `delete_file`, and `restore_file`. They count against the write budget and are covered by the path guards. `http_request` is not filesystem-mutating but is not free either.

---

## MCP server

```python
from auro_runtime.mcp_server import create_stdio_server, create_authenticated_server
```

`AURO_WORKSPACE_ROOT` must name an existing directory before the server starts, and `AURO_MCP_ALLOWED_DIRECTIVE_IDS` must name the directives to expose — unset means none. Both are read at import, so setting them afterwards has no effect, and an invalid directive id in the list raises during import rather than at call time.

`create_stdio_server()` returns a process-wide singleton with no authentication, for local transports. `create_authenticated_server(public_url)` builds a new streamable-HTTP server with bearer auth. Remote mode has one shared token and no per-client identity: the audit log records what happened, not who asked.

The server exposes three MCP tools — `run_directive`, `list_directives`, `list_tools`. They are MCP tool definitions rather than a Python API; to run a directive from Python, call `run()`.
