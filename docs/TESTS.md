# Test catalogue

**216 test functions** across 10 files.

Generated from the test sources by `python -m tests.catalogue`. Do not edit by hand.

A count on its own says nothing about what was checked, so this lists every
test in the published suite and what it asserts. Parametrized tests are counted
once here and expand to more cases at run time, so the number pytest reports is
higher.

This catalogue covers what ships. A separate adversarial pack is withheld from
publication and is neither counted nor named here; it does not run in CI, and no
result in this repository depends on it.

## Summary

| File | Tests |
|---|---:|
| [`tests/test_policy_validation.py`](../tests/test_policy_validation.py) | 29 |
| [`tests/test_guard_bindings.py`](../tests/test_guard_bindings.py) | 10 |
| [`tests/test_enforcement.py`](../tests/test_enforcement.py) | 27 |
| [`tests/test_credentials.py`](../tests/test_credentials.py) | 34 |
| [`tests/test_registry.py`](../tests/test_registry.py) | 31 |
| [`tests/test_directives.py`](../tests/test_directives.py) | 18 |
| [`tests/test_end_to_end.py`](../tests/test_end_to_end.py) | 17 |
| [`tests/test_security_p0.py`](../tests/test_security_p0.py) | 29 |
| [`tests/test_audit_disclosure.py`](../tests/test_audit_disclosure.py) | 14 |
| [`tests/test_distribution_install.py`](../tests/test_distribution_install.py) | 7 |
| **Total** | **216** |

---

## `tests/test_policy_validation.py`

Policy loading and fail-hard validation. The regression barrier for the defect that once made the runtime unable to run any directive: a policy naming a tool that no longer exists.

29 tests.

### TestRealPoliciesLoadAndValidate

- **real policies load and validate cleanly** — The definitive "can the runtime start" test: load_policies() output,
- **real policy shape matches known snapshot** — Guards against a vacuous pass above: if a binding file silently
- **every declared tool in real policies exists in registry** — Direct regression test for the shipped blocker: walk every rule that
- **every declared guard in real policies exists in registry** — Every `guard:` in the real policy files must resolve to a registered guard.
- **real policy enforcement values are all valid**
- **real policy on error values are all valid**
### TestValidatePoliciesSynthetic

- **raises when rule names unknown tool**
- **raises when rule names unknown guard**
- **rejects an empty tools list** — An empty scope list silently disables a rule. `tools: []` is not None,
- **rejects an empty directives list** — Same silent-disable hazard, on the other scoping axis.
- **an unscoped rule fires for every tool** — The security argument for None-meaning-all: a restriction with no
- **passes when tools is none** — tools=None means 'applies to every tool' — must not be treated as an invalid/empty list.
- **raises when enforcing rule has no guard** — enforcement != 'advisory' with no guard is meaningless (nothing would
- **raises on duplicate rule id within a binding**
- **accumulates multiple errors into one exception** — validate_policies collects every problem before raising once, so a
- **guard and tool checks are skipped when registries not passed** — validate_policies(policies) with no registry kwargs only checks
### TestGuardedRuleMustDeclareEnforcement

- **guarded rule omitting enforcement is rejected**
- **guarded rule declaring advisory explicitly is allowed**
- **guardless rule omitting enforcement is still fine** — Prose-only rules are the reason advisory exists. They must stay ergonomic.
- **dropping a guarded advisory rule is logged not silent** — The drop must be announced. Silence is what makes advisory dangerous.
- **guardless advisory rules do not generate noise** — Prose rules are supposed to be advisory, so they must not warn.
### TestLoaderEdgeCases

- **load policies on missing directory returns empty list**
- **load policies on empty directory returns empty list**
- **load policies ignores non yaml files**
- **load policy defaults id to filename stem when missing**
- **load policy missing rules key yields empty rules list**
- **load policy applies field defaults for minimal rule**
- **load policy supports bare string rule shorthand** — A rule entry that is a plain string rather than a mapping becomes an
- **load policy malformed yaml raises** — The loader does not swallow YAML syntax errors — it fails loudly at

---

## `tests/test_guard_bindings.py`

Every registered guard is bound by some policy rule, and every rule names a guard that exists. A registered-but-unbound guard reads as protection while never running.

10 tests.

### TestGuardRegistryShape

- **exactly seven guards registered**
- **registered guard names match expected set**
### TestGuardPolicyBinding

- **every registered guard is bound by some policy rule** — No orphans: a registered guard that no rule ever binds is dead protection.
- **every guard referenced in policy files is registered** — Inverse direction: a typo'd or renamed guard name in YAML must resolve to something real.
- **no bulk writes is bound as warn on write file only** — Locks in a deliberate design choice: bulk-write detection warns
### TestShippedPolicyEnforcementIsPinned

- **enforceable rule ids match the pinned set** — Catches a guard-bound rule being added or removed without a deliberate
- **shipped rule posture is unchanged**
- **every blocking rule fails closed** — Invariant rather than a pinned value: a rule that refuses calls must not
### TestGuardCallableContract

- **every guard is callable with exactly one required parameter** — Mirrors the signature check validate_policies() performs at load
- **every guard no ops cleanly on an unrelated benign call** — None of the 7 guards have any business objecting to a plain `echo`

---

## `tests/test_enforcement.py`

The executor's refusal pipeline: registry check, directive scope, argument schema, then policy guards across block/warn/advisory and fail_closed/fail_open.

27 tests.

- **unknown tool is refused**
- **known tool with no restrictions succeeds**
- **tool outside allowed tools is refused**
- **allowed tools none means unrestricted**
- **tool inside allowed tools proceeds**
- **missing required argument is refused** — write_file requires `content`; omitting it must fail cleanly, not crash.
- **wrong typed argument is refused**
- **malformed arguments do not raise** — Regression: extra={"args": ...} collided with LogRecord's reserved `args`
- **block rule refuses and names the rule**
- **warn rule records the verdict but proceeds** — The heart of the enforcement model: a `warn` rule must audit the denial and
- **advisory rule does not block**
- **rule scoped by tools does not fire for other tools** — The guard used here must NOT filter by tool name itself, or the executor's
- **rule scoped by directives only fires for matching directive**
- **rule naming an unregistered guard is skipped** — The executor silently continues past a guard name it cannot resolve, which is
- **directive is not re read during the step loop** — A run must not be able to widen its own authority.
- **guard exception fail closed refuses**
- **guard exception fail open proceeds**
- **guard exception fails closed for any unrecognised on error** — Only the exact string "fail_open" may fail open. Anything else, including a
- **destructive guard fires for delete and restore not write**
- **write budget blocks once the budget is spent**
- **write budget allows under the limit**
- **bulk writes guard allows rewriting the same path**
- **secret in args is detected**
- **secret in reason is detected**
- **secret guard audit redacts the value** — A secret must never reach the audit log in plaintext.
- **real policies block sensitive path reads** — End of the chain: the actual shipped rules refuse a secrets-file read.
- **real policies allow a benign call**

---

## `tests/test_credentials.py`

Alias resolution and delivery. The property under test throughout is that a resolved secret never appears in a tool result, an error message, or the audit trail.

34 tests.

### TestKeyringBackendRoundTrip

- **stored value round trips**
- **missing alias returns none rather than raising**
- **deleted alias stops resolving**
- **whitespace only value is treated as absent** — `get` strips and treats blank as missing, so a blank entry must not
- **list aliases is empty by design** — Documented limitation: keyring has no portable enumeration. Pinned so
- **env backend resolves an alias**
- **unknown alias returns none**
- **env lookup is case insensitive on the alias**
- **path like aliases are rejected** — Aliases are identifiers, not paths.
- **request scoped secrets take priority**
- **list aliases reports names not values**
- **default selects no extra backend**
- **env is an accepted explicit value**
- **unknown backend name raises**
- **selecting an unusable backend fails loudly not silently** — Explicit selection must distinguish a missing dependency from an alias that
- **backends are imported lazily** — Importing the package must not require any optional dependency.
- **anthropic backend resolves configured alias**
- **anthropic backend uses request scoped alias**
- **anthropic backend alias fails closed**
- **anthropic backend retains environment compatibility**
- **resolve secret reports presence without the value**
- **resolve secret on missing alias**
- **http request injects the resolved token**
- **http request auth scheme is honoured**
- **http request rejects an unknown auth scheme**
- **http request unconfigured alias names the alias not the value**
- **http request without auth alias is unchanged**
- **send notification resolves the url alias** — Slack and Discord webhook URLs contain the token, so the URL is the secret.
- **send notification requires a url or an alias**
- **guard blocks a raw token nested in headers** — The common shape of the mistake. Before alias params existed this guard
- **guard allows the alias parameter**
- **guard blocks a top level raw credential**
- **real policy refuses a raw authorization header** — End of the chain: the shipped rules block it at enforcement level.
- **alias use survives the real policy chain** — Using an alias must not be blocked, and must not leak into the audit.

---

## `tests/test_registry.py`

Tool registry shape, project-root and import wiring, the CLI surface, model-backend selection, and two source-hygiene invariants: loggers stay under the auro_runtime namespace, and no absolute home path reaches shipped source.

31 tests.

### TestToolRegistryShape

- **exactly seventeen tools registered**
- **registered tool names match expected set**
- **every registry entry is a three tuple**
- **every tool callable is actually callable**
- **every tool has a non empty description**
- **each tool name is registered by exactly one register call** — The registry is a plain dict keyed by name: a second, unrelated
### TestToolSchemas

- **expected schema map plus verify tools covers every tool name** — Sanity-check the two constants above against each other before trusting either.
- **schemas present are pydantic basemodel subclasses**
- **exactly the four verify tools have no schema**
- **each tool is wired to its expected schema class**
### TestListToolsTool

- **returns all seventeen with descriptions**
- **include args true adds an args summary per tool**
- **include args false omits the args summary**
- **runs cleanly through the real executor** — Exercises the schema-validation + dispatch path in executor.execute, not just the bare function.
### TestProjectRootAndCoreImports

- **get project root returns the repo root**
- **project root contains expected marker dirs**
- **get registry returns a copy not the live dict** — get_registry()'s docstring promises a copy; mutating the result must not corrupt the real registry.
- **core module imports cleanly**
- **main entrypoint is callable**
### TestCliEntrypoint

- **help lists exactly run and mcp and not web**
### TestSourceTreeHygiene

- **all loggers use the auro runtime namespace**
- **test catalogue is current** — docs/TESTS.md is generated from the test sources. A hand-maintained
- **no absolute home paths in shipped source** — An absolute path into someone's home directory is machine-specific: it
### TestModelBackendSelection

- **default backend is anthropic**
- **openai and openai compatible are aliases for the same backend**
- **unknown backend name raises value error**
- **get backend works even when provider sdks are unimportable** — Simulates neither the anthropic nor the openai SDK being installed by
- **importing models package does not import provider sdks** — A clean-interpreter check (subprocess, not the sys.modules trick
### TestModelCallCounter

- **reset call counts starts at zero**
- **increment call count increments and returns the new total**
- **reset call counts clears a nonzero count**

---

## `tests/test_directives.py`

Shipped directive integrity. A directive naming a tool that no longer exists parses fine, ships fine, and fails only at execution.

18 tests.

### TestEmptyToolScopeFailsClosed

- **empty tools list grants no tools**
- **declared tools are granted exactly**
- **directive without usable tools key grants nothing**
- **no orchestrator call site expands an empty scope** — The idiom was duplicated at three call sites, so a fix applied to one
- **every directive loads** — A directive that cannot be parsed is unusable, and nothing else would notice.
- **directive id matches filename** — load_directive_by_id resolves by filename, so a mismatch makes the id a lie.
- **directive ids are traversal safe**
- **every directive has a description** — The description is what the router sees; an empty one makes the directive unroutable.
- **every directive category is valid**
- **every declared tool is registered** — The regression test for this file's whole reason to exist. A directive naming
- **no directive references pre rename paths** — The carve renamed auro/ -> auro_runtime/ and tools/ -> runtime_tools/. Stale
- **list directives returns every file**
- **validate directive passes for every shipped directive** — Run the project's own validator over its own content.
- **verify project covers the whole gate** — verify_project exists to exercise the verify_* tools nothing else invoked.
- **dynamic verifier fails when test phase is vacuous** — A missing runner or empty collection must never make the gate green.
- **dynamic verifier copies test catalogue** — The temporary project must contain the generated file its tests validate.
- **test coverage audit writes only to a writable dir**
- **verification directives are registered in the set**

---

## `tests/test_end_to_end.py`

Full runs through the real CLI against a stub model server. Only inference is stubbed; orchestrator, executor, guards, tools and audit are real.

17 tests.

- **tool catalog happy path runs to completion** — Full pipeline: load directive -> load+validate policies -> LLM turn ->
- **policy and tool list reach the system prompt** — Regression guard for a silent governance failure: if policy rule text or
- **tool not in directive allowlist is rejected and run completes** — write_file is a real, registered tool, but tool_catalog's front matter
- **sensitive path read is blocked by policy guard** — read_file IS allowed by tool_catalog's front matter, so a rejection here
- **warn tier guard fires but does not block bulk writes** — no_bulk_writes (policies/default.yaml) is bound at enforcement=warn.
- **multi step run records legacy steps in order** — A run with several sequential tool calls must produce legacy_steps in the same order.
- **max steps terminates a never ending script** — A model that keeps calling tools and never returns done must terminate
### TestCompletionShapeTolerance

- **summary as list of strings is accepted**
- **summary as list of dicts is accepted**
- **summary as dict is accepted**
- **summary none becomes empty string**
- **plain string summary is unchanged**
- **run completes when model returns a list summary** — End to end: the shape a real 3B model produced must not kill the run.
- **unknown directive id produces clean error not traceback** — An unknown --directive id should fail gracefully with a structured error, not a stack trace.
- **malformed non json model output fails cleanly** — A model turn that isn't JSON at all — no tool call, no completion — must be
- **backend selection uses openai compatible stub with configured model** — Confirm the run actually goes through the OpenAI-compatible backend
- **invalid tool arguments are rejected by schema validation** — A third validation layer, distinct from directive scope (tier 1) and

---

## `tests/test_security_p0.py`

Regression tests for the package-owned authority split: zero-policy refusal, workspace resolution, protected-path writes, directive exposure sets, MCP startup enforcement, and the static verifier's source-checkout and encoding contracts. Every case proves a seam that is closed in shipped code.

29 tests.

- **zero policy gate rejects every non explicit opt in** — Only the exact documented value ``1`` may disable every policy guard.
- **zero policy gate allows exact explicit opt in** — Positive control: the documented escape hatch remains usable.
- **partial shipped policy profile is refused** — One surviving rule must not masquerade as the complete shipped posture.
- **explicit custom policy profile is not compared to shipped manifest** — Positive control: deliberate custom policy sets remain supported.
- **project root does not trust an arbitrary working directory** — A CWD marker must not redirect policies, directives, or Python imports.
- **invalid explicit root fails instead of falling back**
- **packaged authority assets match reviewed source sets** — Positive content proof: wheel inputs cannot drift from reviewed files.
- **workspace override cannot redirect authority**
- **legacy root cannot redirect authority** — AURO_ROOT may select legacy workspace state, never executable resources.
- **workspace resolution is frozen for process**
- **read tools mount packaged authority not workspace shadow**
- **authority virtual mount refuses traversal**
- **virtual authority mount is read only**
- **source verifier ignores workspace and legacy root**
- **source verifier rejects incomplete explicit checkout**
- **generic write treats directives as intrinsically protected** — No file is created; this exercises the decision function directly.
- **env cannot make protected directives writable** — Import-time configuration must reject an attempted protected-path widening.
- **full pipeline executes the planned directive snapshot** — A second file read must not replace the authority checked during Plan.
- **mcp uses one explicit exposure set for list and run**
- **mcp empty exposure set lists and runs nothing**
- **mcp startup requires the dedicated workspace setting** — A legacy/local workspace is not sufficient authority for an MCP server.
- **authenticated mcp server uses the configured public url**
- **mcp server factories refuse without explicit workspace**
- **cli mcp refuses before transport without explicit workspace** — Exercise the real CLI boundary; a unit-only helper assertion is insufficient.
- **cli remote mcp requires public url for non loopback host**
- **static verifier accepts the current source tree** — The release gate itself must run cleanly, not just its pytest subprocess.
- **static verifier rejects a utf8 bom with a named diagnostic** — The encoding contract is enforced on a hostile tree, not inferred.
- **installed verifiers return source checkout required** — An installed wheel must refuse as data instead of leaking an exception.
- **secret scan covers release manifest and ci workflows** — The whole-tree claim includes publication files outside Python packages.

---

## `tests/test_audit_disclosure.py`

Public contracts for the versioned audit envelope and the shared sanitizer used at audit, executor, transcript, router, model-context, and logging boundaries. Uses only an ordinary synthetic marker; scanner-evasion probes remain in the restricted suite.

14 tests.

- **audit envelope is correlated idempotent and scrubbed** — The live collector and persisted JSONL retain one safe event identity.
- **bulk audit sink scrubs legacy records independently** — Persist is a security boundary even when a caller bypasses event creation.
- **nested audit runs restore outer correlation** — A nested run gets its own sequence without contaminating its caller.
- **plan stage audit uses the pipeline run id** — Early Plan failures correlate with the result even before Execute collects.
- **bad bulk record is safe and does not block later events** — A malformed event fails closed while later valid records still persist.
- **structured sanitizer normalizes supported result shapes** — Tuple, set, bytes, models, and exceptions become safe JSON primitives.
- **public executor scrubs success results errors and logs** — Direct execute() callers receive the same safe representation as the loop.
- **guard verdicts and exceptions are safe** — Custom guard output cannot escape through result or audit channels.
- **classifier limit is explicit but sensitive key provenance still scrubs** — Unknown shapes need provenance; pattern matching is not called omniscient.
- **tool call and result are safe in transcript model context and audit** — Blocked inputs and successful outputs cannot cross any loop representation.
- **raw request and blocked reason are scrubbed before outbound use** — A refused value is absent from model context, transcript, steps, and audit.
- **router reason and backend exception are safe** — Pre-tool router and backend failures use the same outbound scrub contract.
- **mcp errors use the same safe outbound contract** — MCP refusal and exception responses cannot bypass the runtime scrub.
- **cli json and audit are safe** — The real CLI serialization and persisted JSONL share the scrub contract.

---

## `tests/test_distribution_install.py`

Builds a real wheel and sdist, installs each into an isolated environment, and runs the installed package with no source checkout present. Proves the packaged authority split, the source-fallback refusal, and provenance checks hold from the artifact a user actually installs, not just from source.

7 tests.

- **wheel contains reviewed authority assets and record**
- **sdist excludes tests and builds the same authority set**
- **installed library and cli use packaged authority and workspace audit**
- **installed mcp stdio discovers packaged directive and refuses sensitive path**
- **missing installed policy fails without source fallback**
- **missing installed directive fails without source fallback**
- **nonisolated source contamination trips provenance check** — Negative control: the same check rejects a child contaminated by PYTHONPATH.
