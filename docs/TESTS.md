# Test catalogue

**335 test functions** across 14 files.

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
| [`tests/test_policy_validation.py`](../tests/test_policy_validation.py) | 30 |
| [`tests/test_guard_bindings.py`](../tests/test_guard_bindings.py) | 15 |
| [`tests/test_classifier_pins.py`](../tests/test_classifier_pins.py) | 11 |
| [`tests/test_enforcement.py`](../tests/test_enforcement.py) | 43 |
| [`tests/test_sensitive_resource_classification.py`](../tests/test_sensitive_resource_classification.py) | 34 |
| [`tests/test_credentials.py`](../tests/test_credentials.py) | 38 |
| [`tests/test_registry.py`](../tests/test_registry.py) | 35 |
| [`tests/test_directives.py`](../tests/test_directives.py) | 23 |
| [`tests/test_end_to_end.py`](../tests/test_end_to_end.py) | 17 |
| [`tests/test_security_p0.py`](../tests/test_security_p0.py) | 44 |
| [`tests/test_audit_disclosure.py`](../tests/test_audit_disclosure.py) | 27 |
| [`tests/test_archive_integrity.py`](../tests/test_archive_integrity.py) | 6 |
| [`tests/test_distribution_install.py`](../tests/test_distribution_install.py) | 7 |
| [`tests/test_release_evidence.py`](../tests/test_release_evidence.py) | 5 |
| **Total** | **335** |

---

## `tests/test_policy_validation.py`

Policy loading and fail-hard validation. The regression barrier for the defect that once made the runtime unable to run any directive: a policy naming a tool that no longer exists.

30 tests.

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
- **omitting the registries checks against the live ones** — The registries used to default to None, which skipped the guard and tool
- **explicit none still skips the registry checks** — Negative control, and a real use: validating a policy set before the
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

15 tests.

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
### TestEnforcementOptOutSurfaceIsPinned

- **enforcement path reads only the pinned environment variables**
- **pinned opt outs are still read where claimed** — Negative control: a pin naming variables nothing reads proves nothing.
- **the pin catches a new opt out in the sandbox module** — Negative control for the 2026-08-15 widening.
- **only advisory drops a guarded rule from enforcement** — `enforcement` is a free string, so the safe behaviour is that anything
- **only the exact fail open string opts out of failing closed** — A typo in on_error must not become a bypass.
### TestGuardCallableContract

- **every guard is callable with exactly one required parameter** — Mirrors the signature check validate_policies() performs at load
- **every guard no ops cleanly on an unrelated benign call** — None of the 7 guards have any business objecting to a plain `echo`

---

## `tests/test_classifier_pins.py`

Law 10's enforcement: every caller-supplied locator argument is inspected or exempt on the record, and every security inventory declares whether it names places or matches secret values. A classifier that judges a string the filesystem or socket will read differently is the class these pin.

11 tests.

### TestLocatorArgumentsAreClassified

- **every locator argument is inspected or exempt**
- **pinned keys are falsifiable against actual reach** — Law 16c. A key matching no tool field is reach the guard does not have.
- **exempt arguments still exist** — Negative control: exempting arguments nothing declares proves nothing.
- **the scan reports an unclassified locator argument** — Negative control for the scan itself.
### TestLocatorClassifiersAreInventoried

- **every security inventory is classified**
- **classified inventories still exist** — Negative control: pinning names nothing defines proves nothing.
- **every locator module declares how it obtains its subject**
- **the shared classifier is actually shared where claimed** — Every module declaring `shared` must really CALL into it.
- **no module grows its own normalisation** — The duplication must not come back, checked as a mechanism.
- **the normalisation scan catches a private copy** — Negative control for the check above.
- **the scan reports a new inventory** — Negative control for the scan.

---

## `tests/test_enforcement.py`

The executor's refusal pipeline: registry check, directive scope, argument schema, then policy guards across block/warn/advisory and fail_closed/fail_open.

43 tests.

- **unknown tool is refused**
- **known tool with no restrictions succeeds**
- **tool outside allowed tools is refused**
- **omitted security input refuses** — Omission must not select the permissive branch. execute() is public, so a
- **complete context proceeds** — Positive control for the test above: the refusal is about the omission.
- **unrestricted is the only way past a boundary** — The permissive behaviour still exists; it just has to be named. Without this
- **empty policy rules is not a way to run unguarded** — An empty tool scope is a real answer (a directive declaring no tools may call
- **empty allowed tools is a real answer not an omission** — The asymmetry above, from the other side: empty scope refuses the call
- **tool inside allowed tools proceeds**
- **missing required argument is refused** — write_file requires `content`; omitting it must fail cleanly, not crash.
- **wrong typed argument is refused**
- **malformed arguments do not raise** — Regression: extra={"args": ...} collided with LogRecord's reserved `args`
- **block rule refuses and names the rule**
- **warn rule records the verdict but proceeds** — The heart of the enforcement model: a `warn` rule must audit the denial and
- **advisory rule does not block**
- **rule scoped by tools does not fire for other tools** — The guard used here must NOT filter by tool name itself, or the executor's
- **rule scoped by directives only fires for matching directive**
- **rule naming an unregistered guard refuses** — A rule was written to enforce something and names a guard that does not
- **unregistered guard may proceed only under fail open** — Negative control for the test above: the refusal follows on_error rather than
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
- **an unknown argument is refused rather than dropped** — The whole point is that the tool must not run. A misspelled flag that is
- **every registered tool schema forbids unknown arguments** — Stated over the registry rather than over a list of schemas, so a tool added
- **a tool reporting an error is not reported as success** — End to end through a real refusal: write_file's own size cap.
- **a successful tool call is still success** — Control. Without it, marking every call failed would satisfy the test above.
- **a falsy error key is not a failure** — `error: None` on a success path must not be read as a refusal, or a tool
- **a nested error key is not treated as a refusal** — Only a top-level `error` is the failure signal. A tool reporting errors as
- **sensitive directories are blocked in bare and trailing slash forms** — The directory patterns required a trailing separator, and
- **the sensitive path widening does not over block** — Control for the test above. Alternating the trailing separator with `$`
- **trailing dots and spaces do not bypass the sensitive path guard** — Windows discards trailing dots and spaces when it opens a file, so
- **percent encoded dots do not bypass the sensitive path guard** — The canonicaliser decodes `%2e` to a dot before matching. Nothing in the
- **the trailing character strip does not over block** — Control for the test above. Stripping trailing dots and spaces must not

---

## `tests/test_sensitive_resource_classification.py`

The single sensitive-resource inventory and both layers that consume it. Covers that the policy guard and the file tool agree on every family and category, that the tool classifies the resolved path rather than the basename, and that normalisation is host-independent. Facts about this repository's own inventory; the traversal and evasion corpora stay restricted.

34 tests.

### TestTheInventoryIsSharedNotCopied

- **the guard and the read path agree on every family** — The defect this replaced was three lists disagreeing silently. The guard
- **every family reports its category** — Categories exist because they reach the audit record. "Which class of
### TestTheResolvedSubjectIsWiderThanTheBasename

- **a plain name inside a credential directory is classified**
- **the same plain names outside one are not** — Control. Without this, classifying everything would pass above.
- **read file refuses a plain name inside a credential directory** — The property above, driven through the real tool rather than the
- **read file still returns an ordinary neighbouring file** — Control for the test above, in the same directory tree.
### TestFilesystemAliasesAreResolvedBeforeClassification

- **an alternate data stream suffix does not reach file contents** — `output/.env::$DATA` opens the real `output/.env` on NTFS. Measured
- **equivalent spellings all resolve to the same subject** — Spellings the filesystem treats as one path must classify as one path.
- **an extended length path fails closed** — `\\?\C:\...` is NOT normalised by resolve(), and that is the point.
- **an 83 short name alias is expanded before classification** — A short-name alias expands per existing component, so `SSH~1/anything`
### TestEveryMutatingToolClassifiesItsResolvedTarget

- **a manifest derived destination is refused** — The card's gap 3, and the remaining ship blocker before this landed.
- **an ordinary manifest derived destination still restores** — Positive control. Refusing everything would pass the test above.
- **an explicit sensitive restore destination is refused**
- **write file refuses a sensitive destination**
- **write file still writes an ordinary neighbour**
- **delete file refuses a sensitive target**
### TestValidateDirectiveClassifiesToo

- **a sensitive md file is refused** — `.env.md` satisfies the .md requirement and is classified sensitive.
- **an ordinary directive still validates** — Positive control: the refusal must not swallow the tool's real job.
### TestTheAuditDistinguishesApprovedFromNeverRan

- **an approval is recorded**
- **a refusal is recorded with its category and origin**
- **the recorded subject is workspace relative** — An absolute path carries the operator's directory layout off the box.
### TestTheEnvSampleFamilyIsNoLongerRefused

- **the sample family is permitted**
- **the real env family is still refused** — Control. Widening the exclusion until nothing matches would pass above.
- **read file returns an env example** — End to end, because the refusal that mattered was at the tool.
- **direnv is refused** — .envrc was matched by nothing: the old pattern needed a literal dot.
### TestTheAddedCredentialFamilies

- **each added family is refused under its category**
### TestTheRejectedCandidatesStayRejected

- **the rejected pattern would have caused this false positive**
### TestTheTrackedTreeIsNotRefusedByItsOwnGuard

- **no tracked file is classified sensitive** — The population that actually matters, checked against the real tree.
### TestNormalisationIsSharedAndHostIndependent

- **case is folded on every platform** — Lowercasing used to happen only under `os.name == "nt"`, while the copy
- **trailing dots and spaces are stripped**
- **the strip is not a prefix match** — Control for the case above: normalisation must not widen matching.
### TestUncontainedPathsFailClosed

- **a path outside the base is refused with a reason** — Every caller contains before classifying, so being handed an uncontained
- **a contained ordinary file is still permitted** — Control: fail-closed must not mean refuse-everything.
- **the workspace ancestry is not judged** — Only the portion inside the workspace is the tool's subject. A workspace

---

## `tests/test_credentials.py`

Alias resolution and delivery. The property under test throughout is that a resolved secret never appears in a tool result, an error message, or the audit trail.

38 tests.

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
- **guard blocks a raw token nested in headers** — The common shape of the mistake. Before alias params existed this guard
- **guard allows the alias parameter**
- **guard blocks a top level raw credential**
- **real policy refuses a raw authorization header** — End of the chain: the shipped rules block it at enforcement level.
- **alias use survives the real policy chain** — Using an alias must not be blocked, and must not leak into the audit.
- **a refused raw credential is not logged in the clear** — A refusal must not record what it refused.
- **credential key sets do not diverge** — Every key the credential guard will refuse a call over must also be
- **a pre guard refusal does not log a credential** — Argument-schema validation refuses before any guard runs, and writes the
- **targeted redaction reaches a key the name pass does not** — Pins the matched_fields pass on its own.
- **credential header spellings are redacted by name** — `x-api-key` and `x-auth-token` carry credentials and match no secret
- **redacting verdicts carry the field the executor reads** — Pins the contract behind the test above. A verdict whose code is in

---

## `tests/test_registry.py`

Tool registry shape, project-root and import wiring, the CLI surface, model-backend selection, and two source-hygiene invariants: loggers stay under the auro_runtime namespace, and no absolute home path reaches shipped source.

35 tests.

### TestToolRegistryShape

- **exactly twelve tools registered**
- **registered tool names match expected set**
- **every registry entry is a three tuple**
- **every tool callable is actually callable**
- **every tool has a non empty description**
- **each tool name is registered by exactly one register call** — The registry is a plain dict keyed by name: a second, unrelated
### TestToolSchemas

- **expected schema map covers every tool name** — Sanity-check the two constants above against each other before trusting either.
- **schemas present are pydantic basemodel subclasses**
- **every registered tool has an argument schema** — No exemptions since 2026-08-13. A registered tool takes model-supplied
- **each tool is wired to its expected schema class**
### TestListToolsTool

- **returns all twelve with descriptions**
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
- **resolve model reports the id generate would actually call** — The cost gate needs the resolved id. Without this, `model=None` — the
### TestHighCostModelGate

- **the gate fires when the expensive model comes from the default**
- **a cheap default is not gated** — Control. Without it, a gate that stopped every call would satisfy the
- **no high cost list means no gate** — AURO_HIGH_COST_MODELS is empty by default, so the gate is inert.
- **get backend works even when provider sdks are unimportable** — Simulates neither the anthropic nor the openai SDK being installed by
- **importing models package does not import provider sdks** — A clean-interpreter check (subprocess, not the sys.modules trick
### TestModelCallCounter

- **reset call counts starts at zero**
- **increment call count increments and returns the new total**
- **reset call counts clears a nonzero count**

---

## `tests/test_directives.py`

Shipped directive integrity. A directive naming a tool that no longer exists parses fine, ships fine, and fails only at execution.

23 tests.

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
- **verifiers are not reachable from a directive** — The verifiers are operator functions and must stay unregistered.
- **dynamic verifier fails when test phase is vacuous** — A missing runner or empty collection must never make the gate green.
- **dynamic verifier copies test catalogue** — The temporary project must contain the generated file its tests validate.
- **test coverage audit writes only to a writable dir**
- **verification directives are registered in the set**
- **directive catalogue is current** — docs/DIRECTIVES.md is generated from directives/. A hand-maintained
- **directive catalogue would detect an added directive** — Negative control for the test above. A drift check that cannot fail proves
- **directive catalogue refuses an undescribed directive** — A directive grants tool authority. Generation must halt on one it cannot
- **readme directive count matches the shipped set** — The README states how many directives ship. Nothing generates that sentence,
- **readme directive count guard would catch a stale number** — Negative control. A guard that passes on any input proves nothing, so this

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

44 tests.

- **zero policy gate rejects every non explicit opt in** — Only the exact documented value ``1`` may disable every policy guard.
- **zero policy gate allows exact explicit opt in** — Positive control: the documented escape hatch remains usable.
- **a missing policies directory is refused even with the opt in set** — The compound case: AURO_ALLOW_NO_POLICIES=1 left in an environment, plus a
- **an existing empty policies directory still honours the opt in** — Negative control for the test above. The missing-directory refusal must not
- **a downgraded shipped rule is refused at runtime** — The edit that hides: `block` to `advisory` keeps the rule id, so the profile
- **an intact shipped profile still passes** — Negative control. Without this, the test above only proves the copied policy
- **an added rule does not cost the shipped profile check** — An addition can only add a check, so it must not force an operator onto
- **a removed rule still refuses under the shipped profile** — Control for the test above, in the direction that matters: permitting
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
- **hostname resolving to a private address is refused** — Bypass 1. A public-looking name pointing inward must be refused.
- **redirect hops are revalidated** — Bypass 2. A redirect must not walk to an address refused when named.
- **ipv6 destinations are refused** — Bypass 3. The old range table held five IPv4 networks and no IPv6.
- **backslash authority differential is refused** — Bypass 4. urlparse and urllib3 disagree about where the authority ends.
- **a permitted destination still completes** — Positive control. Without this the refusal tests above would also pass
- **globally routable addresses are not refused** — Negative control on the deny-set: it must not simply refuse everything.
- **the destination check is actually installed** — The adapter must really replace the connection class.
- **mounting the guard does not alter other pool managers** — urllib3 assigns pool_classes_by_scheme by reference without copying.
- **no registered tool issues its own http request** — A tool must not carry a private destination check.

---

## `tests/test_audit_disclosure.py`

Public contracts for the versioned audit envelope and the shared sanitizer used at audit, executor, transcript, router, model-context, and logging boundaries. Uses only an ordinary synthetic marker; scanner-evasion probes remain in the restricted suite.

27 tests.

- **audit envelope is correlated idempotent and scrubbed** — The live collector and persisted JSONL retain one safe event identity.
- **file events audit relative paths that correlate** — The audit trail names a file the same way each time, and never absolutely.
- **a failed batch write is reported and names no path** — Losing the trail must be visible to the caller, without leaking the sink's path.
- **a rejected record is not counted as a lost one** — A record that was never valid is a different failure from one that is gone.
- **a swallowed single write failure reaches the operator log** — write_audit_event stays best-effort, but no longer fails invisibly.
- **a run whose audit trail was lost says so in its result** — The reporting is only worth building if the caller actually receives it.
- **a healthy run reports its audit trail persisted** — Negative control: audit_persisted must not be False for everyone.
- **soft delete and permanent prune are distinct events** — The recoverable move and the irreversible unlink must not look alike in the log.
- **a prune that destroys nothing writes nothing** — Negative control: the event must mean destruction, not that prune ran.
- **audit event catalogue is current** — docs/AUDIT_EVENTS.md is generated from the write_audit_event call sites.
- **audit catalogue would detect a renamed event** — Negative control. A drift check that cannot fail proves nothing, and the
- **audit catalogue refuses a non literal event name** — An event name assembled at runtime cannot be documented, grouped on, or
- **step index attributes events and survives persistence** — An event carries the step that owns it, and keeps it when flushed to file.
- **step index does not leak across runs** — A run that ends restores the step its caller was on, including None.
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

## `tests/test_archive_integrity.py`

Soft delete keeps its promise: an archived file is never destroyed by a later one. Archive names carry the directory so same-named files cannot share an entry, an existing entry is never overwritten, restore refuses a name it cannot resolve to one original, and the retention caps govern the write path as well as the delete path.

6 tests.

### TestArchiveNameCollisions

- **same basename in different directories both stay recoverable** — Two same-named files deleted in one second each restore with their own content.
- **redeleting one path in the same second keeps both versions** — A path deleted, recreated and deleted again within a second archives twice.
- **archive name records the directory not only the basename** — The archive name carries the file's directory, which is what made names unique.
### TestRestoreAmbiguity

- **restore refuses an archive name mapping to two originals** — One archive name naming two different files is refused, not silently chosen.
- **repeated rows for one original are not ambiguous** — Many manifest rows naming the same original still resolve and restore.
### TestArchiveRetention

- **overwriting a file prunes stale archive entries** — The age cap governs the write path too, not only delete_file.

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

---

## `tests/test_release_evidence.py`

Pins the publication gate to one explicit Git commit and tree. A dirty checkout, a different expected commit, or ambient source content must not produce release evidence for the reviewed tree.

5 tests.

- **release identity binds head index and commit tree**
- **release identity refuses a different expected commit**
- **release identity refuses untracked or modified source**
- **commit export excludes ambient working tree content**
- **distribution evidence requires a nonzero passed count**
