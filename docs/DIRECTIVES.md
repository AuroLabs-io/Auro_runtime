# Directive catalogue

**13 directives** ship with the runtime.

Generated from `directives/` by `python -m tests.directive_catalogue`. Do not
edit by hand.

The `tools` column is the directive's entire authority. The runtime checks every
proposed call against it before dispatch, so a tool absent from that list is
refused whether the model was told about the boundary or not. This catalogue is
generated with the same loader the executor uses, so what you see here is what
is enforced.

## Summary

| Directive | Category | Tools granted |
|---|---|---:|
| [`active_debug`](#active-debug) | system | 2 |
| [`create_directive`](#create-directive) | system | 8 |
| [`debug_research`](#debug-research) | system | 2 |
| [`edit_directive`](#edit-directive) | system | 4 |
| [`file_analysis`](#file-analysis) | task | 2 |
| [`health_check`](#health-check) | system | 3 |
| [`policy_audit`](#policy-audit) | security | 2 |
| [`review_directive_policies`](#review-directive-policies) | security | 2 |
| [`rotate_credentials`](#rotate-credentials) | security | 2 |
| [`setup_credentials`](#setup-credentials) | security | 3 |
| [`test_coverage_audit`](#test-coverage-audit) | task | 4 |
| [`tool_catalog`](#tool-catalog) | system | 2 |
| [`update_policies`](#update-policies) | security | 2 |

---

## system

Setup, orientation, and authoring.

### active_debug

Use research results or run research, then suggest tool or directive changes to reduce system friction

Authorized tools: `list_dir`, `read_file`

### create_directive

Walk the user through the full lifecycle of designing, drafting, validating, testing, and refining a new workflow directive for the orchestrator. Produces a battle-tested directive file ready to save. Use this whenever a user wants to build a new directive, workflow script, or repeatable task playbook — even if they describe it in plain language without using the word "directive".

Authorized tools: `echo`, `generate_text`, `list_dir`, `list_directives`, `list_tools`, `read_file`, `validate_directive`, `write_file`

### debug_research

Analyze recent system failure logs and report where failures occur with statistics

Authorized tools: `list_dir`, `read_file`

### edit_directive

Walk the user through editing an existing workflow script (directive)

Authorized tools: `echo`, `list_dir`, `read_file`, `write_file`

### health_check

Lightweight sanity check — directives dir, policies dir, audit file, and tool count

Authorized tools: `list_dir`, `list_tools`, `read_file`

### tool_catalog

List all registered tools with name, description, and argument summary for writing directives

Authorized tools: `list_tools`, `read_file`

---

## security

Credential handling and policy review.

### policy_audit

Read all policy files, summarize rules in plain language, and note potential gaps or overlaps

Authorized tools: `list_dir`, `read_file`

### review_directive_policies

Compare a directive's steps and tools to current policies and report alignment or conflicts

Authorized tools: `list_dir`, `read_file`

### rotate_credentials

Guide the user to rotate a secret (same alias, new value) without changing directives

Authorized tools: `list_tools`, `resolve_secret`

### setup_credentials

Walk the user through storing a secret and referencing it by alias, so keys never appear in directives, transcripts, or logs

Authorized tools: `list_dir`, `list_tools`, `resolve_secret`

### update_policies

Walk the user through adding or changing policy rules (guardrails) that apply to every script

Authorized tools: `list_dir`, `read_file`

---

## task

General workflows.

### file_analysis

Analyze files and summarize contents

Authorized tools: `list_dir`, `read_file`

### test_coverage_audit

Audit which parts of the project are untested and rank the gaps by what would be worst if it broke silently

Authorized tools: `list_dir`, `list_tools`, `read_file`, `write_file`
