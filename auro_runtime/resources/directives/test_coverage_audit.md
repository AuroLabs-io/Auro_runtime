---
id: test_coverage_audit
description: Audit which parts of the project are untested and rank the gaps by what would be worst if it broke silently
tools: [list_dir, read_file, list_tools, write_file]
category: task
---

# Test coverage audit

## Purpose
Compare what the project *does* against what its tests *cover*, and produce a prioritized list of gaps. This is advisory: it recommends what to test and in what order. It does not write tests.

The ordering principle is the whole point. Rank gaps by **what would be worst if it broke silently** — not by what is easy to test, not by line count, and not by what a coverage percentage would highlight. A module with 90% line coverage and no test for its refusal path is more dangerous than an untested formatter.

## Steps

1. **Explain** — In one sentence: this is a read-only audit that ends by writing one advisory report to `output/`; it does not modify source or tests.

2. **Inventory the source** — Use `list_dir` with `recursive` true on the main source package. Note the modules and roughly what each is responsible for. Do not read every file; you have a limited step budget.

3. **Inventory the tests** — Use `list_dir` on the `tests` directory. If it does not exist or is empty, that is itself the headline finding — say so and continue, since the ranking below still tells the user where to start.

4. **Sample, don't exhaust** — Use `read_file` on at most two or three of the most security- or correctness-critical source files, and on one or two test files to learn the project's existing conventions (fixture style, naming, how assertions are written). Recommendations should match conventions that already exist rather than importing foreign ones.

5. **Establish what the project claims to enforce** — Use `list_tools` to see the registered capability surface. Anything that refuses, validates, gates, or sanitizes is a claim; every claim needs a test that proves the refusal actually happens, not merely that the happy path works.

6. **Rank the gaps** — Order findings by this heuristic, highest first:
   1. **Anything that has already shipped broken.** A past defect with no regression test is the highest-value test in the project.
   2. **Invariants with no natural alarm** — config that must agree with code, a registered handler nothing invokes, a constant duplicated in two places. These fail silently by construction and only an explicit test notices.
   3. **The core claim of the product** — whatever the project exists to guarantee. Test the refusals, not just the successes.
   4. **Sandbox, path handling, and access control** — and note in the report that these must be tested *adversarially*. Reading such code and judging it sound is much weaker evidence than attacking it.
   5. **Wiring and registry** — counts, schemas, imports, absence of references that should have been removed.
   6. **End to end** — the real entry point with only the outermost dependency stubbed.

7. **Call out the happy-path trap** — For each ranked area, state the *failure* input that should be exercised, not just the success case. Malformed, missing, oversized, wrongly-typed, and hostile inputs are the routine cases in a model-driven system and the ones most often left untested.

8. **Write the report** — Use `write_file` to `output/test-coverage-audit.md`. Structure it: a short summary of what exists today; the ranked gap list with one concrete first test per item; and an explicit "what this audit did not examine" section. Write exactly one file.

9. **Complete** — Respond with `{"done": true, "summary": "..."}`. The summary must name the report path, state the top three gaps in priority order, and say plainly if the project has no tests at all.

## Allowed tools
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use for the source and test inventories.
- `read_file` — Read file contents. Args: `path` (str), optional `encoding` (str). Sample a few critical files only; do not attempt to read the whole tree.
- `list_tools` — List registered tools with descriptions. Args: optional `include_args` (bool). Use to establish the capability surface.
- `write_file` — Write content to a file. Args: `path` (str), `content` (str). Write exactly one report to `output/test-coverage-audit.md`.

## Notes
- Advisory only. Never modify source, tests, or policies.
- Write exactly one file. Writing to a second distinct path in one run triggers the bulk-write guard.
- Do not report a coverage percentage as if it were a safety measure. Say which behaviours are unproven.
- One tool call per message.
