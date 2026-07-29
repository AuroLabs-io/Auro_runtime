---
id: create_directive
description: Walk the user through the full lifecycle of designing, drafting, validating, testing, and refining a new workflow directive for the orchestrator. Produces a battle-tested directive file ready to save. Use this whenever a user wants to build a new directive, workflow script, or repeatable task playbook — even if they describe it in plain language without using the word "directive".
tools: [list_dir, read_file, write_file, validate_directive, list_directives, list_tools, generate_text, echo]
category: system
---
# Create a new directive
## Purpose
Guide the user through the complete directive creation lifecycle:
1. Understand what they want to automate
2. Design the workflow with the right tools
3. Draft a well-structured directive
4. Validate it structurally
5. Define test cases that prove it works
6. Run those test cases and evaluate results
7. Refine based on what fails
8. Save the finished directive
The goal is not just to produce a file — it is to produce a directive that actually does what the user intends, handles edge cases gracefully, and is safe to run. A directive that hasn't been tested is a liability. A directive that has been tested against real inputs is an asset.
Use plain language throughout. Assume the user may have little coding experience. When in doubt, over-explain rather than under-explain.
---
## Phase 1 — Understand the goal
Ask the user in plain language:
- What should this directive do?
- What triggers it? (What would a user say or provide to kick it off?)
- What does a good output look like?
- Are there things it should explicitly NOT do?
If the user is unsure what's possible, use `list_tools` to show the available tool registry and walk through what each tool enables. Use `list_directives` to show what already exists — sometimes the user wants something that's already built, or close enough to extend rather than rebuild.
**Examples to offer if they're stuck:**
- "Review a research paper and summarize how it relates to my project"
- "Write up an architectural decision as a versioned policy document"
- "Compare two technical approaches side by side with a recommendation"
- "Design a minimal experiment to test a hypothesis against real data"
- "Audit a set of claims for what's proven vs. speculative before publishing"
Do not proceed to design until you understand the goal well enough to restate it back to the user in one sentence and have them confirm it.
---
## Phase 2 — Check for duplicates and inspect existing work
Before designing anything new, use `list_directives` to scan all categories for anything similar to what the user described.
If a close match exists:
- Tell the user what you found
- Ask whether they want to enhance the existing directive instead
- If yes, suggest using **edit_directive** rather than continuing here
If nothing close exists, use `read_file` on one or two structurally similar directives (different domain is fine — you're looking at format, not content) to anchor the format before drafting. The correct structure is:
```
---
id: short_snake_case_id
description: One-line description of what this directive does and when to use it
tools: [tool_one, tool_two, ...]
category: system | task | security | debug
---
# Title
## Purpose
...
## Steps
1. ...
2. ...
## Allowed tools
- `tool_name` — what it does, what args it takes
## Notes
...
```
---
## Phase 3 — Design the directive
Work through these decisions with the user before writing a single line of the directive:
**Identity:**
- `id` — short, snake_case, describes what it does (e.g. `policy_writeup`, `paper_review`, `architecture_comparison`)
- `description` — one sentence: what it does AND when to trigger it. This is the primary mechanism that determines whether the orchestrator picks this directive. Make it specific enough to avoid false triggers and broad enough to catch all valid uses.
- `category` — system (infrastructure/meta), task (domain work), security (security ops), debug (diagnostics)
**Tools:**
Use `list_tools` and present only the tools relevant to the goal. For each tool the user wants to include, confirm:
- Does it actually need to be in this directive?
- Is it within the user's permission level?
- If it touches files, is the target path within an allowed directory?
**File path permissions — enforce before drafting:**
| Path | Read | Write | Delete |
|------|------|-------|--------|
| `directives/` | Anyone | Blocked | Blocked |
| `drafts/directives/` | Anyone | Anyone | Soft delete only |
| `policies/`, `docs/` | Anyone | Blocked | Blocked |
| `output/`, `drafts/`, `exports/`, `temp/`, `generated/` | Anyone | Anyone | Soft delete only |
| `auro_runtime/`, `runtime_tools/` | Anyone | Blocked | Blocked |
| `.git/`, `.auro_archive/`, `__pycache__/` | Blocked | Blocked | Blocked |
| `auro_secrets.yaml`, `.env` | Blocked | Blocked | Blocked |
Never draft steps that write to `policies/`, `docs/`, `auro_runtime/`, or `runtime_tools/`. Never reference secrets or credential values directly — use `resolve_secret('alias')` to check if an alias is configured, and note in the directive that the user must set it up via **setup_credentials** before running.
**Steps:**
Design the numbered steps with the user. Each step should:
- Do exactly one thing
- Reference a specific tool by name
- Produce a concrete output or decision point
- Be executable by the orchestrator without ambiguity
If a step requires a decision (e.g. "if the file doesn't exist, ask the user"), make the branching logic explicit in plain language. Don't assume the orchestrator will infer intent.
**Security and requirements disclosure:**
If the directive involves any of the following, you MUST include a `## Notes` section that explains this in plain language before the directive is saved:
- External API calls via `http_request`
- Authentication requirements (API keys, tokens, OAuth)
- Access to sensitive data or admin-only paths
- LLM calls via `generate_text` that may incur cost
- Webhook notifications via `send_notification`
---
## Phase 4 — Draft the directive
Use `generate_text` to produce the full directive draft based on the design decisions above.
The prompt to `generate_text` should include:
- The confirmed goal statement
- The id, description, category, and tool list
- The numbered steps as designed with the user
- Any security/requirements disclosures
- The correct format (show it the structure from Phase 2)
Present the full draft to the user. Ask:
- Does the purpose section capture the intent correctly?
- Do the steps match what you expected?
- Is anything missing or wrong?
Collect feedback before moving to validation. It's cheaper to revise intent now than after test cases are written.
---
## Phase 5 — Validate
Use `validate_directive` on the draft to confirm:
- YAML front matter is well-formed (id, description, tools, category all present)
- All tools listed in front matter exist in the registry (use `list_tools` to cross-check if validation fails)
- No blocked paths are referenced in the steps
- Required sections are present (Purpose, Steps, Allowed tools)
- No secrets or credential values appear anywhere in the text
If validation fails:
1. Read the error carefully
2. Fix the specific issue — don't regenerate the whole directive
3. Re-validate before continuing
4. If the same error persists, use `read_file` on a known-good directive for structural comparison
Do not proceed to test cases until `validate_directive` returns clean.
---
## Phase 6 — Define test cases
This is the most important phase for directive quality. A directive that hasn't been tested against real inputs is unproven. Work with the user to define 2–3 test cases that together cover:
**Test case 1 — Happy path:**
A clean, complete, typical input that should produce a correct output with no edge cases. This confirms the directive works at all.
**Test case 2 — Edge case:**
An input that's valid but unusual — missing optional fields, ambiguous phrasing, a longer-than-typical input, or a case that's on the boundary of what the directive should handle. This confirms the directive is robust.
**Test case 3 — Failure case:**
An input that should be rejected or handled gracefully — bad format, missing required credential, path outside allowed directories, or a request the directive explicitly shouldn't fulfill. This confirms the directive fails safely rather than silently or dangerously.
For each test case document:
```
Test case N — [name]
Input: [exactly what the user would provide]
Expected output: [what a good result looks like, specifically]
Pass criteria: [how to judge whether this passed — be concrete]
Failure signals: [what would indicate this test failed]
```
Do not write vague pass criteria like "output looks good." Write specific ones like "output contains a versioned header, a rationale section, and at least one formula in LaTeX format."
Share the test cases with the user and ask for confirmation before running them. They may want to add cases or adjust the inputs.
---
## Phase 7 — Run test cases and evaluate
Use `generate_text` to simulate running the directive against each test case. The prompt to `generate_text` should:
1. Include the full directive text (purpose + steps + tool descriptions)
2. Include the test case input
3. Instruct the model to follow the directive steps exactly and produce the expected output format
4. Ask it to note any step where it was uncertain or had to make an assumption
Run each test case separately. For each result, evaluate against the pass criteria defined in Phase 6:
```
Test case N — [name]
Result: ✅ Pass | ⚠️ Partial | ❌ Fail
Evidence: [what the output contained that confirmed or contradicted the criteria]
Issues found: [specific steps or outputs that didn't behave as expected]
```
Present the full evaluation to the user clearly. Be specific about what failed and where in the directive the failure originated — which step produced the wrong output, which instruction was ambiguous, which tool call produced unexpected results.
Do not move to refinement until you and the user agree on what the issues are.
---
## Phase 8 — Refine and iterate
Based on the test results and user feedback, identify the root cause of each failure:
- **Ambiguous step** — the instruction was unclear enough that the executor made a wrong assumption. Fix: rewrite the step with more explicit guidance.
- **Wrong tool** — the step used a tool that wasn't right for the job. Fix: replace with the correct tool or break the step into two.
- **Missing step** — the directive assumed something would happen that wasn't explicitly instructed. Fix: add the missing step.
- **Wrong output format** — the output structure wasn't specified precisely enough. Fix: add an explicit output template or example to the relevant step.
- **Scope creep** — the directive did something it shouldn't have. Fix: add an explicit constraint or add a failure case handler.
Use `generate_text` to produce a revised draft targeting only the identified issues. Do not rewrite the whole directive unless the core design was wrong — surgical fixes preserve what's working.
Re-validate with `validate_directive` after every revision.
Re-run only the test cases that failed (plus any new ones added to cover newly discovered edge cases). If a fix for one test case breaks another, that's a design conflict — surface it to the user and resolve it before saving.
Repeat until:
- All test cases pass
- The user confirms they're satisfied
- Or the user explicitly accepts known limitations and wants to ship anyway (document those limitations in `## Notes`)
---
## Phase 9 — Save the directive
Once the directive passes validation and all test cases:
**Save the file:**
Use `write_file` to save the candidate to `drafts/directives/<id>.md`. Confirm the file was written successfully with `read_file` on the saved path — verify the content matches what was intended. Runtime tools cannot activate it: an operator must review and promote it into `directives/` outside model execution.

**Final confirmation:**
After saving, echo back to the user:
- Where the file was saved
- What it does in one sentence
- The test cases that were run and their results
- Any open questions or known limitations
- Suggested next steps (e.g. "run this against a real input", "build a companion directive for X")
---
## Allowed tools
- `list_directives` — List available directives, optionally filtered by category. Args: `category` (str, optional). Use in Phase 1 and 2 to check for duplicates and show the user what exists.
- `list_tools` — List all registered tools with descriptions and argument signatures. Args: none. Use in Phase 1 and 3 to show available tools and cross-check tool names during validation failures.
- `read_file` — Read file contents. Args: `path` (str), `encoding` (str, optional). Use in Phase 2 to inspect existing directives as format reference, and in Phase 9 to verify the saved file.
- `list_dir` — List directory contents. Args: `path` (str), `recursive` (bool, optional). Use to navigate the directives folder or confirm file locations.
- `generate_text` — Single-shot LLM call. Args: `prompt` (str), `model` (str, optional — haiku/sonnet/opus). Use in Phase 4 to draft the directive and in Phase 7 to simulate test case execution. Use haiku for drafts and test runs to keep cost low; escalate to sonnet if output quality is insufficient.
- `validate_directive` — Parse and validate a directive without executing it. Args: `path` (str) or `content` (str). Use in Phase 5 after every draft or revision before running test cases or saving.
- `write_file` — Write content to a file. Args: `path` (str), `content` (str). Use in Phase 9 to save the candidate to `drafts/directives/<id>.md`. Never write to `directives/`, `policies/`, `docs/`, `auro_runtime/`, or `runtime_tools/`.
- `echo` — Echo a message back. Args: `message` (str). Use for confirmations and status updates between phases.
---
## Notes
- **Never skip validation.** A directive that isn't validated may reference non-existent tools or malformed YAML that causes silent failures at runtime. `validate_directive` is cheap — always run it.
- **Never skip test cases.** A directive that hasn't been tested is a guess. Even one happy-path test case is better than none.
- **Never put secrets in a directive.** If the workflow requires credentials, use `resolve_secret('alias')` to check configuration and tell the user to set up the alias via **setup_credentials** before running.
- **Keep steps atomic.** Each step should do one thing. If a step feels like it's doing two things, split it. Compound steps are the most common source of executor confusion.
- **Explain the why in steps, not just the what.** Steps that say "retrieve the file so we can inspect its structure before drafting" are more reliably executed than steps that just say "retrieve the file." The orchestrator has good judgment when given context.
- **If the user wants to edit an existing directive** rather than create a new one, suggest the **edit_directive** directive.
- **If `generate_text` produces poor output** during test simulation, try a more detailed prompt that includes the full directive text and explicit output format instructions before escalating the model tier.
- **Document known limitations** in `## Notes` before saving. A directive with documented limitations is safer than one that silently fails on edge cases the developer knew about.
