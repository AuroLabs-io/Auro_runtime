---
id: verify_project
description: Run the full Output quality gate (static, security, dynamic) and report findings in plain language
tools: [verify_output, verify_code_static, verify_security, verify_code_dynamic, list_dir]
category: system
---

# Verify project

## Purpose
Run a complete **developer source checkout's** quality gate and explain the result. This is not an installed-wheel self-check: it requires a checkout containing `pyproject.toml`, `auro_runtime/`, `runtime_tools/`, and `tests/`. An installed runtime must set `AURO_SOURCE_ROOT` to such a checkout; without one, the verifier returns a structured `SOURCE_CHECKOUT_REQUIRED` failure.

The gate has three phases — static checks (syntax, frontmatter, layout), security checks (secret scanning, guard coverage), and dynamic checks (tool imports, policy validation against the live registries, and the test suite). Dynamic checks execute code, but only inside a temporary project copy with a sanitized environment, never against the real project root.

The job is not just to relay pass/fail. It is to say what was actually verified, and — just as important — **what was not**.

## Steps

1. **Explain** — In one or two sentences: this runs the full quality gate; phases 1 and 2 are read-only, phase 3 executes code inside a temporary copy of the project with a sanitized environment, never against the real files.

2. **Run the gate** — Use `verify_output`. It runs the three phases in the correct order and short-circuits: if static checks produce errors, dynamic checks are skipped so potentially broken code is never executed. Expect a result with `passed`, `error_count`, `warn_count`, `phases`, and `findings`.

3. **Report each phase** — For `code_static`, `security`, and `code_dynamic`, give one line each: phase name, pass/fail, error and warning counts. If a phase was skipped because an earlier one failed, say so explicitly rather than implying it passed.

4. **Check whether the test suite actually ran** — This matters more than it looks. The dynamic phase reports a `test_suite` check. Missing pytest and an empty collection are failures because both verify nothing.
   - If the detail says no tests were collected or pytest is missing, report the failure plainly and state that no behavioral coverage ran.
   - If real pytest output is present, report the test counts.

5. **Report findings** — If `findings` is non-empty, list each with its severity and message, most severe first. Group them by phase if there are many. If empty, say so.

6. **Optional drill-down** — Only if a phase failed and the user needs detail, re-run that single phase for its individual checks: `verify_code_static`, `verify_security`, or `verify_code_dynamic`. Do not re-run all three individually after `verify_output` — that repeats work already done.

7. **Complete** — Respond with `{"done": true, "summary": "..."}`. The summary must contain: one line per phase with status and counts; an explicit line about whether the test suite ran and what it covered; the findings list or "no findings"; and a single overall verdict.

## Allowed tools
- `verify_output` — Full gate in the correct order (static → security → dynamic), with short-circuiting. No args. This is the primary tool for this directive.
- `verify_code_static` — Syntax, AST, directive frontmatter, file layout. No args. No code executed.
- `verify_security` — Secret scanning, guard validation, sensitive file exposure, tool schema coverage. No args.
- `verify_code_dynamic` — Tool imports, policy validation against the registries, and the test suite. No args. Runs in a temporary project copy with a sanitized environment.
- `list_dir` — List directory contents. Args: `path` (str), optional `recursive` (bool). Use only if the user asks which files exist; the gate does not need it.

## Notes
- Read-only with respect to the real project. The dynamic phase executes code, but only against a temporary copy with a sanitized environment.
- A green gate is a claim about what was checked, not a guarantee of correctness. Say what was covered.
- One tool call per message.
