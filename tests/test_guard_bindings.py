"""
Tests for the guard registry and its binding into the real policy files
(auro_runtime.guards + policies/*.yaml).

Two failure modes matter here, and they're mirror images of each other:

* A guard is registered in code but no policy rule ever binds it. It reads as
  protection ("we have a check_no_bulk_writes guard!") while doing nothing at
  runtime, because the executor only ever runs guards a rule's `guard:` key
  names.
* A policy rule names a guard that doesn't exist (a typo, a rename that
  missed one call site). validate_policies() is supposed to catch this at
  load time; this file checks the underlying fact it depends on.

The registry-vs-policy-files checks below parse policies/*.yaml directly with
yaml.safe_load, independent of auro_runtime.policy's own loader, so a bug in
the loader itself couldn't hide a binding problem from this suite.
"""

import inspect
import re
from pathlib import Path

import pytest
import yaml

from auro_runtime.guards import GuardVerdict
from auro_runtime.policy import SHIPPED_ENFORCEMENT_POSTURE

_EXPECTED_GUARD_NAMES = {
    "check_destructive_action",
    "check_no_bulk_writes",
    "check_no_raw_credentials",
    "check_no_secrets_in_args",
    "check_reason_not_empty",
    "check_sensitive_paths",
    "check_write_budget",
}


def _guard_names_used_in_policy_files(repo_root: Path) -> set[str]:
    """Collect every `guard:` value across policies/*.yaml via a raw YAML parse."""
    used: set[str] = set()
    for path in (repo_root / "policies").glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in data.get("rules", []):
            if isinstance(rule, dict) and rule.get("guard"):
                used.add(rule["guard"])
    return used


# --- Registry shape ----------------------------------------------------


class TestGuardRegistryShape:
    def test_exactly_seven_guards_registered(self, guard_registry):
        assert len(guard_registry) == 7

    def test_registered_guard_names_match_expected_set(self, guard_registry):
        assert set(guard_registry.keys()) == _EXPECTED_GUARD_NAMES


# --- Registry <-> policy files cross-check ------------------------------


class TestGuardPolicyBinding:
    def test_every_registered_guard_is_bound_by_some_policy_rule(self, repo_root, guard_registry):
        """No orphans: a registered guard that no rule ever binds is dead protection."""
        used = _guard_names_used_in_policy_files(repo_root)
        unbound = set(guard_registry) - used
        assert unbound == set(), f"registered guards never referenced by any policy rule: {sorted(unbound)}"

    def test_every_guard_referenced_in_policy_files_is_registered(self, repo_root, guard_registry):
        """Inverse direction: a typo'd or renamed guard name in YAML must resolve to something real."""
        used = _guard_names_used_in_policy_files(repo_root)
        unknown = used - set(guard_registry)
        assert unknown == set(), f"policy files reference guards missing from the registry: {sorted(unknown)}"

    def test_no_bulk_writes_is_bound_as_warn_on_write_file_only(self, policy_rules):
        """
        Locks in a deliberate design choice: bulk-write detection warns
        (does not block) and is scoped to write_file only — it should not
        silently start blocking, or start applying to delete_file/restore_file,
        without that being a conscious policy change.
        """
        matches = [r for r in policy_rules if r.guard == "check_no_bulk_writes"]
        assert len(matches) == 1, "expected exactly one policy rule bound to check_no_bulk_writes"
        rule = matches[0]
        assert rule.enforcement == "warn"
        assert rule.tools == ["write_file"]


# --- Shipped policy files: pinned enforcement posture ---------------------


# Every guard-bound rule across policies/*.yaml, with the posture it ships with.
# A rule that binds a guard is one the executor acts on, so all four fields are
# load-bearing at runtime:
#   guard       - which check runs
#   enforcement - block refuses, warn audits and proceeds, advisory does neither
#   on_error    - what happens when the guard itself raises
#   tools       - which tools the rule applies to; None means every tool
# Imported rather than restated. This used to be a second copy of the same
# posture, kept in step with the runtime by hand; since 2026-08-09 the runtime
# checks the same values under AURO_POLICY_PROFILE=shipped, and two pins that
# can disagree are worse than one, because each reports agreement with itself.
_SHIPPED_ENFORCEMENT = SHIPPED_ENFORCEMENT_POSTURE


class TestShippedPolicyEnforcementIsPinned:
    """
    Without these assertions a shipped rule can be silently downgraded and
    nothing notices.

    Verified 2026-07-25 against the real suite: `no_secrets_in_logs` could be
    changed from `block` to `advisory` with 244 passed and 0 failed, and
    `write_budget` likewise. `no_secrets_in_logs` is the rule that stops
    credentials reaching logs via tool arguments, so that downgrade is the
    difference between the product's central claim holding and not.

    Only `no_bulk_writes` had its real shipped posture pinned; the other six
    guards did not. These tests close that gap for all seven.
    """

    def test_enforceable_rule_ids_match_the_pinned_set(self, enforceable_rules):
        """
        Catches a guard-bound rule being added or removed without a deliberate
        update here, which is what would otherwise let a new rule ship
        unreviewed or an existing protection disappear unnoticed.
        """
        assert {r.id for r in enforceable_rules} == set(_SHIPPED_ENFORCEMENT)

    @pytest.mark.parametrize("rule_id", sorted(_SHIPPED_ENFORCEMENT))
    def test_shipped_rule_posture_is_unchanged(self, enforceable_rules, rule_id):
        expected = _SHIPPED_ENFORCEMENT[rule_id]
        matches = [r for r in enforceable_rules if r.id == rule_id]
        assert len(matches) == 1, f"expected exactly one rule with id {rule_id!r}"
        rule = matches[0]
        assert rule.guard == expected["guard"], f"{rule_id}: guard changed"
        assert rule.enforcement == expected["enforcement"], f"{rule_id}: enforcement changed"
        assert rule.on_error == expected["on_error"], f"{rule_id}: on_error changed"
        assert rule.tools == expected["tools"], f"{rule_id}: tool scope changed"

    def test_every_blocking_rule_fails_closed(self, enforceable_rules):
        """
        Invariant rather than a pinned value: a rule that refuses calls must not
        let a guard exception wave them through. A `block` rule shipped with
        on_error=fail_open would be bypassable by making its guard raise.
        """
        offenders = [
            (r.id, r.on_error) for r in enforceable_rules
            if r.enforcement == "block" and r.on_error != "fail_closed"
        ]
        assert offenders == [], f"blocking rules that do not fail closed: {offenders}"


# --- The enforcement opt-out surface -------------------------------------

# Every way a policy guard can be stopped from blocking a call, by environment.
# The point of pinning this is not that any of them is wrong: each is deliberate,
# fail-closed when unset, and unreachable by a model. The point is that the SET
# can grow without anyone noticing, and it already grew past what the people who
# built it carried in mind. A new AURO_* name in the enforcement path fails this
# test until someone classifies it, the same way tests/catalogue.py refuses to
# run for an unclassified test file.
_ENFORCEMENT_ENV_OPT_OUTS = {
    "AURO_ALLOW_NO_POLICIES": (
        "Converts the zero-enforceable-rules refusal into an unguarded run, "
        "which passes UNRESTRICTED down into execute()."
    ),
    "AURO_POLICY_PROFILE": (
        "'custom' skips the check that the loaded bindings and rule ids match "
        "the reviewed shipped set. Guards still run; they are no longer verified "
        "to be the reviewed ones."
    ),
}

# Modules that decide whether a guard runs. Read for AURO_* literals below.
_ENFORCEMENT_PATH = (
    "orchestrator.py",
    "executor.py",
    "policy.py",
    "guards.py",
    "directive.py",
)

_AURO_ENV_RE = re.compile(r"AURO_[A-Z_]+")


class TestEnforcementOptOutSurfaceIsPinned:
    """
    The routes that disable enforcement, held to a known set.

    Opened from the founder's reaction to the inventory on 2026-08-09 — "this is
    a lot more bypass than I thought we had" — which is the argument for this
    class. Each route is individually tested elsewhere; nothing failed when the
    surface grew. See OT-enforcement-opt-outs-are-not-enumerated.
    """

    def test_enforcement_path_reads_only_the_pinned_environment_variables(self, repo_root):
        found: dict[str, str] = {}
        for name in _ENFORCEMENT_PATH:
            path = repo_root / "auro_runtime" / name
            for match in _AURO_ENV_RE.findall(path.read_text(encoding="utf-8")):
                found.setdefault(match, name)

        unpinned = {n: where for n, where in found.items() if n not in _ENFORCEMENT_ENV_OPT_OUTS}
        assert unpinned == {}, (
            f"unclassified AURO_* name(s) in the enforcement path: {unpinned}. "
            f"If it can affect whether a guard runs, add it to "
            f"_ENFORCEMENT_ENV_OPT_OUTS and document it in the README's Opting "
            f"out section. If it cannot, it does not belong in these modules."
        )

    def test_pinned_opt_outs_are_still_read_where_claimed(self, repo_root):
        """Negative control: a pin naming variables nothing reads proves nothing."""
        source = "\n".join(
            (repo_root / "auro_runtime" / name).read_text(encoding="utf-8")
            for name in _ENFORCEMENT_PATH
        )
        for name in _ENFORCEMENT_ENV_OPT_OUTS:
            assert name in source, (
                f"{name} is pinned as an enforcement opt-out but no longer appears "
                f"in the enforcement path. Remove it from the pin, and from the docs."
            )

    def test_only_advisory_drops_a_guarded_rule_from_enforcement(self):
        """
        `enforcement` is a free string, so the safe behaviour is that anything
        unrecognised still enforces. A second non-blocking tier would be a new
        opt-out, and this is what would notice it.
        """
        from auro_runtime.policy import get_enforceable_rules
        from auro_runtime.schemas import PolicyBinding, PolicyRule

        tiers = ("block", "warn", "advisory", "disabled", "off", "")
        binding = PolicyBinding(
            id="probe",
            rules=[
                PolicyRule(
                    id=f"probe_{tier or 'empty'}",
                    description=f"Synthetic probe for enforcement tier {tier!r}.",
                    guard="check_reason_not_empty",
                    enforcement=tier,
                    enforcement_declared=True,
                )
                for tier in tiers
            ],
        )
        dropped = {
            rule.enforcement
            for rule in binding.rules
            if rule.id not in {r.id for r in get_enforceable_rules([binding])}
        }
        assert dropped == {"advisory"}, (
            f"tiers dropped from enforcement changed: {sorted(dropped)}. "
            f"Only 'advisory' should remove a guarded rule from evaluation."
        )

    def test_only_the_exact_fail_open_string_opts_out_of_failing_closed(self):
        """A typo in on_error must not become a bypass."""
        from auro_runtime.policy import _VALID_ON_ERROR

        assert _VALID_ON_ERROR == {"fail_closed", "fail_open"}, (
            "the on_error vocabulary changed; a third value is a new opt-out"
        )


# --- Guard callable contract ---------------------------------------------


class TestGuardCallableContract:
    def test_every_guard_is_callable_with_exactly_one_required_parameter(self, guard_registry):
        """
        Mirrors the signature check validate_policies() performs at load
        time: every guard must accept exactly one required positional/keyword
        parameter (the GuardContext). This is what the executor relies on
        when it calls `guard_fn(ctx)` uniformly for every guard.
        """
        for name, fn in guard_registry.items():
            assert callable(fn), f"{name} is not callable"
            sig = inspect.signature(fn)
            required = [
                p
                for p in sig.parameters.values()
                if p.default is inspect.Parameter.empty
                and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
            ]
            assert len(required) == 1, f"{name} must accept exactly one required parameter, got signature {sig}"

    def test_every_guard_no_ops_cleanly_on_an_unrelated_benign_call(self, guard_registry, make_guard_context):
        """
        None of the 7 guards have any business objecting to a plain `echo`
        call with a non-empty reason and no path/credential-shaped args. Each
        must return None (or, per the GuardFn contract, a GuardVerdict) —
        never raise — and for this specific benign call, every guard's own
        logic no-ops to None. A guard that raised here would take down the
        executor for a tool it has nothing to do with.
        """
        ctx = make_guard_context("echo", args={"message": "hello"}, reason="just testing")
        for name, fn in guard_registry.items():
            verdict = fn(ctx)
            assert verdict is None or isinstance(verdict, GuardVerdict), (
                f"{name} returned {verdict!r}, expected None or a GuardVerdict"
            )
            assert verdict is None, f"{name} should no-op on an unrelated benign 'echo' call, got {verdict!r}"
