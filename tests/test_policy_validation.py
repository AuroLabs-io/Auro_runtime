"""
Tests for the policy loader and validator (auro_runtime.policy).

The load -> validate pipeline is what stands between a typo in a YAML file and
a runtime that silently can't run any directive. That is not hypothetical: a
stale tool name in a policy file once made validate_policies() raise at
startup for every run, and it shipped that way. The tests here check both the
real files under policies/ (the direct regression test) and synthetic
policies built in memory (to pin down the validator's contract independent of
whatever the real files happen to contain today).
"""

import pytest
import yaml

from auro_runtime.policy import load_policies, load_policy, validate_policies
from auro_runtime.schemas import PolicyBinding, PolicyRule

_VALID_ENFORCEMENT = {"block", "warn", "advisory"}
_VALID_ON_ERROR = {"fail_open", "fail_closed"}


# --- The real repo policies -------------------------------------------------
# These exercise the exact call the runtime makes at startup, against the
# real registries and the real policies/ directory.


class TestRealPoliciesLoadAndValidate:
    def test_real_policies_load_and_validate_cleanly(self, policies, guard_registry, registry):
        """
        The definitive "can the runtime start" test: load_policies() output,
        fed straight into validate_policies() with the real tool and guard
        registries, must not raise and must report zero errors.
        """
        errors = validate_policies(policies, guard_registry=guard_registry, tool_registry=registry)
        assert errors == []

    def test_real_policy_shape_matches_known_snapshot(self, policies, policy_rules, enforceable_rules):
        """
        Guards against a vacuous pass above: if a binding file silently
        stopped loading (e.g. renamed out of `*.yaml`), the "no errors" test
        would still pass on whatever's left. Pin the known shape too.
        """
        assert {b.id for b in policies} == {"default", "credential_proxy", "router"}
        assert len(policy_rules) == 21
        assert len(enforceable_rules) == 7

    def test_every_declared_tool_in_real_policies_exists_in_registry(self, policy_rules, registry):
        """
        Direct regression test for the shipped blocker: walk every rule that
        declares a `tools:` list and confirm each name is registered. A stale
        or renamed tool here is exactly what made validate_policies() raise
        at startup for every directive.
        """
        offenders = [
            (rule.id, t)
            for rule in policy_rules
            if rule.tools
            for t in rule.tools
            if t not in registry
        ]
        assert offenders == [], f"rules referencing unregistered tools: {offenders}"

    def test_every_declared_guard_in_real_policies_exists_in_registry(self, policy_rules, guard_registry):
        """Every `guard:` in the real policy files must resolve to a registered guard."""
        offenders = [
            (rule.id, rule.guard)
            for rule in policy_rules
            if rule.guard and rule.guard not in guard_registry
        ]
        assert offenders == [], f"rules referencing unregistered guards: {offenders}"

    def test_real_policy_enforcement_values_are_all_valid(self, policy_rules):
        offenders = [(rule.id, rule.enforcement) for rule in policy_rules if rule.enforcement not in _VALID_ENFORCEMENT]
        assert offenders == [], f"rules with invalid enforcement values: {offenders}"

    def test_real_policy_on_error_values_are_all_valid(self, policy_rules):
        offenders = [(rule.id, rule.on_error) for rule in policy_rules if rule.on_error not in _VALID_ON_ERROR]
        assert offenders == [], f"rules with invalid on_error values: {offenders}"


# --- validate_policies() contract, exercised on synthetic policies ---------
# Built entirely in memory via make_rule/PolicyBinding — nothing here touches
# the files on disk under policies/.


class TestValidatePoliciesSynthetic:
    def test_raises_when_rule_names_unknown_tool(self, make_rule, guard_registry, registry):
        rule = make_rule(
            guard="check_reason_not_empty",
            enforcement="warn",
            tools=["definitely_not_a_registered_tool"],
        )
        binding = PolicyBinding(id="synthetic", rules=[rule])
        with pytest.raises(ValueError, match="definitely_not_a_registered_tool"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_raises_when_rule_names_unknown_guard(self, make_rule, guard_registry, registry):
        rule = make_rule(guard="definitely_not_a_registered_guard", enforcement="warn", tools=None)
        binding = PolicyBinding(id="synthetic", rules=[rule])
        with pytest.raises(ValueError, match="definitely_not_a_registered_guard"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_rejects_an_empty_tools_list(self, make_rule, registry, guard_registry):
        """
        An empty scope list silently disables a rule. `tools: []` is not None,
        so the executor excludes every call, while the rule stays visible in the
        policy file and passes every other check. Omitting the key means "all
        tools", the fail-safe reading; an empty list is never a real intent.
        """
        rule = make_rule(guard="check_destructive_action", tools=[], rule_id="empty_scope")
        binding = PolicyBinding(id="synthetic", rules=[rule])
        with pytest.raises(ValueError, match="empty list"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_rejects_an_empty_directives_list(self, make_rule, registry, guard_registry):
        """Same silent-disable hazard, on the other scoping axis."""
        rule = make_rule(guard="check_destructive_action", directives=[], rule_id="empty_directives")
        binding = PolicyBinding(id="synthetic", rules=[rule])
        with pytest.raises(ValueError, match="empty list"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_an_unscoped_rule_fires_for_every_tool(self, make_tool_call, make_rule, registry):
        """
        The security argument for None-meaning-all: a restriction with no
        `tools` key covers tools that did not exist when the policy was written.
        Inverting it would ship every new tool unguarded until someone
        remembered to extend a list.
        """
        from auro_runtime.executor import execute

        rule = make_rule(guard="check_destructive_action", enforcement="block", rule_id="unscoped")
        result = execute(
            make_tool_call("delete_file", {"path": "output/x.txt"}),
            allowed_tools={"delete_file"},
            policy_rules=[rule], run_history=[],
        )
        assert result.success is False
        assert "unscoped" in result.error

    def test_passes_when_tools_is_none(self, make_rule, guard_registry, registry):
        """tools=None means 'applies to every tool' — must not be treated as an invalid/empty list."""
        rule = make_rule(guard="check_reason_not_empty", enforcement="warn", tools=None)
        binding = PolicyBinding(id="synthetic", rules=[rule])
        errors = validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)
        assert errors == []

    def test_raises_when_enforcing_rule_has_no_guard(self, make_rule, guard_registry, registry):
        """
        enforcement != 'advisory' with no guard is meaningless (nothing would
        ever actually enforce it). make_rule()'s own defaults (guard=None,
        enforcement='block') trigger exactly this case.
        """
        rule = make_rule()
        binding = PolicyBinding(id="synthetic", rules=[rule])
        with pytest.raises(ValueError, match="requires a guard function"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_raises_on_duplicate_rule_id_within_a_binding(self, make_rule, guard_registry, registry):
        rule_a = make_rule(rule_id="dup", guard="check_reason_not_empty", enforcement="warn")
        rule_b = make_rule(rule_id="dup", guard="check_reason_not_empty", enforcement="warn")
        binding = PolicyBinding(id="synthetic", rules=[rule_a, rule_b])
        with pytest.raises(ValueError, match="Duplicate rule id 'dup'"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_accumulates_multiple_errors_into_one_exception(self, make_rule, guard_registry, registry):
        """
        validate_policies collects every problem before raising once, so a
        directive author sees the whole list in one pass instead of
        whack-a-mole-ing one error at a time.
        """
        rule_a = make_rule(rule_id="rule_a", guard="check_reason_not_empty", enforcement="warn", tools=["nonexistent_tool_a"])
        rule_b = make_rule(rule_id="rule_b", guard="nonexistent_guard_b", enforcement="warn")
        binding = PolicyBinding(id="synthetic", rules=[rule_a, rule_b])
        with pytest.raises(ValueError) as excinfo:
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)
        message = str(excinfo.value)
        assert "2 error(s)" in message
        assert "nonexistent_tool_a" in message
        assert "nonexistent_guard_b" in message

    def test_omitting_the_registries_checks_against_the_live_ones(self, make_rule):
        """
        The registries used to default to None, which skipped the guard and tool
        name checks entirely: the safe call was the one you had to remember to
        make. Omission now uses the live registries, so a made-up guard or tool
        raises without the caller having to ask for the check.
        """
        rule = make_rule(guard="totally_made_up_guard", enforcement="warn",
                         tools=["totally_made_up_tool"])
        binding = PolicyBinding(id="synthetic", rules=[rule])

        with pytest.raises(ValueError) as excinfo:
            validate_policies([binding])
        message = str(excinfo.value)
        assert "totally_made_up_guard" in message
        assert "totally_made_up_tool" in message

    def test_explicit_none_still_skips_the_registry_checks(self, make_rule):
        """
        Negative control, and a real use: validating a policy set before the
        registries are populated. Passing None deliberately still opts out, so
        the change above is a change of default rather than of capability.
        """
        rule = make_rule(guard="totally_made_up_guard", enforcement="warn",
                         tools=["totally_made_up_tool"])
        binding = PolicyBinding(id="synthetic", rules=[rule])
        errors = validate_policies([binding], guard_registry=None, tool_registry=None)
        assert errors == []


# --- Advisory: the level that silently disables a guard ----------------------


class TestGuardedRuleMustDeclareEnforcement:
    """
    `advisory` is the default when `enforcement:` is omitted, and advisory rules
    are stripped by get_enforceable_rules() before they reach the executor. So a
    rule naming a guard but omitting enforcement reads like an active control in
    the policy file while its guard never runs, producing no verdict and no
    audit event at all.

    Omission must not be the permissive answer. Declaring `advisory` explicitly
    is still allowed, because guardless prose rules legitimately need it.
    """

    def _binding_from_yaml(self, tmp_path, body):
        path = tmp_path / "probe.yaml"
        path.write_text(body, encoding="utf-8")
        return load_policy(path)

    def test_guarded_rule_omitting_enforcement_is_rejected(self, tmp_path, guard_registry, registry):
        binding = self._binding_from_yaml(tmp_path, (
            "id: probe\n"
            "rules:\n"
            "  - id: forgot_enforcement\n"
            "    description: Has a guard but no enforcement key\n"
            "    guard: check_reason_not_empty\n"
        ))
        assert binding.rules[0].enforcement == "advisory", "precondition: omission defaults to advisory"
        assert binding.rules[0].enforcement_declared is False
        with pytest.raises(ValueError, match="no enforcement key"):
            validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_guarded_rule_declaring_advisory_explicitly_is_allowed(self, tmp_path, guard_registry, registry):
        binding = self._binding_from_yaml(tmp_path, (
            "id: probe\n"
            "rules:\n"
            "  - id: deliberately_advisory\n"
            "    description: Deliberately advisory, guard kept for documentation\n"
            "    guard: check_reason_not_empty\n"
            "    enforcement: advisory\n"
        ))
        assert binding.rules[0].enforcement_declared is True
        validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_guardless_rule_omitting_enforcement_is_still_fine(self, tmp_path, guard_registry, registry):
        """Prose-only rules are the reason advisory exists. They must stay ergonomic."""
        binding = self._binding_from_yaml(tmp_path, (
            "id: probe\n"
            "rules:\n"
            "  - id: prose_only\n"
            "    description: Natural-language intent with nothing to enforce\n"
        ))
        validate_policies([binding], guard_registry=guard_registry, tool_registry=registry)

    def test_dropping_a_guarded_advisory_rule_is_logged_not_silent(self, caplog):
        """The drop must be announced. Silence is what makes advisory dangerous."""
        from auro_runtime.policy import get_enforceable_rules

        binding = PolicyBinding(id="probe", rules=[
            PolicyRule(id="quietly_disabled", description="x",
                       guard="check_reason_not_empty", enforcement="advisory"),
        ])
        with caplog.at_level("WARNING", logger="auro_runtime.policy"):
            enforceable = get_enforceable_rules([binding])

        assert enforceable == [], "an advisory rule must not reach the executor"
        assert "advisory_guarded_rules_not_enforced" in caplog.text
        assert "quietly_disabled" in caplog.text

    def test_guardless_advisory_rules_do_not_generate_noise(self, caplog):
        """Prose rules are supposed to be advisory, so they must not warn."""
        from auro_runtime.policy import get_enforceable_rules

        binding = PolicyBinding(id="probe", rules=[
            PolicyRule(id="prose_only", description="x", guard=None, enforcement="advisory"),
        ])
        with caplog.at_level("WARNING", logger="auro_runtime.policy"):
            get_enforceable_rules([binding])
        assert "advisory_guarded_rules_not_enforced" not in caplog.text


# --- Loader edge cases (tmp_path) -------------------------------------------
# load_policy / load_policies behavior on directory and file shapes that
# don't occur in the real policies/ dir today.


class TestLoaderEdgeCases:
    def test_load_policies_on_missing_directory_returns_empty_list(self, tmp_path):
        result = load_policies(tmp_path / "does_not_exist")
        assert result == []

    def test_load_policies_on_empty_directory_returns_empty_list(self, tmp_path):
        result = load_policies(tmp_path)
        assert result == []

    def test_load_policies_ignores_non_yaml_files(self, tmp_path):
        (tmp_path / "notes.txt").write_text("id: not_a_policy\nrules: []\n", encoding="utf-8")
        (tmp_path / "real.yaml").write_text("id: real\nrules: []\n", encoding="utf-8")
        result = load_policies(tmp_path)
        assert [b.id for b in result] == ["real"]

    def test_load_policy_defaults_id_to_filename_stem_when_missing(self, tmp_path):
        path = tmp_path / "unnamed.yaml"
        path.write_text("rules: []\n", encoding="utf-8")
        binding = load_policy(path)
        assert binding.id == "unnamed"

    def test_load_policy_missing_rules_key_yields_empty_rules_list(self, tmp_path):
        path = tmp_path / "norules.yaml"
        path.write_text("id: norules\n", encoding="utf-8")
        binding = load_policy(path)
        assert binding.rules == []

    def test_load_policy_applies_field_defaults_for_minimal_rule(self, tmp_path):
        path = tmp_path / "minimal.yaml"
        path.write_text(
            "id: minimal\nrules:\n  - id: r1\n    description: does a thing\n",
            encoding="utf-8",
        )
        binding = load_policy(path)
        assert len(binding.rules) == 1
        rule = binding.rules[0]
        assert rule.guard is None
        assert rule.enforcement == "advisory"
        assert rule.on_error == "fail_closed"
        assert rule.tools is None
        assert rule.directives is None

    def test_load_policy_supports_bare_string_rule_shorthand(self, tmp_path):
        """
        A rule entry that is a plain string rather than a mapping becomes an
        advisory, guard-less PolicyRule whose id is the string truncated to
        32 characters (see load_policy's `isinstance(r, str)` branch).
        """
        text = "Always double-check destructive actions before running them for real."
        path = tmp_path / "shorthand.yaml"
        path.write_text(f'id: shorthand\nrules:\n  - "{text}"\n', encoding="utf-8")
        binding = load_policy(path)
        assert len(binding.rules) == 1
        rule = binding.rules[0]
        assert rule.id == text[:32]
        assert rule.description == text
        assert rule.guard is None
        assert rule.enforcement == "advisory"

    def test_load_policy_malformed_yaml_raises(self, tmp_path):
        """
        The loader does not swallow YAML syntax errors — it fails loudly at
        load time rather than silently producing an empty or partial policy.
        """
        path = tmp_path / "broken.yaml"
        path.write_text('id: broken\nrules:\n  - id: r1\n    description: "unterminated\n', encoding="utf-8")
        with pytest.raises(yaml.YAMLError):
            load_policy(path)
