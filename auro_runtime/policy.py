"""
Load and merge Policy Bindings from YAML files.
Validate enforceable rules against the guard and tool registries at load time.
"""

import inspect
import logging
from pathlib import Path

import yaml

from auro_runtime.schemas import PERMISSIVE_ENFORCEMENT, PolicyBinding, PolicyRule

logger = logging.getLogger("auro_runtime.policy")

# Derived from the executor's permissive set so the two cannot drift: adding a
# level that lets denials through must update the executor's refusal test too.
_VALID_ENFORCEMENT = frozenset({"block"}) | PERMISSIVE_ENFORCEMENT
_VALID_ON_ERROR = frozenset({"fail_closed", "fail_open"})


def load_policy(path: Path | str) -> PolicyBinding:
    """Load a single policy binding from a YAML file."""
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = []
    for r in data.get("rules", []):
        if isinstance(r, str):
            rules.append(PolicyRule(id=r[:32], description=r))
        else:
            rules.append(
                PolicyRule(
                    id=r.get("id", ""),
                    description=r.get("description", ""),
                    scope=r.get("scope"),
                    guard=r.get("guard"),
                    enforcement=r.get("enforcement", "advisory"),
                    enforcement_declared="enforcement" in r,
                    tools=r.get("tools"),
                    directives=r.get("directives"),
                    on_error=r.get("on_error", "fail_closed"),
                )
            )
    return PolicyBinding(
        id=data.get("id", path.stem),
        rules=rules,
    )


# Distinguishes "caller said nothing" from "caller explicitly passed None".
# Omission gets the live registries; an explicit None still opts out.
_LIVE_REGISTRY: dict = {}


def load_policies(policies_dir: Path | str, pattern: str = "*.yaml") -> list[PolicyBinding]:
    """Load all policy files from a directory and return as list."""
    policies_dir = Path(policies_dir)
    if not policies_dir.exists():
        return []
    result = []
    for path in sorted(policies_dir.glob(pattern)):
        if path.suffix in (".yaml", ".yml"):
            result.append(load_policy(path))
    return result


def validate_policies(
    policies: list[PolicyBinding],
    guard_registry: dict | None = _LIVE_REGISTRY,
    tool_registry: dict | None = _LIVE_REGISTRY,
) -> list[str]:
    """
    Validate all policy rules. Returns a list of error strings.
    Raises ValueError if any errors are found (fail-hard at load time).

    Both registries default to the live ones, so the call that checks guard and
    tool names is the call you get by writing nothing. Previously they defaulted
    to None, which skipped those checks entirely: the safe call was the one you
    had to remember to make. Passing None explicitly still skips, for callers
    validating a policy set against registries that are not loaded yet.
    """
    if guard_registry is _LIVE_REGISTRY:
        from auro_runtime.guards import get_guard_registry

        guard_registry = get_guard_registry()
    if tool_registry is _LIVE_REGISTRY:
        from auro_runtime.executor import get_registry

        tool_registry = get_registry()

    errors: list[str] = []
    seen_ids: set[str] = set()

    for binding in policies:
        for rule in binding.rules:
            rule_ref = f"[{binding.id}/{rule.id}]"

            if rule.id in seen_ids:
                errors.append(f"{rule_ref} Duplicate rule id '{rule.id}'.")
            seen_ids.add(rule.id)

            if rule.enforcement not in _VALID_ENFORCEMENT:
                errors.append(
                    f"{rule_ref} Invalid enforcement '{rule.enforcement}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_ENFORCEMENT))}."
                )

            if rule.on_error not in _VALID_ON_ERROR:
                errors.append(
                    f"{rule_ref} Invalid on_error '{rule.on_error}'. "
                    f"Must be one of: {', '.join(sorted(_VALID_ON_ERROR))}."
                )

            if rule.enforcement != "advisory" and not rule.guard:
                errors.append(
                    f"{rule_ref} enforcement='{rule.enforcement}' requires a guard function."
                )

            if rule.guard and rule.enforcement == "advisory" and not rule.enforcement_declared:
                # Omission must not be the permissive answer. A guarded rule with no
                # enforcement key defaults to advisory, and advisory rules are filtered
                # out before execution, so the guard would never run and nothing would
                # be audited. Declaring 'advisory' explicitly is still allowed.
                errors.append(
                    f"{rule_ref} has guard '{rule.guard}' but no enforcement key. "
                    f"Omitting it defaults to 'advisory', which drops the rule before "
                    f"execution so the guard never runs and nothing is audited. "
                    f"Declare enforcement explicitly: {', '.join(sorted(_VALID_ENFORCEMENT))}."
                )

            if rule.guard and guard_registry is not None:
                guard_fn = guard_registry.get(rule.guard)
                if guard_fn is None:
                    errors.append(
                        f"{rule_ref} Guard '{rule.guard}' not found in registry."
                    )
                elif not callable(guard_fn):
                    errors.append(
                        f"{rule_ref} Guard '{rule.guard}' is not callable."
                    )
                else:
                    try:
                        sig = inspect.signature(guard_fn)
                        params = [
                            p for p in sig.parameters.values()
                            if p.default is inspect.Parameter.empty
                            and p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
                        ]
                        if len(params) != 1:
                            errors.append(
                                f"{rule_ref} Guard '{rule.guard}' must accept exactly 1 required parameter (GuardContext)."
                            )
                    except (ValueError, TypeError):
                        pass

            # An empty scope list silently disables a rule. `tools: []` is not
            # None, so the executor's `tool not in rule.tools` test excludes
            # every call — the rule stays visible in the policy file, passes
            # validation, and never fires. Omitting the key entirely means
            # "applies to all tools", which is the fail-safe reading for a
            # restriction; an empty list is never a meaningful intent.
            if rule.tools is not None and len(rule.tools) == 0:
                errors.append(
                    f"{rule_ref} 'tools' is an empty list, which silently disables this rule. "
                    f"Omit the key to apply it to all tools, or remove the rule."
                )
            if rule.directives is not None and len(rule.directives) == 0:
                errors.append(
                    f"{rule_ref} 'directives' is an empty list, which silently disables this rule. "
                    f"Omit the key to apply it to all directives, or remove the rule."
                )

            if rule.tools and tool_registry is not None:
                for t in rule.tools:
                    if t not in tool_registry:
                        errors.append(
                            f"{rule_ref} Tool '{t}' in tools list not found in tool registry."
                        )

    if errors:
        raise ValueError(
            f"Policy validation failed with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    return errors


def get_enforceable_rules(policies: list[PolicyBinding]) -> list[PolicyRule]:
    """Return rules that have a guard function assigned and enforcement != advisory."""
    enforceable = [
        rule
        for binding in policies
        for rule in binding.rules
        if rule.guard is not None and rule.enforcement != "advisory"
    ]

    # A guarded advisory rule reads like an active control in the policy file but
    # never reaches the executor, so its guard produces no verdict and no audit
    # event. Silence is what makes that dangerous; name them instead.
    dropped = [
        f"{binding.id}.{rule.id} (guard={rule.guard})"
        for binding in policies
        for rule in binding.rules
        if rule.guard is not None and rule.enforcement == "advisory"
    ]
    if dropped:
        logger.warning(
            "advisory_guarded_rules_not_enforced: %s",
            ", ".join(dropped),
            extra={"dropped_rules": dropped},
        )

    return enforceable


# The reviewed posture of every shipped enforceable rule: which guard runs, at
# what level, what happens when that guard raises, and which tools it covers.
#
# AURO_POLICY_PROFILE=shipped verifies this, not merely that the rule names are
# present. An id-set comparison passes a rule edited from `block` to `advisory`,
# because the id does not change -- and that is the edit that hides. An added or
# removed rule shows up in a diff; a one-word downgrade does not.
#
# One definition, imported by both the runtime check and the test suite that
# pins the same values. Two copies of a pin drift, and a drifting pin is worse
# than no pin: it reports agreement with itself.
SHIPPED_ENFORCEMENT_POSTURE: dict[str, dict] = {
    # policies/default.yaml
    "no_delete_without_confirm": {
        "guard": "check_destructive_action", "enforcement": "warn",
        "on_error": "fail_open", "tools": ["delete_file", "restore_file"],
    },
    "log_actions": {
        "guard": "check_reason_not_empty", "enforcement": "warn",
        "on_error": "fail_open", "tools": None,
    },
    "no_secrets_in_logs": {
        "guard": "check_no_secrets_in_args", "enforcement": "block",
        "on_error": "fail_closed", "tools": None,
    },
    "sensitive_paths": {
        "guard": "check_sensitive_paths", "enforcement": "block",
        "on_error": "fail_closed",
        "tools": ["read_file", "write_file", "delete_file", "list_dir", "restore_file"],
    },
    "no_bulk_writes": {
        "guard": "check_no_bulk_writes", "enforcement": "warn",
        "on_error": "fail_open", "tools": ["write_file"],
    },
    "write_budget": {
        "guard": "check_write_budget", "enforcement": "block",
        "on_error": "fail_closed", "tools": None,
    },
    # policies/credential_proxy.yaml
    "no_hardcoded_secrets": {
        "guard": "check_no_raw_credentials", "enforcement": "block",
        "on_error": "fail_closed", "tools": ["http_request"],
    },
}

_POSTURE_FIELDS = ("guard", "enforcement", "on_error", "tools")


def shipped_posture_drift(policies: list[PolicyBinding]) -> list[str]:
    """
    Describe how the reviewed rules differ from how they actually loaded.

    Empty means no drift. The guarantee is that every reviewed rule is present
    and unmodified, not that the set is exactly the reviewed set: a rule an
    operator added is not drift, because an addition can only add a check. It
    cannot weaken one that is already there.

    Caught here: a reviewed rule that stopped reaching the executor (guard
    removed, or enforcement edited to advisory), one whose guard, enforcement,
    on_error or tool scope changed, and one defined more than once among the
    enforceable rules, where which copy applies depends on load order.
    """
    by_id: dict[str, list[PolicyRule]] = {}
    for rule in get_enforceable_rules(policies):
        by_id.setdefault(rule.id, []).append(rule)

    drift: list[str] = []
    for rule_id in sorted(SHIPPED_ENFORCEMENT_POSTURE):
        matches = by_id.get(rule_id, [])
        if not matches:
            drift.append(
                f"{rule_id}: reviewed as enforceable, but it does not reach the "
                f"executor (no guard, or enforcement is advisory)"
            )
            continue
        if len(matches) > 1:
            drift.append(
                f"{rule_id}: defined {len(matches)} times among the enforceable "
                f"rules, so which one applies depends on load order"
            )
            continue
        expected = SHIPPED_ENFORCEMENT_POSTURE[rule_id]
        for field in _POSTURE_FIELDS:
            actual = getattr(matches[0], field)
            if actual != expected[field]:
                drift.append(
                    f"{rule_id}.{field}: reviewed as {expected[field]!r}, loaded as {actual!r}"
                )
    return drift


def format_policies_for_prompt(policies: list[PolicyBinding]) -> str:
    """Format policy bindings as text for injection into the system prompt."""
    lines = ["# Policy Bindings", ""]
    for binding in policies:
        lines.append(f"## {binding.id}")
        for rule in binding.rules:
            lines.append(f"- **{rule.id}**: {rule.description}")
        lines.append("")
    return "\n".join(lines).strip()
