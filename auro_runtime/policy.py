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
    guard_registry: dict | None = None,
    tool_registry: dict | None = None,
) -> list[str]:
    """
    Validate all policy rules. Returns a list of error strings.
    Raises ValueError if any errors are found (fail-hard at load time).
    """
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


def format_policies_for_prompt(policies: list[PolicyBinding]) -> str:
    """Format policy bindings as text for injection into the system prompt."""
    lines = ["# Policy Bindings", ""]
    for binding in policies:
        lines.append(f"## {binding.id}")
        for rule in binding.rules:
            lines.append(f"- **{rule.id}**: {rule.description}")
        lines.append("")
    return "\n".join(lines).strip()
