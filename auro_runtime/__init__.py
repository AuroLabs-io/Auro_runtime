"""
Directive-Policy Bound Orchestrator.

The LLM is the conductor: it reads Directives, respects Policy Bindings,
and emits structured tool calls that Python executes deterministically.
"""

from auro_runtime.orchestrator import run

__all__ = ["run"]
