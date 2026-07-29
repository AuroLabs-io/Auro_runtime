"""
Pipeline package: single internal contract Intake -> Plan -> Execute -> Verify -> Persist.
"""

from auro_runtime.pipeline.contract import (
    IntakeResult,
    IntakeSource,
    PipelinePlugins,
    Plan,
    PlanContext,
    PersistResult,
    RouterOutcome,
    RouterOutcomeKind,
    RuntimeContext,
    VerifyCheck,
    VerifyResult,
)
from auro_runtime.pipeline.plugins import get_default_plugins
from auro_runtime.pipeline.runner import run_pipeline

__all__ = [
    "IntakeResult",
    "IntakeSource",
    "PipelinePlugins",
    "Plan",
    "PlanContext",
    "PersistResult",
    "RouterOutcome",
    "RouterOutcomeKind",
    "RuntimeContext",
    "VerifyCheck",
    "VerifyResult",
    "get_default_plugins",
    "run_pipeline",
]
