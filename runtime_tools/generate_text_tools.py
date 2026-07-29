"""
General-purpose LLM text generation tool. Lets any directive call the
configured model backend for summarization, extraction, formatting,
classification, etc.

Per-run call cap: _TOTAL_CAP calls total, across all models and backends.
Models whose id contains a substring listed in env AURO_HIGH_COST_MODELS
(comma-separated; default empty -> no confirmation gate) require a one-time
confirmation before the call with that model+prompt proceeds.
"""

import os

from auro_runtime.executor import register
from auro_runtime.models import generate, get_call_count, increment_call_count
from auro_runtime.tool_schemas import GenerateTextArgs

_HITL_CONFIRMED: dict[str, bool] = {}

_TOTAL_CAP = 10


def _high_cost_substrings() -> list[str]:
    raw = os.environ.get("AURO_HIGH_COST_MODELS", "")
    return [s.strip() for s in raw.split(",") if s.strip()]


def _is_high_cost(model: str) -> bool:
    return any(substr in model for substr in _high_cost_substrings())


@register(
    "generate_text",
    "Call the configured model backend with a prompt and optional input text. Returns generated text. "
    "Use for summarization, extraction, formatting, classification, etc. "
    f"Per-run limit: {_TOTAL_CAP} calls total. "
    "Models listed in AURO_HIGH_COST_MODELS also require confirmation — first call returns a prompt, second call proceeds.",
    args_schema=GenerateTextArgs,
)
def generate_text(
    prompt: str,
    input_text: str = "",
    model: str | None = None,
) -> dict:
    """
    Single-shot model call. The prompt is the system instruction; input_text is
    the user content to process. Returns the generated text or an error.
    """
    total_used = get_call_count()
    if total_used >= _TOTAL_CAP:
        return {
            "error": f"Total per-run limit reached ({_TOTAL_CAP} calls across all models). "
                     f"Split work across separate runs.",
            "total_used": total_used,
            "total_limit": _TOTAL_CAP,
        }

    if model and _is_high_cost(model):
        confirm_key = f"{model}:{hash(prompt)}"
        if confirm_key not in _HITL_CONFIRMED:
            _HITL_CONFIRMED[confirm_key] = True
            return {
                "requires_confirmation": True,
                "model": model,
                "message": f"High-cost model ({model}) requested. This is a high-cost call. "
                           f"Call generate_text again with the same prompt to confirm and proceed.",
            }
        del _HITL_CONFIRMED[confirm_key]

    user_message = input_text.strip() if input_text.strip() else "(no input provided)"
    try:
        result = generate(
            system_prompt=prompt,
            user_message=user_message,
            model=model,
        )
        total_used = increment_call_count()
        return {
            "text": result,
            "model": model,
            "length": len(result),
            "total_used": total_used,
            "total_remaining": _TOTAL_CAP - total_used,
        }
    except Exception as e:
        return {"error": str(e)}
