"""
General-purpose LLM text generation tool. Lets any directive call the
configured model backend for summarization, extraction, formatting,
classification, etc.

Per-run call cap: _TOTAL_CAP calls total, across all models and backends.

Models whose RESOLVED id contains a substring listed in env
AURO_HIGH_COST_MODELS (comma-separated; default empty -> gate inert) require a
repeat call before proceeding. Resolved, not requested: omitting `model` asks
for the backend's configured default, so a check against the argument saw
nothing in precisely the case where the default might be the expensive model.

That repeat is not an authorisation control and must not be relied on as one.
The first call marks the key and returns a prompt; the second identical call
clears it and proceeds. Nothing consults a human, and the calling model
completes both steps by itself. What it buys is a record of intent in the
transcript and a deliberate second step, not a veto.
"""

import os

from auro_runtime.executor import register
from auro_runtime.models import generate, get_call_count, increment_call_count, resolve_model
from auro_runtime.tool_schemas import GenerateTextArgs

# Previously named _HITL_CONFIRMED, which claimed something untrue of it.
# Nothing here reaches a human: the first call marks the key confirmed and
# returns a prompt, and the second identical call clears it and proceeds — a
# sequence the calling model completes by itself, unprompted, in one extra
# step. It is a deliberate-repetition speed bump that leaves the intent in the
# transcript, not an authorisation control, and a reader deciding how much to
# trust it needs the name to say so.
_REPEAT_CONFIRMED: dict[str, bool] = {}

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
    "Models listed in AURO_HIGH_COST_MODELS also require confirmation — first call returns a prompt, second call proceeds. "
    "This applies to the model that will actually run, so omitting `model` does not avoid it.",
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

    # Gate on the model that will actually be called, not the one that was
    # asked for. `model=None` is the ordinary way to request the configured
    # default, and the old check (`if model and _is_high_cost(model)`) saw
    # nothing in exactly that case — the backend then substituted its default
    # immediately afterwards, so omitting the argument selected the expensive
    # model while skipping the check meant to catch it.
    effective_model = resolve_model(model)
    if _is_high_cost(effective_model):
        confirm_key = f"{effective_model}:{hash(prompt)}"
        if confirm_key not in _REPEAT_CONFIRMED:
            _REPEAT_CONFIRMED[confirm_key] = True
            return {
                "requires_confirmation": True,
                "model": effective_model,
                "message": f"High-cost model ({effective_model}) requested. This is a high-cost call. "
                           f"Call generate_text again with the same prompt to confirm and proceed.",
            }
        del _REPEAT_CONFIRMED[confirm_key]

    user_message = input_text.strip() if input_text.strip() else "(no input provided)"
    try:
        result = generate(
            system_prompt=prompt,
            # Send the id the gate just evaluated, not the caller's argument.
            # Passing None again would re-resolve inside the backend, so a
            # change to AURO_MODEL between the two would call a model this
            # function never checked.
            user_message=user_message,
            model=effective_model,
        )
        total_used = increment_call_count()
        return {
            "text": result,
            # The resolved id, not the requested one. Reporting the argument
            # meant a caller relying on the default got "model": null back and
            # could not tell from the result what had actually run.
            "model": effective_model,
            "length": len(result),
            "total_used": total_used,
            "total_remaining": _TOTAL_CAP - total_used,
        }
    except Exception as e:
        return {"error": str(e)}
