"""Thin shared LLM helpers. The rest of the code never imports the SDK directly.

The LLM is used for exactly two things: proposing compiled rules (compiler_llm.py) and playing the live
agent (agent.py). It is never used for an allow/deny/escalate decision.
"""
import json
import os
import re
from typing import Any, Dict, Optional

MODEL = os.getenv("CRYPTIX_LLM_MODEL", "claude-haiku-4-5-20251001")
COMPILE_TIMEOUT_S = 10.0
AGENT_TIMEOUT_S = 20.0


def configured() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY")) and os.getenv("CRYPTIX_DISABLE_LLM", "") != "1"


def get_client() -> Any:
    import anthropic  # imported lazily so the app runs without the SDK installed

    return anthropic.Anthropic(timeout=COMPILE_TIMEOUT_S, max_retries=0)


def response_text(resp: Any) -> str:
    return "".join(getattr(b, "text", "") for b in getattr(resp, "content", []) if getattr(b, "type", None) == "text")


def extract_json(text: str) -> Dict[str, Any]:
    """Parse a JSON object out of model text, tolerating stray fences or prose around it."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in model output")
    data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("model output JSON is not an object")
    return data


def self_test(client: Any) -> bool:
    """Startup check. engine.llm_available becomes True only if this returns True."""
    try:
        resp = client.messages.create(
            model=MODEL, max_tokens=40, temperature=0, timeout=COMPILE_TIMEOUT_S,
            system="Reply with JSON only. No prose, no code fences.",
            messages=[{"role": "user", "content": 'Return exactly this JSON: {"ok": true}'}],
        )
        return extract_json(response_text(resp)).get("ok") is True
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


def init_client() -> Optional[Any]:
    """Return a verified client, or None (no key, disabled, SDK missing, or self-test failed)."""
    if not configured():
        return None
    try:
        client = get_client()
    except Exception:  # noqa: BLE001
        return None
    return client if self_test(client) else None
