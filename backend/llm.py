"""Thin shared LLM helpers. The rest of the code never imports the SDK directly.

The LLM is used for exactly two things: proposing compiled rules (compiler_llm.py) and playing the live
agent (agent.py). It is never used for an allow/deny/escalate decision.

Provider: Groq (free tier), reached over its OpenAI-compatible /chat/completions endpoint. agent.py and
compiler_llm.py are written against the Anthropic Messages API shape (client.messages.create(...), content
blocks, stop_reason, tools[].input_schema). Rather than rewrite those two files, _GroqMessages below is an
adapter that exposes that exact same .messages.create(...) call signature and translates it to/from Groq's
chat-completions format underneath. Nothing outside this file needs to know the provider changed.
"""
import json
import os
import re
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

MODEL = os.getenv("CRYPTIX_LLM_MODEL", "openai/gpt-oss-120b")
COMPILE_TIMEOUT_S = 10.0
AGENT_TIMEOUT_S = 20.0


def configured() -> bool:
    return bool(os.getenv("GROQ_API_KEY")) and os.getenv("CRYPTIX_DISABLE_LLM", "") != "1"


class _GroqMessages:
    """Adapter: same call shape as anthropic.Anthropic().messages, backed by Groq's chat.completions."""

    def __init__(self, groq_client: Any) -> None:
        self._client = groq_client

    @staticmethod
    def _tools_to_openai(tools: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        if not tools:
            return None
        return [
            {"type": "function", "function": {
                "name": t["name"], "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            }}
            for t in tools
        ]

    @staticmethod
    def _messages_to_openai(system: Optional[str], messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if system:
            out.append({"role": "system", "content": system})
        for m in messages:
            role, content = m["role"], m["content"]
            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue
            # content is a list of Anthropic-style blocks (assistant tool_use, or user tool_result)
            text_parts = [b["text"] for b in content if b.get("type") == "text"]
            tool_use_blocks = [b for b in content if b.get("type") == "tool_use"]
            tool_result_blocks = [b for b in content if b.get("type") == "tool_result"]
            if tool_use_blocks:
                out.append({
                    "role": "assistant",
                    "content": "\n".join(text_parts) or None,
                    "tool_calls": [
                        {"id": b["id"], "type": "function",
                         "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                        for b in tool_use_blocks
                    ],
                })
            for b in tool_result_blocks:
                c = b.get("content", "")
                if b.get("is_error"):
                    c = f"ERROR: {c}"
                out.append({"role": "tool", "tool_call_id": b["tool_use_id"], "content": c})
            if not tool_use_blocks and not tool_result_blocks and text_parts:
                out.append({"role": role, "content": "\n".join(text_parts)})
        return out

    def create(self, model: str, max_tokens: int, temperature: float = 0, timeout: Optional[float] = None,
               system: Optional[str] = None, tools: Optional[List[Dict[str, Any]]] = None,
               messages: Optional[List[Dict[str, Any]]] = None) -> Any:
        oa_messages = self._messages_to_openai(system, messages or [])
        oa_tools = self._tools_to_openai(tools)
        kwargs: Dict[str, Any] = dict(
            model=model, messages=oa_messages, max_tokens=max_tokens, temperature=temperature,
        )
        if timeout is not None:
            kwargs["timeout"] = timeout
        if "gpt-oss" in model:
            # Reasoning model: without this it can spend the whole max_tokens budget on
            # internal chain-of-thought and return empty visible content.
            kwargs["reasoning_effort"] = "low"
        if oa_tools:
            kwargs["tools"] = oa_tools
            kwargs["tool_choice"] = "auto"
        resp = self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg = choice.message
        content: List[Any] = []
        if msg.content:
            content.append(SimpleNamespace(type="text", text=msg.content))
        for tc in (msg.tool_calls or []):
            try:
                parsed_input = json.loads(tc.function.arguments or "{}")
            except (json.JSONDecodeError, TypeError):
                parsed_input = {}
            content.append(SimpleNamespace(type="tool_use", id=tc.id, name=tc.function.name, input=parsed_input))
        stop_reason = "tool_use" if (msg.tool_calls) else "end_turn"
        return SimpleNamespace(content=content, stop_reason=stop_reason)


def get_client() -> Any:
    import groq  # imported lazily so the app runs without the SDK installed

    raw = groq.Groq(api_key=os.getenv("GROQ_API_KEY"), timeout=COMPILE_TIMEOUT_S, max_retries=0)
    return SimpleNamespace(messages=_GroqMessages(raw))


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
            model=MODEL, max_tokens=200, temperature=0, timeout=COMPILE_TIMEOUT_S,
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
