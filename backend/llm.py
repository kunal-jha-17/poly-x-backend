"""Model providers. The rest of the code never talks HTTP to a model directly.

A model is used for exactly three things: proposing compiled rules (compiler_llm.py), playing the live agent
(agent.py) and proposing new attack cases (attackgen.py). It is NEVER used for an allow / deny / escalate decision.

Every provider is an OpenAI-compatible /chat/completions endpoint, so cloud, local and "bring your own" are
interchangeable with no code change:

  local  LOCAL_LLM_BASE_URL + LOCAL_LLM_MODEL   e.g. Ollama (http://localhost:11434/v1), llama.cpp server, LM Studio
  cloud  LLM_BASE_URL + LLM_API_KEY + LLM_MODEL  default: Groq serving the open-weight openai/gpt-oss-120b
  rules  no model at all: the deterministic rule parser in compiler.py (always available, always last)

agent.py and compiler_llm.py are written against a small "messages.create(...)" call shape (system, messages,
tools with input_schema, content blocks, stop_reason). OpenAICompatClient exposes that shape and translates it
to and from chat-completions, so those files do not care which provider is behind it.
"""
import json
import os
import re
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v:
            return v.strip()
    return default


GROQ_BASE_URL = "https://api.groq.com/openai/v1"
MODEL = _env("LLM_MODEL", "POLYX_LLM_MODEL", "CRYPTIX_LLM_MODEL", default="openai/gpt-oss-120b")
COMPILE_TIMEOUT_S = 10.0
AGENT_TIMEOUT_S = 20.0
LOCAL_DEFAULT_MODEL = "qwen2.5:3b"
PROVIDER_ORDER_DEFAULT = "local,cloud"


def disabled() -> bool:
    return _env("POLYX_DISABLE_LLM", "CRYPTIX_DISABLE_LLM") == "1"


def configured() -> bool:
    """True when a cloud key exists and models are not disabled (v1.0.0 meaning)."""
    return bool(_env("LLM_API_KEY", "GROQ_API_KEY")) and not disabled()


class LLMHTTPError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


class OpenAICompatClient:
    """`client.messages.create(...)` in front of any OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, base_url: str, api_key: Optional[str] = None, default_timeout: float = COMPILE_TIMEOUT_S) -> None:
        import httpx  # imported lazily: the deterministic engine runs without it

        self.base_url = base_url.rstrip("/")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.Client(headers=headers, timeout=default_timeout)
        self.messages = self  # so callers can write client.messages.create(...)
        self._json_mode_ok = True

    # ---- translation helpers
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

    def _post(self, payload: Dict[str, Any], timeout: Optional[float]) -> Dict[str, Any]:
        resp = self._http.post(f"{self.base_url}/chat/completions", json=payload, timeout=timeout)
        if resp.status_code >= 400:
            raise LLMHTTPError(resp.status_code, resp.text)
        return resp.json()

    def create(self, model: str, max_tokens: int, temperature: float = 0, timeout: Optional[float] = None,
               system: Optional[str] = None, tools: Optional[List[Dict[str, Any]]] = None,
               messages: Optional[List[Dict[str, Any]]] = None, json_mode: bool = False) -> Any:
        payload: Dict[str, Any] = {
            "model": model, "messages": self._messages_to_openai(system, messages or []),
            "max_tokens": max_tokens, "temperature": temperature,
        }
        if "gpt-oss" in model:
            # Reasoning model: without this it can spend the whole max_tokens budget on hidden reasoning.
            payload["reasoning_effort"] = "low"
        oa_tools = self._tools_to_openai(tools)
        if oa_tools:
            payload["tools"] = oa_tools
            payload["tool_choice"] = "auto"
        use_json = json_mode and self._json_mode_ok and not oa_tools
        if use_json:
            payload["response_format"] = {"type": "json_object"}
        try:
            data = self._post(payload, timeout)
        except LLMHTTPError as exc:
            if not (use_json and exc.status == 400):
                raise
            # this server or model rejects response_format: remember that and ask again in plain mode
            self._json_mode_ok = False
            payload.pop("response_format", None)
            data = self._post(payload, timeout)
        msg = (data.get("choices") or [{}])[0].get("message") or {}
        content: List[Any] = []
        if msg.get("content"):
            content.append(SimpleNamespace(type="text", text=msg["content"]))
        tool_calls = msg.get("tool_calls") or []
        for i, tc in enumerate(tool_calls):
            fn = tc.get("function") or {}
            raw = fn.get("arguments") or "{}"
            try:
                parsed = raw if isinstance(raw, dict) else json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            content.append(SimpleNamespace(type="tool_use", id=tc.get("id") or f"call_{i}", name=fn.get("name", ""), input=parsed))
        return SimpleNamespace(content=content, stop_reason="tool_use" if tool_calls else "end_turn")

    def list_models(self, timeout: float = 5.0) -> List[str]:
        resp = self._http.get(f"{self.base_url}/models", timeout=timeout)
        if resp.status_code >= 400:
            raise LLMHTTPError(resp.status_code, resp.text)
        return [m.get("id", "") for m in (resp.json().get("data") or [])]


@dataclass
class Provider:
    name: str  # "local" | "cloud"
    label: str
    location: str  # "local" | "cloud"
    base_url: str
    model: str
    api_key: Optional[str] = None
    compile_timeout_s: float = COMPILE_TIMEOUT_S
    agent_timeout_s: float = AGENT_TIMEOUT_S
    client: Any = None
    available: bool = False
    last_checked: Optional[float] = None  # epoch seconds
    last_error: Optional[str] = None
    latency_ms: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> Optional[str]:
        try:
            return urlparse(self.base_url).hostname
        except ValueError:
            return None


def make_provider(name: str, base_url: str, model: str, api_key: Optional[str] = None, label: Optional[str] = None,
                  compile_timeout_s: Optional[float] = None, agent_timeout_s: Optional[float] = None) -> Provider:
    local = name == "local"
    return Provider(
        name=name, label=label or ("Local open-source model" if local else "Cloud open-weight model"),
        location="local" if local else "cloud", base_url=base_url.rstrip("/"), model=model, api_key=api_key or None,
        compile_timeout_s=compile_timeout_s or (60.0 if local else COMPILE_TIMEOUT_S),
        agent_timeout_s=agent_timeout_s or (90.0 if local else AGENT_TIMEOUT_S),
    )


def _float_env(name: str) -> Optional[float]:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return None


def providers_from_env() -> List[Provider]:
    """Read the environment. Returns the configured providers (unverified). Empty when models are disabled."""
    if disabled():
        return []
    out: List[Provider] = []
    local_url = _env("LOCAL_LLM_BASE_URL")
    if local_url:
        out.append(make_provider(
            "local", local_url, _env("LOCAL_LLM_MODEL", default=LOCAL_DEFAULT_MODEL), _env("LOCAL_LLM_API_KEY") or None,
            _env("LOCAL_LLM_LABEL") or None, _float_env("LOCAL_LLM_TIMEOUT_S"), _float_env("LOCAL_LLM_AGENT_TIMEOUT_S"),
        ))
    key = _env("LLM_API_KEY", "GROQ_API_KEY")
    if key:
        out.append(make_provider(
            "cloud", _env("LLM_BASE_URL", default=GROQ_BASE_URL), MODEL, key, _env("LLM_LABEL") or None,
            _float_env("LLM_TIMEOUT_S"), _float_env("LLM_AGENT_TIMEOUT_S"),
        ))
    return out


def provider_order() -> List[str]:
    raw = _env("LLM_PROVIDER_ORDER", default=PROVIDER_ORDER_DEFAULT)
    order = [p.strip() for p in raw.split(",") if p.strip() in ("local", "cloud")]
    return order + [p for p in ("local", "cloud") if p not in order]


def response_text(resp: Any) -> str:
    return "".join(getattr(b, "text", "") for b in getattr(resp, "content", []) if getattr(b, "type", None) == "text")


def extract_json(text: str) -> Dict[str, Any]:
    """Parse a JSON object out of model text, tolerating reasoning tags, stray fences or prose around it."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in model output")
    data = json.loads(text[start: end + 1])
    if not isinstance(data, dict):
        raise ValueError("model output JSON is not an object")
    return data


def self_test(client: Any, model: Optional[str] = None, timeout: Optional[float] = None) -> bool:
    """A provider counts as available only if this returns True."""
    try:
        resp = client.messages.create(
            model=model or MODEL, max_tokens=200, temperature=0, timeout=timeout or COMPILE_TIMEOUT_S,
            system="Reply with JSON only. No prose, no code fences.",
            messages=[{"role": "user", "content": 'Return exactly this JSON: {"ok": true}'}],
        )
        return extract_json(response_text(resp)).get("ok") is True
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


def probe(provider: Provider) -> Provider:
    """Build the client and run the self-test. Fills available / last_error / latency_ms. Never raises."""
    provider.last_checked = time.time()
    provider.available = False
    provider.latency_ms = None
    try:
        if provider.client is None:
            provider.client = OpenAICompatClient(provider.base_url, provider.api_key, provider.compile_timeout_s)
        t0 = time.perf_counter()
        resp = provider.client.messages.create(
            model=provider.model, max_tokens=200, temperature=0,
            timeout=min(provider.compile_timeout_s, 30.0),
            system="Reply with JSON only. No prose, no code fences.",
            messages=[{"role": "user", "content": 'Return exactly this JSON: {"ok": true}'}],
        )
        ok = extract_json(response_text(resp)).get("ok") is True
        provider.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        provider.available = ok
        provider.last_error = None if ok else "The model answered, but not with the JSON it was asked for."
    except Exception as exc:  # noqa: BLE001
        provider.last_error = _explain(provider, exc)
    return provider


def _explain(provider: Provider, exc: Exception) -> str:
    name = type(exc).__name__
    if isinstance(exc, LLMHTTPError):
        if exc.status in (401, 403):
            return "The model server rejected the API key."
        if exc.status == 404:
            hint = ""
            try:
                names = [n for n in provider.client.list_models() if n][:8]
                if names:
                    hint = f" Models on that server: {', '.join(names)}."
            except Exception:  # noqa: BLE001
                pass
            return f"Model '{provider.model}' was not found on the server.{hint}"
        if exc.status == 429:
            return "The model server is rate-limiting requests."
        return f"The model server answered HTTP {exc.status}."
    if "Timeout" in name:
        return "The model server did not answer in time."
    if "Connect" in name:
        return "Could not connect to the model server. Is it running and reachable from this host?"
    return f"{name}: {str(exc)[:160]}"


# ---------------------------------------------------------------- v1.0.0 helpers (kept for callers that used them)
def get_client() -> Any:
    return OpenAICompatClient(_env("LLM_BASE_URL", default=GROQ_BASE_URL), _env("LLM_API_KEY", "GROQ_API_KEY"), COMPILE_TIMEOUT_S)


def init_client() -> Optional[Any]:
    """Return a verified cloud client, or None (no key, disabled, or self-test failed)."""
    if not configured():
        return None
    try:
        client = get_client()
    except Exception:  # noqa: BLE001
        return None
    return client if self_test(client) else None
