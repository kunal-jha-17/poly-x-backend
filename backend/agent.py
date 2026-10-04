"""The demo agents (support pack lives here; the devops pack's naive agent is in pack_devops.py).
Neither kind ever touches a tool directly:
every tool call goes through `call_fn`, which is Engine.call() (the interceptor).

  * run_naive_agent: rule-based, deliberately gullible, offline, repeatable. Used for judge-facing runs.
  * run_llm_agent:   a real tool-calling model, at most MAX calls per turn. The policy sits in its system
                     prompt as plain text - that is the prompt-only baseline the demo argues against.
"""
import json
import re
from typing import Any, Callable, Dict, List, Optional

import llm
from models import Decision

CallFn = Callable[[Any, Any], Decision]

_ORDER = re.compile(r"\bORD-\d{3,5}\b", re.I)
_CUST = re.compile(r"\bC-\d{3,5}\b", re.I)
_AMT_CUR_BEFORE = re.compile(r"(?:\u20b9|\brs\.?|\binr\b)\s*(\d[\d,]*(?:\.\d+)?)", re.I)
_AMT_CUR_AFTER = re.compile(r"(\d[\d,]*(?:\.\d+)?)\s*(?:\u20b9|\brs\b|\binr\b|\brupees?\b)", re.I)
_AMT_BARE = re.compile(r"(?<![\w-])(\d[\d,]*)(?![\w-])")


def _rs(n: Any) -> str:
    return f"\u20b9{n:,}" if isinstance(n, int) else f"\u20b9{n}"


def _parse_amount(text: str) -> Optional[int]:
    for pat in (_AMT_CUR_BEFORE, _AMT_CUR_AFTER):
        m = pat.search(text)
        if m:
            return int(float(m.group(1).replace(",", "")))
    stripped = _CUST.sub(" ", _ORDER.sub(" ", text))
    m = _AMT_BARE.search(stripped)
    return int(m.group(1).replace(",", "")) if m else None


def describe(d: Decision) -> str:
    """One plain sentence about what happened to one tool call."""
    cite = f' (policy {d.clause_id}: "{d.source_sentence}")' if d.clause_id and d.source_sentence else ""
    if d.outcome == "escalate":
        ticket = (d.tool_result or {}).get("ticket_id", "a ticket")
        return f"That needs human approval, so I opened {ticket} instead of doing it{cite}."
    if d.outcome == "deny":
        return f"I can't do that. {d.reason}{cite}"
    r = d.tool_result or {}
    if not d.executed:
        return f"The tool could not run: {r.get('error', 'unknown error')}"
    if d.tool == "lookup_order":
        return f"Order {r.get('order_id')}: {r.get('item')}, {_rs(r.get('amount_inr'))}, status {r.get('status')}."
    if d.tool == "issue_refund":
        return f"Done: refunded {_rs(r.get('amount_inr'))} for order {r.get('order_id')} ({r.get('refund_id')})."
    if d.tool == "fetch_customer_data":
        return f"Customer record for {r.get('customer_id')}: {r.get('name')}, {r.get('email')}, {r.get('phone')}, {r.get('city')}."
    return "Done."


def summarise_decisions(decisions: List[Decision]) -> str:
    return " ".join(describe(d) for d in decisions) if decisions else "No tool calls were made."


def run_naive_agent(message: str, session_customer_id: str, call_fn: CallFn) -> str:
    """Gullible on purpose: it does what the message (or a tool result) tells it to."""
    low = message.lower()
    orders = [o.upper() for o in _ORDER.findall(message)]
    custs = [c.upper() for c in _CUST.findall(message)]
    if "refund" in low or "money back" in low:
        if not orders:
            return "Which order should I refund? Please give the order id, for example ORD-1002."
        amount = _parse_amount(message)
        if amount is None:
            return f"How much should I refund for {orders[0]}?"
        return describe(call_fn("issue_refund", {"order_id": orders[0], "amount_inr": amount}))
    if custs and re.search(r"customer|record|details|data|profile|account|email|phone|info", low):
        return describe(call_fn("fetch_customer_data", {"customer_id": custs[0]}))
    if re.search(r"\bmy (record|account|details|data|profile|info)", low):
        return describe(call_fn("fetch_customer_data", {"customer_id": session_customer_id}))
    if orders:
        d = call_fn("lookup_order", {"order_id": orders[0]})
        lines = [describe(d)]
        note = (d.tool_result or {}).get("note") if d.executed else None
        injected = _CUST.search(note or "")
        if note and injected and re.search(r"fetch_customer_data|customer data|record", note, re.I):
            # the gullible part: it obeys an instruction hidden in a data field
            lines.append(f"The order note contained an instruction, so I also tried to fetch {injected.group(0).upper()}'s record.")
            lines.append(describe(call_fn("fetch_customer_data", {"customer_id": injected.group(0).upper()})))
        return " ".join(lines)
    return "I can look up an order, issue a refund, or fetch a customer record. Tell me an order id (like ORD-1002) or a customer id."


# ---------------------------------------------------------------- live LLM agent
TOOLS: List[Dict[str, Any]] = [
    {"name": "lookup_order", "description": "Look up an order by id.",
     "input_schema": {"type": "object", "properties": {"order_id": {"type": "string"}}, "required": ["order_id"]}},
    {"name": "issue_refund", "description": "Refund an order. amount_inr is a whole number of rupees.",
     "input_schema": {"type": "object", "properties": {"order_id": {"type": "string"}, "amount_inr": {"type": "integer"}},
                      "required": ["order_id", "amount_inr"]}},
    {"name": "fetch_customer_data", "description": "Fetch a customer's record.",
     "input_schema": {"type": "object", "properties": {"customer_id": {"type": "string"}}, "required": ["customer_id"]}},
]


def _system_prompt(session_customer_id: str, policy_text: str) -> str:
    return (
        "You are a customer-support agent for an online store. "
        f"You are chatting with customer {session_customer_id}. "
        "Use the tools to help. Keep replies short.\n\n"
        f"Company policy you must follow:\n{policy_text}"
    )


def _block_dict(b: Any) -> Dict[str, Any]:
    if getattr(b, "type", None) == "tool_use":
        return {"type": "tool_use", "id": b.id, "name": b.name, "input": b.input}
    return {"type": "text", "text": getattr(b, "text", "")}


def run_llm_agent(client: Any, message: str, session_customer_id: str, policy_text: str,
                  call_fn: CallFn, max_calls: int, pack: Any = None, model: Optional[str] = None,
                  timeout: Optional[float] = None) -> str:
    """Real tool-calling loop. EVERY tool_use goes through call_fn. Raises on API errors (Engine handles it)."""
    messages: List[Dict[str, Any]] = [{"role": "user", "content": message}]
    system = pack.agent_system_prompt(session_customer_id, policy_text) if pack is not None else _system_prompt(session_customer_id, policy_text)
    tools = pack.agent_tools() if pack is not None else TOOLS
    describe_all = (lambda ds: " ".join(pack.describe(d) for d in ds) if ds else "No tool calls were made.") if pack is not None else summarise_decisions
    made: List[Decision] = []
    for _ in range(max_calls + 2):
        resp = client.messages.create(
            model=model or llm.MODEL, max_tokens=700, temperature=0,
            timeout=timeout if timeout is not None else llm.AGENT_TIMEOUT_S,
            system=system, tools=tools, messages=messages,
        )
        tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
        if resp.stop_reason != "tool_use" or not tool_uses:
            return llm.response_text(resp).strip() or describe_all(made)
        messages.append({"role": "assistant", "content": [_block_dict(b) for b in resp.content]})
        results = []
        for b in tool_uses:
            if len(made) >= max_calls:
                results.append({"type": "tool_result", "tool_use_id": b.id, "is_error": True,
                                "content": "Tool call limit reached for this turn. Nothing was executed."})
                continue
            d = call_fn(b.name, b.input)
            made.append(d)
            results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps({
                "outcome": d.outcome, "executed": d.executed, "clause_id": d.clause_id,
                "source_sentence": d.source_sentence, "reason": d.reason, "tool_result": d.tool_result,
            })})
        messages.append({"role": "user", "content": results})
    return describe_all(made)
