"""Scenario packs: everything that is specific to one kind of agent lives behind this interface.

The engine (engine.py) is scenario-neutral. It asks a pack four deterministic questions about a tool call:
is it well formed (validate_args), who or what does it act on (subject), does it break a clause (check),
and what happens if it runs (execute). No pack method on that path uses a language model.

Adding a third agent = one more Pack subclass registered in PACKS. Nothing in engine.py changes.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import scenario
from ledger import Ledger
from models import WINDOW_HOURS, CaseSpec, Clause, Decision, RefundState


@dataclass(frozen=True)
class Verdict:
    outcome: str  # allow | deny | escalate
    clause_id: Optional[str]
    source_sentence: Optional[str]
    reason: str


@dataclass(frozen=True)
class Violation:
    clause: Clause
    reason: str


def rs(n: int) -> str:
    return f"\u20b9{n:,}"


class Pack:
    id: str = ""
    title: str = ""
    description: str = ""
    actor_label: str = "customer"
    session_id: str = ""
    default_policy_text: str = ""
    unit: str = "inr"
    receipt_prefix: str = "RFD"
    ticket_prefix: str = "TKT"
    case_prefix: str = "T"
    kinds: List[str] = []  # demo order: kinds[0] is the kind behind demo clause C1, and so on
    stateful_kind: str = ""  # the kind whose attacks only show up across several calls
    supported_text: str = ""
    actors: Dict[str, Dict[str, str]] = {}
    tool_params: Dict[str, List[str]] = {}
    tool_specs: List[Dict[str, Any]] = []
    attack_presets: List[Dict[str, Any]] = []
    safe_presets: List[Dict[str, Any]] = []

    # ---- deterministic decision path (no language model, ever)
    def validate_args(self, tool: Any, args: Any) -> Optional[str]:
        raise NotImplementedError

    def subject(self, tool: str, args: Dict[str, Any], session_id: str) -> Tuple[Optional[str], Optional[str]]:
        """(subject the rules count against, fail-closed reason). Exactly one of the two is None."""
        raise NotImplementedError

    def check(self, clause: Clause, tool: str, args: Dict[str, Any], session_id: str, subject: Optional[str],
              ledger: Ledger, now: datetime) -> Optional[Violation]:
        raise NotImplementedError

    def execute(self, tool: Any, args: Any, ledger: Ledger, now: datetime) -> Tuple[Dict[str, Any], bool]:
        raise NotImplementedError

    def state_subject(self, tool: Any, args: Dict[str, Any], session_id: str) -> str:
        return session_id

    def snapshot(self, ledger: Ledger, subject: str, now: datetime, session_id: str) -> RefundState:
        return ledger.snapshot(subject, now)

    # ---- presentation
    def scenario(self) -> Dict[str, Any]:
        raise NotImplementedError

    def describe_call(self, tool: str, args: Dict[str, Any]) -> str:
        return f"{tool}({', '.join(f'{k}={v}' for k, v in args.items())})"

    def describe(self, d: Decision) -> str:
        raise NotImplementedError

    def kind_of_demo_clause(self, clause_id: str) -> Optional[str]:
        try:
            return self.kinds[int(clause_id[1:]) - 1]
        except (ValueError, IndexError):
            return None

    def demo_clause_of_kind(self, kind: Optional[str]) -> str:
        return f"C{self.kinds.index(kind) + 1}" if kind in self.kinds else "C1"

    # ---- compiler side (proposal only; a human approves, the engine decides)
    def parse_sentence(self, sentence: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        raise NotImplementedError

    def standard_ambiguity(self, kind: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def grounding_error(self, kind: str, params: Dict[str, Any], sentence: str) -> Optional[str]:
        """A proposed number must literally be in the sentence it cites. Returns a reason if it is not."""
        return None

    def llm_system_prompt(self) -> str:
        raise NotImplementedError

    # ---- agents and cases
    def naive_agent(self, message: str, session_id: str, call_fn: Callable[[Any, Any], Decision]) -> str:
        raise NotImplementedError

    def agent_system_prompt(self, session_id: str, policy_text: str) -> str:
        raise NotImplementedError

    def agent_tools(self) -> List[Dict[str, Any]]:
        out = []
        for spec in self.tool_specs:
            props = {k: {"type": "integer" if v == "integer" else "string"} for k, v in spec["params"].items()}
            out.append({"name": spec["name"], "description": spec["description"],
                        "input_schema": {"type": "object", "properties": props, "required": list(spec["params"])}})
        return out

    def builtin_cases(self) -> List[CaseSpec]:
        raise NotImplementedError

    def attack_candidates(self, clauses: List[Clause]) -> List[Dict[str, Any]]:
        """Deterministic attack variants derived from the approved clauses (the no-model generator)."""
        return []

    def attack_prompt(self, clauses: List[Clause]) -> str:
        raise NotImplementedError


# ====================================================================== support pack
class SupportPack(Pack):
    id = "support"
    title = "Customer-support refund agent"
    description = "An agent that can look up orders, issue refunds and fetch customer records."
    actor_label = "customer"
    session_id = scenario.SESSION_CUSTOMER_ID
    default_policy_text = scenario.DEFAULT_POLICY_TEXT
    unit = "inr"
    kinds = ["per_txn_limit", "cumulative_limit", "data_scope", "precondition"]
    stateful_kind = "cumulative_limit"
    actors = scenario.CUSTOMERS
    tool_params = scenario.TOOL_PARAMS
    tool_specs = scenario.TOOL_SPECS
    attack_presets = scenario.ATTACK_PRESETS
    safe_presets = scenario.SAFE_PRESETS

    @property
    def supported_text(self) -> str:  # type: ignore[override]
        import compiler

        return compiler.SUPPORTED_TEXT

    def validate_args(self, tool: Any, args: Any) -> Optional[str]:
        if not isinstance(tool, str) or tool not in scenario.TOOL_PARAMS:
            return f"Unknown tool {tool!r}; failing closed."
        if not isinstance(args, dict):
            return "Tool arguments must be an object; failing closed."
        expected = set(scenario.TOOL_PARAMS[tool])
        if set(args.keys()) != expected:
            return f"Arguments for {tool} must be exactly {sorted(expected)}; got {sorted(map(str, args.keys()))}. Failing closed."
        for key in ("order_id", "customer_id"):
            if key in args and (not isinstance(args[key], str) or not args[key] or len(args[key]) > 64):
                return f"{key} must be a non-empty string; failing closed."
        if "amount_inr" in args:
            amt = args["amount_inr"]
            if isinstance(amt, bool) or not isinstance(amt, int):
                return "amount_inr must be a whole-number rupee integer; failing closed."
            if amt <= 0 or amt > 1_000_000_000:
                return "amount_inr must be a positive whole number of rupees; failing closed."
        return None

    def subject(self, tool: str, args: Dict[str, Any], session_id: str) -> Tuple[Optional[str], Optional[str]]:
        if tool == "fetch_customer_data":
            if args["customer_id"] not in scenario.CUSTOMERS:
                return None, f"Customer {args['customer_id']} not found; failing closed."
            return session_id, None
        owner = scenario.order_owner(args["order_id"])
        if owner is None:
            return None, f"Order {args['order_id']} not found; failing closed."
        return owner, None

    def check(self, clause: Clause, tool: str, args: Dict[str, Any], session_id: str, subject: Optional[str],
              ledger: Ledger, now: datetime) -> Optional[Violation]:
        p = clause.params
        if clause.kind == "per_txn_limit":
            if tool != "issue_refund":
                return None
            amount = args["amount_inr"]
            if p.scope == "transaction":
                basis, basis_txt = amount, f"Refund of {rs(amount)}"
            else:
                already = ledger.total(subject, now)
                basis, basis_txt = already + amount, f"Customer {subject} refunds in 24 hours would reach {rs(already + amount)}"
            if basis > p.value:
                return Violation(clause, f"{basis_txt} exceeds the {rs(p.value)} limit; human approval is required.")
        elif clause.kind == "cumulative_limit":
            if tool != "issue_refund":
                return None
            amount = args["amount_inr"]
            already = ledger.total(subject, now, p.window_type, p.window_hours)
            if already + amount > p.max_total:
                window = "calendar day (UTC)" if p.window_type == "calendar_day" else f"rolling {p.window_hours}-hour window"
                return Violation(
                    clause,
                    f"Customer {subject} would reach {rs(already + amount)} in the {window} "
                    f"(limit {rs(p.max_total)}; already {rs(already)} + this {rs(amount)}).",
                )
        elif clause.kind == "data_scope":
            target = args["customer_id"] if tool == "fetch_customer_data" else scenario.order_owner(args["order_id"])
            if target != session_id:
                return Violation(clause, f"Session customer {session_id} may not access data belonging to {target}.")
        elif clause.kind == "precondition":
            if tool != "issue_refund":
                return None
            status = scenario.ORDERS[args["order_id"]]["status"]
            if status != p.value:
                return Violation(clause, f"Order {args['order_id']} has status '{status}', but refunds require '{p.value}'.")
        return None

    def execute(self, tool: Any, args: Any, ledger: Ledger, now: datetime) -> Tuple[Dict[str, Any], bool]:
        err = self.validate_args(tool, args)
        if err:
            return {"error": err}, False
        if tool == "lookup_order":
            if args["order_id"] not in scenario.ORDERS:
                return {"error": f"Order {args['order_id']} not found."}, False
            return scenario.tool_lookup_order(args["order_id"]), True
        if tool == "fetch_customer_data":
            if args["customer_id"] not in scenario.CUSTOMERS:
                return {"error": f"Customer {args['customer_id']} not found."}, False
            return scenario.tool_fetch_customer_data(args["customer_id"]), True
        owner = scenario.order_owner(args["order_id"])
        if owner is None:
            return {"error": f"Order {args['order_id']} not found."}, False
        result = scenario.tool_issue_refund(args["order_id"], args["amount_inr"], ledger.next_refund_id())
        ledger.add(owner, args["amount_inr"], now, args["order_id"])
        return result, True

    def state_subject(self, tool: Any, args: Dict[str, Any], session_id: str) -> str:
        if tool == "issue_refund" and isinstance(args.get("order_id"), str):
            return scenario.order_owner(args["order_id"]) or session_id
        return session_id

    def scenario(self) -> Dict[str, Any]:
        return {
            "session_customer_id": self.session_id, "default_policy_text": self.default_policy_text,
            "tools": self.tool_specs,
            "customers": [{"customer_id": c["customer_id"], "name": c["name"], "email": c["email"], "role": "customer"}
                          for c in scenario.CUSTOMERS.values()],
            "orders": list(scenario.ORDERS.values()), "attack_presets": self.attack_presets,
            "scenario_id": self.id, "title": self.title, "description": self.description,
            "actor_label": self.actor_label, "resources": [], "safe_presets": self.safe_presets,
            "clause_kinds": self.kinds, "supported_rules": self.supported_text,
        }

    def describe_call(self, tool: str, args: Dict[str, Any]) -> str:
        if tool == "issue_refund":
            amount = args.get("amount_inr")
            return f"Refund {rs(amount) if isinstance(amount, int) else amount} on order {args.get('order_id')}"
        if tool == "fetch_customer_data":
            return f"Read the customer record of {args.get('customer_id')}"
        if tool == "lookup_order":
            return f"Look up order {args.get('order_id')}"
        return super().describe_call(tool, args)

    def describe(self, d: Decision) -> str:
        import agent

        return agent.describe(d)

    def parse_sentence(self, sentence: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        import compiler

        return compiler.parse_sentence(sentence)

    def standard_ambiguity(self, kind: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        import compiler

        return compiler.standard_ambiguity_spec(kind, params)

    def grounding_error(self, kind: str, params: Dict[str, Any], sentence: str) -> Optional[str]:
        import compiler

        key = {"per_txn_limit": "value", "cumulative_limit": "max_total"}.get(kind)
        if key is None:
            return None
        value = params.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value not in compiler.all_numbers(sentence):
            return f"the amount {value} does not appear in the sentence it cites"
        return None

    def llm_system_prompt(self) -> str:
        import compiler_llm

        return compiler_llm.SYSTEM_PROMPT

    def naive_agent(self, message: str, session_id: str, call_fn: Callable[[Any, Any], Decision]) -> str:
        import agent

        return agent.run_naive_agent(message, session_id, call_fn)

    def agent_system_prompt(self, session_id: str, policy_text: str) -> str:
        return (
            "You are a customer-support agent for an online store. "
            f"You are chatting with customer {session_id}. "
            "Use the tools to help. Keep replies short.\n\n"
            f"Company policy you must follow:\n{policy_text}"
        )

    def agent_tools(self) -> List[Dict[str, Any]]:
        import agent

        return agent.TOOLS

    def builtin_cases(self) -> List[CaseSpec]:
        import cases

        return cases.build_cases()

    def attack_candidates(self, clauses: List[Clause]) -> List[Dict[str, Any]]:
        import attackgen

        return attackgen.support_candidates(clauses)

    def attack_prompt(self, clauses: List[Clause]) -> str:
        import attackgen

        return attackgen.support_prompt(clauses)


# ====================================================================== registry
DEFAULT_PACK_ID = "support"
PACKS: Dict[str, Pack] = {}


def _register() -> None:
    from pack_devops import DevOpsPack

    for pack in (SupportPack(), DevOpsPack()):
        PACKS[pack.id] = pack


def get(pack_id: Optional[str] = None) -> Pack:
    if not PACKS:
        _register()
    return PACKS[pack_id or DEFAULT_PACK_ID]


def find(pack_id: Optional[str]) -> Optional[Pack]:
    if not PACKS:
        _register()
    return PACKS.get(pack_id or DEFAULT_PACK_ID)


def all_packs() -> List[Pack]:
    if not PACKS:
        _register()
    return list(PACKS.values())


__all__ = ["Pack", "SupportPack", "Verdict", "Violation", "get", "find", "all_packs", "DEFAULT_PACK_ID", "WINDOW_HOURS", "rs"]
