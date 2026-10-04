"""POLY-X guard for Python agents. Standard library only: copy this file next to your agent.

    from polyx_guard import PolyX, Blocked, NeedsApproval

    guard = PolyX("https://your-polyx-host", scenario="support")

    @guard.tool("issue_refund")
    def issue_refund(order_id: str, amount_inr: int) -> dict:
        return payments.refund(order_id, amount_inr)      # your real tool

    issue_refund(order_id="ORD-1001", amount_inr=7500)    # raises NeedsApproval(ticket_id="TKT-0001")

The decision is made by POLY-X's deterministic engine, never by a model. If the guard cannot be reached the
call is BLOCKED (fail closed), because an unreachable firewall must not mean "everything is allowed".

By default the call is RECORDED: POLY-X adds it to its ledger, so multi-step limits (a daily total, a deploy
count) see it, and an escalation opens a ticket in the approval inbox. Pass dry_run=True to only ask
"would this be allowed?" - nothing is recorded, counted or held.
"""
import functools
import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional


class Blocked(Exception):
    def __init__(self, verdict: Dict[str, Any]):
        super().__init__(f"blocked by policy {verdict.get('clause_id') or '(fail closed)'}: {verdict.get('reason')}")
        self.verdict = verdict


class NeedsApproval(Blocked):
    def __init__(self, verdict: Dict[str, Any]):
        super().__init__(verdict)
        self.ticket_id = verdict.get("ticket_id")


class PolyX:
    def __init__(self, base_url: str, scenario: str = "support", session_id: Optional[str] = None, timeout: float = 5.0):
        self.url = base_url.rstrip("/") + "/api/v1/guard/check"
        self.scenario, self.session_id, self.timeout = scenario, session_id, timeout

    def check(self, tool: str, args: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        body = {"tool": tool, "args": args, "scenario": self.scenario, "dry_run": dry_run}
        if self.session_id:
            body["session_customer_id"] = self.session_id
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            return {"allowed": False, "outcome": "deny", "clause_id": None, "ticket_id": None,
                    "reason": f"Policy guard unreachable ({type(exc).__name__}); failing closed."}

    def enforce(self, tool: str, args: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        verdict = self.check(tool, args, dry_run)
        if verdict["outcome"] == "escalate":
            raise NeedsApproval(verdict)
        if not verdict["allowed"]:
            raise Blocked(verdict)
        return verdict

    def tool(self, name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: the wrapped function only runs if the policy allows the call (keyword arguments = tool args)."""
        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(fn)
            def guarded(**kwargs: Any) -> Any:
                self.enforce(name, kwargs)
                return fn(**kwargs)
            return guarded
        return wrap
