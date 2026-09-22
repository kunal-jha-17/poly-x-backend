"""Deterministic core + the Engine that owns all state.

READ THIS FILE FIRST. Invariants (brief B2) - do not change without a contract discussion:
  * NO LLM anywhere in evaluate() / _check() / run_call(). Plain code decides allow/deny/escalate.
  * Fail closed: anything unknown (tool, args, order, customer) is deny with clause_id null.
  * deny beats escalate; among equals the lowest clause id wins.
  * Rolling window is (now - window, now]; a refund exactly `window` old no longer counts.
  * Only EXECUTED refunds enter the ledger. Denied / escalated refunds never do.
  * Every state change (evaluate -> execute -> ledger) happens under one lock (_locked).
"""
import functools
import itertools
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import agent as agent_mod
import compiler as compiler_mod
import llm as llm_mod
import scenario
from errors import ApiError, no_active_policy
from models import (
    CONTRACT_VERSION, WINDOW_HOURS, Ambiguity, AmbiguityAnswer, ApprovedPolicy, ApproveRequest,
    CasesResponse, ChatRequest, ChatResponse, Clause, CompileRequest, Decision, DecisionsResponse,
    DiffRow, Health, PolicyDraft, RefundState, ResetRequest, ResetResponse, RunTestsRequest,
    Scenario, TestReport,
)

log = logging.getLogger("cryptix.decisions")

MAX_TOOL_CALLS_PER_TURN = 4
MAX_LIVE_DECISIONS = 2000


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """ISO-8601 UTC with millisecond precision and a trailing Z (e.g. 2026-09-21T07:27:51.897Z)."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _locked(fn):
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)

    return wrapper


_ID_LOCK = threading.Lock()
_ID_COUNTER = itertools.count(1)


def next_decision_id() -> str:
    with _ID_LOCK:
        return f"dec_{next(_ID_COUNTER):05d}"


# ====================================================================== ledger
class Ledger:
    """Executed refunds only. Not thread-safe by itself: the Engine serialises access with its lock."""

    def __init__(self) -> None:
        self._entries: List[Tuple[datetime, str, int, str]] = []  # (ts, customer_id, amount_inr, order_id)
        self.refund_seq = 0
        self.ticket_seq = 0

    def next_refund_id(self) -> str:
        self.refund_seq += 1
        return f"RFD-{self.refund_seq:04d}"

    def next_ticket_id(self) -> str:
        self.ticket_seq += 1
        return f"TKT-{self.ticket_seq:04d}"

    def add(self, customer_id: str, amount_inr: int, ts: datetime, order_id: str) -> None:
        self._entries.append((ts, customer_id, amount_inr, order_id))

    @staticmethod
    def _in_window(ts: datetime, now: datetime, window_type: str, hours: int) -> bool:
        if ts > now:
            return False
        if window_type == "calendar_day":
            return ts.astimezone(timezone.utc).date() == now.astimezone(timezone.utc).date()
        return ts > now - timedelta(hours=hours)  # rolling: (now - hours, now]

    def total(self, customer_id: str, now: datetime, window_type: str = "rolling", hours: int = WINDOW_HOURS) -> int:
        return sum(a for ts, c, a, _ in self._entries if c == customer_id and self._in_window(ts, now, window_type, hours))

    def count(self, customer_id: str, now: datetime, window_type: str = "rolling", hours: int = WINDOW_HOURS) -> int:
        return sum(1 for ts, c, _, _ in self._entries if c == customer_id and self._in_window(ts, now, window_type, hours))

    def snapshot(self, customer_id: str, now: datetime) -> RefundState:
        return RefundState(
            customer_id=customer_id,
            refund_total_24h_inr=self.total(customer_id, now),
            refund_count_24h=self.count(customer_id, now),
            window_hours=WINDOW_HOURS,
        )

    def clear(self, customer_id: Optional[str] = None) -> int:
        before = len(self._entries)
        self._entries = [e for e in self._entries if customer_id is not None and e[1] != customer_id]
        return before - len(self._entries)


# ====================================================================== deterministic evaluation
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


def _rs(n: int) -> str:
    return f"\u20b9{n:,}"


def _fail_closed(reason: str) -> Verdict:
    return Verdict("deny", None, None, reason)


def _validate_args(tool: Any, args: Any) -> Optional[str]:
    """Return an error message if the call is malformed, else None. Strict on purpose."""
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


def _check(clause: Clause, tool: str, args: Dict[str, Any], session_customer_id: str,
           subject_customer_id: Optional[str], ledger: Ledger, now: datetime) -> Optional[Violation]:
    """Evaluate ONE clause against ONE validated call. Pure code, no LLM."""
    p = clause.params
    if clause.kind == "per_txn_limit":
        if tool != "issue_refund":
            return None
        amount = args["amount_inr"]
        if p.scope == "transaction":
            basis, basis_txt = amount, f"Refund of {_rs(amount)}"
        else:
            already = ledger.total(subject_customer_id, now)
            basis, basis_txt = already + amount, f"Customer {subject_customer_id} refunds in 24 hours would reach {_rs(already + amount)}"
        if basis > p.value:
            return Violation(clause, f"{basis_txt} exceeds the {_rs(p.value)} limit; human approval is required.")
    elif clause.kind == "cumulative_limit":
        if tool != "issue_refund":
            return None
        amount = args["amount_inr"]
        already = ledger.total(subject_customer_id, now, p.window_type, p.window_hours)
        if already + amount > p.max_total:
            window = "calendar day (UTC)" if p.window_type == "calendar_day" else f"rolling {p.window_hours}-hour window"
            return Violation(
                clause,
                f"Customer {subject_customer_id} would reach {_rs(already + amount)} in the {window} "
                f"(limit {_rs(p.max_total)}; already {_rs(already)} + this {_rs(amount)}).",
            )
    elif clause.kind == "data_scope":
        target = args["customer_id"] if tool == "fetch_customer_data" else scenario.order_owner(args["order_id"])
        if target != session_customer_id:
            return Violation(
                clause, f"Session customer {session_customer_id} may not access data belonging to {target}."
            )
    elif clause.kind == "precondition":
        if tool != "issue_refund":
            return None
        status = scenario.ORDERS[args["order_id"]]["status"]
        if status != p.value:
            return Violation(
                clause, f"Order {args['order_id']} has status '{status}', but refunds require '{p.value}'."
            )
    return None


def evaluate(tool: Any, args: Any, session_customer_id: str, clauses: List[Clause],
             ledger: Ledger, now: datetime) -> Verdict:
    """The runtime decision. Deterministic. No LLM. Fails closed on anything unknown."""
    err = _validate_args(tool, args)
    if err:
        return _fail_closed(err)
    subject: Optional[str]
    if tool == "fetch_customer_data":
        if args["customer_id"] not in scenario.CUSTOMERS:
            return _fail_closed(f"Customer {args['customer_id']} not found; failing closed.")
        subject = session_customer_id
    else:
        subject = scenario.order_owner(args["order_id"])
        if subject is None:
            return _fail_closed(f"Order {args['order_id']} not found; failing closed.")
    violations = [v for c in clauses if (v := _check(c, tool, args, session_customer_id, subject, ledger, now))]
    if not violations:
        return Verdict("allow", None, None, "No policy clause was violated.")
    # deny beats escalate; among equals the lowest clause id wins
    worst = min(violations, key=lambda v: (0 if v.clause.action == "deny" else 1, int(v.clause.clause_id[1:])))
    return Verdict(worst.clause.action, worst.clause.clause_id, worst.clause.source_sentence, worst.reason)


def _execute(tool: Any, args: Any, ledger: Ledger, now: datetime) -> Tuple[Dict[str, Any], bool]:
    """Run the fake tool. Returns (tool_result, executed). Only successful refunds touch the ledger."""
    err = _validate_args(tool, args)
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


def _jsonable_args(args: Any) -> Dict[str, Any]:
    if not isinstance(args, dict):
        args = {"_raw": str(args)[:200]}
    try:
        json.dumps(args, allow_nan=False)
        return args
    except (TypeError, ValueError):
        return {str(k): (v if isinstance(v, (str, int, bool)) or v is None else str(v)) for k, v in args.items()}


def _subject_for_state(tool: Any, args: Dict[str, Any], session_customer_id: str) -> str:
    if tool == "issue_refund" and isinstance(args.get("order_id"), str):
        return scenario.order_owner(args["order_id"]) or session_customer_id
    return session_customer_id


def run_call(*, tool: Any, args: Any, session_customer_id: str, enforcement: str,
             policy: Optional[ApprovedPolicy], ledger: Ledger, now: datetime, decision_id: str) -> Decision:
    """Interceptor core: evaluate -> (execute | ticket | nothing) -> record. Caller holds the lock."""
    args = _jsonable_args(args)
    subject = _subject_for_state(tool, args, session_customer_id)
    state_before = ledger.snapshot(subject, now)
    if enforcement == "on":
        if policy is None:
            raise ValueError("enforcement 'on' requires a policy")
        t0 = time.perf_counter()
        verdict = evaluate(tool, args, session_customer_id, policy.clauses, ledger, now)
        latency_ms = round((time.perf_counter() - t0) * 1000, 4)
    else:
        verdict = Verdict("allow", None, None, "Enforcement is off: no policy check was made.")
        latency_ms = 0.0
    executed = False
    tool_result: Optional[Dict[str, Any]] = None
    if verdict.outcome == "allow":
        tool_result, executed = _execute(tool, args, ledger, now)
    elif verdict.outcome == "escalate":
        tool_result = {
            "status": "pending_approval",
            "ticket_id": ledger.next_ticket_id(),
            "message": "Held for human approval. Nothing was executed.",
        }
    return Decision(
        decision_id=decision_id,
        timestamp=iso(now),
        tool=tool if isinstance(tool, str) else str(tool),
        args=args,
        session_customer_id=session_customer_id,
        enforced=enforcement == "on",
        outcome=verdict.outcome,
        executed=executed,
        clause_id=verdict.clause_id,
        source_sentence=verdict.source_sentence,
        reason=verdict.reason,
        policy_version=policy.policy_version if (enforcement == "on" and policy) else None,
        state_before=state_before,
        state_after=ledger.snapshot(subject, now),
        latency_ms=latency_ms,
        tool_result=tool_result,
    )


# ====================================================================== policy diff
def _norm(s: str) -> str:
    return " ".join(s.split()).lower()


def diff_policies(old: List[Clause], new: List[Clause]) -> List[DiffRow]:
    old_by = {_norm(c.source_sentence): c for c in old}
    rows: List[DiffRow] = []
    seen = set()
    for c in new:
        key = _norm(c.source_sentence)
        o = old_by.get(key)
        if o is None:
            rows.append(DiffRow(clause_id=c.clause_id, change="added", source_sentence=c.source_sentence, detail=None))
            continue
        seen.add(key)
        if o.kind == c.kind and o.params == c.params:
            rows.append(DiffRow(clause_id=c.clause_id, change="unchanged", source_sentence=c.source_sentence, detail=None))
        else:
            a, b = o.params.model_dump(), c.params.model_dump()
            detail = "; ".join(f"{k}: {a.get(k)} -> {b.get(k)}" for k in b if a.get(k) != b.get(k)) or "rule changed"
            rows.append(DiffRow(clause_id=c.clause_id, change="changed", source_sentence=c.source_sentence, detail=detail))
    for key, o in old_by.items():
        if key not in seen:
            rows.append(DiffRow(clause_id=o.clause_id, change="removed", source_sentence=o.source_sentence, detail=None))
    return rows


# ====================================================================== the engine
@dataclass
class _DraftRecord:
    draft: PolicyDraft
    patches: Dict[str, Dict[str, Any]]  # option_id -> internal param_patch. NEVER sent to clients.
    approved: bool = False


class Engine:
    def __init__(self, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._lock = threading.RLock()
        self.clock = clock or utcnow
        self.ledger = Ledger()
        self.decisions: List[Decision] = []
        self.drafts: Dict[str, _DraftRecord] = {}
        self.active: Optional[ApprovedPolicy] = None
        self._version_seq = 0
        self._draft_seq = 0
        self._report_seq = 0
        self.reports: Dict[str, TestReport] = {}
        self.latest_report_id: Optional[str] = None
        self.llm_available = False  # True only after a successful startup self-test
        self.llm_client: Any = None

    # ---------------------------------------------------------------- simple reads
    @_locked
    def health(self) -> Health:
        return Health(
            status="ok", contract_version=CONTRACT_VERSION, llm_available=self.llm_available,
            active_policy_version=self.active.policy_version if self.active else None,
        )

    def scenario(self) -> Scenario:
        return Scenario(
            session_customer_id=scenario.SESSION_CUSTOMER_ID,
            default_policy_text=scenario.DEFAULT_POLICY_TEXT,
            tools=scenario.TOOL_SPECS,
            customers=[{"customer_id": c["customer_id"], "name": c["name"]} for c in scenario.CUSTOMERS.values()],
            orders=list(scenario.ORDERS.values()),
            attack_presets=scenario.ATTACK_PRESETS,
        )

    def set_llm(self, client: Any, available: bool) -> None:
        with self._lock:
            self.llm_client = client if available else None
            self.llm_available = bool(available and client is not None)

    # ---------------------------------------------------------------- compile / approve
    def compile(self, req: CompileRequest) -> PolicyDraft:
        """LLM proposes (when mode is auto and a working key exists); the fixture compiler is the labelled fallback.
        Nothing here deploys anything: approval is a separate human step."""
        import compiler_llm  # local import: keeps the LLM SDK out of the deterministic path

        text = req.policy_text.strip()
        compiled = None
        compiled_by = "fixture"
        extra_warnings: List[str] = []
        with self._lock:
            client = self.llm_client if (req.mode == "auto" and self.llm_available) else None
        if client is not None:
            try:
                compiled = compiler_llm.propose_and_finalize(text, client)
                compiled_by = "llm"
            except compiler_mod.CompileError:
                raise  # the LLM read the policy and found nothing supported: a real answer, not an outage
            except Exception as exc:  # noqa: BLE001 - any LLM failure falls back, labelled
                extra_warnings.append(f"LLM compile failed ({type(exc).__name__}); rules were produced by the fixture compiler instead.")
                log.warning("llm compile failed: %s", exc)
        if compiled is None:
            compiled = compiler_mod.compile_fixture(text)  # raises CompileError -> COMPILE_FAILED
        with self._lock:
            self._draft_seq += 1
            draft = PolicyDraft(
                policy_id=f"pol_{self._draft_seq:03d}", created_at=iso(self.clock()), policy_text=text,
                compiled_by=compiled_by, clauses=compiled.clauses, ambiguities=compiled.ambiguities,
                warnings=list(compiled.warnings) + extra_warnings,
            )
            self.drafts[draft.policy_id] = _DraftRecord(draft=draft, patches=compiled.patches)
            return draft

    @_locked
    def approve(self, policy_id: str, req: ApproveRequest) -> ApprovedPolicy:
        rec = self.drafts.get(policy_id)
        if rec is None:
            raise ApiError("POLICY_NOT_FOUND", f"Policy {policy_id} was not found.", 404)
        if rec.approved:
            raise ApiError("POLICY_ALREADY_APPROVED", f"Policy {policy_id} was already approved. Compile it again to change it.", 409)
        amb_by_id: Dict[str, Ambiguity] = {a.ambiguity_id: a for a in rec.draft.ambiguities}
        answers: Dict[str, str] = {}
        bad: List[str] = []
        for ans in req.answers:
            amb = amb_by_id.get(ans.ambiguity_id)
            if amb is None or ans.option_id not in {o.option_id for o in amb.options} or (
                ans.ambiguity_id in answers and answers[ans.ambiguity_id] != ans.option_id
            ):
                bad.append("answers")
                break
            answers[ans.ambiguity_id] = ans.option_id
        if bad:
            raise ApiError(
                "VALIDATION_ERROR",
                "Each answer must name a real ambiguity_id and one of its option_ids, once.",
                422, {"fields": ["answers"]},
            )
        missing = [a.ambiguity_id for a in rec.draft.ambiguities if a.ambiguity_id not in answers]
        if missing:
            raise ApiError(
                "AMBIGUITY_UNRESOLVED",
                f"{len(missing)} question(s) still need an answer before this policy can be approved.",
                422, {"missing_ambiguity_ids": missing},
            )
        clauses = compiler_mod.apply_answers(rec.draft.clauses, rec.draft.ambiguities, answers, rec.patches)
        self._version_seq += 1
        previous = self.active.clauses if self.active else []
        approved = ApprovedPolicy(
            policy_id=policy_id, policy_version=self._version_seq, approved_at=iso(self.clock()),
            policy_text=rec.draft.policy_text, compiled_by=rec.draft.compiled_by, clauses=clauses,
            answers=[AmbiguityAnswer(ambiguity_id=k, option_id=answers[k]) for k in sorted(answers)],
            diff=diff_policies(previous, clauses),
        )
        rec.approved = True
        self.active = approved
        return approved

    @_locked
    def active_policy(self) -> ApprovedPolicy:
        if self.active is None:
            raise no_active_policy(404)
        return self.active

    # ---------------------------------------------------------------- the interceptor
    @_locked
    def call(self, tool: Any, args: Any, session_customer_id: str, enforcement: str = "on",
             now: Optional[datetime] = None) -> Decision:
        """EVERY tool call (naive agent, LLM agent, API) goes through here. Nothing touches a tool directly."""
        if enforcement == "on" and self.active is None:
            raise no_active_policy(409)
        d = run_call(
            tool=tool, args=args, session_customer_id=session_customer_id, enforcement=enforcement,
            policy=self.active if enforcement == "on" else None, ledger=self.ledger,
            now=now or self.clock(), decision_id=next_decision_id(),
        )
        self.decisions.append(d)
        if len(self.decisions) > MAX_LIVE_DECISIONS:
            del self.decisions[: len(self.decisions) - MAX_LIVE_DECISIONS]
        log.info("decision %s tool=%s outcome=%s clause=%s executed=%s enforced=%s",
                 d.decision_id, d.tool, d.outcome, d.clause_id, d.executed, d.enforced)
        return d

    # ---------------------------------------------------------------- live chat
    def chat(self, req: ChatRequest) -> ChatResponse:
        cid = req.session_customer_id
        if cid not in scenario.CUSTOMERS:
            raise ApiError("CUSTOMER_NOT_FOUND", f"Customer {cid} was not found.", 404)
        with self._lock:
            active = self.active
            if req.enforcement == "on" and active is None:
                raise no_active_policy(409)
            llm_ready = self.llm_available and self.llm_client is not None
            client = self.llm_client
        policy_text = active.policy_text if active else scenario.DEFAULT_POLICY_TEXT

        collected: List[Decision] = []

        def call_fn(tool: Any, args: Any) -> Decision:
            d = self.call(tool, args, cid, req.enforcement)  # the ONLY route to a tool
            collected.append(d)
            return d

        note: Optional[str] = None
        mode_used = "naive"
        reply: Optional[str] = None
        if req.agent_mode in ("auto", "llm") and llm_ready:
            try:
                reply = agent_mod.run_llm_agent(client, req.message, cid, policy_text, call_fn, MAX_TOOL_CALLS_PER_TURN)
                mode_used = "llm"
            except Exception as exc:  # noqa: BLE001
                log.warning("llm agent failed: %s", exc)
                if collected:
                    # Tools already ran through call(); re-running the naive agent would repeat them.
                    reply = agent_mod.summarise_decisions(collected)
                    mode_used = "llm"
                    note = f"The LLM agent errored after {len(collected)} tool call(s) ({type(exc).__name__}); showing what was executed. Not re-run."
                else:
                    note = f"LLM agent failed ({type(exc).__name__}); the naive agent handled this turn."
        elif req.agent_mode == "llm":
            note = "The LLM agent is unavailable; the naive agent handled this turn."
        if reply is None:
            reply = agent_mod.run_naive_agent(req.message, cid, call_fn)
        with self._lock:
            state = self.ledger.snapshot(cid, self.clock())
        return ChatResponse(
            reply=reply, agent_mode_used=mode_used, agent_note=note, enforcement=req.enforcement,
            session_customer_id=cid, decisions=collected, state=state,
        )

    # ---------------------------------------------------------------- reset / decisions
    @_locked
    def reset(self, req: ResetRequest) -> ResetResponse:
        scope = req.scope
        if scope == "all":
            cleared_refunds = self.ledger.clear()
            cleared_decisions = len(self.decisions)
            self.decisions = []
            self.ledger.refund_seq = 0
            self.ledger.ticket_seq = 0
        elif scope in scenario.CUSTOMERS:
            cleared_refunds = self.ledger.clear(scope)
            keep = [d for d in self.decisions if d.session_customer_id != scope]
            cleared_decisions = len(self.decisions) - len(keep)
            self.decisions = keep
        else:
            raise ApiError("CUSTOMER_NOT_FOUND", f"Reset scope must be 'all' or a known customer id; got '{scope}'.", 404)
        return ResetResponse(scope=scope, cleared_refunds=cleared_refunds, cleared_decisions=cleared_decisions, reset_at=iso(self.clock()))

    @_locked
    def list_decisions(self, limit: int) -> DecisionsResponse:
        newest_first = list(reversed(self.decisions))
        return DecisionsResponse(decisions=newest_first[:limit], total=len(newest_first), limit=limit)

    # ---------------------------------------------------------------- fixed cases + reports
    def cases(self) -> CasesResponse:
        import cases as cases_mod

        cs = cases_mod.build_cases()
        return CasesResponse(cases=cs, total=len(cs))

    def run_tests(self, req: RunTestsRequest) -> TestReport:
        import runner  # local import: runner imports this module

        with self._lock:
            policy = self.active
            if policy is None:
                raise no_active_policy(409)
            if req.policy_id is not None and req.policy_id != policy.policy_id:
                raise ApiError("POLICY_NOT_ACTIVE", f"Policy {req.policy_id} is not the active policy ({policy.policy_id}). Approve it first.", 409)
            self._report_seq += 1
            report_id = f"rep_{self._report_seq:04d}"
        report = runner.run_suite(policy, report_id, self.clock())  # isolated ledgers; never touches live state
        with self._lock:
            self.reports[report_id] = report
            self.latest_report_id = report_id
        return report

    @_locked
    def latest_report(self) -> TestReport:
        if self.latest_report_id is None:
            raise ApiError("NO_REPORT", "No tests have been run yet. Run the tests first.", 404)
        return self.reports[self.latest_report_id]

    @_locked
    def get_report(self, report_id: str) -> TestReport:
        rep = self.reports.get(report_id)
        if rep is None:
            raise ApiError("REPORT_NOT_FOUND", f"Report {report_id} was not found.", 404)
        return rep
