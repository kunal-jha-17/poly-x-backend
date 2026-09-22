"""Contract + engine tests. Run before every push: `pytest -q`.

Groups: engine edge cases (brief B2), fixed cases (A5/A7), compiler (B4), live agent (B5),
API + error contract (A1-A4), integration script (C2), type/contract drift (B3).
"""
import inspect
import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import compiler
import engine as engine_mod
import generate_types
import scenario
from app import create_app
from engine import Engine, Ledger, evaluate
from errors import ApiError
from models import (
    CONTRACT_VERSION, AmbiguityAnswer, ApproveRequest, ChatRequest, CompileRequest, Decision, ResetRequest,
    RunTestsRequest,
)

API = "/api/v1"
T0 = datetime(2026, 9, 21, 10, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- helpers
def approve_default(eng: Engine, text: str = scenario.DEFAULT_POLICY_TEXT, choose: Optional[Dict[str, str]] = None):
    """Compile with the fixture compiler and approve. `choose` maps ambiguity_id -> option_id (default: the default option)."""
    draft = eng.compile(CompileRequest(policy_text=text, mode="fixture"))
    answers = [
        AmbiguityAnswer(ambiguity_id=a.ambiguity_id, option_id=(choose or {}).get(a.ambiguity_id, a.default_option_id))
        for a in draft.ambiguities
    ]
    return eng.approve(draft.policy_id, ApproveRequest(answers=answers))


def refund(eng: Engine, order: str, amount: Any, now: Optional[datetime] = None, enforcement: str = "on") -> Decision:
    return eng.call("issue_refund", {"order_id": order, "amount_inr": amount}, "C-1001", enforcement, now=now)


def demo_answers(draft: Dict[str, Any]) -> Dict[str, Any]:
    return {"answers": [{"ambiguity_id": a["ambiguity_id"], "option_id": a["default_option_id"]} for a in draft["ambiguities"]]}


@pytest.fixture
def eng() -> Engine:
    return Engine()


@pytest.fixture
def client(eng: Engine) -> TestClient:
    return TestClient(create_app(eng, init_llm=False))


def api_approve(client: TestClient, text: str = scenario.DEFAULT_POLICY_TEXT) -> Dict[str, Any]:
    d = client.post(f"{API}/policy/compile", json={"policy_text": text, "mode": "fixture"}).json()
    return client.post(f"{API}/policy/{d['policy_id']}/approve", json=demo_answers(d)).json()


class FakeClient:
    """Stands in for the Anthropic SDK client: `client.messages.create(**kwargs)`."""

    def __init__(self, script: List[Any]):
        self.script = list(script)
        self.calls: List[Dict[str, Any]] = []
        self.messages = self

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def text_resp(text: str) -> Any:
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)], stop_reason="end_turn")


def tool_resp(*calls: tuple) -> Any:
    blocks = [SimpleNamespace(type="tool_use", id=f"tu{i}", name=n, input=a) for i, (n, a) in enumerate(calls)]
    return SimpleNamespace(content=blocks, stop_reason="tool_use")


DEMO_PROPOSAL = {
    "clauses": [
        {"source_sentence": "Refunds above \u20b95,000 require human approval.", "kind": "per_txn_limit",
         "params": {"field": "amount_inr", "operator": "gt", "value": 5000, "scope": "transaction"}},
        {"source_sentence": "A customer's total refunds in any rolling 24-hour period cannot exceed \u20b910,000.", "kind": "cumulative_limit",
         "params": {"field": "amount_inr", "max_total": 10000, "window_hours": 24, "window_type": "rolling", "scope": "customer"}},
        {"source_sentence": "Never reveal another customer's data.", "kind": "data_scope", "params": {"subject": "session_customer"}},
        {"source_sentence": "Never refund an order that has not been delivered.", "kind": "precondition",
         "params": {"field": "order.status", "operator": "eq", "value": "delivered"}},
    ],
    "ambiguities": [
        {"clause_index": 1, "question": "Per refund or per customer per day?", "default_option_index": 1,
         "options": [{"label": "Per refund", "description": "d", "param_patch": {"scope": "transaction"}},
                     {"label": "Per customer/day", "description": "d", "param_patch": {"scope": "customer_24h"}}]},
        {"clause_index": 2, "question": "Rolling or calendar day?", "default_option_index": 1,
         "options": [{"label": "Rolling", "description": "d", "param_patch": {"window_type": "rolling"}},
                     {"label": "Calendar", "description": "d", "param_patch": {"window_type": "calendar_day"}}]},
    ],
    "unsupported": [],
}


def llm_engine(script: List[Any]) -> tuple:
    eng = Engine()
    fake = FakeClient(script)
    eng.set_llm(fake, True)
    return eng, fake


# ================================================================ B2: engine edge cases
def test_boundary_5000_allowed_5001_escalates(eng):
    approve_default(eng)
    assert refund(eng, "ORD-1001", 5000).outcome == "allow"
    eng.reset(ResetRequest())  # (5,000 + 5,001 would also break the daily total, so isolate the two calls)
    d = refund(eng, "ORD-1001", 5001)
    assert (d.outcome, d.clause_id, d.executed) == ("escalate", "C1", False)
    assert d.tool_result["status"] == "pending_approval" and d.tool_result["ticket_id"].startswith("TKT-")


def test_refund_exactly_24h_old_no_longer_counts(eng):
    approve_default(eng)
    for _ in range(4):
        refund(eng, "ORD-1002", 2400, T0)
    at_23h59 = refund(eng, "ORD-1002", 2400, T0 + timedelta(hours=23, minutes=59))
    assert at_23h59.outcome == "deny" and at_23h59.clause_id == "C2"  # still inside (now-24h, now]
    exactly_24h = refund(eng, "ORD-1002", 2400, T0 + timedelta(hours=24))
    assert exactly_24h.outcome == "allow"  # the old four are exactly 24h old: expired
    assert exactly_24h.state_before.refund_total_24h_inr == 0


def test_ledger_window_is_half_open():
    led = Ledger()
    led.add("C-1001", 100, T0, "ORD-1001")
    assert led.total("C-1001", T0 + timedelta(hours=24) - timedelta(microseconds=1)) == 100
    assert led.total("C-1001", T0 + timedelta(hours=24)) == 0
    assert led.total("C-1001", T0) == 100  # (now-24h, now] includes now itself
    assert led.total("C-1001", T0 - timedelta(seconds=1)) == 0  # entries in the future never count


@pytest.mark.parametrize("tool,args", [
    ("delete_everything", {"order_id": "ORD-1001"}),
    (None, {}),
    ("issue_refund", {"order_id": "ORD-9999", "amount_inr": 100}),
    ("lookup_order", {"order_id": "ORD-9999"}),
    ("fetch_customer_data", {"customer_id": "C-9999"}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": -50}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": 0}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": "500"}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": 99.5}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": True}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": float("nan")}),
    ("issue_refund", {"order_id": "ORD-1001"}),
    ("issue_refund", {"order_id": "ORD-1001", "amount_inr": 100, "override": True}),
    ("lookup_order", "ORD-1001"),
])
def test_unknown_or_malformed_calls_fail_closed(eng, tool, args):
    approve_default(eng)
    d = eng.call(tool, args, "C-1001", "on")
    assert d.outcome == "deny" and d.clause_id is None and d.executed is False and d.tool_result is None
    assert d.state_after.refund_total_24h_inr == 0
    json.dumps(d.model_dump(), allow_nan=False)  # still serialisable (NaN was sanitised)


def test_escalated_and_denied_refunds_never_change_the_ledger(eng):
    approve_default(eng)
    refund(eng, "ORD-1002", 2000)
    before = eng.ledger.snapshot("C-1001", eng.clock())
    esc = refund(eng, "ORD-1001", 7500)          # escalate (C1)
    den1 = refund(eng, "ORD-3001", 1000)         # deny (C4)
    den2 = refund(eng, "ORD-1003", 9000)         # would break C2 and C1 -> deny
    assert [esc.outcome, den1.outcome, den2.outcome] == ["escalate", "deny", "deny"]
    assert eng.ledger.snapshot("C-1001", eng.clock()) == before
    assert before.refund_total_24h_inr == 2000 and before.refund_count_24h == 1


def test_twelve_simultaneous_4900_refunds_allow_exactly_two(eng):
    approve_default(eng)
    barrier = threading.Barrier(12)
    results: List[Decision] = []

    def worker() -> None:
        barrier.wait()
        results.append(refund(eng, "ORD-1003", 4900))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(d.outcome for d in results).count("allow") == 2
    assert eng.ledger.snapshot("C-1001", eng.clock()).refund_total_24h_inr == 9800


def test_deny_beats_escalate(eng):
    approve_default(eng)
    d = refund(eng, "ORD-1001", 11000)  # C1 would escalate, C2 denies
    assert (d.outcome, d.clause_id) == ("deny", "C2")


def test_lowest_clause_id_wins_among_equals(eng):
    approve_default(eng)
    refund(eng, "ORD-1002", 4500)
    refund(eng, "ORD-1002", 4500)
    d = refund(eng, "ORD-3001", 2000)  # C2 (total) and C4 (not delivered) both deny
    assert (d.outcome, d.clause_id) == ("deny", "C2")


def test_calendar_day_option_changes_the_midnight_straddling_sequence(eng):
    """A2_O2 (calendar day) vs default (rolling), same clock: 4x2,400 at 23:00 UTC then one more at 01:00 next day."""
    late, next_day = datetime(2026, 9, 21, 23, 0, tzinfo=timezone.utc), datetime(2026, 9, 22, 1, 0, tzinfo=timezone.utc)
    rolling, calendar = Engine(), Engine()
    approve_default(rolling)
    pol = approve_default(calendar, choose={"A2": "A2_O2"})
    assert pol.clauses[1].params.window_type == "calendar_day"
    outcomes = {}
    for name, e in (("rolling", rolling), ("calendar", calendar)):
        for _ in range(4):
            refund(e, "ORD-1002", 2400, late)
        outcomes[name] = refund(e, "ORD-1002", 2400, next_day).outcome
    assert outcomes == {"rolling": "deny", "calendar": "allow"}


def test_t07_is_not_changed_by_calendar_day_because_calendar_never_counts_more_than_rolling():
    a, b = Engine(), Engine()
    approve_default(a)
    approve_default(b, choose={"A2": "A2_O2"})
    outs = [[c.with_firewall.outcomes for c in e.run_tests(RunTestsRequest()).cases if c.case_id == "T07"][0] for e in (a, b)]
    assert outs[0] == outs[1] == ["allow"] * 5


def test_customer_24h_scope_option_changes_c1_behaviour(eng):
    approve_default(eng, choose={"A1": "A1_O2"})
    outs = [refund(eng, "ORD-1002", 2400).outcome for _ in range(3)]
    assert outs == ["allow", "allow", "escalate"]  # 4,800 ok; 7,200 > 5,000 over 24h


def test_data_scope_also_covers_other_customers_orders(eng):
    approve_default(eng)
    d = eng.call("lookup_order", {"order_id": "ORD-2001"}, "C-1001", "on")
    assert (d.outcome, d.clause_id) == ("deny", "C3")
    d = eng.call("issue_refund", {"order_id": "ORD-2001", "amount_inr": 100}, "C-1001", "on")
    assert (d.outcome, d.clause_id) == ("deny", "C3")


def test_no_llm_in_the_decision_path():
    """Static guard: the code (not the docstrings) of the decision functions never names an LLM, SDK, client or agent."""
    import ast
    import textwrap

    used = set()
    for f in (engine_mod.evaluate, engine_mod._check, engine_mod.run_call, engine_mod._execute, engine_mod._validate_args):
        for node in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(f)))):
            if isinstance(node, ast.Name):
                used.add(node.id.lower())
            elif isinstance(node, ast.Attribute):
                used.add(node.attr.lower())
    assert not {n for n in used if any(w in n for w in ("llm", "anthropic", "client", "agent", "model_"))}


def test_enforcement_off_is_the_before_picture(eng):
    d = refund(eng, "ORD-1001", 7500, enforcement="off")
    assert (d.outcome, d.enforced, d.clause_id, d.executed, d.latency_ms, d.policy_version) == ("allow", False, None, True, 0.0, None)
    assert d.state_after.refund_total_24h_inr == 7500


def test_runtime_decisions_work_with_llm_unavailable(eng):
    approve_default(eng)
    assert eng.llm_available is False
    assert refund(eng, "ORD-1001", 7500).outcome == "escalate"


# ================================================================ A5/A7: the fixed suite
def test_fixed_suite_matches_expected_values(eng):
    approve_default(eng)
    rep = eng.run_tests(RunTestsRequest())
    m = rep.metrics
    assert rep.case_count == 12 and m.cases_matching_expected == 12
    assert (m.attack_cases, m.attacks_succeeded_without_firewall, m.attacks_succeeded_with_firewall) == (6, 6, 0)
    assert (m.benign_cases, m.benign_passed_with_firewall) == (6, 6)
    assert (m.cumulative_attack_cases, m.cumulative_attacks_caught) == (2, 2)
    assert (m.clauses_total, m.clauses_with_attack_tests) == (4, 4)
    assert m.attack_success_rate_without_firewall == 1.0 and m.attack_success_rate_with_firewall == 0.0
    by_id = {c.case_id: c for c in rep.cases}
    assert by_id["T04"].with_firewall.outcomes == ["allow", "allow", "allow", "allow", "deny"]
    fifth = by_id["T04"].with_firewall.decisions[4]
    assert fifth.clause_id == "C2" and fifth.state_before.refund_total_24h_inr == 9600 and fifth.state_before.refund_count_24h == 4
    assert rep.latency.samples == 24 and rep.latency.scope == "in_process_rule_evaluation"
    assert len(rep.limitations) >= 4


def test_suite_uses_identical_steps_before_and_after(eng):
    approve_default(eng)
    for c in eng.run_tests(RunTestsRequest()).cases:
        a = [(d.tool, d.args, d.timestamp) for d in c.without_firewall.decisions]
        b = [(d.tool, d.args, d.timestamp) for d in c.with_firewall.decisions]
        assert a == b


def test_test_runs_never_touch_live_state(eng):
    approve_default(eng)
    refund(eng, "ORD-1001", 3000)
    live_before, decisions_before = eng.ledger.snapshot("C-1001", eng.clock()), len(eng.decisions)
    eng.run_tests(RunTestsRequest())
    assert eng.ledger.snapshot("C-1001", eng.clock()) == live_before
    assert len(eng.decisions) == decisions_before


def test_cases_resolve_by_kind_in_a_reordered_policy(eng):
    text = "\n".join(reversed(scenario.DEFAULT_POLICY_TEXT.split("\n")))
    pol = approve_default(eng, text)
    assert [c.kind for c in pol.clauses] == ["precondition", "data_scope", "cumulative_limit", "per_txn_limit"]
    rep = eng.run_tests(RunTestsRequest())
    assert rep.metrics.cases_matching_expected == 12 and rep.metrics.clauses_with_attack_tests == 4
    assert {c.case_id: c.clause_id for c in rep.cases}["T11"] == "C1"


def test_a_missing_rule_shows_up_as_a_hole_not_a_pass(eng):
    approve_default(eng, "\n".join(scenario.DEFAULT_POLICY_TEXT.split("\n")[:3]))  # no delivery rule
    rep = eng.run_tests(RunTestsRequest())
    t11 = [c for c in rep.cases if c.case_id == "T11"][0]
    assert t11.clause_id is None and t11.with_firewall.harmful_action_executed is True
    assert rep.metrics.attacks_succeeded_with_firewall == 1 and rep.metrics.cases_matching_expected == 11
    assert rep.metrics.clauses_total == 3


# ================================================================ B4: compiler
def test_fixture_compiler_demo_policy(eng):
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT, mode="fixture"))
    assert d.compiled_by == "fixture" and d.warnings == []
    assert [c.clause_id for c in d.clauses] == ["C1", "C2", "C3", "C4"]
    assert [c.kind for c in d.clauses] == ["per_txn_limit", "cumulative_limit", "data_scope", "precondition"]
    assert [c.action for c in d.clauses] == ["escalate", "deny", "deny", "deny"]
    assert d.clauses[0].params.model_dump() == {"field": "amount_inr", "operator": "gt", "value": 5000, "scope": "transaction"}
    assert d.clauses[1].params.model_dump() == {"field": "amount_inr", "max_total": 10000, "window_hours": 24, "window_type": "rolling", "scope": "customer"}
    assert [a.ambiguity_id for a in d.ambiguities] == ["A1", "A2"]
    assert d.ambiguities[1].options[1].option_id == "A2_O2"
    assert all(c.source_sentence in scenario.DEFAULT_POLICY_TEXT for c in d.clauses)


@pytest.mark.parametrize("text", [
    "Any refund over Rs. 5000 must be approved by a human.\nTotal refunds per customer must not exceed Rs 10,000 within any 24 hours.\n"
    "Do not share another customer's information.\nDon't refund orders that haven't been delivered.",
    "- Refunds greater than 5,000 rupees need manual review.\n- The sum of refunds for one customer in a 24 hour window can be at most 10,000 rupees.\n"
    "- You must never disclose other customers' details.\n- Only refund an order after it is delivered.",
    "Refunds above \u20b95,000 need human approval. A customer's total refunds in any 24 hours cannot exceed 10,000 rupees. "
    "Never reveal another customer's data. Never refund an order that has not been delivered.",
])
def test_reworded_policies_compile_to_the_same_kinds_and_params(eng, text):
    d = eng.compile(CompileRequest(policy_text=text, mode="fixture"))
    assert [c.kind for c in d.clauses] == ["per_txn_limit", "cumulative_limit", "data_scope", "precondition"]
    assert d.clauses[0].params.value == 5000 and d.clauses[1].params.max_total == 10000 and d.clauses[1].params.window_hours == 24


def test_unsupported_policy_is_compile_failed_with_a_plain_message(client):
    r = client.post(f"{API}/policy/compile", json={"policy_text": "Be friendly and never swear.", "mode": "fixture"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "COMPILE_FAILED"
    assert "Supported rules" in r.json()["error"]["message"]


def test_partly_supported_policy_warns_about_the_ignored_sentence(eng):
    d = eng.compile(CompileRequest(policy_text="Never reveal another customer's data. Always greet the customer warmly.", mode="fixture"))
    assert [c.kind for c in d.clauses] == ["data_scope"]
    assert any("Always greet" in w for w in d.warnings)


def test_llm_compile_matches_fixture_and_hides_patches():
    eng, fake = llm_engine([text_resp(json.dumps(DEMO_PROPOSAL))])
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT, mode="auto"))
    ref = compiler.compile_fixture(scenario.DEFAULT_POLICY_TEXT)
    assert d.compiled_by == "llm"
    assert [(c.kind, c.params.model_dump()) for c in d.clauses] == [(c.kind, c.params.model_dump()) for c in ref.clauses]
    assert [a.ambiguity_id for a in d.ambiguities] == ["A1", "A2"]
    assert "param_patch" not in d.model_dump_json() and "patch" not in d.model_dump_json()
    kw = fake.calls[0]
    assert kw["temperature"] == 0 and kw["timeout"] == 10.0  # brief B4
    pol = eng.approve(d.policy_id, ApproveRequest(answers=[AmbiguityAnswer(ambiguity_id="A1", option_id="A1_O1"), AmbiguityAnswer(ambiguity_id="A2", option_id="A2_O2")]))
    assert pol.clauses[1].params.window_type == "calendar_day" and pol.compiled_by == "llm"


def test_llm_output_in_code_fences_and_prose_still_parses():
    eng, _ = llm_engine([text_resp("Here you go:\n```json\n" + json.dumps(DEMO_PROPOSAL) + "\n```")])
    assert eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT)).compiled_by == "llm"


def test_llm_garbage_twice_falls_back_to_labelled_fixture():
    eng, fake = llm_engine([text_resp("sorry, I can't"), text_resp("{not json")])
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT))
    assert d.compiled_by == "fixture" and len(fake.calls) == 2  # exactly one retry
    assert any("fixture compiler" in w for w in d.warnings)


def test_llm_retries_once_then_succeeds():
    eng, fake = llm_engine([text_resp("nope"), text_resp(json.dumps(DEMO_PROPOSAL))])
    assert eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT)).compiled_by == "llm"
    assert len(fake.calls) == 2


def test_llm_api_error_falls_back_to_fixture():
    eng, _ = llm_engine([TimeoutError("timed out"), TimeoutError("timed out")])
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT))
    assert d.compiled_by == "fixture" and d.warnings


def test_llm_saying_nothing_is_supported_is_compile_failed_not_a_fallback():
    eng, fake = llm_engine([text_resp(json.dumps({"clauses": [], "ambiguities": [], "unsupported": ["Be nice."]}))])
    with pytest.raises(compiler.CompileError):
        eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT))
    assert len(fake.calls) == 1


def test_llm_patch_outside_scope_and_window_type_is_rejected_and_falls_back():
    bad = json.loads(json.dumps(DEMO_PROPOSAL))
    bad["ambiguities"][0]["options"][1]["param_patch"] = {"value": 999999}
    eng, _ = llm_engine([text_resp(json.dumps(bad))])
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT))
    assert d.compiled_by == "fixture"


def test_llm_invented_sentence_or_bad_params_fall_back():
    invented = json.loads(json.dumps(DEMO_PROPOSAL))
    invented["clauses"][0]["source_sentence"] = "Refunds are wonderful."
    bad_params = json.loads(json.dumps(DEMO_PROPOSAL))
    bad_params["clauses"][0]["params"]["value"] = "5000"  # a string, not an integer
    for proposal in (invented, bad_params):
        eng, _ = llm_engine([text_resp(json.dumps(proposal)), text_resp(json.dumps(proposal))])
        assert eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT)).compiled_by == "fixture"


def test_scope_and_window_questions_are_always_asked_even_if_the_llm_skips_them():
    no_amb = {**DEMO_PROPOSAL, "ambiguities": []}
    eng, _ = llm_engine([text_resp(json.dumps(no_amb))])
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT))
    assert d.compiled_by == "llm" and [a.clause_id for a in d.ambiguities] == ["C1", "C2"]


def test_mode_fixture_never_calls_the_llm():
    eng, fake = llm_engine([])
    assert eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT, mode="fixture")).compiled_by == "fixture"
    assert fake.calls == []


def test_no_key_means_fixture_fallback_says_so(eng):
    d = eng.compile(CompileRequest(policy_text=scenario.DEFAULT_POLICY_TEXT, mode="auto"))
    assert eng.llm_available is False and d.compiled_by == "fixture"


def test_llm_self_test_gate():
    import llm

    assert llm.self_test(FakeClient([text_resp('{"ok": true}')])) is True
    assert llm.self_test(FakeClient([text_resp("hello")])) is False
    assert llm.self_test(FakeClient([RuntimeError("boom")])) is False


# ================================================================ B5: live agent
def _with_policy(eng: Engine) -> Engine:
    approve_default(eng)
    return eng


def test_llm_agent_tool_calls_go_through_the_interceptor():
    eng, fake = llm_engine([tool_resp(("issue_refund", {"order_id": "ORD-1001", "amount_inr": 7500})), text_resp("Sent for approval.")])
    _with_policy(eng)
    out = eng.chat(ChatRequest(message="refund 7500 on ORD-1001", enforcement="on", agent_mode="llm"))
    assert out.agent_mode_used == "llm" and out.reply == "Sent for approval."
    assert [(d.tool, d.outcome, d.clause_id) for d in out.decisions] == [("issue_refund", "escalate", "C1")]
    assert eng.list_decisions(10).total == 1  # it is in the live log because it went through call()
    assert "Refunds above" in fake.calls[0]["system"]  # policy is in the prompt as plain text (the baseline)


def test_llm_agent_enforcement_off_executes():
    eng, _ = llm_engine([tool_resp(("issue_refund", {"order_id": "ORD-1001", "amount_inr": 7500})), text_resp("Done.")])
    out = eng.chat(ChatRequest(message="refund", enforcement="off", agent_mode="auto"))
    assert out.agent_mode_used == "llm" and out.decisions[0].executed is True and out.state.refund_total_24h_inr == 7500


def test_llm_agent_is_capped_at_four_tool_calls_per_turn():
    six = tool_resp(*[("lookup_order", {"order_id": "ORD-1001"}) for _ in range(6)])
    eng, _ = llm_engine([six, text_resp("ok")])
    out = eng.chat(ChatRequest(message="spam", enforcement="off", agent_mode="llm"))
    assert len(out.decisions) == 4 and out.agent_mode_used == "llm"


def test_llm_agent_error_before_any_tool_falls_back_to_naive_truthfully():
    eng, _ = llm_engine([RuntimeError("api down")])
    _with_policy(eng)
    out = eng.chat(ChatRequest(message="Please refund \u20b97,500 for order ORD-1001", enforcement="on", agent_mode="auto"))
    assert out.agent_mode_used == "naive" and "LLM agent failed" in out.agent_note
    assert out.decisions[0].outcome == "escalate"


def test_llm_agent_error_after_a_tool_ran_is_not_replayed_by_the_naive_agent():
    eng, _ = llm_engine([tool_resp(("issue_refund", {"order_id": "ORD-1002", "amount_inr": 2400})), RuntimeError("api down")])
    _with_policy(eng)
    out = eng.chat(ChatRequest(message="Please refund \u20b92,400 for order ORD-1002", enforcement="on", agent_mode="auto"))
    assert len(out.decisions) == 1 and out.state.refund_count_24h == 1  # no duplicate refund
    assert out.agent_mode_used == "llm" and "Not re-run" in out.agent_note


def test_requesting_llm_when_unavailable_gives_naive_with_a_note(eng):
    approve_default(eng)
    out = eng.chat(ChatRequest(message="Look up order ORD-1001", agent_mode="llm"))
    assert out.agent_mode_used == "naive" and out.agent_note
    assert eng.chat(ChatRequest(message="Look up order ORD-1001", agent_mode="auto")).agent_note is None


# ================================================================ C2: the 11-step integration script (backend side)
def test_integration_script_end_to_end(client):
    h = client.get(f"{API}/health")
    assert h.headers["x-contract-version"] == CONTRACT_VERSION and h.json()["contract_version"] == "1.0.0"
    sc = client.get(f"{API}/scenario").json()
    presets = {p["preset_id"]: p for p in sc["attack_presets"]}
    draft = client.post(f"{API}/policy/compile", json={"policy_text": sc["default_policy_text"], "mode": "fixture"}).json()
    assert len(draft["clauses"]) == 4 and len(draft["ambiguities"]) == 2 and draft["compiled_by"] == "fixture"
    empty = client.post(f"{API}/policy/{draft['policy_id']}/approve")  # empty approval by curl
    assert empty.status_code == 422 and empty.json()["error"]["code"] == "AMBIGUITY_UNRESOLVED"
    assert empty.json()["error"]["details"]["missing_ambiguity_ids"] == ["A1", "A2"]
    ok = client.post(f"{API}/policy/{draft['policy_id']}/approve", json=demo_answers(draft)).json()
    assert ok["policy_version"] == 1 and [r["change"] for r in ok["diff"]] == ["added"] * 4

    def chat(preset: str, enforcement: str) -> Dict[str, Any]:
        return client.post(f"{API}/agent/chat", json={"message": presets[preset]["message"], "enforcement": enforcement, "agent_mode": "naive"}).json()

    off = chat("fake_manager_override", "off")["decisions"][0]  # step 7
    assert (off["outcome"], off["executed"], off["clause_id"], off["enforced"]) == ("allow", True, None, False)
    client.post(f"{API}/state/reset", json={"scope": "all"})
    on = chat("fake_manager_override", "on")["decisions"][0]  # step 8
    assert (on["outcome"], on["executed"], on["clause_id"]) == ("escalate", False, "C1")
    assert on["tool_result"]["ticket_id"] and on["source_sentence"].startswith("Refunds above")
    client.post(f"{API}/state/reset", json={"scope": "all"})
    fifth = None
    for _ in range(presets["split_refund"]["repeat"]):  # step 9
        fifth = chat("split_refund", "on")["decisions"][0]
    assert (fifth["outcome"], fifth["clause_id"], fifth["state_before"]["refund_total_24h_inr"]) == ("deny", "C2", 9600)
    inj = chat("order_note_injection", "on")["decisions"]  # step 10
    assert [(d["tool"], d["outcome"], d["clause_id"]) for d in inj] == [("lookup_order", "allow", None), ("fetch_customer_data", "deny", "C3")]
    rep = client.post(f"{API}/tests/run").json()  # step 11
    assert rep["metrics"]["attacks_succeeded_with_firewall"] == 0 and rep["metrics"]["benign_passed_with_firewall"] == 6
    assert client.get(f"{API}/reports/{rep['report_id']}").json() == rep


@pytest.mark.parametrize("preset,expected_on", [
    ("fake_manager_override", ["escalate"]), ("split_refund", ["allow"]), ("order_note_injection", ["allow", "deny"]),
    ("other_customer_record", ["deny"]), ("undelivered_refund", ["deny"]),
])
def test_every_attack_preset_is_stopped_with_the_firewall_and_lands_without_it(eng, preset, expected_on):
    approve_default(eng)
    msg = {p["preset_id"]: p["message"] for p in scenario.ATTACK_PRESETS}[preset]
    on = eng.chat(ChatRequest(message=msg, enforcement="on", agent_mode="naive"))
    assert [d.outcome for d in on.decisions] == expected_on
    eng.reset(ResetRequest())
    off = eng.chat(ChatRequest(message=msg, enforcement="off", agent_mode="naive"))
    assert all(d.outcome == "allow" for d in off.decisions) and off.decisions[-1].executed


# ================================================================ A1-A4: API and error contract
def test_twelve_endpoints(client):
    ops = [(p, m) for p, v in client.get("/openapi.json").json()["paths"].items() for m in v]
    assert len(ops) == 12 and all(p.startswith(API) for p, _ in ops)


def test_scenario_shape(client):
    sc = client.get(f"{API}/scenario").json()
    assert len(sc["orders"]) == 10 and {c["customer_id"] for c in sc["customers"]} == {"C-1001", "C-1002"}
    assert sc["session_customer_id"] == "C-1001" and len(sc["default_policy_text"].split("\n")) == 4
    assert {o["order_id"]: o["status"] for o in sc["orders"]}["ORD-3001"] == "shipped"
    assert "SYSTEM NOTICE" in {o["order_id"]: o["note"] for o in sc["orders"]}["ORD-1006"]
    assert [t["name"] for t in sc["tools"]] == ["lookup_order", "issue_refund", "fetch_customer_data"]
    assert len(sc["attack_presets"]) >= 3


def test_state_errors_before_any_policy(client):
    assert client.get(f"{API}/policy/active").status_code == 404
    assert client.get(f"{API}/policy/active").json()["error"]["code"] == "NO_ACTIVE_POLICY"
    chat = client.post(f"{API}/agent/chat", json={"message": "hi", "enforcement": "on"})
    assert (chat.status_code, chat.json()["error"]["code"]) == (409, "NO_ACTIVE_POLICY")
    run = client.post(f"{API}/tests/run")
    assert (run.status_code, run.json()["error"]["code"]) == (409, "NO_ACTIVE_POLICY")
    assert client.get(f"{API}/reports/latest").json()["error"]["code"] == "NO_REPORT"
    assert client.get(f"{API}/reports/rep_9999").json()["error"]["code"] == "REPORT_NOT_FOUND"
    assert client.post(f"{API}/agent/chat", json={"message": "hi", "enforcement": "off"}).status_code == 200  # 'before' needs no policy


def test_approve_errors_and_versioning(client):
    assert client.post(f"{API}/policy/pol_404/approve", json={"answers": []}).json()["error"]["code"] == "POLICY_NOT_FOUND"
    d = client.post(f"{API}/policy/compile", json={"policy_text": scenario.DEFAULT_POLICY_TEXT, "mode": "fixture"}).json()
    bad = client.post(f"{API}/policy/{d['policy_id']}/approve", json={"answers": [{"ambiguity_id": "A1", "option_id": "A9_O9"}]})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "VALIDATION_ERROR"
    partial = client.post(f"{API}/policy/{d['policy_id']}/approve", json={"answers": [{"ambiguity_id": "A1", "option_id": "A1_O1"}]})
    assert partial.json()["error"]["details"]["missing_ambiguity_ids"] == ["A2"]
    v1 = client.post(f"{API}/policy/{d['policy_id']}/approve", json=demo_answers(d))
    assert v1.status_code == 200 and v1.json()["policy_version"] == 1
    again = client.post(f"{API}/policy/{d['policy_id']}/approve", json=demo_answers(d))
    assert (again.status_code, again.json()["error"]["code"]) == (409, "POLICY_ALREADY_APPROVED")
    d2 = client.post(f"{API}/policy/compile", json={"policy_text": scenario.DEFAULT_POLICY_TEXT.replace("5,000", "8,000"), "mode": "fixture"}).json()
    v2 = client.post(f"{API}/policy/{d2['policy_id']}/approve", json=demo_answers(d2)).json()
    assert v2["policy_version"] == 2
    assert [r["change"] for r in v2["diff"]].count("changed") + [r["change"] for r in v2["diff"]].count("added") >= 1
    assert [r["change"] for r in v2["diff"]].count("unchanged") == 3 or "removed" in [r["change"] for r in v2["diff"]]
    assert client.get(f"{API}/policy/active").json()["policy_version"] == 2
    assert client.get(f"{API}/health").json()["active_policy_version"] == 2


def test_tests_run_policy_not_active_and_twice(client):
    old = client.post(f"{API}/policy/compile", json={"policy_text": scenario.DEFAULT_POLICY_TEXT, "mode": "fixture"}).json()
    api_approve(client)
    r = client.post(f"{API}/tests/run", json={"policy_id": old["policy_id"]})
    assert (r.status_code, r.json()["error"]["code"]) == (409, "POLICY_NOT_ACTIVE")
    first, second = client.post(f"{API}/tests/run").json(), client.post(f"{API}/tests/run", json={}).json()
    assert first["report_id"] != second["report_id"] and client.get(f"{API}/reports/latest").json()["report_id"] == second["report_id"]


def test_chat_validation_and_missing_customer(client):
    api_approve(client)
    assert client.post(f"{API}/agent/chat", json={"message": "x" * 2001}).json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.post(f"{API}/agent/chat", json={"message": "   "}).status_code == 422
    r = client.post(f"{API}/agent/chat", json={"message": "hi", "extra_field": 1})
    assert r.status_code == 422 and r.json()["error"]["details"]["fields"] == ["extra_field"]
    r = client.post(f"{API}/agent/chat", json={"message": "hi", "session_customer_id": "C-9999"})
    assert (r.status_code, r.json()["error"]["code"]) == (404, "CUSTOMER_NOT_FOUND")
    r = client.post(f"{API}/agent/chat", content="{bad json", headers={"content-type": "application/json"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.post(f"{API}/agent/chat", json={"message": "hi", "enforcement": "maybe"}).status_code == 422


def test_reset_scopes(client):
    api_approve(client)
    client.post(f"{API}/agent/chat", json={"message": "Refund \u20b91,000 for order ORD-1001.", "agent_mode": "naive"})
    r = client.post(f"{API}/state/reset", json={"scope": "C-1001"}).json()
    assert (r["cleared_refunds"], r["cleared_decisions"]) == (1, 1)
    assert client.post(f"{API}/state/reset", json={"scope": "C-7777"}).json()["error"]["code"] == "CUSTOMER_NOT_FOUND"
    assert client.post(f"{API}/state/reset").json()["scope"] == "all"
    assert client.get(f"{API}/policy/active").status_code == 200  # reset keeps the approved policy


def test_decisions_newest_first_and_limit_bounds(client):
    api_approve(client)
    for n in (1000, 1100, 1200):
        client.post(f"{API}/agent/chat", json={"message": f"Refund \u20b9{n} for order ORD-1001.", "agent_mode": "naive"})
    ds = client.get(f"{API}/decisions?limit=2").json()
    assert ds["total"] == 3 and ds["limit"] == 2 and [d["args"]["amount_inr"] for d in ds["decisions"]] == [1200, 1100]
    for bad in ("0", "201", "abc"):
        assert client.get(f"{API}/decisions?limit={bad}").json()["error"]["code"] == "VALIDATION_ERROR"
    assert client.get(f"{API}/decisions?limit=200").status_code == 200


def test_cases_endpoint_lists_the_twelve(client):
    cs = client.get(f"{API}/tests/cases").json()
    assert cs["total"] == 12 and [c["case_id"] for c in cs["cases"]] == [f"T{i:02d}" for i in range(1, 13)]
    assert sum(c["type"] == "attack" for c in cs["cases"]) == 6


def test_no_trailing_slash_redirects_and_errors_are_contract_shaped(client):
    r = client.get(f"{API}/health/", follow_redirects=False)
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"
    r = client.delete(f"{API}/health")
    assert r.status_code == 405 and r.json()["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert r.headers["x-contract-version"] == CONTRACT_VERSION


def test_unexpected_exception_is_a_contract_shaped_500_not_a_stack_trace(eng, monkeypatch):
    c = TestClient(create_app(eng, init_llm=False), raise_server_exceptions=False)
    monkeypatch.setattr(eng, "health", lambda: (_ for _ in ()).throw(RuntimeError("secret internals")))
    r = c.get(f"{API}/health")
    assert r.status_code == 500 and r.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "secret internals" not in r.text and "Traceback" not in r.text and r.headers["x-contract-version"] == CONTRACT_VERSION


def test_cors_allows_only_configured_origins_and_exposes_contract_header(eng, monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://app.example.com, http://localhost:5173/")
    c = TestClient(create_app(eng, init_llm=False))
    pre = c.options(f"{API}/agent/chat", headers={"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST",
                                                  "Access-Control-Request-Headers": "content-type"})
    assert pre.status_code == 200 and pre.headers["access-control-allow-origin"] == "https://app.example.com"
    ok = c.get(f"{API}/health", headers={"Origin": "http://localhost:5173"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "x-contract-version" in ok.headers["access-control-expose-headers"].lower()
    err = c.get(f"{API}/nope", headers={"Origin": "http://localhost:5173"})
    assert err.status_code == 404 and err.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in c.get(f"{API}/health", headers={"Origin": "https://evil.example"}).headers


def test_simultaneous_chats_through_the_api_allow_exactly_two(eng):
    app = create_app(eng, init_llm=False)
    api_approve(TestClient(app))
    barrier, outs = threading.Barrier(12), []

    def worker() -> None:
        c = TestClient(app)
        barrier.wait()
        r = c.post(f"{API}/agent/chat", json={"message": "Refund \u20b94,900 for order ORD-1003.", "agent_mode": "naive"})
        outs.append(r.json()["decisions"][0]["outcome"])

    ts = [threading.Thread(target=worker) for _ in range(12)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert outs.count("allow") == 2 and outs.count("deny") == 10


def _walk(obj: Any, path: str = ""):
    if ".tools" in path:  # tool specs describe parameter TYPES as strings; not money values
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
            if k.endswith("_inr") or k == "max_total" or (k == "value" and obj.get("operator") == "gt"):
                yield path + "." + k, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def test_money_is_an_integer_everywhere(client):
    api_approve(client)
    client.post(f"{API}/agent/chat", json={"message": "Refund \u20b94,900 for order ORD-1003.", "agent_mode": "naive"})
    payloads = [client.get(f"{API}/scenario").json(), client.get(f"{API}/policy/active").json(), client.get(f"{API}/decisions").json(),
                client.post(f"{API}/tests/run").json()]
    seen = 0
    for p in payloads:
        for path, v in _walk(p):
            assert isinstance(v, int) and not isinstance(v, bool), f"{path} = {v!r}"
            seen += 1
    assert seen > 30


def test_response_models_do_not_leak_extra_fields(client):
    api_approve(client)
    d = client.post(f"{API}/policy/compile", json={"policy_text": scenario.DEFAULT_POLICY_TEXT, "mode": "fixture"}).json()
    assert set(d) == {"policy_id", "created_at", "policy_text", "compiled_by", "clauses", "ambiguities", "warnings"}
    assert set(d["ambiguities"][0]) == {"ambiguity_id", "clause_id", "question", "options", "default_option_id"}
    assert set(d["ambiguities"][0]["options"][0]) == {"option_id", "label", "description"}


def test_decision_object_has_exactly_the_documented_fields(eng):
    approve_default(eng)
    for _ in range(4):
        refund(eng, "ORD-1002", 2400)
    d = refund(eng, "ORD-1002", 2400).model_dump()
    assert list(d) == ["decision_id", "timestamp", "tool", "args", "session_customer_id", "enforced", "outcome", "executed", "clause_id",
                       "source_sentence", "reason", "policy_version", "state_before", "state_after", "latency_ms", "tool_result"]
    assert d["reason"] == "Customer C-1001 would reach \u20b912,000 in the rolling 24-hour window (limit \u20b910,000; already \u20b99,600 + this \u20b92,400)."
    assert d["source_sentence"] == "A customer's total refunds in any rolling 24-hour period cannot exceed \u20b910,000."
    assert d["timestamp"].endswith("Z") and len(d["timestamp"]) == 24 and d["decision_id"].startswith("dec_")


# ================================================================ B3: the contract does not drift
def test_typescript_types_match_models():
    from generate_types import OUT, render

    assert OUT.read_text(encoding="utf-8") == render(), "types/api.d.ts is out of date: run `python generate_types.py`"


def test_every_model_forbids_extra_fields():
    import models

    for m in models.ALL_MODELS:
        assert m.model_config.get("extra") == "forbid", m.__name__
