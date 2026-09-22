"""Runs the 12 fixed cases twice on identical scripted steps: firewall OFF ("before") and ON ("after").

Each run uses its own fresh Ledger and a simulated clock, so a test run never touches the live demo
state. The ON run uses the SAME approved clauses the live agent uses (one policy drives both).
"""
import math
import statistics
from datetime import datetime, timedelta
from typing import List, Optional

from cases import CLAUSE_KIND, build_cases
from engine import Ledger, iso, next_decision_id, run_call
from models import (
    ApprovedPolicy, CaseResult, CaseSpec, ClauseCoverage, LatencySummary, Metrics, RunResult, TestReport,
)

LIMITATIONS = [
    "The 12 fixed cases are scripted tool-call sequences that simulate an agent that was already manipulated. "
    "They test whether the tool boundary holds; they do not test any language model.",
    "All numbers in this report cover these 12 scripted cases only. They are not a general security benchmark.",
    "Latency is the time spent evaluating rules inside the server process. It is not end-to-end network time.",
    "Enforcement is at the tool-call boundary. It does not stop prompt injection or text-only harms; "
    "OS-level sandboxing is a roadmap item, not part of this prototype.",
    "Compiled rules are only as good as the human review and the tests. A rule the policy never states is not enforced.",
    "Examples are illustrative and are not legal advice.",
]


def _run_case(case: CaseSpec, enforcement: str, policy: Optional[ApprovedPolicy], base: datetime) -> RunResult:
    ledger = Ledger()
    decisions = []
    for i, step in enumerate(case.steps):
        now = base + timedelta(hours=step.at_offset_hours, seconds=i)
        decisions.append(run_call(
            tool=step.tool, args=step.args, session_customer_id=case.session_customer_id, enforcement=enforcement,
            policy=policy, ledger=ledger, now=now, decision_id=next_decision_id(),
        ))
    outcomes = [d.outcome for d in decisions]
    harmful = case.harm_step is not None and decisions[case.harm_step].executed
    return RunResult(outcomes=outcomes, harmful_action_executed=harmful, all_allowed=all(o == "allow" for o in outcomes), decisions=decisions)


def _rate(n: int, d: int) -> float:
    return round(n / d, 4) if d else 0.0


def _latency(values: List[float]) -> LatencySummary:
    if not values:
        return LatencySummary(scope="in_process_rule_evaluation", samples=0, mean_ms=0.0, median_ms=0.0, p95_ms=0.0, max_ms=0.0)
    s = sorted(values)
    p95 = s[max(0, math.ceil(0.95 * len(s)) - 1)]  # nearest-rank
    return LatencySummary(
        scope="in_process_rule_evaluation", samples=len(s), mean_ms=round(statistics.fmean(s), 4),
        median_ms=round(statistics.median(s), 4), p95_ms=round(p95, 4), max_ms=round(s[-1], 4),
    )


def run_suite(policy: ApprovedPolicy, report_id: str, now: datetime) -> TestReport:
    cases = build_cases()
    first_of_kind = {}
    for c in policy.clauses:
        first_of_kind.setdefault(c.kind, c)  # a case resolves to the FIRST clause of its kind

    results: List[CaseResult] = []
    latencies: List[float] = []
    for case in cases:
        base = now - timedelta(hours=max(s.at_offset_hours for s in case.steps))
        without = _run_case(case, "off", None, base)
        with_ = _run_case(case, "on", policy, base)
        latencies += [d.latency_ms for d in with_.decisions]
        clause = first_of_kind.get(CLAUSE_KIND[case.clause_id])
        results.append(CaseResult(
            case_id=case.case_id, clause_id=clause.clause_id if clause else None, type=case.type, title=case.title,
            expected_outcomes=case.expected_outcomes, matches_expected=with_.outcomes == case.expected_outcomes,
            without_firewall=without, with_firewall=with_,
        ))

    attacks = [r for r in results if r.type == "attack"]
    benign = [r for r in results if r.type == "benign"]
    kind_of = {c.case_id: CLAUSE_KIND[c.clause_id] for c in cases}
    cumulative = [r for r in attacks if kind_of[r.case_id] == "cumulative_limit"]
    coverage = []
    for c in policy.clauses:
        a_ids = [r.case_id for r in attacks if r.clause_id == c.clause_id]
        b_ids = [r.case_id for r in benign if r.clause_id == c.clause_id]
        coverage.append(ClauseCoverage(clause_id=c.clause_id, source_sentence=c.source_sentence,
                                       attack_case_ids=a_ids, benign_case_ids=b_ids, covered=bool(a_ids)))
    won_without = sum(r.without_firewall.harmful_action_executed for r in attacks)
    won_with = sum(r.with_firewall.harmful_action_executed for r in attacks)
    benign_ok = sum(r.with_firewall.all_allowed for r in benign)
    metrics = Metrics(
        attack_cases=len(attacks), attacks_succeeded_without_firewall=won_without, attacks_succeeded_with_firewall=won_with,
        attack_success_rate_without_firewall=_rate(won_without, len(attacks)),
        attack_success_rate_with_firewall=_rate(won_with, len(attacks)),
        benign_cases=len(benign), benign_passed_with_firewall=benign_ok,
        benign_pass_rate_with_firewall=_rate(benign_ok, len(benign)),
        cumulative_attack_cases=len(cumulative),
        cumulative_attacks_caught=sum(not r.with_firewall.harmful_action_executed for r in cumulative),
        clauses_total=len(policy.clauses), clauses_with_attack_tests=sum(c.covered for c in coverage),
        cases_matching_expected=sum(r.matches_expected for r in results),
    )
    return TestReport(
        report_id=report_id, created_at=iso(now), policy_id=policy.policy_id, policy_version=policy.policy_version,
        compiled_by=policy.compiled_by, case_count=len(results), metrics=metrics, coverage=coverage,
        latency=_latency(latencies), cases=results, limitations=LIMITATIONS,
    )
