"""CI-ready views of a test report: JUnit XML (test dashboards) and Markdown (pull-request / job summary).

Both are pure functions of a TestReport, so the JSON report stays the single source of truth.
A case is a JUnit <testcase>. It fails when the firewall's outcomes differ from the expected ones, or when an
attack's harmful step executed. report.exit_code (0 / 1) is what a CI job should exit with.
"""
from typing import List
from xml.sax.saxutils import escape, quoteattr

from models import CaseResult, TestReport


def _trace(case: CaseResult) -> str:
    lines: List[str] = []
    for i, d in enumerate(case.with_firewall.decisions):
        cite = f" [{d.clause_id}]" if d.clause_id else ""
        lines.append(f"step {i + 1}: {d.tool} {d.args} -> {d.outcome}{cite} (executed={str(d.executed).lower()}) {d.reason}")
    return "\n".join(lines)


def _failure_message(case: CaseResult) -> str:
    got, want = case.with_firewall.outcomes, case.expected_outcomes
    if case.type == "attack" and case.with_firewall.harmful_action_executed:
        if case.clause_id is None:
            return f"POLICY GAP: no {case.clause_kind or 'matching'} rule in this policy, so the attack executed."
        return f"ATTACK EXECUTED with the firewall on. Expected {want}, got {got}."
    if case.type == "benign":
        return f"LEGITIMATE CALL BLOCKED. Expected {want}, got {got}."
    return f"Outcomes changed. Expected {want}, got {got}."


def _failed(case: CaseResult) -> bool:
    return not case.matches_expected or (case.type == "attack" and case.with_firewall.harmful_action_executed)


def junit_xml(report: TestReport) -> str:
    failures = sum(_failed(c) for c in report.cases)
    suite = f"polyx.{report.scenario_id}"
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           f'<testsuites name="POLY-X policy tests" tests="{report.case_count}" failures="{failures}" errors="0">',
           f'  <testsuite name={quoteattr(suite)} tests="{report.case_count}" failures="{failures}" errors="0" skipped="0" '
           f'timestamp={quoteattr(report.created_at[:19])} time="{report.latency.mean_ms * report.latency.samples / 1000:.6f}">',
           "    <properties>",
           f'      <property name="report_id" value={quoteattr(report.report_id)}/>',
           f'      <property name="scenario" value={quoteattr(report.scenario_id)}/>',
           f'      <property name="policy_version" value="{report.policy_version}"/>',
           f'      <property name="compiled_by" value={quoteattr(report.compiled_by)}/>',
           f'      <property name="attacks_executed_without_firewall" value="{report.metrics.attacks_succeeded_without_firewall}/{report.metrics.attack_cases}"/>',
           f'      <property name="attacks_executed_with_firewall" value="{report.metrics.attacks_succeeded_with_firewall}/{report.metrics.attack_cases}"/>',
           f'      <property name="rule_eval_p95_ms" value="{report.latency.p95_ms}"/>',
           "    </properties>"]
    for c in report.cases:
        classname = f"{suite}.{c.clause_kind or 'unmapped'}"
        seconds = sum(d.latency_ms for d in c.with_firewall.decisions) / 1000
        name = f"{c.case_id} [{c.type}] {c.title}"
        out.append(f"    <testcase classname={quoteattr(classname)} name={quoteattr(name)} time=\"{seconds:.6f}\">")
        if _failed(c):
            out.append(f"      <failure type={quoteattr('PolicyGap' if c.clause_id is None else 'UnexpectedOutcome')} "
                       f"message={quoteattr(_failure_message(c))}>{escape(_trace(c))}</failure>")
        out.append(f"      <system-out>{escape(_trace(c))}</system-out>")
        out.append("    </testcase>")
    out += ["  </testsuite>", "</testsuites>", ""]
    return "\n".join(out)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def markdown_summary(report: TestReport) -> str:
    m, lat = report.metrics, report.latency
    verdict = "PASS" if report.passed else "FAIL"
    lines = [
        f"## POLY-X policy tests: {verdict}",
        "",
        f"Scenario `{report.scenario_id}` \u00b7 policy v{report.policy_version} \u00b7 rules proposed by `{report.compiled_by}` \u00b7 "
        f"report `{report.report_id}` \u00b7 {report.created_at}",
        "",
        "| | Without firewall | With firewall |",
        "| --- | --- | --- |",
        f"| Attacks that executed | {m.attacks_succeeded_without_firewall} of {m.attack_cases} | **{m.attacks_succeeded_with_firewall} of {m.attack_cases}** |",
        f"| Legitimate cases allowed | {m.benign_cases} of {m.benign_cases} | **{m.benign_passed_with_firewall} of {m.benign_cases}** |",
        "",
        f"- Cases matching expected outcomes: **{m.cases_matching_expected} of {report.case_count}** "
        f"({report.builtin_case_count} built-in, {report.custom_case_count} custom or generated)",
        f"- Multi-step attacks caught: {m.cumulative_attacks_caught} of {m.cumulative_attack_cases}",
        f"- Rules with at least one attack test: {m.clauses_with_attack_tests} of {m.clauses_total}",
        f"- Rule evaluation, in process: median {lat.median_ms} ms, p95 {lat.p95_ms} ms (n = {lat.samples})",
        "",
    ]
    failed = [c for c in report.cases if _failed(c)]
    if failed:
        lines += ["### Failures", "", "| Case | Type | What happened |", "| --- | --- | --- |"]
        lines += [f"| {c.case_id} {_cell(c.title)} | {c.type} | {_cell(_failure_message(c))} |" for c in failed]
        lines.append("")
    uncovered = [c for c in report.coverage if not c.covered]
    if uncovered:
        lines += ["### Rules with no attack test", ""]
        lines += [f"- `{c.clause_id}` {_cell(c.source_sentence)}" for c in uncovered]
        lines.append("")
    lines += ["<details><summary>All cases</summary>", "", "| Case | Type | Rule | Expected | Got | Result |", "| --- | --- | --- | --- | --- | --- |"]
    for c in report.cases:
        lines.append(f"| {c.case_id} {_cell(c.title)} | {c.type} | {c.clause_id or 'none'} | {' '.join(c.expected_outcomes)} | "
                     f"{' '.join(c.with_firewall.outcomes)} | {'fail' if _failed(c) else 'pass'} |")
    lines += ["", "</details>", "", "<details><summary>Limits of this report</summary>", ""]
    lines += [f"- {text}" for text in report.limitations]
    lines += ["", "</details>", ""]
    return "\n".join(lines)
