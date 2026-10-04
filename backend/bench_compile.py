"""Compile benchmark: how often does a compiler turn plain English into the right clauses?

16 varied policies (10 support, 6 devops), each with a HAND-WRITTEN reference: the clauses a careful human
would expect. The reference is not produced by any compiler in this repo, so the rule parser is scored on the
same footing as a model.

Two numbers per run:
  exact match   every clause of the policy (kind + every parameter) equals the reference, nothing extra
  clause match  reference clauses reproduced exactly / all reference clauses

Run it from the app (POST /api/v1/bench/compile) or from a terminal:

    python bench_compile.py --provider fixture                 # the rule parser, in process
    LOCAL_LLM_BASE_URL=http://localhost:11434/v1 LOCAL_LLM_MODEL=qwen2.5:3b python bench_compile.py --provider local
    python bench_compile.py --base-url https://<host> --provider cloud   # against a running server

16 policies is a smoke benchmark, not a research result. Quote it as "N of 16 on our own reference set".
"""
import argparse
import json
import pathlib
import sys
import time
from typing import Any, Dict, List, Tuple

NOTE = ("16 policies with hand-written reference clauses. Exact match = every clause's kind and parameters equal the "
        "reference. A model that fails the gate is replaced by the rule parser and counted under 'fell back'. "
        "The rule parser was written with these phrasings in view, so its own score is a regression check, not an "
        "independent measure; a model's score is. This is a small in-house reference set, not a general benchmark.")

PER = lambda v, scope="transaction": ("per_txn_limit", {"field": "amount_inr", "operator": "gt", "value": v, "scope": scope})  # noqa: E731
CUM = lambda m, h=24, w="rolling": ("cumulative_limit", {"field": "amount_inr", "max_total": m, "window_hours": h, "window_type": w, "scope": "customer"})  # noqa: E731
SCOPE = ("data_scope", {"subject": "session_customer"})
PRE = ("precondition", {"field": "order.status", "operator": "eq", "value": "delivered"})
ENV = lambda *e: ("env_approval", {"field": "environment", "operator": "in", "environments": list(e)})  # noqa: E731
RATE = lambda n, h=24, w="rolling": ("deploy_rate_limit", {"field": "deploy_count", "max_count": n, "window_hours": h, "window_type": w, "scope": "environment"})  # noqa: E731
SECRET = ("secret_protection", {"subject": "secret_values"})
BLOCK = lambda mode="denylist": ("command_block", {"category": "destructive", "mode": mode})  # noqa: E731

CORPUS: List[Dict[str, Any]] = [
    {"id": "S01", "scenario": "support", "text": "Refunds above \u20b95,000 require human approval.\nA customer's total refunds in any rolling 24-hour period cannot exceed \u20b910,000.\nNever reveal another customer's data.\nNever refund an order that has not been delivered.",
     "expected": [PER(5000), CUM(10000), SCOPE, PRE]},
    {"id": "D01", "scenario": "devops", "text": "Deploys to production require human approval.\nNo more than 3 deploys to the same environment in any rolling 24-hour period.\nNever print or reveal secret values.\nNever run destructive shell commands.",
     "expected": [ENV("production"), RATE(3), SECRET, BLOCK()]},
    {"id": "S02", "scenario": "support", "text": "Any refund greater than 3k rupees must be reviewed by a human.", "expected": [PER(3000)]},
    {"id": "S03", "scenario": "support", "text": "Cap total refunds per customer at \u20b98,000 per calendar day.", "expected": [CUM(8000, 24, "calendar_day")]},
    {"id": "D02", "scenario": "devops", "text": "Any release to prod or staging must be signed off by a human.", "expected": [ENV("staging", "production")]},
    {"id": "S04", "scenario": "support", "text": "The agent must never share details of a different customer.\nOnly refund orders that were delivered.", "expected": [SCOPE, PRE]},
    {"id": "S05", "scenario": "support", "text": "Refunds of more than INR 7500 need manager approval.\nBe polite and concise.", "expected": [PER(7500)]},
    {"id": "D03", "scenario": "devops", "text": "Limit deployments to five per calendar day per environment.", "expected": [RATE(5, 24, "calendar_day")]},
    {"id": "S06", "scenario": "support", "text": "Refund requests exceeding 1 lakh rupees must be escalated for manual review.", "expected": [PER(100000)]},
    {"id": "S07", "scenario": "support", "text": "Customers cannot receive more than \u20b920,000 in refunds in any rolling 48-hour period.", "expected": [CUM(20000, 48)]},
    {"id": "D04", "scenario": "devops", "text": "The agent must not log API keys or passwords.\nDo not execute dangerous commands such as rm -rf or force-push.", "expected": [SECRET, BLOCK()]},
    {"id": "S08", "scenario": "support", "text": "No refunds before delivery.\nDon't disclose someone else's order information.", "expected": [PRE, SCOPE]},
    {"id": "S09", "scenario": "support", "text": "1. Refunds above Rs. 2,500 per single transaction require human approval.\n2. A customer's total refunds in any rolling 24-hour period cannot exceed Rs. 6,000.", "expected": [PER(2500), CUM(6000)]},
    {"id": "D05", "scenario": "devops", "text": "Only read-only shell commands may be run; destructive commands are forbidden.", "expected": [BLOCK("allowlist")]},
    {"id": "S10", "scenario": "support", "text": "A refund above five thousand rupees requires approval.\nNever refund an order that has not been delivered.\nNever reveal another customer's data.", "expected": [PER(5000), PRE, SCOPE]},
    {"id": "D06", "scenario": "devops", "text": "Production deploys need approval from a human reviewer.\nNo more than two deploys to the same environment in any rolling 12-hour period.\nNever reveal secrets.", "expected": [ENV("production"), RATE(2, 12), SECRET]},
]


def _key(kind: str, params: Dict[str, Any]) -> str:
    return json.dumps([kind, params], sort_keys=True)


def score(expected: List[Tuple[str, Dict[str, Any]]], got: List[Tuple[str, Dict[str, Any]]]) -> Tuple[int, bool]:
    want, have = [_key(k, p) for k, p in expected], [_key(k, p) for k, p in got]
    matched = sum(1 for w in want if w in have)
    return matched, sorted(want) == sorted(have)


def run_item(engine: Any, entry: Dict[str, Any], provider: str) -> Any:
    from compiler import CompileError
    from models import BenchItem

    pack = engine._pack(entry["scenario"])
    t0 = time.perf_counter()
    try:
        compiled, compiled_by, info, _ = engine._compile_text(entry["text"], pack, provider)
        got = [(c.kind, c.params.model_dump()) for c in compiled.clauses]
        matched, exact = score(entry["expected"], got)
        used, error = info.provider, None
    except CompileError as exc:
        matched, exact, compiled_by, used, error = 0, False, None, None, str(exc)[:160]
    return BenchItem(item_id=entry["id"], scenario_id=entry["scenario"], policy_text=entry["text"],
                     expected_clauses=len(entry["expected"]), matched_clauses=matched, exact=exact, compiled_by=compiled_by,
                     provider=used, latency_ms=round((time.perf_counter() - t0) * 1000, 1), error=error)


def _sheet(b: Dict[str, Any]) -> str:
    rows = "\n".join(f"| {i['item_id']} | {i['scenario_id']} | {i['matched_clauses']}/{i['expected_clauses']} | "
                     f"{'yes' if i['exact'] else 'NO'} | {i['provider'] or 'none'} | {i['latency_ms']} ms |" for i in b["items"])
    return f"""# Compile benchmark ({b['started_at']})
Requested compiler: `{b['requested_provider']}`{f" (model `{b['model']}`)" if b['model'] else ""}

| Metric | Value |
| --- | --- |
| Policies with every clause exactly right | **{b['exact_matches']} of {b['total']}** ({b['exact_match_rate']:.0%}) |
| Reference clauses reproduced | {b['clause_matches']} of {b['clause_total']} ({b['clause_match_rate']:.0%}) |
| Policies where the model failed the gate and the rule parser answered | {b['fell_back']} |
| Median compile time | {b['median_latency_ms']} ms |

| Policy | Scenario | Clauses matched | Exact | Answered by | Time |
| --- | --- | --- | --- | --- | --- |
{rows}

{b['note']}
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", default="auto", choices=["auto", "local", "cloud", "fixture"])
    ap.add_argument("--base-url", default=None, help="run against a server (https://host); omit to run in process")
    ap.add_argument("--out", default="measurements")
    a = ap.parse_args()
    if a.base_url:
        import httpx

        base = a.base_url.rstrip("/") + "/api/v1"
        with httpx.Client(timeout=30) as c:
            r = c.post(f"{base}/bench/compile", json={"provider": a.provider})
            if r.status_code >= 400:
                sys.exit(f"could not start: {r.status_code} {r.text[:200]}")
            while True:
                b = c.get(f"{base}/bench/compile/latest").json()
                print(f"\r{b['completed']}/{b['total']}", end="", flush=True)
                if b["status"] != "running":
                    break
                time.sleep(2)
        print()
    else:
        from engine import Engine
        from models import BenchRequest

        eng = Engine()
        if a.provider != "fixture":
            eng.init_providers()
            print("providers:", {n: (p.model, p.available, p.last_error) for n, p in eng.providers.items()} or "none configured")
        eng.start_bench(BenchRequest(provider=a.provider))
        while eng.latest_bench().status == "running":
            time.sleep(0.2)
        b = eng.latest_bench().model_dump()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = b["started_at"].replace(":", "").replace("-", "")[:15]
    (out / f"compile_bench_{a.provider}_{stamp}.json").write_text(json.dumps(b, indent=2, ensure_ascii=False), encoding="utf-8")
    sheet = _sheet(b)
    (out / f"compile_bench_{a.provider}.md").write_text(sheet, encoding="utf-8")
    print(sheet)


if __name__ == "__main__":
    main()
