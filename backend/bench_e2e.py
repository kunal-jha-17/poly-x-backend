"""Brief B6: measure honestly and save every number as a file.

    python bench_e2e.py --base-url https://<host> --machine "Kunal's laptop, home Wi-Fi" --host "Render free, Singapore"

What it does (against a running server):
  1. POST /state/reset, make sure a policy is active (approves the DEFAULT answers if none is - benchmark only),
  2. POST /tests/run and save the full report JSON (the ONLY source for attack / benign / coverage / in-process latency),
  3. send 200 timed POST /agent/chat requests with enforcement off, then 200 with enforcement on (after 5 warm-ups),
     using a read-only 'look up order' message so state does not change; record median and p95,
  4. write measurements/measurement_sheet.md whose numbers are copied from those saved JSON files.
End-to-end time includes network from THIS machine to THAT host. Say so in the pitch; never call it rule latency.
"""
import argparse
import json
import math
import pathlib
import platform
import statistics
import time
from datetime import datetime, timezone

import httpx

MESSAGE = "Look up order ORD-1001"


def pct(sorted_vals, q):  # nearest rank
    return sorted_vals[max(0, math.ceil(q * len(sorted_vals)) - 1)]


def timed_chat(client, base, enforcement, n, warmup=5):
    body = {"message": MESSAGE, "enforcement": enforcement, "agent_mode": "naive"}
    for _ in range(warmup):
        client.post(f"{base}/agent/chat", json=body)
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = client.post(f"{base}/agent/chat", json=body)
        times.append((time.perf_counter() - t0) * 1000)
        if r.status_code != 200:
            raise SystemExit(f"chat failed ({enforcement}): {r.status_code} {r.text[:200]}")
    s = sorted(times)
    return {"samples": len(s), "median_ms": round(statistics.median(s), 2), "p95_ms": round(pct(s, 0.95), 2),
            "min_ms": round(s[0], 2), "max_ms": round(s[-1], 2)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True, help="e.g. https://host or http://localhost:8000 (no trailing slash)")
    ap.add_argument("--machine", default="UNSPECIFIED", help="the machine running this script")
    ap.add_argument("--host", default="UNSPECIFIED", help="the server host / plan being measured")
    ap.add_argument("--requests", type=int, default=200)
    ap.add_argument("--out", default="measurements")
    a = ap.parse_args()
    base = a.base_url.rstrip("/") + "/api/v1"
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    with httpx.Client(timeout=30) as c:
        health = c.get(f"{base}/health").json()
        c.post(f"{base}/state/reset", json={"scope": "all"})
        if c.get(f"{base}/policy/active").status_code == 404:
            sc = c.get(f"{base}/scenario").json()
            d = c.post(f"{base}/policy/compile", json={"policy_text": sc["default_policy_text"], "mode": "fixture"}).json()
            answers = [{"ambiguity_id": x["ambiguity_id"], "option_id": x["default_option_id"]} for x in d["ambiguities"]]
            c.post(f"{base}/policy/{d['policy_id']}/approve", json={"answers": answers}).raise_for_status()
        report = c.post(f"{base}/tests/run").json()
        (out / f"report_{report['report_id']}_{stamp}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        e2e = {
            "measured_at": stamp, "base_url": a.base_url, "machine": a.machine, "server_host": a.host,
            "client_python": platform.python_version(), "client_platform": platform.platform(),
            "message": MESSAGE, "agent_mode": "naive", "server_health": health,
            "enforcement_off": timed_chat(c, base, "off", a.requests), "enforcement_on": timed_chat(c, base, "on", a.requests),
        }
        c.post(f"{base}/state/reset", json={"scope": "all"})
    (out / f"e2e_{stamp}.json").write_text(json.dumps(e2e, indent=2), encoding="utf-8")

    m, lat = report["metrics"], report["latency"]
    sheet = f"""# Measurement sheet ({stamp})
Every number below is copied from the saved JSON files in this folder. Scope: the 12 scripted cases only.

## Fixed suite: report `{report['report_id']}` (policy v{report['policy_version']}, rules compiled by: {report['compiled_by']}, {report['case_count']} cases)
| Metric | Value |
| --- | --- |
| Attacks that executed WITHOUT firewall | {m['attacks_succeeded_without_firewall']} of {m['attack_cases']} |
| Attacks that executed WITH firewall | {m['attacks_succeeded_with_firewall']} of {m['attack_cases']} |
| Legitimate (benign) cases fully allowed | {m['benign_passed_with_firewall']} of {m['benign_cases']} |
| Cumulative (split-refund) attacks caught | {m['cumulative_attacks_caught']} of {m['cumulative_attack_cases']} |
| Clauses with at least one attack test | {m['clauses_with_attack_tests']} of {m['clauses_total']} |
| Cases matching expected outcomes | {m['cases_matching_expected']} of {report['case_count']} |
| In-process rule evaluation (report) | median {lat['median_ms']} ms, p95 {lat['p95_ms']} ms, n = {lat['samples']} |

## End-to-end `/agent/chat` (message: "{MESSAGE}", naive agent)
Client machine: {a.machine}. Server host: {a.host}. Includes network time.

| Enforcement | Median | p95 | Samples |
| --- | --- | --- | --- |
| off | {e2e['enforcement_off']['median_ms']} ms | {e2e['enforcement_off']['p95_ms']} ms | {e2e['enforcement_off']['samples']} |
| on | {e2e['enforcement_on']['median_ms']} ms | {e2e['enforcement_on']['p95_ms']} ms | {e2e['enforcement_on']['samples']} |

Limitations (from the report): {' | '.join(report['limitations'][:3])}
"""
    (out / "measurement_sheet.md").write_text(sheet, encoding="utf-8")
    print(sheet)


if __name__ == "__main__":
    main()
