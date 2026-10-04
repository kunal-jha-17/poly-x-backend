#!/usr/bin/env python3
"""polyx-ci: test an agent policy in CI. Standard library only: copy this one file into any repo.

    python polyx_ci.py --api https://your-polyx-host --policy policy.md
    python polyx_ci.py --api https://your-polyx-host --lock policy.lock.json --scenario devops

What it does:
  1. wakes the server (free hosts sleep) and waits for /health,
  2. POSTs the policy to /api/v1/ci/run - stateless, the live policy is never touched,
  3. writes JUnit XML, a Markdown summary and the full JSON report,
  4. exits 0 if every case behaved as expected, 1 if a case failed (an attack ran, a legitimate call was
     blocked, or a rule is missing), 2 if the run itself could not happen (server down, policy did not compile).

--policy  plain-English rules, one per line (your policy.md). Compiled by the deterministic rule parser by default,
          so the same file gives the same result on every run.
--lock    a clause file exported from POLY-X (GET /api/v1/policy/export). Tests exactly the reviewed clauses,
          with the answers a human gave. This is the one to commit and gate merges on.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

EXIT_PASS, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def call(method: str, url: str, body: Optional[Dict[str, Any]] = None, timeout: float = 60.0) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", "User-Agent": "polyx-ci/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw), dict(exc.headers)
        except json.JSONDecodeError:
            return exc.code, {"error": {"code": "BAD_JSON", "message": raw[:200]}}, dict(exc.headers)


def wake(base: str, budget_s: float) -> Dict[str, Any]:
    deadline, delay, last = time.monotonic() + budget_s, 2.0, "no answer"
    while True:
        try:
            status, body, _ = call("GET", f"{base}/health", timeout=20)
            if status == 200 and body.get("status") == "ok":
                return body
            last = f"HTTP {status}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = type(exc).__name__
        if time.monotonic() + delay > deadline:
            sys.exit(_fatal(f"POLY-X server did not wake up within {budget_s:.0f}s ({last})."))
        print(f"polyx-ci: waiting for the server ({last}) ...", file=sys.stderr)
        time.sleep(delay)
        delay = min(delay * 1.6, 15.0)


def _fatal(message: str) -> int:
    print(f"polyx-ci: ERROR: {message}", file=sys.stderr)
    return EXIT_ERROR


def main() -> int:
    ap = argparse.ArgumentParser(prog="polyx-ci", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default=os.getenv("POLYX_API"), help="server base URL, e.g. https://polyx.onrender.com (or env POLYX_API)")
    ap.add_argument("--policy", help="path to policy.md (plain-English rules)")
    ap.add_argument("--lock", help="path to an exported clause file (polyx.policy/v1 JSON)")
    ap.add_argument("--scenario", default=None, help="support (default) or devops; a lock file carries its own")
    ap.add_argument("--compiler", default="fixture", choices=["fixture", "auto", "local", "cloud"],
                    help="who proposes clauses from --policy. fixture = deterministic rule parser (default, repeatable)")
    ap.add_argument("--junit", default="polyx-junit.xml")
    ap.add_argument("--summary", default="polyx-summary.md")
    ap.add_argument("--json", default="polyx-report.json", dest="json_out")
    ap.add_argument("--wake-timeout", type=float, default=120.0, help="seconds to wait for a sleeping server")
    a = ap.parse_args()
    if not a.api:
        return _fatal("--api (or env POLYX_API) is required.")
    if not a.policy and not a.lock:
        return _fatal("give --policy policy.md or --lock policy.lock.json.")
    base = a.api.rstrip("/") + "/api/v1"

    body: Dict[str, Any] = {"provider": a.compiler}
    try:
        if a.lock:
            bundle = json.loads(open(a.lock, encoding="utf-8").read())
            if bundle.get("format") != "polyx.policy/v1":
                return _fatal(f"{a.lock} is not a polyx.policy/v1 file.")
            body.update(policy_text=bundle["policy_text"], clauses=bundle["clauses"], scenario=a.scenario or bundle.get("scenario_id", "support"))
        if a.policy:
            body["policy_text"] = open(a.policy, encoding="utf-8").read()
            body.setdefault("scenario", a.scenario or "support")
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        return _fatal(f"could not read the policy: {exc}")

    health = wake(base, a.wake_timeout)
    print(f"polyx-ci: server ok (contract {health.get('contract_version')}), scenario {body['scenario']}", file=sys.stderr)
    for _ in range(3):
        status, result, headers = call("POST", f"{base}/ci/run", body, timeout=120)
        if status != 429:
            break
        time.sleep(min(60, int(headers.get("Retry-After", "5"))))
    if status != 200:
        err = result.get("error", {})
        return _fatal(f"{err.get('code', status)}: {err.get('message', 'request failed')}")

    with open(a.junit, "w", encoding="utf-8") as f:
        f.write(result["junit_xml"])
    with open(a.summary, "w", encoding="utf-8") as f:
        f.write(result["markdown"])
    with open(a.json_out, "w", encoding="utf-8") as f:
        json.dump(result["report"], f, indent=2, ensure_ascii=False)
    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(result["markdown"] + "\n")

    print(result["summary"])
    for w in result.get("warnings", []):
        print(f"  warning: {w}")
    for case in result["report"]["cases"]:
        failed = case["case_id"] in result["report"]["failed_case_ids"]
        print(f"  {'FAIL' if failed else 'ok  '} {case['case_id']} [{case['type']}] {case['title']}"
              + (f"  expected {case['expected_outcomes']} got {case['with_firewall']['outcomes']}" if failed else ""))
    print(f"wrote {a.junit}, {a.summary}, {a.json_out}", file=sys.stderr)
    return EXIT_PASS if result["exit_code"] == 0 else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
