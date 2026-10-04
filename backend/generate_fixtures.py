"""Write REAL responses from the reference API into ../fixtures (they feed the frontend's offline / mock mode).

Run when the contract or the built-in cases change:
    python generate_fixtures.py
Files are named NN_<name>_<http status>.json and hold the raw response body the API returned.
Uses the fixture compiler and the naive agent, so output is repeatable (ids and timestamps aside).
"""
import json
import pathlib
import shutil
from typing import Any, Dict

from fastapi.testclient import TestClient

from app import create_app
from engine import Engine

API = "/api/v1"
OUT = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    c = TestClient(create_app(Engine(), init_llm=False))
    n = 0

    def save(name: str, resp: Any) -> Dict[str, Any]:
        nonlocal n
        n += 1
        body = resp.json()
        (OUT / f"{n:02d}_{name}_{resp.status_code}.json").write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return body

    def chat(msg: str, enforcement: str, **extra: Any) -> Any:
        return c.post(f"{API}/agent/chat", json={"message": msg, "enforcement": enforcement, "agent_mode": "naive", **extra})

    # ---- before any policy exists
    save("health", c.get(f"{API}/health"))
    sc = save("scenario", c.get(f"{API}/scenario"))
    presets = {p["preset_id"]: p["message"] for p in sc["attack_presets"]}
    save("policy_active_no_policy", c.get(f"{API}/policy/active"))
    save("chat_no_active_policy", chat("hi", "on"))
    save("tests_run_no_active_policy", c.post(f"{API}/tests/run"))
    save("reports_latest_no_report", c.get(f"{API}/reports/latest"))
    save("compile_failed", c.post(f"{API}/policy/compile", json={"policy_text": "Be friendly.", "mode": "fixture"}))
    save("validation_error", c.post(f"{API}/agent/chat", json={"message": ""}))
    # ---- compile + approve
    draft = save("compile_draft", c.post(f"{API}/policy/compile", json={"policy_text": sc["default_policy_text"], "mode": "fixture"}))
    pid = draft["policy_id"]
    save("approve_ambiguity_unresolved", c.post(f"{API}/policy/{pid}/approve"))
    save("approve_policy_not_found", c.post(f"{API}/policy/pol_999/approve", json={"answers": []}))
    answers = {"answers": [{"ambiguity_id": a["ambiguity_id"], "option_id": a["default_option_id"]} for a in draft["ambiguities"]]}
    save("approve_ok_v1", c.post(f"{API}/policy/{pid}/approve", json=answers))
    save("approve_already_approved", c.post(f"{API}/policy/{pid}/approve", json=answers))
    save("policy_active", c.get(f"{API}/policy/active"))
    # ---- live agent: before / after
    save("chat_off_manager_override", chat(presets["fake_manager_override"], "off"))
    c.post(f"{API}/state/reset", json={"scope": "all"})
    save("chat_on_manager_override_escalate", chat(presets["fake_manager_override"], "on"))
    c.post(f"{API}/state/reset", json={"scope": "all"})
    for i in range(1, 6):
        r = chat(presets["split_refund"], "on")
        if i in (1, 5):
            save(f"chat_split_refund_{i}", r)
    save("chat_order_note_injection", chat(presets["order_note_injection"], "on"))
    save("chat_other_customer_record", chat(presets["other_customer_record"], "on"))
    save("chat_customer_not_found", chat("hi", "on", session_customer_id="C-9999"))
    save("decisions", c.get(f"{API}/decisions?limit=10"))
    save("state_reset_all", c.post(f"{API}/state/reset", json={"scope": "all"}))
    # ---- fixed cases + report
    save("tests_cases", c.get(f"{API}/tests/cases"))
    rep = save("tests_run", c.post(f"{API}/tests/run"))
    save("reports_latest", c.get(f"{API}/reports/latest"))
    save("reports_by_id", c.get(f"{API}/reports/{rep['report_id']}"))
    save("report_not_found", c.get(f"{API}/reports/rep_9999"))

    # ================================================================ added in v1.1.0 (files 29+)
    def save_text(name: str, resp: Any, ext: str) -> None:
        nonlocal n
        n += 1
        (OUT / f"{n:02d}_{name}_{resp.status_code}.{ext}").write_text(resp.text, encoding="utf-8")

    c.post(f"{API}/state/reset", json={"scope": "all"})
    save("scenarios", c.get(f"{API}/scenarios"))
    ops = save("scenario_devops", c.get(f"{API}/scenario?scenario=devops"))
    save("models", c.get(f"{API}/models"))
    save("policy_prompt", c.get(f"{API}/policy/prompt"))
    # ---- devops: compile, approve, live, approval inbox
    ddraft = save("devops_compile_draft", c.post(f"{API}/policy/compile", json={"policy_text": ops["default_policy_text"], "mode": "fixture", "scenario": "devops"}))
    danswers = {"answers": [{"ambiguity_id": a["ambiguity_id"], "option_id": a["default_option_id"]} for a in ddraft["ambiguities"]]}
    save("devops_approve_ok_v1", c.post(f"{API}/policy/{ddraft['policy_id']}/approve", json=danswers))
    dpresets = {p["preset_id"]: p["message"] for p in ops["attack_presets"]}

    def dchat(msg: str, enforcement: str) -> Any:
        return c.post(f"{API}/agent/chat", json={"message": msg, "enforcement": enforcement, "agent_mode": "naive", "scenario": "devops"})

    save("devops_chat_off_wipe_database", dchat(dpresets["wipe_database"], "off"))
    save("devops_chat_on_wipe_database", dchat(dpresets["wipe_database"], "on"))
    save("devops_chat_on_release_notes_injection", dchat(dpresets["release_notes_injection"], "on"))
    save("devops_chat_on_fake_cto_escalate", dchat(dpresets["fake_cto_approval"], "on"))
    save("chat_on_manager_override_opens_ticket", chat(presets["fake_manager_override"], "on"))
    save("approvals_pending", c.get(f"{API}/approvals?status=pending"))
    save("approval_resolve_approve", c.post(f"{API}/approvals/TKT-0001/resolve", json={"action": "approve", "approver": "Asha (phone)", "note": "Verified with the customer."}))
    save("approval_resolve_reject", c.post(f"{API}/approvals/CHG-0001/resolve", json={"action": "reject", "approver": "Asha (phone)"}))
    save("approval_already_resolved", c.post(f"{API}/approvals/TKT-0001/resolve", json={"action": "approve"}))
    save("approvals_all", c.get(f"{API}/approvals"))
    # ---- guard API
    save("guard_allow", c.post(f"{API}/guard/check", json={"tool": "issue_refund", "args": {"order_id": "ORD-1005", "amount_inr": 1500}}))
    save("guard_deny", c.post(f"{API}/guard/check", json={"tool": "fetch_customer_data", "args": {"customer_id": "C-1002"}}))
    save("guard_dry_run_escalate", c.post(f"{API}/guard/check", json={"tool": "deploy", "args": {"service": "payments-api", "environment": "production"}, "scenario": "devops", "dry_run": True}))
    # ---- policy as code
    d2 = c.post(f"{API}/policy/compile", json={"policy_text": sc["default_policy_text"].replace("5,000", "8,000"), "mode": "fixture"}).json()
    c.post(f"{API}/policy/{d2['policy_id']}/approve", json={"answers": [{"ambiguity_id": a["ambiguity_id"], "option_id": a["default_option_id"]} for a in d2["ambiguities"]]})
    save("policy_history", c.get(f"{API}/policy/history"))
    save("policy_diff_v1_v2", c.get(f"{API}/policy/diff?from_version=1&to_version=2"))
    bundle = save("policy_export_v1", c.get(f"{API}/policy/export?version=1"))
    save("policy_import_draft", c.post(f"{API}/policy/import", json=bundle))
    save("policy_rollback_v3", c.post(f"{API}/policy/rollback", json={"version": 1}))
    # ---- custom + generated cases, reports, CI
    save("tests_case_added", c.post(f"{API}/tests/cases", json={"type": "attack", "title": "Six thousand on a watch",
                                                                "steps": [{"tool": "issue_refund", "args": {"order_id": "ORD-1003", "amount_inr": 6000}}]}))
    save("tests_generate_mutation", c.post(f"{API}/tests/generate", json={"provider": "fixture"}))
    save("tests_cases_with_custom", c.get(f"{API}/tests/cases"))
    save("tests_run_with_custom", c.post(f"{API}/tests/run"))
    save("devops_tests_run", c.post(f"{API}/tests/run", json={"scenario": "devops"}))
    save_text("report_junit", c.get(f"{API}/reports/latest/junit"), "xml")
    save_text("report_markdown", c.get(f"{API}/reports/latest/markdown"), "md")
    save("ci_run_pass", c.post(f"{API}/ci/run", json={"policy_text": sc["default_policy_text"]}))
    save("ci_run_fail_missing_rule", c.post(f"{API}/ci/run", json={"policy_text": "\n".join(sc["default_policy_text"].split("\n")[:3])}))
    # ---- audit, health, errors
    save("audit", c.get(f"{API}/audit?limit=20"))
    save("audit_verify", c.get(f"{API}/audit/verify"))
    save("health_armed", c.get(f"{API}/health"))
    save("scenario_not_found", c.get(f"{API}/scenario?scenario=nope"))
    save("models_local_admin_required", c.put(f"{API}/models/local", json={"base_url": "http://localhost:11434/v1", "model": "qwen2.5:3b"}))
    print(f"wrote {n} fixtures to {OUT}")


if __name__ == "__main__":
    main()
