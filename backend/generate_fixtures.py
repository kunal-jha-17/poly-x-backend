"""Write REAL responses from the reference API into ../fixtures (they feed Gaurav's mock).

Run only when the contract or the fixed cases change, then tell Gaurav:
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
    print(f"wrote {n} fixtures to {OUT}")


if __name__ == "__main__":
    main()
