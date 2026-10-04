# Deploying on Render

## If your service already exists (the usual case)
1. Replace the repo contents with this version and push. Keep the service's **root directory** as `backend`.
2. In the Render dashboard, check the commands:
   - **Native Python runtime:** build `pip install -r requirements.txt`, start
     `uvicorn app:app --host 0.0.0.0 --port $PORT --workers 1`
   - **Docker runtime:** nothing to change; `backend/Dockerfile` is used.
3. Environment tab, add or confirm:

   | Key | Value |
   | --- | --- |
   | `CORS_ORIGINS` | your frontend origin, e.g. `https://poly-x.vercel.app` (no trailing slash; comma separate several) |
   | `GROQ_API_KEY` | your existing key (unchanged) |
   | `POLYX_AUTOARM` | `1` |
   | `POLYX_ADMIN_TOKEN` | a long random string (only if you want to switch the local model at runtime) |

   `groq` is no longer a dependency; the server talks to Groq over plain HTTPS. You can remove nothing else.
4. Health check path (Settings): `/healthz`.

A new service can use `render.yaml` at the repo root as a blueprint instead.

## Verify after the deploy (2 minutes)
Replace `$API` with your Render URL.

```bash
curl -s $API/api/v1/health
# expect: "contract_version":"1.1.0", "auto_armed":true, both scenarios with "active_policy_version":1
#         models[].available true for "cloud" a few seconds after boot (it is probed in the background)

curl -s -X POST $API/api/v1/guard/check -H 'Content-Type: application/json' \
  -d '{"tool":"issue_refund","args":{"order_id":"ORD-1001","amount_inr":7500}}'
# expect: "outcome":"escalate","clause_id":"C1","ticket_id":"TKT-0001"

curl -s -X POST $API/api/v1/tests/run -H 'Content-Type: application/json' -d '{"scenario":"devops"}' | head -c 300
# expect: "case_count":12 ... and further down "passed":true

python ci/polyx_ci.py --api $API --lock examples/support.policy.lock.json; echo "exit $?"
# expect: PASS: 12/12 ... exit 0
```

Then one real model check, because the model paths were only tested against stand-ins:

```bash
curl -s -X POST $API/api/v1/policy/compile -H 'Content-Type: application/json' \
  -d '{"policy_text":"Refunds over ₹2,345 need a manager'"'"'s sign-off.","provider":"cloud"}'
# good: "compiled_by":"llm" and compiler.provider "cloud", value 2345
# if you see compiled_by "fixture": read compiler.attempts[0].error and GET /api/v1/models (last_error)
```

## Keeping it awake
A free instance sleeps after about 15 minutes idle and takes up to a minute to wake. Startup itself is now fast
(the server no longer waits for the model before opening the port), but the platform's wake-up time remains.

- Best: upgrade the instance for the finale days.
- Otherwise: an external monitor hitting `GET` or `HEAD $API/healthz` every 5 minutes, plus
  `.github/workflows/keep-warm.yml` as a second line (set the `POLYX_API` repository variable). GitHub cron can
  run late, so do not rely on it alone.
- With `POLYX_AUTOARM=1`, even a full restart comes back with both default policies active.

## What a restart loses
Everything in memory: approved policies beyond the default, custom cases, reports, the audit trail and any local
model set through `PUT /models/local`. Before the pitch: wake the server, approve your demo policy, run one
suite, and do not redeploy afterwards.
