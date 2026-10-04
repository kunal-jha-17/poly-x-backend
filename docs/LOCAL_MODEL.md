# Running a local or open-source model

The server treats every model as an OpenAI-compatible `/chat/completions` endpoint, so nothing in the code is
specific to one runtime. Three ways to meet the "local or open-source model at the core" deliverable, from most
to least dependable.

## A. Everything on the laptop (recommended for the finale)
The model and the backend run on the laptop; the phone reaches the backend.

```bash
# 1. model
ollama pull qwen2.5:3b            # or any instruct model you have; `ollama list` shows them
ollama serve                      # serves http://localhost:11434
curl http://localhost:11434/v1/models

# 2. backend, pointed at it
cd backend
LOCAL_LLM_BASE_URL=http://localhost:11434/v1 LOCAL_LLM_MODEL=qwen2.5:3b \
POLYX_AUTOARM=1 CORS_ORIGINS=https://<your-frontend-origin> \
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 1

curl http://localhost:8000/api/v1/models      # local: "available": true
```

The phone app is served over HTTPS, and a browser will not let an HTTPS page call `http://<laptop-ip>:8000`. So
give the laptop backend an HTTPS address with a tunnel (for example `cloudflared tunnel --url http://localhost:8000`
or ngrok) and open the app with `?api=<tunnel-url>`. The tunnel needs internet; the model itself does not.

`GROQ_API_KEY` can stay set as well: `auto` tries local first and falls back to cloud, then to the rule parser.

## B. Backend on Render, model on the laptop
Tunnel the model instead of the backend, then tell the hosted server where it is. No redeploy:

```bash
cloudflared tunnel --url http://localhost:11434      # prints https://<random>.trycloudflare.com

curl -X PUT $API/api/v1/models/local -H 'Content-Type: application/json' \
  -H "X-Admin-Token: $POLYX_ADMIN_TOKEN" \
  -d '{"base_url":"https://<random>.trycloudflare.com/v1","model":"qwen2.5:3b"}'
# the response shows local.available and, if false, local.last_error in plain words
```

If the tunnel answers 403, the model server is rejecting the tunnel's Host header; start the tunnel with a
host-header override for `localhost:11434` (cloudflared: `--http-host-header`). The setting is lost when the
Render instance restarts, so keep the curl command ready. This path has more moving parts than A.

## C. On the phone itself (stretch)
The frontend runs a small model in the browser, using the prompt from `GET /api/v1/policy/prompt`, and posts the
model's raw JSON as `proposal` to `POST /api/v1/policy/compile`. The server runs it through the same gate and
labels the draft `compiler.provider: "device"`. If the proposal fails the gate, the rule parser answers and the
draft says so. The backend side of this is done and tested; the in-browser model is frontend work and depends
on the phone.

## Which model
Compiling is a small structured-output task. A 3 to 4 billion parameter instruct model is a reasonable
starting point; what matters is that it returns valid JSON and copies numbers faithfully. The gate catches both
failures (bad JSON, an invented number) and falls back, so a weaker model costs you accuracy on the benchmark,
never a wrong rule in front of the reviewer. Local timeouts default to 60 s for compile and 90 s for the agent
(`LOCAL_LLM_TIMEOUT_S`, `LOCAL_LLM_AGENT_TIMEOUT_S`).

Tool calling (the live agent) is harder for small models than compiling. If the local model fumbles it, the
turn falls back to the scripted agent and the response says so in `agent_note`. For the demo, the scripted
agent is the repeatable choice anyway; the local model's job is the compile step.

## Get your benchmark number
```bash
cd backend
LOCAL_LLM_BASE_URL=http://localhost:11434/v1 LOCAL_LLM_MODEL=qwen2.5:3b python bench_compile.py --provider local
# or against a running server:  python bench_compile.py --base-url $API --provider local
```
It writes `measurements/compile_bench_local.md`. Read three numbers: exact matches out of 16, clause match
rate, and "fell back" (policies where the model failed the gate and the rule parser answered). Quote it as
"N of 16 on our own reference set, with every miss caught by the gate or shown to the reviewer".

## Pre-flight (finale)
1. `ollama serve` running, `curl localhost:11434/v1/models` lists your model.
2. `GET /api/v1/models`: local `available: true`. If not, `POST /api/v1/models/refresh` and read `last_error`.
3. Compile one new sentence with `"provider":"local"` and check `compiler.provider` is `local`.
4. Pull the network cable test: stop Ollama, compile again, confirm the draft still arrives and is labelled
   as the rule parser. That is your fallback working.
