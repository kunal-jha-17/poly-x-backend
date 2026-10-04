# Changelog

## 1.1.0 (4 October 2026)
Additive over 1.0.0. Every 1.0.0 endpoint, field and error keeps its meaning.

### Added
- **Scenario packs.** A second agent, `devops` (`run_shell`, `deploy`, `read_secret`), on the same engine, with
  four rule kinds, 12 built-in cases and attack presets. `GET /scenarios`; `scenario` on most endpoints.
- **Model providers.** Local and cloud models behind one OpenAI-compatible layer, tried in order with automatic
  fallback to the rule parser. `GET /models`, `POST /models/refresh`, `PUT /models/local` (admin token).
  Drafts and policies carry `compiler` (who really proposed the clauses) and `validation` (what the gate checked).
- **On-device proposals.** `proposal` on `/policy/compile` and `GET /policy/prompt`.
- **Grounding check.** A number in a proposed clause must appear in the sentence it cites.
- **Camera scans.** `source: "ocr"` re-joins wrapped lines before compiling.
- **Guard API.** `POST /guard/check`, with `dry_run`.
- **Approval inbox.** Escalations become tickets: `GET /approvals`, `POST /approvals/{id}/resolve`.
- **Policy as code.** History, version, diff, export, import, rollback.
- **Custom and generated cases.** `POST|DELETE /tests/cases`, `POST /tests/generate` (model or mutation, with a replay gate).
- **CI.** `POST /ci/run`, JUnit and Markdown report exports, `passed` / `exit_code` on reports, `ci/polyx_ci.py`.
- **Audit trail.** Hash-chained events: `GET /audit`, `/audit/verify`, `/audit/export`.
- **Compile benchmark.** `POST /bench/compile`, `bench_compile.py`, 16 hand-written references.
- **Hardening.** Rate limits, body cap, security headers, `CORS_ORIGIN_REGEX`.
- **Operations.** `HEAD /health`, `/healthz`, `POLYX_AUTOARM`, background model probing at startup.
- Customer `email` in `/scenario`; `safe_presets`.

### Changed
- When a model says a policy has no supported rule, that is believed only if the rule parser agrees. Otherwise
  the parser's rules are returned with a warning. (Was: always `COMPILE_FAILED`.)
- The rule parser understands more phrasings (word amounts, any N-hour window, "before delivery", totals
  without the word "total").
- `ChatRequest.session_customer_id` is optional and defaults to the scenario's session actor.
- The `groq` SDK dependency is gone; the server calls the same endpoint over HTTPS with `httpx`.
- Product name in titles and logs: POLY-X.

### Tests
186 (was 81). Four 1.0.0 tests were edited for the additive contract change; each edit is marked `v1.1.0:`.
