# API reference (contract v1.1.0)

Base path `/api/v1`. JSON in, JSON out, snake_case, no trailing slashes. Every response carries
`X-Contract-Version`. Shapes are named after the models in `backend/models.py`; the same names are in
`types/api.d.ts`. A real recorded response for almost every row is in `fixtures/`.

Also outside the prefix: `GET /` (service info) and `GET|HEAD /healthz` (for uptime pingers).

## Errors

Always `{"error": {"code": "...", "message": "...", "details": {...} | null}}`. The message is written to be
shown to a person.

| Code | HTTP | When |
| --- | --- | --- |
| `VALIDATION_ERROR` | 422 | Body or query did not match. `details.fields` lists them. |
| `COMPILE_FAILED` | 422 | No supported rule in the text. The message lists what is supported. |
| `AMBIGUITY_UNRESOLVED` | 422 | Approve without all answers. `details.missing_ambiguity_ids`. |
| `IMPORT_INVALID`, `CASE_INVALID` | 422 | A clause file or a test case failed the gate. |
| `NO_ACTIVE_POLICY` | 404 on read, 409 on action | Nothing approved yet for that scenario. |
| `POLICY_NOT_FOUND`, `REPORT_NOT_FOUND`, `NO_REPORT`, `VERSION_NOT_FOUND`, `CASE_NOT_FOUND`, `APPROVAL_NOT_FOUND`, `SCENARIO_NOT_FOUND`, `CUSTOMER_NOT_FOUND`, `NO_BENCH` | 404 | The named thing does not exist. |
| `POLICY_ALREADY_APPROVED`, `POLICY_NOT_ACTIVE`, `APPROVAL_ALREADY_RESOLVED`, `BENCH_RUNNING` | 409 | State conflict. |
| `ADMIN_REQUIRED` | 403 | `PUT /models/local` without a valid `X-Admin-Token`. |
| `PAYLOAD_TOO_LARGE` | 413 | Body over 64 KB. |
| `RATE_LIMITED` | 429 | `Retry-After` header and `details.retry_after_s`. |
| `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `INTERNAL_ERROR` | 404, 405, 500 | Safety nets, same shape. |

## Scenarios

Almost every endpoint takes a scenario: `support` (default) or `devops`. On GET and DELETE it is the query
parameter `scenario`; on POST it is the body field `scenario`. Each scenario has its own active policy, version
numbers, ledger, custom cases and latest report. In devops, `session_customer_id` is the engineer id (`U-2001`).

## Endpoints

### service

| Method | Path | Body | Returns | Query |
| --- | --- | --- | --- | --- |
| GET | `/health` |  | `Health` |  |
| GET | `/scenario` |  | `Scenario` | scenario |
| GET | `/scenarios` |  | `ScenariosResponse` |  |

### models

| Method | Path | Body | Returns | Query |
| --- | --- | --- | --- | --- |
| GET | `/models` |  | `ModelsResponse` |  |
| POST | `/models/refresh` |  | `ModelsResponse` |  |
| PUT | `/models/local` | `LocalModelConfig` | `ModelsResponse` |  |

### policy

| Method | Path | Body | Returns | Query |
| --- | --- | --- | --- | --- |
| POST | `/policy/compile` | `CompileRequest` | `PolicyDraft` |  |
| GET | `/policy/prompt` |  | `PromptResponse` | scenario |
| POST | `/policy/import` | `PolicyBundle` | `PolicyDraft` |  |
| POST | `/policy/rollback` | `RollbackRequest` | `ApprovedPolicy` |  |
| POST | `/policy/{policy_id}/approve` | `ApproveRequest` | `ApprovedPolicy` |  |
| GET | `/policy/active` |  | `ApprovedPolicy` | scenario |
| GET | `/policy/history` |  | `PolicyHistoryResponse` | scenario |
| GET | `/policy/diff` |  | `PolicyDiffResponse` | from_version, to_version, scenario |
| GET | `/policy/export` |  | `PolicyBundle` | scenario, version |
| GET | `/policy/versions/{version}` |  | `ApprovedPolicy` | scenario |

### runtime

| Method | Path | Body | Returns | Query |
| --- | --- | --- | --- | --- |
| POST | `/guard/check` | `GuardRequest` | `GuardResponse` |  |
| POST | `/agent/chat` | `ChatRequest` | `ChatResponse` |  |
| GET | `/approvals` |  | `ApprovalsResponse` | status, scenario, limit |
| GET | `/approvals/{ticket_id}` |  | `Approval` |  |
| POST | `/approvals/{ticket_id}/resolve` | `ResolveRequest` | `ApprovalResolution` |  |
| POST | `/state/reset` | `ResetRequest` | `ResetResponse` |  |
| GET | `/decisions` |  | `DecisionsResponse` | limit, scenario, outcome |

### tests

| Method | Path | Body | Returns | Query |
| --- | --- | --- | --- | --- |
| GET | `/tests/cases` |  | `CasesResponse` | scenario |
| POST | `/tests/cases` | `CaseCreate` | `CaseSpec` |  |
| DELETE | `/tests/cases` |  | `CasesResponse` | scenario |
| DELETE | `/tests/cases/{case_id}` |  | `CasesResponse` | scenario |
| POST | `/tests/generate` | `GenerateRequest` | `GenerateResponse` |  |
| POST | `/tests/run` | `RunTestsRequest` | `TestReport` |  |
| GET | `/reports/latest` |  | `TestReport` | scenario |
| GET | `/reports/{report_id}` |  | `TestReport` |  |
| GET | `/reports/{report_id}/junit` |  | text |  |
| GET | `/reports/{report_id}/markdown` |  | text |  |
| POST | `/ci/run` | `CiRunRequest` | `CiRunResponse` |  |
| POST | `/bench/compile` | `BenchRequest` | `BenchStatus` |  |
| GET | `/bench/compile/latest` |  | `BenchStatus` |  |

### audit

| Method | Path | Body | Returns | Query |
| --- | --- | --- | --- | --- |
| GET | `/audit` |  | `AuditResponse` | limit, scenario, type |
| GET | `/audit/verify` |  | `AuditVerifyResponse` |  |
| GET | `/audit/export` |  | text | format |

## Notes per area

### Compile and who compiled
`POST /policy/compile` body: `policy_text` (required), `scenario`, `mode` (`auto` | `fixture`, v1.0.0),
`provider` (`auto` | `local` | `cloud` | `fixture`, overrides `mode`), `source` (`typed` | `voice` | `ocr` |
`share` | `file`), and optionally `proposal` + `proposal_model`.

- `provider: "local"` means "try local first"; if it is unreachable or fails the gate, the next compiler
  answers and `warnings` says so. The demo never dead-ends on a model.
- `source: "ocr"` re-joins lines that a camera scan wrapped and returns the cleaned text in `policy_text`. Show
  that text back in the editor.
- `proposal` is for a model running on the phone: fetch `GET /policy/prompt`, run the model with that system
  prompt, send its raw JSON here. It passes the same gate; `compiler.provider` comes back as `device`.

The draft tells you who really answered:

```json
"compiled_by": "llm",
"compiler": {"provider": "local", "model": "qwen2.5:3b", "location": "local",
             "label": "Local open-source model · qwen2.5:3b", "latency_ms": 1840.2,
             "attempts": [{"provider": "local", "model": "qwen2.5:3b", "ok": true, "latency_ms": 1839.9, "error": null}]},
"validation": [{"check": "numbers_grounded", "passed": true, "detail": "..."}]
```

`compiled_by` stays `llm` | `fixture` (plus `import`). `compiler.provider` is the precise one: `local`, `cloud`,
`device`, `rules`, `import`. `fixture` / `rules` is the deterministic rule parser: it reads your text, it is
not a canned answer.

### Approve
`POST /policy/{policy_id}/approve` body `{answers: [{ambiguity_id, option_id}], approved_by?}`. Returns the
`ApprovedPolicy` with `policy_version` (per scenario) and `diff` against the previous version.

### Chat, guard and the approval inbox
- `POST /agent/chat` runs the demo agent. New response fields: `scenario_id`, `agent_model`, and `approvals`
  (tickets this turn opened).
- `POST /guard/check` is the same interceptor without an agent: `{tool, args, scenario, dry_run}`.
  `dry_run: true` evaluates only: nothing executes, nothing is recorded, no ticket.
- Every `escalate` creates an `Approval` (`TKT-0001` for support, `CHG-0001` for devops). Poll
  `GET /approvals?status=pending` (it is cheap; `GET /health` also carries `pending_approvals`).
- `POST /approvals/{ticket_id}/resolve` body `{action: "approve" | "reject", approver, note?}`. On approve the
  held call is evaluated again: the escalate rule is satisfied by the human, every deny rule still applies. So
  `approval.status` can be `approved` while `approval.result_outcome` is `deny`. Show `result_reason`.
- `POST /state/reset` body `{scope: "all" | "<actor id>", scenario?}` also clears approvals. It keeps policies,
  custom cases and the audit trail.

### Decisions
`Decision` gained `scenario_id`, `ticket_id`, `approved_by`, `dry_run`. `state_before` / `state_after` gained a
scenario-neutral view: `subject`, `unit` (`inr` | `deploys`), `total`, `count`. For support these mirror the
v1.0.0 refund fields; for devops they count deploys to the environment.

### Tests
- `GET /tests/cases` returns built-in plus custom cases; each has `origin` (`builtin` | `custom` | `generated`).
- `POST /tests/cases` adds one. `expected_outcomes` is optional: for an attack it is recorded from the active
  policy, and the harmful step is never expected to be `allow`, so an attack the policy does not stop becomes a
  failing case instead of a silent pass.
- `POST /tests/generate` body `{scenario, count, provider, save}`. Returns `cases` (caught, added to the suite),
  `uncaught` (the policy allowed them: show these prominently, they are never auto-added), `rejected`, `notes`,
  and `generated_by` (`llm` | `mutation`).
- `POST /tests/run` body `{scenario, include_custom}`. The report gained `passed`, `exit_code`,
  `failed_case_ids`, `builtin_case_count`, `custom_case_count`, `scenario_id`.
- `GET /reports/{id}/junit` and `/markdown` return text. `{id}` may be `latest`.
- `POST /ci/run` is stateless: it never changes the active policy or `/reports/latest`, but the report can be
  opened by id (`ci_0001`).
- `POST /bench/compile` starts in the background and returns at once; poll `GET /bench/compile/latest` until
  `status` is not `running`.

### Rate limits to design around
300 requests a minute per client, and 60 a minute across compile, chat, generate, ci/run, bench and
models/refresh together. `/health` is exempt. Polling approvals every 3 seconds is 20 a minute.
