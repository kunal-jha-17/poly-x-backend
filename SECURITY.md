# Security notes

## What is in place
- **No secrets in the repo.** Keys come from the host's environment. `.env` is git-ignored; `.env.example` has no values.
- **CORS** is limited to `CORS_ORIGINS` (plus an optional regex). No credentials are allowed.
- **Rate limits** per client: 300 requests a minute, 60 a minute on endpoints that can spend model tokens. `429` with `Retry-After`.
- **Input caps:** 64 KB request body, 5,000 characters of policy text, 2,000 characters per chat message, 8 steps per test case.
- **Strict request models:** unknown fields are rejected.
- **No stack traces** in responses; every error has the same `{error: {code, message, details}}` shape.
- **Runtime model switch** (`PUT /models/local`) is off unless `POLYX_ADMIN_TOKEN` is set, and then needs that token.
- **The audit trail never stores tool results**, so a secret leaked in the "firewall off" demo is not copied into it.
- **API keys are never returned.** `/models` shows a host name, not a URL or key.

## Prompt injection: what this does and does not do
POLY-X does not try to detect or remove injected text. A model can still be fooled by an order note or a file that
says "ignore your instructions". What POLY-X does is make sure the fooled model cannot turn that into an action:
every tool call is checked by deterministic code against clauses a human approved, and the model has no way to
change those clauses.

The compiler prompt marks policy text as data and the gate rejects anything that is not a valid, grounded clause,
so a policy file cannot instruct the compiler into inventing a rule. A human still approves every clause.

Not covered: harmful text replies with no tool call, attacks on tools that are not behind the guard, and
commands obfuscated to slip past the shell deny-list (use allow-list mode).

## Known gaps (prototype)
No user authentication, one shared in-memory state, one admin token, audit log not signed or stored off-host.
