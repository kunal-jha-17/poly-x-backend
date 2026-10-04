// POLY-X guard for TypeScript / JavaScript agents. No dependencies: copy this file next to your agent.
//
//   const guard = new PolyX("https://your-polyx-host", { scenario: "devops" });
//   const deploy = guard.tool("deploy", async (args: { service: string; environment: string }) => realDeploy(args));
//   await deploy({ service: "payments-api", environment: "production" });   // throws NeedsApproval (ticket CHG-0001)
//
// The decision is made by POLY-X's deterministic engine, never by a model. If the guard cannot be reached the
// call is BLOCKED (fail closed).

export type Outcome = "allow" | "deny" | "escalate";

export interface Verdict {
  allowed: boolean;
  outcome: Outcome;
  clause_id: string | null;
  source_sentence?: string | null;
  reason: string;
  ticket_id: string | null;
  policy_version?: number | null;
  latency_ms?: number;
}

export class Blocked extends Error {
  constructor(public verdict: Verdict) {
    super(`blocked by policy ${verdict.clause_id ?? "(fail closed)"}: ${verdict.reason}`);
    this.name = "Blocked";
  }
}

export class NeedsApproval extends Blocked {
  ticketId: string | null;
  constructor(verdict: Verdict) {
    super(verdict);
    this.name = "NeedsApproval";
    this.ticketId = verdict.ticket_id;
  }
}

export class PolyX {
  private url: string;
  constructor(
    baseUrl: string,
    private opts: { scenario?: string; sessionId?: string; timeoutMs?: number } = {},
  ) {
    this.url = baseUrl.replace(/\/$/, "") + "/api/v1/guard/check";
  }

  /**
   * By default the call is recorded: it counts toward multi-step limits and an escalation opens a ticket in the
   * approval inbox. dryRun = true only asks "would this be allowed?" - nothing is recorded, counted or held.
   */
  async check(tool: string, args: Record<string, unknown>, dryRun = false): Promise<Verdict> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs ?? 5000);
    try {
      const res = await fetch(this.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          tool,
          args,
          scenario: this.opts.scenario ?? "support",
          dry_run: dryRun,
          ...(this.opts.sessionId ? { session_customer_id: this.opts.sessionId } : {}),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as Verdict;
    } catch (err) {
      return {
        allowed: false,
        outcome: "deny",
        clause_id: null,
        ticket_id: null,
        reason: `Policy guard unreachable (${(err as Error).name}); failing closed.`,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async enforce(tool: string, args: Record<string, unknown>, dryRun = false): Promise<Verdict> {
    const verdict = await this.check(tool, args, dryRun);
    if (verdict.outcome === "escalate") throw new NeedsApproval(verdict);
    if (!verdict.allowed) throw new Blocked(verdict);
    return verdict;
  }

  /** Wrap a tool: the function only runs if the policy allows the call. */
  tool<A extends Record<string, unknown>, R>(name: string, fn: (args: A) => Promise<R> | R) {
    return async (args: A): Promise<R> => {
      await this.enforce(name, args);
      return fn(args);
    };
  }
}
