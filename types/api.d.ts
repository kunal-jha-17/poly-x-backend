// GENERATED from backend/models.py by backend/generate_types.py. DO NOT EDIT BY HAND.
// Contract change process: brief Part C4 (edit models.py, regenerate, bump CONTRACT_VERSION, tell Gaurav).

export declare const CONTRACT_VERSION: "1.0.0";

export type Outcome = "allow" | "deny" | "escalate";
export type Enforcement = "on" | "off";
export type AgentModeRequest = "auto" | "naive" | "llm";
export type AgentModeUsed = "naive" | "llm";
export type CompiledBy = "llm" | "fixture";
export type CompileMode = "auto" | "fixture";
export type ClauseKind = "per_txn_limit" | "cumulative_limit" | "data_scope" | "precondition";
export type ClauseAction = "deny" | "escalate";
export type CaseType = "attack" | "benign";
export type OrderStatus = "delivered" | "shipped" | "processing";
export type DiffChange = "added" | "changed" | "removed" | "unchanged";
export type ToolName = "lookup_order" | "issue_refund" | "fetch_customer_data";
export type ErrorCode = "VALIDATION_ERROR" | "COMPILE_FAILED" | "AMBIGUITY_UNRESOLVED" | "POLICY_NOT_FOUND" | "REPORT_NOT_FOUND" | "CUSTOMER_NOT_FOUND" | "NO_ACTIVE_POLICY" | "POLICY_ALREADY_APPROVED" | "POLICY_NOT_ACTIVE" | "NO_REPORT" | "NETWORK_ERROR" | "BAD_JSON" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" | "INTERNAL_ERROR";

export interface ErrorBody {
  code: ErrorCode;
  message: string;
  details: Record<string, unknown> | null;
}

export interface ErrorEnvelope {
  error: ErrorBody;
}

export interface PerTxnParams {
  field: "amount_inr";
  operator: "gt";
  value: number;
  scope: "transaction" | "customer_24h";
}

export interface CumulativeParams {
  field: "amount_inr";
  max_total: number;
  window_hours: number;
  window_type: "rolling" | "calendar_day";
  scope: "customer";
}

export interface DataScopeParams {
  subject: "session_customer";
}

export interface PreconditionParams {
  field: "order.status";
  operator: "eq";
  value: OrderStatus;
}

export interface Clause {
  clause_id: string;
  source_sentence: string;
  kind: ClauseKind;
  action: ClauseAction;
  params: PerTxnParams | CumulativeParams | DataScopeParams | PreconditionParams;
}

export interface RefundState {
  customer_id: string;
  refund_total_24h_inr: number;
  refund_count_24h: number;
  window_hours: number;
}

export interface Decision {
  decision_id: string;
  timestamp: string;
  tool: string;
  args: Record<string, unknown>;
  session_customer_id: string;
  enforced: boolean;
  outcome: Outcome;
  executed: boolean;
  clause_id: string | null;
  source_sentence: string | null;
  reason: string;
  policy_version: number | null;
  state_before: RefundState;
  state_after: RefundState;
  latency_ms: number;
  tool_result: Record<string, unknown> | null;
}

export interface Health {
  status: "ok";
  contract_version: string;
  llm_available: boolean;
  active_policy_version: number | null;
}

export interface ToolSpec {
  name: ToolName;
  description: string;
  params: Record<string, string>;
}

export interface Customer {
  customer_id: string;
  name: string;
}

export interface Order {
  order_id: string;
  customer_id: string;
  status: OrderStatus;
  amount_inr: number;
  item: string;
  note: string | null;
}

export interface AttackPreset {
  preset_id: string;
  title: string;
  description: string;
  clause_id: string;
  message: string;
  repeat: number;
}

export interface Scenario {
  session_customer_id: string;
  default_policy_text: string;
  tools: ToolSpec[];
  customers: Customer[];
  orders: Order[];
  attack_presets: AttackPreset[];
}

export interface CompileRequest {
  policy_text: string;
  mode?: CompileMode;
}

export interface AmbiguityOption {
  option_id: string;
  label: string;
  description: string;
}

export interface Ambiguity {
  ambiguity_id: string;
  clause_id: string;
  question: string;
  options: AmbiguityOption[];
  default_option_id: string;
}

export interface PolicyDraft {
  policy_id: string;
  created_at: string;
  policy_text: string;
  compiled_by: CompiledBy;
  clauses: Clause[];
  ambiguities: Ambiguity[];
  warnings: string[];
}

export interface AmbiguityAnswer {
  ambiguity_id: string;
  option_id: string;
}

export interface ApproveRequest {
  answers?: AmbiguityAnswer[];
}

export interface DiffRow {
  clause_id: string;
  change: DiffChange;
  source_sentence: string;
  detail: string | null;
}

export interface ApprovedPolicy {
  policy_id: string;
  policy_version: number;
  approved_at: string;
  policy_text: string;
  compiled_by: CompiledBy;
  clauses: Clause[];
  answers: AmbiguityAnswer[];
  diff: DiffRow[];
}

export interface ChatRequest {
  message: string;
  session_customer_id?: string;
  enforcement?: Enforcement;
  agent_mode?: AgentModeRequest;
}

export interface ChatResponse {
  reply: string;
  agent_mode_used: AgentModeUsed;
  agent_note: string | null;
  enforcement: Enforcement;
  session_customer_id: string;
  decisions: Decision[];
  state: RefundState;
}

export interface ResetRequest {
  scope?: string;
}

export interface ResetResponse {
  scope: string;
  cleared_refunds: number;
  cleared_decisions: number;
  reset_at: string;
}

export interface DecisionsResponse {
  decisions: Decision[];
  total: number;
  limit: number;
}

export interface CaseStep {
  tool: string;
  args: Record<string, unknown>;
  at_offset_hours: number;
}

export interface CaseSpec {
  case_id: string;
  clause_id: string;
  type: CaseType;
  title: string;
  description: string;
  session_customer_id: string;
  steps: CaseStep[];
  harm_step: number | null;
  expected_outcomes: Outcome[];
}

export interface CasesResponse {
  cases: CaseSpec[];
  total: number;
}

export interface RunTestsRequest {
  policy_id?: string | null;
}

export interface RunResult {
  outcomes: Outcome[];
  harmful_action_executed: boolean;
  all_allowed: boolean;
  decisions: Decision[];
}

export interface CaseResult {
  case_id: string;
  clause_id: string | null;
  type: CaseType;
  title: string;
  expected_outcomes: Outcome[];
  matches_expected: boolean;
  without_firewall: RunResult;
  with_firewall: RunResult;
}

export interface ClauseCoverage {
  clause_id: string;
  source_sentence: string;
  attack_case_ids: string[];
  benign_case_ids: string[];
  covered: boolean;
}

export interface LatencySummary {
  scope: "in_process_rule_evaluation";
  samples: number;
  mean_ms: number;
  median_ms: number;
  p95_ms: number;
  max_ms: number;
}

export interface Metrics {
  attack_cases: number;
  attacks_succeeded_without_firewall: number;
  attacks_succeeded_with_firewall: number;
  attack_success_rate_without_firewall: number;
  attack_success_rate_with_firewall: number;
  benign_cases: number;
  benign_passed_with_firewall: number;
  benign_pass_rate_with_firewall: number;
  cumulative_attack_cases: number;
  cumulative_attacks_caught: number;
  clauses_total: number;
  clauses_with_attack_tests: number;
  cases_matching_expected: number;
}

export interface TestReport {
  report_id: string;
  created_at: string;
  policy_id: string;
  policy_version: number;
  compiled_by: CompiledBy;
  case_count: number;
  metrics: Metrics;
  coverage: ClauseCoverage[];
  latency: LatencySummary;
  cases: CaseResult[];
  limitations: string[];
}
