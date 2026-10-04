// GENERATED from backend/models.py by backend/generate_types.py. DO NOT EDIT BY HAND.
// Contract change process: edit models.py, run `python generate_types.py`, bump CONTRACT_VERSION.

export declare const CONTRACT_VERSION: "1.1.0";

export type Outcome = "allow" | "deny" | "escalate";
export type Enforcement = "on" | "off";
export type AgentModeRequest = "auto" | "naive" | "llm";
export type AgentModeUsed = "naive" | "llm";
export type CompiledBy = "llm" | "fixture" | "import";
export type CompileMode = "auto" | "fixture";
export type ProviderChoice = "auto" | "local" | "cloud" | "fixture";
export type CompilerProvider = "local" | "cloud" | "device" | "rules" | "import";
export type ModelLocation = "local" | "cloud" | "on_device" | "server";
export type PolicySource = "typed" | "voice" | "ocr" | "share" | "file";
export type ClauseKind = "per_txn_limit" | "cumulative_limit" | "data_scope" | "precondition" | "env_approval" | "deploy_rate_limit" | "secret_protection" | "command_block";
export type ClauseAction = "deny" | "escalate";
export type CaseType = "attack" | "benign";
export type CaseOrigin = "builtin" | "custom" | "generated";
export type OrderStatus = "delivered" | "shipped" | "processing";
export type Environment = "dev" | "staging" | "production";
export type DiffChange = "added" | "changed" | "removed" | "unchanged";
export type ToolName = "lookup_order" | "issue_refund" | "fetch_customer_data" | "run_shell" | "deploy" | "read_secret";
export type ApprovalStatus = "pending" | "approved" | "rejected";
export type ApprovalAction = "approve" | "reject";
export type StateUnit = "inr" | "deploys";
export type ErrorCode = "VALIDATION_ERROR" | "COMPILE_FAILED" | "AMBIGUITY_UNRESOLVED" | "POLICY_NOT_FOUND" | "REPORT_NOT_FOUND" | "CUSTOMER_NOT_FOUND" | "NO_ACTIVE_POLICY" | "POLICY_ALREADY_APPROVED" | "POLICY_NOT_ACTIVE" | "NO_REPORT" | "NETWORK_ERROR" | "BAD_JSON" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" | "INTERNAL_ERROR" | "SCENARIO_NOT_FOUND" | "APPROVAL_NOT_FOUND" | "APPROVAL_ALREADY_RESOLVED" | "CASE_NOT_FOUND" | "CASE_INVALID" | "VERSION_NOT_FOUND" | "IMPORT_INVALID" | "MODEL_UNAVAILABLE" | "ADMIN_REQUIRED" | "RATE_LIMITED" | "PAYLOAD_TOO_LARGE" | "BENCH_RUNNING" | "NO_BENCH";

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

export interface EnvApprovalParams {
  field: "environment";
  operator: "in";
  environments: Environment[];
}

export interface DeployRateParams {
  field: "deploy_count";
  max_count: number;
  window_hours: number;
  window_type: "rolling" | "calendar_day";
  scope: "environment";
}

export interface SecretProtectionParams {
  subject: "secret_values";
}

export interface CommandBlockParams {
  category: "destructive";
  mode: "denylist" | "allowlist";
}

export interface Clause {
  clause_id: string;
  source_sentence: string;
  kind: ClauseKind;
  action: ClauseAction;
  params: PerTxnParams | CumulativeParams | DataScopeParams | PreconditionParams | EnvApprovalParams | DeployRateParams | SecretProtectionParams | CommandBlockParams;
}

export interface RefundState {
  customer_id: string;
  refund_total_24h_inr: number;
  refund_count_24h: number;
  window_hours: number;
  subject?: string;
  unit?: StateUnit;
  total?: number;
  count?: number;
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
  scenario_id?: string;
  ticket_id?: string | null;
  approved_by?: string | null;
  dry_run?: boolean;
}

export interface ModelInfo {
  provider: "local" | "cloud" | "rules";
  label: string;
  model: string | null;
  host: string | null;
  location: ModelLocation;
  configured: boolean;
  available: boolean;
  last_checked_at: string | null;
  last_error: string | null;
  latency_ms: number | null;
}

export interface ModelsResponse {
  providers: ModelInfo[];
  order: string[];
  runtime_config_enabled: boolean;
}

export interface LocalModelConfig {
  base_url: string;
  model: string;
  api_key?: string | null;
}

export interface CompileAttempt {
  provider: CompilerProvider;
  model: string | null;
  ok: boolean;
  latency_ms: number;
  error: string | null;
}

export interface CompilerInfo {
  provider: CompilerProvider;
  model: string | null;
  location: ModelLocation;
  label: string;
  latency_ms: number;
  attempts: CompileAttempt[];
}

export interface ValidationCheck {
  check: string;
  passed: boolean;
  detail: string;
}

export interface ScenarioStatus {
  scenario_id: string;
  title: string;
  active_policy_version: number | null;
}

export interface Health {
  status: "ok";
  contract_version: string;
  llm_available: boolean;
  active_policy_version: number | null;
  service?: string;
  uptime_s?: number;
  scenarios?: ScenarioStatus[];
  models?: ModelInfo[];
  pending_approvals?: number;
  auto_armed?: boolean;
}

export interface ToolSpec {
  name: ToolName;
  description: string;
  params: Record<string, string>;
}

export interface Customer {
  customer_id: string;
  name: string;
  email?: string | null;
  role?: string | null;
}

export interface Order {
  order_id: string;
  customer_id: string;
  status: OrderStatus;
  amount_inr: number;
  item: string;
  note: string | null;
}

export interface Resource {
  resource_id: string;
  kind: string;
  name: string;
  detail: string | null;
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
  scenario_id?: string;
  title?: string;
  description?: string;
  actor_label?: string;
  resources?: Resource[];
  safe_presets?: AttackPreset[];
  clause_kinds?: ClauseKind[];
  supported_rules?: string;
}

export interface ScenarioSummary {
  scenario_id: string;
  title: string;
  description: string;
  actor_label: string;
  tools: string[];
  clause_kinds: ClauseKind[];
  active_policy_version: number | null;
  builtin_cases: number;
  custom_cases: number;
}

export interface ScenariosResponse {
  scenarios: ScenarioSummary[];
  default_scenario_id: string;
}

export interface CompileRequest {
  policy_text: string;
  mode?: CompileMode;
  scenario?: string;
  provider?: ProviderChoice | null;
  source?: PolicySource;
  proposal?: Record<string, unknown> | null;
  proposal_model?: string | null;
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
  scenario_id?: string;
  compiler?: CompilerInfo | null;
  validation?: ValidationCheck[];
  source?: PolicySource;
}

export interface AmbiguityAnswer {
  ambiguity_id: string;
  option_id: string;
}

export interface ApproveRequest {
  answers?: AmbiguityAnswer[];
  approved_by?: string | null;
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
  scenario_id?: string;
  compiler?: CompilerInfo | null;
  approved_by?: string;
  note?: string | null;
}

export interface PromptResponse {
  scenario_id: string;
  system_prompt: string;
  user_template: string;
  clause_kinds: ClauseKind[];
}

export interface PolicyHistoryResponse {
  scenario_id: string;
  versions: ApprovedPolicy[];
  active_policy_version: number | null;
}

export interface TextDiffLine {
  op: "same" | "add" | "remove";
  text: string;
}

export interface PolicyDiffResponse {
  scenario_id: string;
  from_version: number;
  to_version: number;
  clause_diff: DiffRow[];
  text_diff: TextDiffLine[];
  unified: string;
}

export interface PolicyBundle {
  format: "polyx.policy/v1";
  scenario_id: string;
  policy_version?: number | null;
  policy_text: string;
  clauses: Clause[];
  compiled_by?: CompiledBy | null;
  exported_at?: string | null;
  checksum?: string | null;
}

export interface RollbackRequest {
  scenario?: string;
  version: number;
  approved_by?: string | null;
}

export interface Approval {
  ticket_id: string;
  scenario_id: string;
  status: ApprovalStatus;
  created_at: string;
  decision_id: string;
  tool: string;
  args: Record<string, unknown>;
  session_customer_id: string;
  summary: string;
  clause_id: string | null;
  source_sentence: string | null;
  reason: string;
  policy_version: number | null;
  resolved_at: string | null;
  resolved_by: string | null;
  note: string | null;
  result_decision_id: string | null;
  result_outcome: Outcome | null;
  result_reason: string | null;
}

export interface ApprovalsResponse {
  approvals: Approval[];
  pending: number;
  total: number;
}

export interface ResolveRequest {
  action: ApprovalAction;
  approver?: string;
  note?: string | null;
}

export interface ApprovalResolution {
  approval: Approval;
  decision: Decision | null;
}

export interface ChatRequest {
  message: string;
  session_customer_id?: string | null;
  enforcement?: Enforcement;
  agent_mode?: AgentModeRequest;
  scenario?: string;
  provider?: ProviderChoice | null;
}

export interface ChatResponse {
  reply: string;
  agent_mode_used: AgentModeUsed;
  agent_note: string | null;
  enforcement: Enforcement;
  session_customer_id: string;
  decisions: Decision[];
  state: RefundState;
  scenario_id?: string;
  agent_model?: string | null;
  approvals?: Approval[];
}

export interface GuardRequest {
  tool: string;
  args?: Record<string, unknown>;
  scenario?: string;
  session_customer_id?: string | null;
  dry_run?: boolean;
}

export interface GuardResponse {
  allowed: boolean;
  outcome: Outcome;
  executed: boolean;
  clause_id: string | null;
  source_sentence: string | null;
  reason: string;
  ticket_id: string | null;
  policy_version: number | null;
  latency_ms: number;
  dry_run: boolean;
  decision: Decision;
}

export interface ResetRequest {
  scope?: string;
  scenario?: string | null;
}

export interface ResetResponse {
  scope: string;
  cleared_refunds: number;
  cleared_decisions: number;
  reset_at: string;
  cleared_approvals?: number;
}

export interface DecisionsResponse {
  decisions: Decision[];
  total: number;
  limit: number;
}

export interface CaseStep {
  tool: string;
  args: Record<string, unknown>;
  at_offset_hours?: number;
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
  scenario_id?: string;
  clause_kind?: ClauseKind | null;
  origin?: CaseOrigin;
  generated_by?: string | null;
}

export interface CasesResponse {
  cases: CaseSpec[];
  total: number;
  builtin?: number;
  custom?: number;
  scenario_id?: string;
}

export interface CaseCreate {
  scenario?: string;
  type: CaseType;
  title: string;
  description?: string;
  session_customer_id?: string | null;
  clause_kind?: ClauseKind | null;
  steps: CaseStep[];
  harm_step?: number | null;
  expected_outcomes?: Outcome[] | null;
}

export interface GenerateRequest {
  scenario?: string;
  count?: number;
  provider?: ProviderChoice | null;
  save?: boolean;
}

export interface GenerateResponse {
  scenario_id: string;
  generated_by: "llm" | "mutation";
  model: string | null;
  cases: CaseSpec[];
  uncaught: CaseSpec[];
  rejected: number;
  notes: string[];
}

export interface RunTestsRequest {
  policy_id?: string | null;
  scenario?: string;
  include_custom?: boolean;
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
  description?: string;
  origin?: CaseOrigin;
  clause_kind?: ClauseKind | null;
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
  scenario_id?: string;
  passed?: boolean;
  exit_code?: number;
  builtin_case_count?: number;
  custom_case_count?: number;
  failed_case_ids?: string[];
}

export interface CiRunRequest {
  policy_text: string;
  scenario?: string;
  provider?: ProviderChoice;
  answers?: AmbiguityAnswer[];
  clauses?: Clause[] | null;
  include_custom?: boolean;
}

export interface CiRunResponse {
  passed: boolean;
  exit_code: number;
  summary: string;
  report: TestReport;
  clauses: Clause[];
  answers: AmbiguityAnswer[];
  warnings: string[];
  junit_xml: string;
  markdown: string;
}

export interface AuditEvent {
  seq: number;
  timestamp: string;
  type: string;
  scenario_id: string | null;
  actor: string;
  summary: string;
  data: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditResponse {
  events: AuditEvent[];
  total: number;
  limit: number;
  head_hash: string;
  chain_valid: boolean;
}

export interface AuditVerifyResponse {
  chain_valid: boolean;
  events: number;
  head_hash: string;
  first_seq: number | null;
  broken_at_seq: number | null;
  algorithm: "sha256";
}

export interface BenchRequest {
  provider?: ProviderChoice;
  limit?: number;
}

export interface BenchItem {
  item_id: string;
  scenario_id: string;
  policy_text: string;
  expected_clauses: number;
  matched_clauses: number;
  exact: boolean;
  compiled_by: CompiledBy | null;
  provider: CompilerProvider | null;
  latency_ms: number;
  error: string | null;
}

export interface BenchStatus {
  bench_id: string;
  status: "running" | "done" | "failed";
  requested_provider: ProviderChoice;
  model: string | null;
  total: number;
  completed: number;
  exact_matches: number;
  clause_matches: number;
  clause_total: number;
  exact_match_rate: number;
  clause_match_rate: number;
  fell_back: number;
  median_latency_ms: number;
  started_at: string;
  finished_at: string | null;
  items: BenchItem[];
  note: string;
}
